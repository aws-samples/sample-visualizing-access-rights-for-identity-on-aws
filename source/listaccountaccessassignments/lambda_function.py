import json
import os
import boto3
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.config import Config
from botocore.exceptions import ClientError

# Reuse clients/resources across warm invocations. Adaptive retries absorb the
# throttling that comes with running many Account Access Manager calls
# concurrently, and a larger connection pool lets threads make requests without
# contending for sockets.
#
# NOTE: the 'account-access' service model is recent. The Lambda runtime's
# bundled boto3 may predate it and not expose this client, in which case an
# up-to-date boto3/botocore must be bundled in the deployment package
BOTO_CONFIG = Config(
    retries={'max_attempts': 10, 'mode': 'adaptive'},
    max_pool_connections=50
)
account_access = boto3.client('account-access', config=BOTO_CONFIG)
dynamodb = boto3.resource('dynamodb')

# Number of principals processed concurrently. list_entitlements is I/O bound,
# so threading gives a near-linear speedup despite the GIL.
MAX_WORKERS = int(os.environ.get('MAX_WORKERS', '15'))

# Stop submitting new work once fewer than this many milliseconds remain, so
# in-flight results can still be flushed to DynamoDB before the Lambda timeout.
RUNTIME_SAFETY_BUFFER_MS = 30_000


def _scan_all(table, **kwargs):
    # Scan a table fully, following pagination. A plain table.scan() only returns
    # the first 1 MB page, which silently drops data on larger tables.
    items = []
    response = table.scan(**kwargs)
    items.extend(response.get('Items', []))
    while 'LastEvaluatedKey' in response:
        response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'], **kwargs)
        items.extend(response.get('Items', []))
    return items


def _chunk(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]

def get_application_arn():
    # Resolve the Account Access Manager application ARN that scopes
    # list_entitlements. Discovery is preferred: list_applications() returns the
    # org instance's applications and we take the first applicationArn. An optional
    # AAM_APPLICATION_ARN environment variable is used as a fallback/override when
    # discovery returns nothing or is unavailable.
    #
    # Returning a false value (None) is deliberate: it signals "AAM not enabled /
    # no application found" so lambda_handler can be a graceful no-op rather than
    # failing the collection workflow (Requirement 1.5).
    try:
        # list_applications is paginated; a single call only returns the first
        # page, which can silently miss applications on later pages. Follow the
        # NextToken chain and return the first applicationArn we encounter.
        next_token = None
        while True:
            kwargs = {'nextToken': next_token} if next_token else {}
            response = account_access.list_applications(**kwargs)
            for application in response.get('applications', []):
                application_arn = application.get('applicationArn')
                if application_arn:
                    return application_arn
            next_token = response.get('nextToken')
            if not next_token:
                break
        print("No Account Access Manager application found via list_applications")
    except ClientError as e:
        print(f"Error discovering Account Access Manager application ARN: {e}")
    except Exception as e:
        print(f"Unexpected error discovering Account Access Manager application ARN: {e}")

    # Fallback/override: an operator-supplied application ARN. Empty/unset yields
    # a falsy return so the handler no-ops.
    return os.environ.get('AAM_APPLICATION_ARN')


def load_principal_names():
    # Load principal id -> name maps once from the already-collected IdC tables so
    # entitlement rows can be labelled without any Identity Store API calls
    # (Requirement 2.4). This mirrors load_permission_set_names / load_account_names
    # in listuseraccountassignments: a single full scan of each dependency table
    # into an in-memory dict, rather than a get_item per entitlement.
    #
    # Attribute names are taken verbatim from the collection Lambdas that populate
    # these tables (source/listusers and source/listgroups):
    #   AriaIdCUsers : key 'UserId',  name 'UserName'
    #   AriaIdCGroups: key 'GroupId', name 'GroupName'
    #
    # Returns a (user_names, group_names) tuple of {id: name} dicts. Missing names
    # fall back to 'N/A' so a partially populated row never carries a null; callers
    # that hit an id absent from these dicts also fall back to 'N/A' (Requirement 2.3).
    users_table = dynamodb.Table('AriaIdCUsers')
    groups_table = dynamodb.Table('AriaIdCGroups')

    user_names = {
        item['UserId']: item.get('UserName', 'N/A')
        for item in _scan_all(users_table)
    }
    group_names = {
        item['GroupId']: item.get('GroupName', 'N/A')
        for item in _scan_all(groups_table)
    }
    return user_names, group_names


def build_role_arn(account_id, role_name, path='/'):
    # Defensive fallback for an entitlement that carries a role name + path
    # instead of a full ARN. The confirmed SDK model always returns a full
    # `roleArn` (path embedded), so this is not exercised by the current API, but
    # Requirement 1.3 mandates a construction path so role identity stays
    # consistent if the shape ever changes.
    #
    # The IAM role path must be preserved and must both start and end with '/'
    # (e.g. '/', '/team/', '/team/sub/'), yielding
    # arn:aws:iam::<accountId>:role<path><roleName>.
    if not path:
        path = '/'
    if not path.startswith('/'):
        path = '/' + path
    if not path.endswith('/'):
        path = path + '/'
    return f"arn:aws:iam::{account_id}:role{path}{role_name}"


def _resolve_role_arn(principal_role):
    # Prefer the full ARN the API returns (path already embedded); fall back to
    # constructing it only when the ARN is absent. RoleName/path attribute names
    # are best-effort since the confirmed model exposes only `roleArn`.
    role_arn = principal_role.get('roleArn')
    if role_arn:
        return role_arn

    role_name = principal_role.get('roleName', '')
    if not role_name:
        return None
    account_id = principal_role.get('account', '')
    path = principal_role.get('rolePath') or principal_role.get('path') or '/'
    return build_role_arn(account_id, role_name, path)


def _entitlement_filter(principal_type, principal_id):
    # list_entitlements REQUIRES a filter; there is no unfiltered scan-all. The
    # principal dimension is set via the Identity Center id, and PrincipalType is
    # derived from which key is populated (userId => USER, groupId => GROUP) since
    # the model carries no explicit type field.
    key = 'userId' if principal_type == 'USER' else 'groupId'
    return {
        'principalRole': {
            'principal': {'identityCenter': {key: principal_id}}
        }
    }


def collect_entitlements_for_principal(app_arn, principal_id, principal_type, principal_name):
    # Return all AAM entitlement rows for a single principal, following pagination
    # fully. One filtered list_entitlements call covers every account the
    # principal is entitled into; the response carries the account id and a full
    # role ARN per entitlement.
    rows = []
    entitlement_filter = _entitlement_filter(principal_type, principal_id)
    paginator = account_access.get_paginator('list_entitlements')
    for page in paginator.paginate(applicationArn=app_arn, filter=entitlement_filter):
        for member in page.get('entitlements', []):
            principal_role = member.get('entitlement', {}).get('principalRole', {})
            role_arn = _resolve_role_arn(principal_role)
            if not role_arn:
                # No usable role reference; skip rather than store a keyless row.
                print(f"Skipping entitlement for {principal_type} {principal_id} with no role ARN")
                continue
            account_id = principal_role.get('account', '')
            rows.append({
                'PrincipalId': principal_id,
                'IamRoleArn': role_arn,
                'PrincipalType': principal_type,
                'PrincipalName': principal_name or 'N/A',
                # RoleName is the final ARN segment, preserving any embedded path.
                'RoleName': role_arn.split('/')[-1],
                'AccountId': account_id,
                'Source': 'AccountAccessManager',
                'UpdatedAt': datetime.now(timezone.utc).isoformat()
            })
    return rows


def collect_entitlements(app_arn, principal_names):
    # Fan out list_entitlements per known principal because a filter is mandatory
    # (no unfiltered scan-all). The principal ids come from the AriaIdCUsers /
    # AriaIdCGroups data already loaded for name resolution, so no extra scan is
    # needed and every id is labelled without an Identity Store call.
    #
    # principal_names is the (user_names, group_names) tuple from
    # load_principal_names(). USER ids resolve to their user name, GROUP ids to
    # their group name; a name missing from the dict falls back to 'N/A'
    # (Requirement 2.3). I/O-bound calls are parallelised with the same
    # ThreadPoolExecutor(MAX_WORKERS) pattern used by listuseraccountassignments.
    user_names, group_names = principal_names
    principals = [
        (pid, 'USER', name) for pid, name in user_names.items()
    ] + [
        (pid, 'GROUP', name) for pid, name in group_names.items()
    ]

    rows = []
    print(f"Collecting entitlements for {len(principals)} principals with up to {MAX_WORKERS} workers")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_principal = {
            executor.submit(
                collect_entitlements_for_principal, app_arn, pid, ptype, pname
            ): (pid, ptype)
            for pid, ptype, pname in principals
        }
        for future in as_completed(future_to_principal):
            pid, ptype = future_to_principal[future]
            try:
                rows.extend(future.result())
            except Exception as e:
                print(f"Error collecting entitlements for {ptype} {pid}: {e}")

    print(f"Collected {len(rows)} entitlement rows")
    return rows


def empty_table(table):
    # Remove all existing rows before repopulating, so entitlements revoked since
    # the last run do not linger as stale rows or graph edges. The table is fully
    # rebuilt on every run (Requirement 3.3). This mirrors the empty-then-rebuild
    # strategy in listuseraccountassignments: scan only the key attributes, then
    # batch-delete via a main-thread batch_writer.
    #
    # The AriaIdCAccountAccessAssignments key schema is PrincipalId (HASH) +
    # IamRoleArn (RANGE), so both are projected and supplied to delete_item.
    with table.batch_writer() as batch:
        for item in _scan_all(table, ProjectionExpression='PrincipalId, IamRoleArn'):
            batch.delete_item(Key={
                'PrincipalId': item['PrincipalId'],
                'IamRoleArn': item['IamRoleArn']
            })


def lambda_handler(event, context):
    # Resolve the AAM application ARN first. A falsy result means Account Access
    # Manager is not enabled / no application exists in this region, so the
    # function is a graceful no-op: it returns success and leaves the table empty
    # rather than failing the collection workflow (Requirement 1.5).
    try:
        app_arn = get_application_arn()
        if not app_arn:
            message = "No Account Access Manager application found; nothing to collect"
            print(message)
            return {
                'statusCode': 200,
                'body': json.dumps({'message': message, 'complete': True})
            }

        # Names come only from the already-collected IdC tables (no Identity Store
        # calls), then entitlements are gathered per principal.
        principal_names = load_principal_names()
        rows = collect_entitlements(app_arn, principal_names)

        # Empty then rebuild so revoked entitlements do not persist as stale rows,
        # storing one item per (PrincipalId, IamRoleArn) pair (Requirements 3.2,
        # 3.3, 3.4).
        table = dynamodb.Table('AriaIdCAccountAccessAssignments')
        empty_table(table)

        total = len(rows)
        written = 0
        complete = True

        # batch_writer batches up to 25 writes per request and handles retries; it
        # is driven only from this main thread. overwrite_by_pkeys de-duplicates
        # the buffer on the full primary key so a repeated (PrincipalId, IamRoleArn)
        # within a flush window cannot trigger the BatchWriteItem duplicate-key
        # error. The RUNTIME_SAFETY_BUFFER_MS guard stops writing before the Lambda
        # deadline and reports the partial run via the complete flag.
        with table.batch_writer(overwrite_by_pkeys=['PrincipalId', 'IamRoleArn']) as batch:
            for row in rows:
                if context is not None and context.get_remaining_time_in_millis() < RUNTIME_SAFETY_BUFFER_MS:
                    print(f"Approaching Lambda timeout; stopping after {written}/{total} entitlement rows")
                    complete = False
                    break
                batch.put_item(Item=row)
                written += 1

        message = f"Stored {written}/{total} Account Access Manager entitlement rows"
        print(message)
        return {
            'statusCode': 200,
            'body': json.dumps({'message': message, 'complete': complete})
        }
    except Exception as e:
        print(f"Error collecting Account Access Manager entitlements: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error collecting Account Access Manager entitlements: {str(e)}")
        }
