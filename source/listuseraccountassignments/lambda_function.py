import json
import os
import boto3
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.config import Config
from botocore.exceptions import ClientError

# Reuse clients/resources across warm invocations. Adaptive retries absorb the
# throttling that comes with running many SSO Admin calls concurrently, and a
# larger connection pool lets threads make requests without contending for
# sockets.
BOTO_CONFIG = Config(
    retries={'max_attempts': 10, 'mode': 'adaptive'},
    max_pool_connections=50
)
sso_admin = boto3.client('sso-admin', config=BOTO_CONFIG)
dynamodb = boto3.resource('dynamodb')

# Number of principals processed concurrently. list_account_assignments_for_principal
# is I/O bound, so threading gives a near-linear speedup despite the GIL.
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


def get_instance_arn():
    # Get the IAM Identity Center instance ARN
    return sso_admin.list_instances()['Instances'][0]['InstanceArn']


def load_permission_set_names():
    # Load PermissionSetArn -> Name once so we never call get_item per assignment.
    permset_table = dynamodb.Table('AriaIdCPermissionSets')
    return {
        item['PermissionSetArn']: item.get('Name', 'N/A')
        for item in _scan_all(permset_table)
    }


def load_account_names():
    # Load AccountId -> Name once. This replaces the per-account API/scan work and
    # lets us resolve account names from the assignment response instead.
    accounts_table = dynamodb.Table('AriaIdCAccounts')
    return {
        item['AccountId']: item.get('Name', 'N/A')
        for item in _scan_all(accounts_table)
    }


def collect_assignments_for_user(user, instance_arn, permset_names, account_names):
    # Return all assignment rows for a single user across every account.
    #
    # The AccountId filter is intentionally omitted: a single paginated call to
    # list_account_assignments_for_principal returns the user's assignments in all
    # accounts. This collapses the previous users x accounts API explosion down to
    # one call per user, and the response already carries the AccountId.
    user_id = user['UserId']
    user_name = user.get('UserName', 'N/A')
    rows = []

    paginator = sso_admin.get_paginator('list_account_assignments_for_principal')
    for page in paginator.paginate(
        InstanceArn=instance_arn,
        PrincipalType='USER',
        PrincipalId=user_id
    ):
        for assignment in page['AccountAssignments']:
            account_id = assignment['AccountId']
            permset_arn = assignment['PermissionSetArn']
            rows.append({
                'AccountId': account_id,
                # Composite sort key that makes each (user, permission set) unique
                # within an account. UserId and PermissionSetArn are also stored as
                # their own attributes below for the graph export.
                'UserPermissionSet': f"{user_id}#{permset_arn}",
                'UserId': user_id,
                'PrincipalType': 'USER',
                'PrincipalName': user_name,
                'AccountName': account_names.get(account_id, 'N/A'),
                'PermissionSetArn': permset_arn,
                'Name': permset_names.get(permset_arn, 'N/A'),
                'UpdatedAt': datetime.now(timezone.utc).isoformat()
            })
    return rows


def empty_user_account_assignments_table(table):
    # Remove all existing rows before repopulating, so assignments that were
    # revoked since the last run do not linger as stale graph edges. The table is
    # fully rebuilt on every run.
    with table.batch_writer() as batch:
        for item in _scan_all(table, ProjectionExpression='AccountId, UserPermissionSet'):
            batch.delete_item(Key={
                'AccountId': item['AccountId'],
                'UserPermissionSet': item['UserPermissionSet']
            })


def list_account_assignments_for_users(instance_arn, context):
    # List all account assignments for users and store them in DynamoDB.
    print("Listing all account assignments for USER principals")

    table = dynamodb.Table('AriaIdCUserAccountAssignments')
    users = _scan_all(dynamodb.Table('AriaIdCUsers'))
    permset_names = load_permission_set_names()
    account_names = load_account_names()

    empty_user_account_assignments_table(table)

    total = len(users)
    processed = 0
    written = 0
    print(f"Processing {total} users with up to {MAX_WORKERS} workers")

    # batch_writer batches up to 25 writes per request and handles retries. It is
    # driven only from this main thread, so it stays thread-safe while worker
    # threads perform the (read-only) API lookups.
    #
    # overwrite_by_pkeys de-duplicates the buffer on the full primary key so that
    # any repeated (AccountId, UserPermissionSet) within a flush window cannot
    # trigger the "list of item keys contains duplicates" BatchWriteItem error.
    with table.batch_writer(overwrite_by_pkeys=['AccountId', 'UserPermissionSet']) as batch:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for chunk in _chunk(users, MAX_WORKERS):
                if context is not None and context.get_remaining_time_in_millis() < RUNTIME_SAFETY_BUFFER_MS:
                    print(f"Approaching Lambda timeout; stopping after {processed}/{total} users")
                    break

                future_to_user = {
                    executor.submit(
                        collect_assignments_for_user, user, instance_arn, permset_names, account_names
                    ): user
                    for user in chunk
                }
                for future in as_completed(future_to_user):
                    user = future_to_user[future]
                    try:
                        for row in future.result():
                            batch.put_item(Item=row)
                            written += 1
                    except Exception as e:
                        print(f"Error processing assignments for user {user.get('UserId')}: {e}")
                processed += len(chunk)

    print(f"Wrote {written} assignment rows for {processed}/{total} users")
    return processed, total


def lambda_handler(event, context):

    instance_arn = get_instance_arn()

    # List account assignments for all users
    try:
        processed, total = list_account_assignments_for_users(instance_arn, context)
        complete = processed >= total
        message = f"Listed account assignments for {processed}/{total} USER principals"
        print(message)
        return {
            'statusCode': 200,
            'body': json.dumps({'message': message, 'complete': complete})
        }
    except Exception as e:
        print(f"Error listing account assignments for USER principals: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error listing account assignments for USER principals: {str(e)}")
        }
