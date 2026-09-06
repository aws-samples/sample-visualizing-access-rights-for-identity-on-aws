import json
import os
import re
from urllib.parse import unquote
import boto3
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.config import Config
from botocore.exceptions import ClientError

# Role to assume in member accounts (created via StackSet, must exist in all accounts)
ROLE_TO_ASSUME = 'AriaIdCInventoryAccessRole-LimitedReadOnly'

# Reuse clients/resources across warm invocations. Adaptive retries absorb the
# throttling from running many STS/IAM calls concurrently.
BOTO_CONFIG = Config(
    retries={'max_attempts': 10, 'mode': 'adaptive'},
    max_pool_connections=50
)
sts_client = boto3.client('sts', config=BOTO_CONFIG)
dynamodb = boto3.resource('dynamodb')

# Accounts processed concurrently. The per-account work (assume role, list roles,
# list attached policies) is I/O bound, so threading is the largest wall-clock win.
MAX_WORKERS = int(os.environ.get('MAX_WORKERS', '10'))

# Stop submitting new work once fewer than this many milliseconds remain, so
# in-flight results can still be flushed to DynamoDB before the Lambda timeout.
RUNTIME_SAFETY_BUFFER_MS = 30_000

# Length of the trailing "_<random-suffix>" that IAM Identity Center appends to
# AWSReservedSSO_<PermissionSetName> role names.
SSO_ROLE_SUFFIX_LEN = 17

# sts:AssumeRole-family actions, lowercased for case-insensitive matching. Used
# both for the trust-policy Action gate and the permission-policy chain-capable test.
ASSUME_ROLE_ACTIONS = {'sts:assumerole', 'sts:assumerolewithsaml', 'sts:assumerolewithwebidentity'}

# Principal ARN classification patterns for normalize_principal. Account ids are
# 12 digits; the role/user name segment may itself contain a path with slashes,
# so it is matched greedily and left unchanged. The assumed-role pattern captures
# the account and role so the session segment can be discarded during
# normalization to the underlying IAM role ARN.
_ACCOUNT_ROOT_RE = re.compile(r'^arn:aws:iam::\d{12}:root$')
_IAM_ROLE_RE = re.compile(r'^arn:aws:iam::\d{12}:role/.+$')
_IAM_USER_RE = re.compile(r'^arn:aws:iam::\d{12}:user/.+$')
_STS_ASSUMED_ROLE_RE = re.compile(
    r'^arn:aws:sts::(?P<account>\d{12}):assumed-role/(?P<role>[^/]+)/.+$'
)


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


def assume_role(account_id, role_name):
    # Assume a role in the target account
    try:
        response = sts_client.assume_role(
            RoleArn=f'arn:aws:iam::{account_id}:role/{role_name}',
            RoleSessionName='ListSSORolesSession'
        )
        return response['Credentials']
    except ClientError as e:
        print(f"Error assuming role in account {account_id}: {e}")
        return None


def parse_trust_document(raw_document):
    # Return the trust policy as a dict. list_roles returns
    # AssumeRolePolicyDocument as URL-encoded JSON, so unquote then json.loads.
    # Boto3 may also hand back an already-decoded dict; accept both. Returns {}
    # on any decode error so a malformed document yields no principals rather
    # than raising.
    if isinstance(raw_document, dict):
        return raw_document
    try:
        return json.loads(unquote(raw_document))
    except (json.JSONDecodeError, TypeError):
        return {}


def normalize_principal(principal_value):
    # Map a single Principal.AWS value to a qualifying IAM role/user ARN, or None
    # if it should be dropped. See the design's "Principal Normalization
    # Algorithm" (Req 3.2, 3.3, 3.4, 3.5).
    #
    # Kept  : arn:aws:iam::<acct>:role/<path/name>   (IAM role ARN)
    #         arn:aws:iam::<acct>:user/<path/name>   (IAM user ARN)
    # Mapped: arn:aws:sts::<acct>:assumed-role/<role>/<session>
    #           -> arn:aws:iam::<acct>:role/<role>   (session discarded)
    # Dropped (-> None): "*" wildcard, account-root (arn:aws:iam::<acct>:root),
    #         bare 12-digit account ids, SAML/OIDC providers, federated-user,
    #         and any other non-matching form.
    if not isinstance(principal_value, str):
        return None

    value = principal_value.strip()

    # Wildcard.
    if value == '*':
        return None

    # Account-root: arn:aws:iam::<account>:root.
    if _ACCOUNT_ROOT_RE.match(value):
        return None

    # IAM role or user ARN: keep unchanged. The <path/name> may contain slashes
    # for a role/user path, so match the remainder greedily.
    if _IAM_ROLE_RE.match(value) or _IAM_USER_RE.match(value):
        return value

    # STS assumed-role ARN: normalize to the underlying IAM role ARN, discarding
    # the trailing session segment.
    assumed = _STS_ASSUMED_ROLE_RE.match(value)
    if assumed:
        account = assumed.group('account')
        role = assumed.group('role')
        return f'arn:aws:iam::{account}:role/{role}'

    # Everything else (bare account id, SAML/OIDC provider, federated-user, any
    # unrecognized form) is not a qualifying principal.
    return None


def extract_qualifying_principals(trust_document):
    # Walk the trust policy's statements and collect the set of qualifying IAM
    # role/user principal ARNs (Req 3.1, 3.6).
    #
    # For each Effect==Allow statement whose Action (string or list, compared
    # case-insensitively) intersects ASSUME_ROLE_ACTIONS, read Principal.AWS
    # (string or list), run each value through normalize_principal, and collect
    # the non-None results into a set. Only the AWS key of Principal is
    # considered; Service / Federated / CanonicalUser keys are ignored (Req 3.3).
    #
    # A non-empty result also serves as the cheap first gate of the chain-capable
    # test: it means the role trusts at least one concrete IAM principal.
    principals = set()
    if not isinstance(trust_document, dict):
        return principals

    statements = trust_document.get('Statement')
    if statements is None:
        return principals
    # Coerce a single-object Statement into a one-element list.
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return principals

    for statement in statements:
        if not isinstance(statement, dict):
            continue
        if statement.get('Effect') != 'Allow':
            continue
        if not _action_grants_assume_role(statement.get('Action')):
            continue

        principal = statement.get('Principal')
        if not isinstance(principal, dict):
            # A bare "*" Principal (string) or NotPrincipal is not a qualifying
            # AWS principal.
            continue

        aws_principals = principal.get('AWS')
        if aws_principals is None:
            continue
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        elif not isinstance(aws_principals, list):
            continue

        for candidate in aws_principals:
            normalized = normalize_principal(candidate)
            if normalized is not None:
                principals.add(normalized)

    return principals


def _action_grants_assume_role(action):
    # True if the statement's Action (string or list) contains at least one
    # sts:AssumeRole-family action, compared case-insensitively. Used as the
    # trust-policy Action gate in extract_qualifying_principals (Req 3.1).
    if isinstance(action, str):
        actions = [action]
    elif isinstance(action, list):
        actions = action
    else:
        return False
    for entry in actions:
        if isinstance(entry, str) and entry.lower() in ASSUME_ROLE_ACTIONS:
            return True
    return False


def parse_arn_identity(arn):
    # Parse account id and trailing name from an IAM role/user ARN. See the
    # design's "ARN identity parse" algorithm (Req 4.2, 5.4).
    #   arn:aws:iam::<acct>:role/<path.../><name>  or  .../user/<path.../><name>
    # AccountId is the 5th ':'-delimited field. Name is the last '/'-segment of
    # the resource (path-aware). Returns (account_id, name) or (None, None) if
    # the ARN does not match a role/user shape.
    if not isinstance(arn, str):
        return None, None
    fields = arn.split(':')
    if len(fields) != 6 or fields[0:3] != ['arn', 'aws', 'iam']:
        return None, None
    account_id = fields[4]
    resource = fields[5]
    if not (resource.startswith('role/') or resource.startswith('user/')):
        return None, None
    name = resource.split('/')[-1]
    if re.fullmatch(r'\d{12}', account_id) and name:
        return account_id, name
    return None, None


def classify_principal(arn):
    # Classify a normalized qualifying ARN as 'role', 'user', or None using the
    # same regexes used by normalize_principal (_IAM_ROLE_RE / _IAM_USER_RE).
    # See the design's "Principal classification" algorithm.
    if _IAM_ROLE_RE.match(arn):
        return 'role'
    if _IAM_USER_RE.match(arn):
        return 'user'
    return None


def list_all_roles_in_account(credentials, account_id):
    # List EVERY IAM role in the account via the list_roles paginator (no name
    # filter). list_roles returns AssumeRolePolicyDocument on each role object,
    # so no per-role get_role call is needed; attached policies are read per role
    # via list_attached_role_policies, as today (Req 1.1).
    #
    # Returns [{'AccountId','RoleName','RoleId','Arn','AttachedPolicies',
    #           'CreateDate','AssumeRolePolicyDocument'}].
    if not credentials:
        return []

    iam = boto3.client(
        'iam',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        config=BOTO_CONFIG
    )

    try:
        roles = []
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                # Wrap per-role work so a malformed/failing single role is logged
                # and skipped without aborting the whole account (Req 1.9).
                try:
                    policies = iam.list_attached_role_policies(RoleName=role['RoleName'])
                    roles.append({
                        'AccountId': account_id,
                        'RoleName': role['RoleName'],
                        'RoleId': role['RoleId'],
                        'Arn': role['Arn'],
                        'AttachedPolicies': [p['PolicyName'] for p in policies['AttachedPolicies']],
                        'CreateDate': role['CreateDate'],
                        'AssumeRolePolicyDocument': role.get('AssumeRolePolicyDocument')
                    })
                except Exception as e:
                    print(f"Error processing role {role.get('RoleName')} in account {account_id}: {e}")
        return roles
    except ClientError as e:
        print(f"Error listing roles in account {account_id}: {e}")
        return []


def build_provisioned_permission_set_index():
    # Scan AriaIdCProvisionedPermissionSets once and index it as
    # AccountId -> {PermissionSetName: PermissionSetArn}.
    #
    # The previous approach ran a filtered full-table scan per account (AccountId
    # is the sort key, not the partition key, so it could not be queried directly).
    # A single scan plus an in-memory dict removes that accounts x scans cost and
    # turns the per-role lookup into O(1).
    table = dynamodb.Table('AriaIdCProvisionedPermissionSets')
    index = {}
    for item in _scan_all(table):
        account_id = item.get('AccountId')
        if account_id is None:
            continue
        index.setdefault(account_id, {})[item.get('PermissionSetName')] = item.get('PermissionSetArn')
    return index


def build_role_item(role, permset_index):
    # Build the enriched AriaIdCIAMRoles item for one enumerated role (role is a
    # dict from list_all_roles_in_account). See the design's "Components >
    # GetIAMRoles build_role_item" and the "enriched enumerated role" data model.
    #
    # TrustedPrincipals is always present: a sorted list of the normalized
    # qualifying principal ARNs, possibly empty (Req 2.2). It is what drives the
    # CAN_ASSUME edges downstream.
    #
    # TrustPolicyDocument (the decoded trust policy as a JSON string, Req 2.1) is
    # stored ONLY for roles that yield at least one qualifying trusted principal
    # (TrustedPrincipals non-empty). Most roles trust only AWS services,
    # account-root, or federated providers and yield no qualifying principals;
    # the raw trust document is the largest per-item payload, so omitting it for
    # those roles cuts item size and in-memory footprint at large-org scale.
    # Because TrustedPrincipals (not the raw document) drives the CAN_ASSUME
    # edges, dropping the document for non-trusting roles loses no graph data.
    # Req 2.1's "store the raw trust document" therefore now applies only to
    # roles with qualifying principals.
    #
    # Source is 'PermissionSet' for SSO roles else 'IAM' (Req 3.1, 3.2). SSO
    # roles derive PermissionSetName/PermissionSetArn from permset_index; non-SSO
    # roles keep the existing 'N/A' convention (Req 3.4, 3.5).
    account_id = role['AccountId']
    role_name = role['RoleName']

    # Parse the trust document once and compute the qualifying principals first,
    # so the stored-document decision can key off whether any principals qualify.
    trust_document = parse_trust_document(role.get('AssumeRolePolicyDocument'))
    trusted_principals = sorted(extract_qualifying_principals(trust_document))

    if role_name.startswith('AWSReservedSSO_'):
        source = 'PermissionSet'
        # Strip the "AWSReservedSSO_" prefix and the trailing "_<suffix>",
        # exactly as collect_roles_for_account does.
        permsetname = role_name.replace('AWSReservedSSO_', '')[:-SSO_ROLE_SUFFIX_LEN]
        permsetarn = permset_index.get(account_id, {}).get(permsetname, 'N/A')
    else:
        source = 'IAM'
        permsetname = 'N/A'
        permsetarn = 'N/A'

    item = {
        'IamRoleArn': role['Arn'],
        'RoleName': role_name,
        'AccountId': account_id,
        'RoleId': role['RoleId'],
        'AttachedPolicies': role['AttachedPolicies'],
        'CreateDate': role['CreateDate'].isoformat(),
        'TrustedPrincipals': trusted_principals,
        'Source': source,
        'PermissionSetName': permsetname,
        'PermissionSetArn': permsetarn
    }

    # Store the raw trust document only when the role actually yields qualifying
    # principals; roles with no qualifying principals omit the attribute entirely
    # (not an empty string or "{}").
    if trusted_principals:
        item['TrustPolicyDocument'] = json.dumps(trust_document)

    return item


def build_role_stub(arn):
    # Minimal backfill role item for a trusted IAM-role principal that was not
    # otherwise enumerated. See the design's "backfilled role stub" data model
    # (Req 4.1, 4.2, 4.3). RoleName and AccountId are parsed from the ARN;
    # trust, permission-set, and attached-policy attributes are intentionally
    # absent. Source is 'TrustPolicy'.
    account_id, name = parse_arn_identity(arn)
    return {
        'IamRoleArn': arn,
        'RoleName': name,
        'AccountId': account_id,
        'Source': 'TrustPolicy'
    }


def build_user_stub(arn):
    # Minimal backfill user item for a trusted IAM-user principal. See the
    # design's "backfilled user stub" data model (Req 5.3, 5.4). UserName and
    # AccountId are parsed from the ARN; Source is 'TrustPolicy'.
    account_id, name = parse_arn_identity(arn)
    return {
        'IamUserArn': arn,
        'UserName': name,
        'AccountId': account_id,
        'Source': 'TrustPolicy'
    }


def compute_backfill(enumerated_arns, trusted_principals):
    # Pure function computing the backfill stubs from the full enumerated set and
    # the union of trusted principals across all roles. See the design's
    # "Components > GetIAMRoles compute_backfill" and the "Backfill dedupe"
    # algorithm (Req 4.1, 4.4, 5.3, 5.5).
    #
    #   enumerated_arns:     set of IamRoleArn of enumerated roles (E)
    #   trusted_principals:  set/iterable of normalized qualifying ARNs (T)
    #
    # T is partitioned by classify_principal into role-typed and user-typed ARNs.
    # Role stubs are produced only for trusted role ARNs not already enumerated
    # (T_role - E), so enumerated roles win over stubs (Req 4.4, Property 5).
    # User-typed ARNs route only to user stubs, and role-typed ARNs only to role
    # stubs (Property 6). Sorting yields deterministic output, and set semantics
    # mean a principal trusted by many roles yields at most one stub.
    t_role = {a for a in trusted_principals if classify_principal(a) == 'role'}
    t_user = {a for a in trusted_principals if classify_principal(a) == 'user'}

    role_stubs = [build_role_stub(a) for a in sorted(t_role - enumerated_arns)]
    user_stubs = [build_user_stub(a) for a in sorted(t_user)]
    return role_stubs, user_stubs


def collect_roles_for_account(account_id, permset_index):
    # Assume into the account, list EVERY IAM role, and build one enriched item
    # per enumerated role via build_role_item. See the design's "Components >
    # GetIAMRoles collect_roles_for_account" (Req 1.1, 1.2). Runs inside a worker
    # thread; performs only reads (no DynamoDB writes). Per-role resilience
    # already lives in list_all_roles_in_account (Req 1.9).
    credentials = assume_role(account_id, ROLE_TO_ASSUME)
    roles = list_all_roles_in_account(credentials, account_id)
    return [build_role_item(role, permset_index) for role in roles]


def empty_iam_roles_table():
    # Empty the IAM roles table before repopulating it.
    table = dynamodb.Table('AriaIdCIAMRoles')
    with table.batch_writer() as batch:
        for item in _scan_all(table, ProjectionExpression='IamRoleArn'):
            batch.delete_item(Key={'IamRoleArn': item['IamRoleArn']})


def empty_iam_users_table():
    # Empty the IAM users table before repopulating it, following the
    # Empty_Then_Rebuild pattern (Req 5). Mirrors empty_iam_roles_table but
    # deletes by the IamUserArn key.
    table = dynamodb.Table('AriaIdCIAMUsers')
    with table.batch_writer() as batch:
        for item in _scan_all(table, ProjectionExpression='IamUserArn'):
            batch.delete_item(Key={'IamUserArn': item['IamUserArn']})


def lambda_handler(event, context):
    # Two-phase collect-then-backfill write model (see the design's "GetIAMRoles
    # two-phase collect-then-backfill write model"). The collect phase fans out
    # per account on worker threads that only READ; the main thread accumulates
    # all enumerated items, the full set of enumerated role ARNs, and the union
    # of trusted principals. Only AFTER collection completes are the destination
    # tables emptied and rewritten, so a failed or truncated collect never blanks
    # a table before its replacement data exists (Req 1.7, 4.4).

    # Build the permission-set lookup index once, up front.
    permset_index = build_provisioned_permission_set_index()

    accounts_table = dynamodb.Table('AriaIdCAccounts')
    account_ids = [item['AccountId'] for item in _scan_all(accounts_table, ProjectionExpression='AccountId')]
    total = len(account_ids)
    processed = 0
    print(f"Processing {total} accounts with up to {MAX_WORKERS} workers")

    # --- Collect phase (threaded, read-only workers) ---
    enumerated_items = []
    enumerated_arns = set()
    trusted = set()
    complete = True

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for chunk in _chunk(account_ids, MAX_WORKERS):
            if context is not None and context.get_remaining_time_in_millis() < RUNTIME_SAFETY_BUFFER_MS:
                print(f"Approaching Lambda timeout; stopping after {processed}/{total} accounts")
                complete = False
                break

            future_to_account = {
                executor.submit(collect_roles_for_account, account_id, permset_index): account_id
                for account_id in chunk
            }
            for future in as_completed(future_to_account):
                account_id = future_to_account[future]
                try:
                    for item in future.result():
                        enumerated_items.append(item)
                        enumerated_arns.add(item['IamRoleArn'])
                        trusted.update(item.get('TrustedPrincipals', []))
                except Exception as e:
                    print(f"Error processing account {account_id}: {e}")
            processed += len(chunk)

    # --- Backfill compute phase (pure, main thread) ---
    role_stubs, user_stubs = compute_backfill(enumerated_arns, trusted)

    # --- Write phase (main thread, AFTER the collect loop) ---
    # Empty-then-rebuild happens only now, so a failed/truncated collect never
    # blanks a table before replacement data exists (critical ordering).
    empty_iam_roles_table()
    empty_iam_users_table()

    with dynamodb.Table('AriaIdCIAMRoles').batch_writer(overwrite_by_pkeys=['IamRoleArn']) as batch:
        for item in enumerated_items:
            batch.put_item(Item=item)
        for item in role_stubs:
            batch.put_item(Item=item)

    with dynamodb.Table('AriaIdCIAMUsers').batch_writer(overwrite_by_pkeys=['IamUserArn']) as batch:
        for item in user_stubs:
            batch.put_item(Item=item)

    message = (
        f"Wrote {len(enumerated_items)} enumerated roles, {len(role_stubs)} role stubs, "
        f"{len(user_stubs)} user stubs across {processed}/{total} accounts"
    )
    print(message)
    return {
        'statusCode': 200,
        'body': json.dumps({'message': message, 'complete': complete})
    }
