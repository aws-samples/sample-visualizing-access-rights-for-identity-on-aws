import json
import os
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


def list_idc_roles_in_account(credentials, account_id):
    # List IAM roles created by IAM Identity Center in a specific account
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
        idc_roles = []
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                if role['RoleName'].startswith('AWSReservedSSO_'):
                    # Get attached policies
                    policies = iam.list_attached_role_policies(RoleName=role['RoleName'])
                    idc_roles.append({
                        'AccountId': account_id,
                        'RoleName': role['RoleName'],
                        'RoleId': role['RoleId'],
                        'Arn': role['Arn'],
                        'AttachedPolicies': [p['PolicyName'] for p in policies['AttachedPolicies']],
                        'CreateDate': role['CreateDate']
                    })
        return idc_roles
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


def collect_roles_for_account(account_id, permset_index):
    # Assume into the account, list its Identity Center roles, and build the rows
    # to write. Runs inside a worker thread; performs only reads.
    credentials = assume_role(account_id, ROLE_TO_ASSUME)
    idc_roles = list_idc_roles_in_account(credentials, account_id)
    account_permsets = permset_index.get(account_id, {})

    items = []
    for role in idc_roles:
        # Strip the "AWSReservedSSO_" prefix and the trailing "_<suffix>".
        permsetname = role['RoleName'].replace('AWSReservedSSO_', '')[:-SSO_ROLE_SUFFIX_LEN]
        # Default to 'N/A' when there is no matching provisioned permission set,
        # rather than leaving the value unbound or stale from a previous role.
        permsetarn = account_permsets.get(permsetname, 'N/A')

        items.append({
            'IamRoleArn': role['Arn'],
            'RoleName': role['RoleName'],
            'AccountId': role['AccountId'],
            'RoleId': role['RoleId'],
            'AttachedPolicies': role['AttachedPolicies'],
            'PermissionSetName': permsetname,
            'PermissionSetArn': permsetarn,
            'CreateDate': role['CreateDate'].isoformat()
        })
    return items


def empty_iam_roles_table():
    # Empty the IAM roles table before repopulating it.
    table = dynamodb.Table('AriaIdCIAMRoles')
    with table.batch_writer() as batch:
        for item in _scan_all(table, ProjectionExpression='IamRoleArn'):
            batch.delete_item(Key={'IamRoleArn': item['IamRoleArn']})


def lambda_handler(event, context):

    accounts_table = dynamodb.Table('AriaIdCAccounts')
    iamroles_table = dynamodb.Table('AriaIdCIAMRoles')

    # Build the lookup index once, up front, then clear the destination table.
    permset_index = build_provisioned_permission_set_index()
    empty_iam_roles_table()

    account_ids = [item['AccountId'] for item in _scan_all(accounts_table, ProjectionExpression='AccountId')]
    total = len(account_ids)
    processed = 0
    written = 0
    print(f"Processing {total} accounts with up to {MAX_WORKERS} workers")

    # batch_writer is driven only from this main thread (thread-safe); worker
    # threads perform the read-only assume-role/list-roles calls in parallel.
    with iamroles_table.batch_writer() as batch:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for chunk in _chunk(account_ids, MAX_WORKERS):
                if context is not None and context.get_remaining_time_in_millis() < RUNTIME_SAFETY_BUFFER_MS:
                    print(f"Approaching Lambda timeout; stopping after {processed}/{total} accounts")
                    break

                future_to_account = {
                    executor.submit(collect_roles_for_account, account_id, permset_index): account_id
                    for account_id in chunk
                }
                for future in as_completed(future_to_account):
                    account_id = future_to_account[future]
                    try:
                        for item in future.result():
                            batch.put_item(Item=item)
                            written += 1
                    except Exception as e:
                        print(f"Error processing account {account_id}: {e}")
                processed += len(chunk)

    message = f"Wrote {written} IAM roles across {processed}/{total} accounts"
    print(message)
    return {
        'statusCode': 200,
        'body': json.dumps({'message': message, 'complete': processed >= total})
    }
