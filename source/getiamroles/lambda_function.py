import json
import boto3
import time
from datetime import datetime
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

def assume_role(account_id, role_name):
    # Assume a role in target account
    sts_client = boto3.client('sts')
    try:
        # print(f"Assuming role {role_name} in account {account_id}")
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
    else:
        iam = boto3.client('iam',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    
    try:
        idc_roles = []
        paginator = iam.get_paginator('list_roles')
        
        for page in paginator.paginate():
            for role in page['Roles']:
                if role['RoleName'].startswith('AWSReservedSSO_'):
                    # print(f"Found Identity Center IAM role: {role['RoleName']}")

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

# Get all permission sets and accounts cached in dynamodb table AriaIdCProvisionedPermissionSets
def get_provisioned_permission_sets(account_id):
    # Get list of all permission sets in AriaIdCProvisionedPermissionSets for a given Account
    dynamodb = boto3.resource('dynamodb')
    provisioned_permission_sets_table = dynamodb.Table('AriaIdCProvisionedPermissionSets')
    provisioned_permission_sets = []

    try:
        # Construct the Filter Expression
        filter_expression = (Attr('AccountId').eq(account_id))
        response = provisioned_permission_sets_table.scan(
           FilterExpression=filter_expression
        )

        # Process items in the response
        for item in response['Items']:
            provisioned_permission_set = {
                'AccountId': item.get('AccountId', 'N/A'),
                'AccountName': item.get('AccountName', 'N/A'),
                'PermissionSetArn': item.get('PermissionSetArn', 'N/A'),
                'PermissionSetName': item.get('PermissionSetName', 'N/A')
            }
            provisioned_permission_sets.append(provisioned_permission_set)
        return provisioned_permission_sets
    except ClientError as e:
        print(f"An error occurred: {e.response['Error']['Message']}")
        return None

# Initialize clients
def initialize_clients():
    # Initialize required AWS clients
    dynamodb = boto3.resource('dynamodb')
    return dynamodb

def empty_iam_roles_table():
    # Empty the provisioned permission sets table
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('AriaIdCIAMRoles')
    scan = table.scan()
    with table.batch_writer() as batch:
        for each in scan['Items']:
            batch.delete_item(
                Key={
                    'IamRoleArn': each['IamRoleArn']
                }
            )

def lambda_handler(event, context):

    # Role to assume in member accounts (needs to exist in all accounts) - created using stackset (see elsewhere)
    role_to_assume = 'AriaIdCInventoryAccessRole-LimitedReadOnly'

    dynamodb = initialize_clients()
    accounts_table = dynamodb.Table('AriaIdCAccounts')
    iamroles_table = dynamodb.Table('AriaIdCIAMRoles')
    
    empty_iam_roles_table()
    
    for account in accounts_table.scan()['Items']:
        account_id=account['AccountId']
        
        # Get all provisioned permission sets in account
        # print(f"Fetching list of provisioned permission sets in account {account_id}")
        provisioned_permission_sets_in_account = []
        provisioned_permission_sets_in_account = get_provisioned_permission_sets(account_id)
        
        credentials = assume_role(account_id, role_to_assume)
        idc_roles = []
        idc_roles = list_idc_roles_in_account(credentials, account_id)
    
        for role in idc_roles:
            permsetname = role['RoleName'].replace('AWSReservedSSO_', '')
            permsetname = permsetname[:-17]

            # If permsetname exists in provisioned_permission_sets then get the permsetarn
            for permissionset in provisioned_permission_sets_in_account:
                # for permset in permissionset:
                if permissionset['PermissionSetName'] == permsetname:
                    permsetarn = permissionset['PermissionSetArn']
                    # print(f"Permission Set Name: {permsetname}, Permission Set Arn: {permsetarn}, IAM Role Name: {role['RoleName']}, IAM Role Arn: {role['Arn']}")
                    break

            # Write role information to DynamoDB
            # print(f"Writing role information to DynamoDB table for account {account_id}")
            iamroles_table.put_item(Item={
                'IamRoleArn': role['Arn'],
                'RoleName': role['RoleName'],
                'AccountId': role['AccountId'],
                'RoleId': role['RoleId'],
                'AttachedPolicies': role['AttachedPolicies'],
                'PermissionSetName': permsetname,
                'PermissionSetArn': permsetarn,
                'CreateDate': role['CreateDate'].isoformat()
            })
