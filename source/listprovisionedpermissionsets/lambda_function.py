import json
import boto3
import time
import os
from datetime import datetime

# Get all accounts in the AriaIdCAccounts table
def get_all_accounts():
    # List all accounts in AriaIdCAccounts
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('AriaIdCAccounts')
    response = table.scan()
    accounts = response['Items']
    return accounts

# Get all permission sets in the AriaIdCPermissionSets table
def get_all_permission_sets():
    # List all permission sets in AriaIdCPermissionSets
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('AriaIdCPermissionSets')
    response = table.scan()
    permission_sets = response['Items']
    return permission_sets

# List all provisioned permission sets and store in DynamoDB
def list_provisioned_permission_sets(sso_admin, dynamodb, instance_arn):
    # List all provisioned permission sets by account and store in DynamoDB
    print(f"Listing all provisioned permission sets")
    
    table = dynamodb.Table('AriaIdCProvisionedPermissionSets')
    organizations = boto3.client('organizations')
    management_account_id = organizations.describe_organization()["Organization"]["MasterAccountId"]
    # print(f"Management account ID: {management_account_id}")

    accounts = get_all_accounts()
    permission_sets = get_all_permission_sets()
    # print(f"Permission sets from AriaIdCPermissionSets table: {permission_sets}")

    for account in accounts:
        try:
            # print(f"Listing provisioned permission sets for account {account['AccountId']}")
            #if account['Id'] == management_account_id:
            #    print(f"Skipping management account {account['Id']}")
            #    continue
                # Skip Management account
            if account['Status'] != 'ACTIVE':
                print(f"Skipping inactive account {account['AccountId']}")
                continue
                # Skip inactive accounts
            else:
                response = sso_admin.list_permission_sets_provisioned_to_account(
                    InstanceArn=instance_arn,
                    AccountId=account['AccountId']
                )
                provisioned_permission_sets = response['PermissionSets']
                # print(f"Provisioned permission sets for account {account['AccountId']}: {provisioned_permission_sets}")

                for permission_set_arn in provisioned_permission_sets:
                    # Find Name in permission_sets where PermissionSetArn = permission_set_arn
                    permission_set_name = next((item['Name'] for item in permission_sets if item['PermissionSetArn'] == permission_set_arn), None)

                    table.put_item(Item={
                        'PermissionSetArn': permission_set_arn,
                        'PermissionSetName': permission_set_name,
                        'AccountId': account['AccountId'],
                        'AccountName': account['Name'],
                        'UpdatedAt': datetime.now().isoformat()
                    })
        except Exception as e:
            print(f"Error processing account {account['AccountId']}: {str(e)}")

# Initialize clients
def initialize_clients():
    # Initialize required AWS clients
    sso_admin = boto3.client('sso-admin')
    dynamodb = boto3.resource('dynamodb')
    
    # Get Identity Store ID
    sso = boto3.client('sso-admin')
    instance_arn = sso.list_instances()['Instances'][0]['InstanceArn']
    
    return sso_admin, dynamodb, instance_arn

def empty_provisioned_permission_sets_table():
    # Empty the provisioned permission sets table
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('AriaIdCProvisionedPermissionSets')
    scan = table.scan()
    with table.batch_writer() as batch:
        for each in scan['Items']:
            batch.delete_item(
                Key={
                    'PermissionSetArn': each['PermissionSetArn'],
                    'AccountId': each['AccountId']
                }
            )

def lambda_handler(event, context):

    sso_admin, dynamodb, instance_arn = initialize_clients()

    # List permission sets
    try:
        empty_provisioned_permission_sets_table()
        list_provisioned_permission_sets(sso_admin, dynamodb, instance_arn)
        print("Listed provisioned permission sets successfully")
        return {
            'statusCode': 200,
            'body': json.dumps('Listed provisioned permission sets successfully')
        }
        # Return success response
    except Exception as e:
        print(f"Error listing provisioned permission sets: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error listing provisioned permission sets')
        }
