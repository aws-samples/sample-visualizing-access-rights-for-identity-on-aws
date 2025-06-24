import json
import boto3
import time
from datetime import datetime

# Get all accounts cached in the dynamodb table
def get_all_accounts():
    # Get list of all accounts in the organization
    dynamodb = boto3.resource('dynamodb')
    accounts_table = dynamodb.Table('AriaIdCAccounts')
    accounts = []

    try:
        response = accounts_table.scan()

        # Process items in the response
        for item in response['Items']:
            account = {
                'Name': item.get('Name', 'N/A'),
                'AccountId': item.get('AccountId', 'N/A')
            }
            accounts.append(account)
        return accounts
    
    except ClientError as e:
        print(f"An error occurred: {e.response['Error']['Message']}")
        return None
    
# List all account assignments for principals with permission sets in DynamoDB
def list_account_assignments_for_users(sso_admin, dynamodb, instance_arn):
    # List all account assignments for users and store in DynamoDB
    print(f"Listing all account assigments and permission set assignments for principals")
    
    table = dynamodb.Table('AriaIdCUserAccountAssignments')
    permset_table = dynamodb.Table('AriaIdCPermissionSets')
    users_table = dynamodb.Table('AriaIdCUsers')
    users = users_table.scan()['Items']
    
    # Get all accounts
    print("Fetching account list...")
    accounts = get_all_accounts()
    
    for user in users:
        for account in accounts:
            try:
                #print(f"Processing assignments for user {user['UserId']} in account {account['AccountId']}")
                paginator = sso_admin.get_paginator('list_account_assignments_for_principal')
                for page in paginator.paginate(
                    InstanceArn=instance_arn,
                    Filter={'AccountId': account['AccountId']},
                    PrincipalType='USER',
                    PrincipalId=user['UserId']
                ):
                    for assignment in page['AccountAssignments']:
                        # print(f"Processing assignments for user {user['UserId']} in account {account['Name']} with assignment {assignment['PermissionSetArn']}")
                        permset_name = permset_table.get_item(Key={'PermissionSetArn': assignment['PermissionSetArn']})['Item']['Name']
                        # print(f"Processing {permset_name}")
                        table.put_item(Item={
                            'UserId': user['UserId'],
                            'AccountId': account['AccountId'],
                            'PrincipalType': 'USER',
                            'PrincipalName': user.get('UserName', 'N/A'),
                            'AccountName': account['Name'],
                            'PermissionSetArn': assignment['PermissionSetArn'],
                            'Name': permset_name,
                            'UpdatedAt': datetime.now().isoformat()
                        })
            except Exception as e:
                print(f"Error processing assignments for user {user['UserId']} in account {account['AccountId']}: {str(e)}")

# Initialize clients
def initialize_clients():
    # Initialize required AWS clients
    sso_admin = boto3.client('sso-admin')
    dynamodb = boto3.resource('dynamodb')
    
    # Get Identity Store ID
    sso = boto3.client('sso-admin')
    instance_arn = sso.list_instances()['Instances'][0]['InstanceArn']
    
    return sso_admin, dynamodb, instance_arn

def lambda_handler(event, context):

    sso_admin, dynamodb, instance_arn = initialize_clients()

    # List account assignments for all users
    try:
        list_account_assignments_for_users(sso_admin, dynamodb, instance_arn)
        print("Listed account assignments for USER principals successfully")
        return {
            'statusCode': 200,
            'body': json.dumps('Listed account assignments for USER principals successfully')
        }
        # Return success response
    except Exception as e:
        print(f"Error listing account assignments for USER principals: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error listing account assignments for USER principals')
        }
    