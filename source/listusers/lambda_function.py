import json
import boto3
import time
from datetime import datetime

# List all users and store in DynamoDB
def list_users(identitystore, dynamodb, identity_store_id):
    print(f"Listing all users")
    table = dynamodb.Table('AriaIdCUsers')
    paginator = identitystore.get_paginator('list_users')
    
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        for user in page['Users']:
            table.put_item(Item={
                'UserId': user['UserId'],
                'UserName': user['UserName'],
                'Email': user.get('Emails', [{}])[0].get('Value', ''),
                'UpdatedAt': datetime.now().isoformat()
            })

# Initialize clients and get Identity Store ID
def initialize_clients():
    # Initialize required AWS clients
    identitystore = boto3.client('identitystore')
    dynamodb = boto3.resource('dynamodb')
    
    # Get Identity Store ID
    sso = boto3.client('sso-admin')
    identity_store_id = sso.list_instances()['Instances'][0]['IdentityStoreId']
    
    return identitystore, sso_admin, dynamodb, identity_store_id, instance_arn

def lambda_handler(event, context):

    identitystore, dynamodb, identity_store_id = initialize_clients()

    # List users
    try:
        list_users(identitystore, dynamodb, identity_store_id)
        print("Listed users successfully")
        return {
            'statusCode': 200,
            'body': json.dumps('Listed users successfully')
        }
        # Return success response
    except Exception as e:
        print(f"Error listing users: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error listing users')
        }
