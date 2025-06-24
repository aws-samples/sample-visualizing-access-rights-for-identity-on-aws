import json
import boto3
import time
from datetime import datetime

# List all groups and store in DynamoDB
def list_groups(identitystore, dynamodb, identity_store_id):
    # List all groups and store in DynamoDB
    print(f"Listing all groups")
    table = dynamodb.Table('AriaIdCGroups')
    paginator = identitystore.get_paginator('list_groups')
    
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        for group in page['Groups']:
            table.put_item(Item={
                'GroupId': group['GroupId'],
                'GroupName': group['DisplayName'],
                'UpdatedAt': datetime.now().isoformat()
            })


# Initialize clients
def initialize_clients():
    # Initialize required AWS clients
    identitystore = boto3.client('identitystore')
    sso_admin = boto3.client('sso-admin')
    dynamodb = boto3.resource('dynamodb')
    
    # Get Identity Store ID
    sso = boto3.client('sso-admin')
    identity_store_id = sso.list_instances()['Instances'][0]['IdentityStoreId']
    instance_arn = sso.list_instances()['Instances'][0]['InstanceArn']
    
    return identitystore, sso_admin, dynamodb, identity_store_id, instance_arn

def lambda_handler(event, context):

    identitystore, sso_admin, dynamodb, identity_store_id, instance_arn = initialize_clients()

    # List groups
    try:
        list_groups(identitystore, dynamodb, identity_store_id)
        print("Listed groups successfully")
        return {
            'statusCode': 200,
            'body': json.dumps('Listed groups successfully')
        }
        # Return success response
    except Exception as e:
        print(f"Error listing groups: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error listing groups')
        }
