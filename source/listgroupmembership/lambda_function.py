import json
import boto3
import time
from datetime import datetime

# List all group memberships and store in DynamoDB
def list_group_memberships(identitystore, dynamodb, identity_store_id):
    # List all group memberships and store in DynamoDB
    print(f"Listing all group memberships")
    table = dynamodb.Table('AriaIdCGroupMembership')
    groups_table = dynamodb.Table('AriaIdCGroups')
    groups = groups_table.scan()['Items']
    
    for group in groups:
        paginator = identitystore.get_paginator('list_group_memberships')
        for page in paginator.paginate(
            IdentityStoreId=identity_store_id,
            GroupId=group['GroupId']
        ):
            for membership in page['GroupMemberships']:
                table.put_item(Item={
                    'GroupId': group['GroupId'],
                    'UserId': membership['MemberId']['UserId'],
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

    # List group memberships
    try:
        list_group_memberships(identitystore, dynamodb, identity_store_id)
        print("Listed group memberships successfully")
        return {
            'statusCode': 200,
            'body': json.dumps('Listed group memberships successfully')
        }
        # Return success response
    except Exception as e:
        print(f"Error listing group memberships: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error listing group memberships')
        }
