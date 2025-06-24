import json
import boto3
import time
from datetime import datetime

# List all permission sets and store in DynamoDB
def list_permission_sets(sso_admin, dynamodb, instance_arn):
    # List all permission sets and store in DynamoDB
    print(f"Listing all permission sets")
    table = dynamodb.Table('AriaIdCPermissionSets')
    paginator = sso_admin.get_paginator('list_permission_sets')
    
    for page in paginator.paginate(InstanceArn=instance_arn):
        for permission_set_arn in page['PermissionSets']:
            details = sso_admin.describe_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            )['PermissionSet']
            
            table.put_item(Item={
                'PermissionSetArn': permission_set_arn,
                'Name': details['Name'],
                'Description': details.get('Description', ''),
                'UpdatedAt': datetime.now().isoformat()
            })

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

    # List permission sets
    try:
        list_permission_sets(sso_admin, dynamodb, instance_arn)
        print("Listed permission sets successfully")
        return {
            'statusCode': 200,
            'body': json.dumps('Listed permission sets successfully')
        }
        # Return success response
    except Exception as e:
        print(f"Error listing permissionsets: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error listing permissionsets')
        }
