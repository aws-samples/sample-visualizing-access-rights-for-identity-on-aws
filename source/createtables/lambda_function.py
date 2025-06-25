import json
import boto3
import time
from datetime import datetime

# Create required tables in DynamoDB
def create_tables(dynamodb):
    # Create DynamoDB tables if they don't exist
    tables = {
        'AriaIdCUsers': {
            'KeySchema': [
                {'AttributeName': 'UserId', 'KeyType': 'HASH'}
            ],
            'AttributeDefinitions': [
                {'AttributeName': 'UserId', 'AttributeType': 'S'}
            ]
        },
        'AriaIdCGroups': {
            'KeySchema': [
                {'AttributeName': 'GroupId', 'KeyType': 'HASH'}
            ],
            'AttributeDefinitions': [
                {'AttributeName': 'GroupId', 'AttributeType': 'S'}
            ]
        },
        'AriaIdCGroupMembership': {
            'KeySchema': [
                {'AttributeName': 'GroupId', 'KeyType': 'HASH'},
                {'AttributeName': 'UserId', 'KeyType': 'RANGE'}
            ],
            'AttributeDefinitions': [
                {'AttributeName': 'GroupId', 'AttributeType': 'S'},
                {'AttributeName': 'UserId', 'AttributeType': 'S'}
            ]
        },
        'AriaIdCPermissionSets': {
            'KeySchema': [
                {'AttributeName': 'PermissionSetArn', 'KeyType': 'HASH'},
            ],
            'AttributeDefinitions': [
                {'AttributeName': 'PermissionSetArn', 'AttributeType': 'S'},
            ]
        },
        'AriaIdCProvisionedPermissionSets': {
            'KeySchema': [
                {'AttributeName': 'PermissionSetArn', 'KeyType': 'HASH'},
                {'AttributeName': 'AccountId', 'KeyType': 'RANGE'}
            ],
            'AttributeDefinitions': [
                {'AttributeName': 'PermissionSetArn', 'AttributeType': 'S'},
                {'AttributeName': 'AccountId', 'AttributeType': 'S'}
            ]
        },
        'AriaIdCAccounts': {
            'KeySchema': [
                {'AttributeName': 'AccountId', 'KeyType': 'HASH'}
            ],
            'AttributeDefinitions': [
                {'AttributeName': 'AccountId', 'AttributeType': 'S'}
            ]
        },
        'AriaIdCUserAccountAssignments': {
            'KeySchema': [
                {'AttributeName': 'AccountId', 'KeyType': 'HASH'},
                {'AttributeName': 'UserId', 'KeyType': 'RANGE'}
            ],
            'AttributeDefinitions': [
                {'AttributeName': 'AccountId', 'AttributeType': 'S'},
                {'AttributeName': 'UserId', 'AttributeType': 'S'}
            ]
        },
        'AriaIdCGroupAccountAssignments': {
            'KeySchema': [
                {'AttributeName': 'GroupId', 'KeyType': 'HASH'},
                {'AttributeName': 'AccountId', 'KeyType': 'RANGE'}
            ],
            'AttributeDefinitions': [
                {'AttributeName': 'GroupId', 'AttributeType': 'S'},
                {'AttributeName': 'AccountId', 'AttributeType': 'S'}
            ]
        },
        'AriaIdCIAMRoles': {
            'KeySchema': [
                {'AttributeName': 'IamRoleArn', 'KeyType': 'HASH'}
            ],
            'AttributeDefinitions': [
                {'AttributeName': 'IamRoleArn', 'AttributeType': 'S'}
            ]
        },
        'AriaIdCInternalAAFindings': {
            'KeySchema': [
                {'AttributeName': 'FindingId', 'KeyType': 'HASH'}
            ],
            'AttributeDefinitions': [
                {'AttributeName': 'FindingId', 'AttributeType': 'S'}
            ]
        },
        'AriaIdCUnusedAAFindings': {
            'KeySchema': [
                {'AttributeName': 'FindingId', 'KeyType': 'HASH'}
            ],
            'AttributeDefinitions': [
                {'AttributeName': 'FindingId', 'AttributeType': 'S'}
            ]
        },
        'AriaIdCExternalAAFindings': {
            'KeySchema': [
                {'AttributeName': 'FindingId', 'KeyType': 'HASH'}
            ],
            'AttributeDefinitions': [
                {'AttributeName': 'FindingId', 'AttributeType': 'S'}
            ]
        }
    }

    for table_name, schema in tables.items():
        print(f"Creating dynamoDB table: {table_name}")
        try:
            table = dynamodb.create_table(
                TableName=table_name,
                KeySchema=schema['KeySchema'],
                AttributeDefinitions=schema['AttributeDefinitions'],
                BillingMode='PAY_PER_REQUEST',
                SSESpecification={
                    'Enabled': True,
                    'SSEType': 'KMS'
                },
                Tags=[
                    {
                        'Key': 'aria',
                        'Value': 'data'
                    }
                ]
            )
            table.wait_until_exists()
            print(f"Table created: {table_name}")
        except dynamodb.meta.client.exceptions.ResourceInUseException:
            print(f"Table {table_name} already exists so did not create")

# Initialize clients
def initialize_clients():
    # Initialize AWS clients
    dynamodb = boto3.resource('dynamodb')
    return dynamodb

def lambda_handler(event, context):

    dynamodb = initialize_clients()

    # Create tables
    try:
        create_tables(dynamodb)
        print("Tables created successfully")
        return {
            'statusCode': 200,
            'body': json.dumps('Tables created successfully')
        }
        # Return success response
    except Exception as e:
        print(f"Error creating tables: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error creating tables')
        }
