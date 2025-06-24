import json
import boto3
import time
from datetime import datetime

# List all permission sets and store in DynamoDB
def list_accounts(dynamodb):
    
    table = dynamodb.Table('AriaIdCAccounts')

    # Get a list of all accounts in the organization
    organizations = boto3.client('organizations')
    accounts = []
    paginator = organizations.get_paginator('list_accounts')
    for page in paginator.paginate():
        accounts.extend(page['Accounts'])
    
    for account in accounts:
        try:
            # print(f"Account info: {account}")
            table.put_item(Item={
                'AccountId': account['Id'],
                'Name': account['Name'],
                'Status': account['Status'],
                'UpdatedAt': datetime.now().isoformat()
            })
        except Exception as e:
            print(f"Error processing accounts")

# Initialize clients
def initialize_clients():
    # Initialize required AWS clients
    dynamodb = boto3.resource('dynamodb')
    
    return dynamodb

def lambda_handler(event, context):

    dynamodb = initialize_clients()

    # List accounts
    try:
        list_accounts(dynamodb)
        print("Listed accounts successfully")
        return {
            'statusCode': 200,
            'body': json.dumps('Listed accounts successfully')
        }
        # Return success response
    except Exception as e:
        print(f"Error listing accounts: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error listing accounts')
        }
