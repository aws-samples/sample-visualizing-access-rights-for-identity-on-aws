import json
import boto3
from datetime import datetime
import re
from botocore.exceptions import ClientError

# Internal Access Finding
def parse_internalaccess_finding(event,table_ia):
    # Parse the event detail
    detail = (event['detail'])

    delimiter = ", " # Define a delimiter
    
    # Extract relevant information from the event
    finding_id = detail['id']
    finding_type = detail['findingType']

    # print(f"Parsing finding {finding_id} and extracting relevant attributes...")

    principal = detail['principal']['AWS']
    principal_type = detail.get('principalType', 'N/A')
    principal_owner_account = detail.get('principalOwnerAccount', 'N/A')
    principal_name = extract_role_name(principal)

    resource_type = detail.get('resourceType', 'N/A')
    resource_arn = detail.get('resource', 'N/A')
    resource_account = detail.get('accountId', 'N/A')
    
    rcp_policyrestriction_type = detail.get('resourceControlPolicyRestrictionType', 'N/A')
    scp_policyrestriction_type = detail.get('serviceControlPolicyRestrictionType', 'N/A')
    
    access_type = detail.get('accessType', 'N/A')
    status = detail['status']
    
    action_array = detail.get('action', '')
    action = delimiter.join(action_array)
    
    created_at = detail['createdAt']
    updated_at = detail['updatedAt']
    
    # Prepare the item to be inserted into DynamoDB
    item = {
        'FindingId': finding_id,
        'FindingType': finding_type,
        'Principal': principal,
        'PrincipalName': principal_name,
        'PrincipalOwnerAccount': principal_owner_account,
        'PrincipalType': principal_type,
        'ResourceType': resource_type,
        'ResourceARN': resource_arn,
        'ResourceAccount': resource_account,
        'ResourceControlPolicyRestrictionType': rcp_policyrestriction_type,
        'ServiceControlPolicyRestrictionType': scp_policyrestriction_type,
        'AccessType': access_type,
        'Action': action,
        'Status': status,
        'CreatedAt': created_at,
        'UpdatedAt': updated_at,
        'ProcessedAt': datetime.now().isoformat()
    }
    
    # Add the item to the DynamoDB table
    table_ia.put_item(Item=item)

# Unused Access Finding
def parse_unusedaccess_finding(event,table_ua):
    # Parse the event detail
    detail = (event['detail'])

    delimiter = ", " # Define a delimiter
    
    # Extract relevant information from the event
    finding_id = detail['findingId']
    finding_type = detail['findingType']
    num_unused_services = detail['numberOfUnusedServices']
    num_unused_actions = detail['numberOfUnusedActions']

    # print(f"Parsing unused finding {finding_id} and extracting relevant attributes...")

    principal = detail['resource']
    principal_name = extract_role_name(principal)
    principal_type = detail.get('resourceType', 'N/A')
    principal_owner_account = detail.get('accountId', 'N/A')

    resource_arn = detail.get('resource', 'N/A')
    resource_account = detail.get('accountId', 'N/A')
    resource_type = detail.get('resourceType', 'N/A')
    
    status = detail['status']
        
    created_at = detail['createdAt']
    updated_at = detail['updatedAt']
    analyzed_at = detail['analyzedAt']
    
    # Prepare the item to be inserted into DynamoDB
    item = {
        'FindingId': finding_id,
        'AccessType': 'UNUSED',
        'FindingType': finding_type,
        'Principal': principal,
        'PrincipalName': principal_name,
        'PrincipalType': principal_type,
        'PrincipalOwnerAccount': principal_owner_account,
        'ResourceARN': resource_arn,
        'ResourceType': resource_type,
        'ResourceAccount': resource_account,
        'Status': status,
        'NumberOfUnusedServices': num_unused_services,
        'NumberOfUnusedActions': num_unused_actions,
        'CreatedAt': created_at,
        'UpdatedAt': updated_at,
        'AnalyzedAt': analyzed_at,
        'ProcessedAt': datetime.now().isoformat()
    }
    
    # Add the item to the DynamoDB table
    table_ua.put_item(Item=item)

def delete_item_by_finding_id(finding_id, table_name):
    try:
        response = table_name.delete_item(
            Key={
                'FindingId': str(finding_id)
            },
            ConditionExpression='attribute_exists(FindingId)'
        )
        
        print(f"Item with FindingId {finding_id} was successfully deleted.")
        return True
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            print(f"Item with FindingId {finding_id} does not exist.")
        else:
            print(f"An error occurred: {e.response['Error']['Message']}")
        return False


def extract_role_name(arn):
    # Split by '/' and get the last element
    role_name = arn.split('/')[-1]
    return role_name
    
def lambda_handler(event, context):
    dynamodb = boto3.resource('dynamodb')
    table_ia = dynamodb.Table('AriaIdCInternalAAFindings')
    table_ua = dynamodb.Table('AriaIdCUnusedAAFindings')
    table_ea = dynamodb.Table('AriaIdCExternalAAFindings')
    
    try:    
        if (event['detail']['findingType'] == 'InternalAccess'):
            if (event['detail']['status'] == 'RESOLVED'):
                delete_item_by_finding_id(event['detail']['id'], table_ia)
            else:
                parse_internalaccess_finding(event, table_ia)
        
        if (event['detail']['findingType'] == 'UnusedPermission' or 'UnusedIAMRole'):
            if (event['detail']['status'] == 'ARCHIVED'):
                delete_item_by_finding_id(event['detail']['findingId'], table_ua)
            else:
                parse_unusedaccess_finding(event, table_ua)

        # print(f"Successfully added finding {finding_id} to DynamoDB")
        return {
            'statusCode': 200,
            'body': json.dumps('Finding added successfully')
        }
    except Exception as e:
        print(f"Error processing finding: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error processing finding')
        }
    