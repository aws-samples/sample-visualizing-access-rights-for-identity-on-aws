import json
import time
import boto3
from datetime import datetime
import re
from botocore.exceptions import ClientError

# Reuse the DynamoDB resource across warm invocations rather than recreating it
# per event - cheaper, and it backs the AAM scope-check cache below.
dynamodb = boto3.resource('dynamodb')

# Roles provisioned by IAM Identity Center live under this reserved path. The
# unused-access EventBridge rule now forwards every IAM-role finding, so the
# ingestion Lambda re-applies the "roles we visualize" scope: an IdC/SSO role or
# an Account Access Manager (AAM) entitled role. NOTE: this matches the standard
# 'aws' partition only, mirroring the previous rule; broaden the partition
# segment (e.g. arn:[^:]+:iam::) for GovCloud/China.
_SSO_ROLE_PATTERN = re.compile(
    r'^arn:aws:iam::\d+:role/aws-reserved/sso\.amazonaws\.com/AWSReservedSSO_'
)

# Module-level cache of AAM-entitled role ARNs, shared across warm invocations so
# a burst of findings on one container triggers at most one table scan per TTL
# window instead of a scan per event.
_aam_roles_cache = None
_aam_roles_cache_ts = 0.0
_AAM_CACHE_TTL_SECONDS = 300  # refresh at most once every 5 minutes


def get_aam_role_arns():
    """Return the set of IAM role ARNs entitled via Account Access Manager.

    Reads AriaIdCAccountAccessAssignments (the only source that knows which
    arbitrary IAM roles are AAM roles), projecting just the IamRoleArn attribute.
    Cached at module scope and refreshed only once the TTL has elapsed.
    """
    global _aam_roles_cache, _aam_roles_cache_ts
    now = time.time()
    if _aam_roles_cache is not None and (now - _aam_roles_cache_ts) < _AAM_CACHE_TTL_SECONDS:
        return _aam_roles_cache

    table = dynamodb.Table('AriaIdCAccountAccessAssignments')
    role_arns = set()
    kwargs = {'ProjectionExpression': 'IamRoleArn'}
    response = table.scan(**kwargs)
    while True:
        for item in response.get('Items', []):
            arn = item.get('IamRoleArn')
            if arn:
                role_arns.add(arn)
        if 'LastEvaluatedKey' not in response:
            break
        response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'], **kwargs)

    _aam_roles_cache = role_arns
    _aam_roles_cache_ts = now
    return role_arns


def is_tracked_role(role_arn):
    """True if this role is one we visualize: an IdC (SSO) role or an AAM role.

    The cheap SSO path check runs first so SSO findings never trigger a scan.
    """
    if not role_arn:
        return False
    if _SSO_ROLE_PATTERN.match(role_arn):
        return True
    return role_arn in get_aam_role_arns()


def get_finding_id(detail):
    """Return the finding identifier, tolerating both event schemas.

    IAM Access Analyzer uses different keys per finding family: internal and
    external (Access Analyzer Finding) events carry 'id', while unused-access
    events carry 'findingId'. Accept either so no family throws a KeyError.
    """
    return detail.get('id') or detail.get('findingId')


# Internal Access Finding
def parse_internalaccess_finding(event,table_ia):
    # Parse the event detail
    detail = (event['detail'])
    #print(f"Event detail:{detail}")

    delimiter = ", " # Define a delimiter
    
    # Extract relevant information from the event
    finding_id = get_finding_id(detail)
    finding_type = detail['findingType']

    print(f"Parsing Internal Access finding {finding_id} and extracting relevant attributes...")

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
    #print(f"Event detail:{detail}")

    delimiter = ", " # Define a delimiter
    
    # Extract relevant information from the event
    finding_id = get_finding_id(detail)
    finding_type = detail['findingType']

    print(f"Parsing Unused Access Analyzer finding {finding_id} and extracting relevant attributes...")

    num_unused_services = detail['numberOfUnusedServices']
    num_unused_actions = detail['numberOfUnusedActions']

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

# External Access Finding
def parse_externalaccess_finding(event, table_ea):
    # Parse the event detail
    detail = (event['detail'])
    #print(f"Event detail:{detail}")

    delimiter = ", " # Define a delimiter

    # Extract relevant information from the event. External access findings
    # (detail-type "Access Analyzer Finding") do NOT carry a findingType attribute,
    # so it is synthesised here for consistency with the other finding tables.
    finding_id = get_finding_id(detail)

    print(f"Parsing External Access Analyzer finding {finding_id} and extracting relevant attributes...")

    # The external principal is a single-entry map keyed by principal type, e.g.
    # {"AWS": "123456789012"}, {"Federated": "..."}, {"Service": "..."}. A public
    # grant surfaces as {"AWS": "*"} together with isPublic == True.
    principal_map = detail.get('principal', {}) or {}
    if principal_map:
        principal_type = next(iter(principal_map))
        principal = principal_map[principal_type]
    else:
        principal_type = 'N/A'
        principal = 'N/A'

    is_public = detail.get('isPublic', False)
    if is_public and principal == '*':
        # Collapse anonymous/public access to a single named principal so all
        # public-exposure findings share one graph node.
        principal = 'PUBLIC'
        principal_type = 'Public'

    resource_arn = detail.get('resource', 'N/A')
    resource_type = detail.get('resourceType', 'N/A')
    # The finding reports the owning account of the exposed resource.
    resource_account = detail.get('resourceOwnerAccount', detail.get('accountId', 'N/A'))

    action_array = detail.get('action', [])
    action = delimiter.join(action_array)

    condition = json.dumps(detail.get('condition', {}))

    status = detail['status']

    created_at = detail.get('createdAt', 'N/A')
    updated_at = detail.get('updatedAt', 'N/A')
    analyzed_at = detail.get('analyzedAt', 'N/A')

    # Prepare the item to be inserted into DynamoDB
    item = {
        'FindingId': finding_id,
        'FindingType': 'ExternalAccess',
        'AccessType': 'EXTERNAL',
        'Principal': principal,
        'PrincipalName': extract_role_name(principal),
        'PrincipalType': principal_type,
        'ResourceARN': resource_arn,
        'ResourceType': resource_type,
        'ResourceAccount': resource_account,
        'Action': action,
        'Condition': condition,
        'IsPublic': str(is_public),
        'Status': status,
        'CreatedAt': created_at,
        'UpdatedAt': updated_at,
        'AnalyzedAt': analyzed_at,
        'ProcessedAt': datetime.now().isoformat()
    }

    # Add the item to the DynamoDB table
    table_ea.put_item(Item=item)

def delete_item_by_finding_id(finding_id, table_name):
    print(f"Item with FindingId {finding_id} to be deleted...")
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
    # dynamodb is a module-level resource reused across warm invocations.
    table_ia = dynamodb.Table('AriaIdCInternalAAFindings')
    table_ua = dynamodb.Table('AriaIdCUnusedAAFindings')
    table_ea = dynamodb.Table('AriaIdCExternalAAFindings')

    detail = event['detail']
    # Finding id key differs by family (id vs findingId); accept either.
    finding_id = get_finding_id(detail)
    if not finding_id:
        print(f"Finding event has no id/findingId; detail keys: {list(detail.keys())}")
        return {
            'statusCode': 400,
            'body': json.dumps('Finding event missing id/findingId')
        }

    # Routing is driven by the EventBridge detail-type because the three finding
    # families do not share a schema:
    #   - "Internal Access Finding" / "Unused Access Finding for IAM entities"
    #     carry a findingType attribute in the detail.
    #   - "Access Analyzer Finding" (external access) does NOT carry findingType,
    #     so reading detail['findingType'] unconditionally would raise KeyError and
    #     drop every external finding.
    detail_type = event.get('detail-type', '')
    finding_type = detail.get('findingType')

    try:
        if detail_type == 'Access Analyzer Finding' or finding_type == 'ExternalAccess':
            print("Finding type is External Access...")
            if 'error' in detail:
                # Error findings (e.g. ACCESS_DENIED) have no principal/access data
                # to model, so there is nothing to ingest.
                print(f"Skipping External Access error finding {finding_id}: {detail.get('error')}")
            elif detail.get('status') == 'RESOLVED' or detail.get('isDeleted') is True:
                print("Deleting External Access Analyzer Finding...")
                delete_item_by_finding_id(finding_id, table_ea)
            else:
                print("Parsing External Access Analyzer Finding...")
                parse_externalaccess_finding(event, table_ea)
        else:
            match finding_type:
                case 'InternalAccess':
                    print("Finding type is Internal Access...")
                    # The EventBridge rule now forwards every internal finding with
                    # an IAM-role principal, so scope here to the roles we
                    # visualize: IdC/SSO roles and AAM-entitled roles. For internal
                    # findings the role is the principal (detail.principal.AWS).
                    role_arn = detail.get('principal', {}).get('AWS', '')
                    if detail.get('status') == 'RESOLVED':
                        # Always honor deletes regardless of current scope, so a
                        # role that has since dropped out of AAM cannot leave a
                        # stale finding row behind.
                        print("Deleting Internal Access Analyzer Finding...")
                        delete_item_by_finding_id(finding_id, table_ia)
                    elif is_tracked_role(role_arn):
                        print("Parsing Internal Access Analyzer Finding...")
                        parse_internalaccess_finding(event, table_ia)
                    else:
                        print(f"Skipping internal finding for out-of-scope role {role_arn}")
                case 'UnusedPermission' | 'UnusedIAMRole':
                    print("Finding type is Unused Access...")
                    # The EventBridge rule now forwards every IAM-role unused
                    # finding, so scope here to the roles we visualize: IdC/SSO
                    # roles and AAM-entitled roles.
                    role_arn = detail.get('resource', '')
                    if detail.get('status') == 'RESOLVED':
                        # Always honor deletes regardless of current scope, so a
                        # role that has since dropped out of AAM cannot leave a
                        # stale finding row behind.
                        print("Deleting Unused Access Analyzer Finding...")
                        delete_item_by_finding_id(finding_id, table_ua)
                    elif is_tracked_role(role_arn):
                        print("Parsing Unused Access Analyzer Finding...")
                        parse_unusedaccess_finding(event, table_ua)
                    else:
                        print(f"Skipping unused finding for out-of-scope role {role_arn}")

        print(f"Successfully processed finding {finding_id}")
        return {
            'statusCode': 200,
            'body': json.dumps('Finding processed OK')
        }
    except Exception as e:
        detail = (event['detail'])
        #print(f"Error processing event detail:{detail}")
        print(f"Error processing finding: {finding_id}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error processing finding')
        }
    