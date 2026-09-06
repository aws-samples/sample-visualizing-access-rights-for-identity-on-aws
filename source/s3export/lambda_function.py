import boto3
import csv
import io
import json
import uuid
from botocore.exceptions import ClientError

# This function uses the standard python csv library, semgrep may flag this as a potential for a malicious csv to be
# created, however all csv generation is programmatic with no user input so the risk is low
def convert_to_csv(items, table_headers, csv_headers, generate_uuid=False, label=None, skip_if_missing=None):
    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(csv_headers)
    
    writer = csv.DictWriter(csv_buffer, fieldnames=table_headers, extrasaction='ignore')
    
    for item in items:
        # print(f"{item}")
        if skip_if_missing and any(not item.get(header) for header in skip_if_missing):
            # Item lacks a usable value for a field this export requires (e.g.
            # PermissionSetArn on a backfilled role stub) - omit the row entirely
            # rather than writing an empty value into a required ~from/~to column.
            continue

        row={}
        for header in table_headers:
            if header in item:
                row[header] = item[header]
            else:
                # Handle special columns
                if header == 'UniqueId' and generate_uuid:
                    row[header] = str(uuid.uuid4())
                elif header == 'Label' and label:
                    row[header] = label
                else:
                    row[header] = ''
                
        # print(f"{row}")
        writer.writerow(row)

    return csv_buffer.getvalue()

#REMOVES DUPLICATES:
def remove_duplicates_from_items(items, unique_key_fields):
    unique_items = {}
    for item in items:
        # Create a tuple of values from the specified fields
        unique_key = tuple(item.get(field, '') for field in unique_key_fields)
        
        # Keep only the first occurrence of each unique combination
        if unique_key not in unique_items:
            unique_items[unique_key] = item
    
    return list(unique_items.values())

def export_dynamodb_to_s3(dynamodb_table, s3_bucket, s3_key, table_headers, csv_headers, generate_uuid=False, label=None, dedup_fields=None, skip_if_missing=None, exclude_field_values=None):
    """Export a DynamoDB table to a Neptune CSV, optionally excluding rows.

    ``exclude_field_values`` maps a source attribute to the set of values that
    must not appear in the export. It is applied before deduplication so node
    projections can exclude a type without changing the finding table or any
    relationship CSV that uses the same source rows.
    """
    print(f"Exporting {dynamodb_table} to {s3_bucket}/{s3_key}")
    dynamodb = boto3.resource('dynamodb')
    s3 = boto3.client('s3')
    s3.delete_object(Bucket=s3_bucket, Key=s3_key)
    table = dynamodb.Table(dynamodb_table)
    response = table.scan()
    items = response['Items']
    if items:
        if exclude_field_values:
            items = [
                item for item in items
                if all(item.get(field) not in values for field, values in exclude_field_values.items())
            ]
        if dedup_fields:
            items = remove_duplicates_from_items(items, dedup_fields)
        # When a source table has rows but every row is excluded (for example,
        # IAM roles in the CriticalResources projection), retain a header-only
        # CSV so downstream imports never encounter a missing expected object.
        if items or exclude_field_values:
            csv_data = convert_to_csv(items, table_headers, csv_headers, generate_uuid, label, skip_if_missing)
            s3.put_object(Bucket=s3_bucket, Key=s3_key, Body=csv_data)
            print(f"Data exported to S3: {s3_bucket}/{s3_key}")

def check_table_has_items(dynamodb_table):
    try:
        # Create DynamoDB client
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(dynamodb_table)
        
        # Scan table with limit 1 to check for any items
        response = table.scan(
            Select='COUNT',
            Limit=1
        )
        
        # Check if count is greater than 0
        item_count = response['Count']
        has_items = item_count > 0
        
        return has_items
        
    except ClientError as e:
        print(f"Error checking table: {e}")
        raise


def lambda_handler(event, context):    
    
    # The s3bucket parameter is passed in to the function from the calling step function
    s3_bucket = event['s3bucket']

#NODES
    # Export AriaIdCUsers to csv file
    table_headers = ["UserId", "UserName", "Label"]
    csv_headers = ["~id", "username:String","~label"]
    export_dynamodb_to_s3("AriaIdCUsers", s3_bucket, "AriaIdCUsers.csv", table_headers, csv_headers,label="UserName")

    # Export AriaIdCGroups to csv file
    table_headers = ["GroupId", "GroupName", "Label"]
    csv_headers = ["~id", "groupname:String","~label"]
    export_dynamodb_to_s3("AriaIdCGroups", s3_bucket, "AriaIdCGroups.csv", table_headers, csv_headers,label="GroupName")

    # Export AriaIdCPermissionSets to csv file
    table_headers = ["PermissionSetArn", "Name", "Description", "Label"]
    csv_headers = ["~id", "name:String", "description:String","~label"]
    export_dynamodb_to_s3("AriaIdCPermissionSets", s3_bucket, "AriaIdCPermissionSets.csv", table_headers, csv_headers,label="PermissionSet")

    # Export AriaIdCAccounts to csv file
    table_headers = ["AccountId", "Name", "Label"]
    csv_headers = ["~id", "name:String","~label"]
    export_dynamodb_to_s3("AriaIdCAccounts", s3_bucket, "AriaIdCAccounts.csv", table_headers, csv_headers,label="AccountName")

    # Export AriaIdCIAMRoles to csv file. The source:String property records role
    # provenance (PermissionSet / IAM / TrustPolicy). TrustedPrincipals and
    # TrustPolicyDocument are intentionally not exported as node properties: the
    # trust relationships are exported separately as CAN_ASSUME edges.
    table_headers = ["IamRoleArn", "AccountId", "RoleId", "RoleName", "AttachedPolicies", "Source", "Label"]
    csv_headers = ["~id", "accountid:String", "roleid:String", "rolename:String", "attachedpolicies:String", "source:String", "~label"]
    export_dynamodb_to_s3("AriaIdCIAMRoles", s3_bucket, "AriaIdCIAMRoles.csv", table_headers, csv_headers,label="RoleName")

    # Only export IAM user nodes if the table has items. IamUser nodes are the
    # user-typed CAN_ASSUME endpoints materialized from role trust policies.
    if check_table_has_items("AriaIdCIAMUsers"):
        table_headers = ["IamUserArn", "UserName", "AccountId", "Source", "Label"]
        csv_headers = ["~id", "username:String", "accountid:String", "source:String", "~label"]
        export_dynamodb_to_s3("AriaIdCIAMUsers", s3_bucket, "AriaIdCIAMUsers.csv", table_headers, csv_headers, label="IamUser", dedup_fields=["IamUserArn"])

    # Only export Internal Access Analyzer Findings if the table has items
    if check_table_has_items("AriaIdCInternalAAFindings"):
        #Export InternalAccessAnalyzerFindings to csv file
        table_headers = ["FindingId", "ResourceARN", "FindingType", "AccessType", "Principal", "PrincipalName", "PrincipalOwnerAccount", "ResourceType", "Action", "ResourceControlPolicyRestrictionType", "ServiceControlPolicyRestrictionType", "Status", "NumberofUnusedActions", "NumberofUnusedServices", "Label"]
        csv_headers = ["~id", "resourcearn:String", "findingtype:String", "accesstype:String", "principal:String", "principalname:String", "principalowneraccount:String", "resourcetype:String", "action:String", "resourcecontrolpolicyrestrictiontype:String", "servicecontrolpolicyrestrictiontype:String", "status:String", "numberofunusedactions:String", "numberofunusedservices:String", "~label"]
        export_dynamodb_to_s3("AriaIdCInternalAAFindings", s3_bucket, "AriaIdCInternalAAFindings.csv", table_headers, csv_headers,label="InternalAccessFinding")

        # IAM roles are graph RoleName nodes, not CriticalResources. Keep the
        # finding and role-targeted edges, but do not export a second critical
        # resource node for an AWS::IAM::Role target.
        table_headers =  ["ResourceARN", "ResourceType", "Label"]
        csv_headers = ["~id", "resourcetype:String", "~label"]
        export_dynamodb_to_s3(
            "AriaIdCInternalAAFindings",
            s3_bucket,
            "AriaIdCCriticalResources.csv",
            table_headers,
            csv_headers,
            label="CriticalResources",
            exclude_field_values={"ResourceType": {"AWS::IAM::Role"}},
        )
    
    # Only export Unused Access Analyzer Findings if the table has items
    if check_table_has_items("AriaIdCUnusedAAFindings"):
        #Export UnusedAccessAnalyzerFindings to csv file
        table_headers = ["FindingId", "ResourceARN", "FindingType", "AccessType", "ResourceType", "Status", "NumberOfUnusedActions", "NumberOfUnusedServices", "Label"]
        csv_headers = ["~id", "resourcearn:String", "findingtype:String", "accesstype:String", "resourcetype:String",  "status:String", "numberofunusedactions:String", "numberofunusedservices:String", "~label"]
        export_dynamodb_to_s3("AriaIdCUnusedAAFindings", s3_bucket, "AriaIdCUnusedAAFindings.csv", table_headers, csv_headers,label="UnusedAccessFinding")

    # Only export External Access Analyzer Findings if the table has items
    if check_table_has_items("AriaIdCExternalAAFindings"):
        # Export ExternalAccessFinding nodes.
        table_headers = ["FindingId", "ResourceARN", "FindingType", "AccessType", "Principal", "PrincipalName", "PrincipalType", "ResourceType", "ResourceAccount", "Action", "Condition", "IsPublic", "Status", "Label"]
        csv_headers = ["~id", "resourcearn:String", "findingtype:String", "accesstype:String", "principal:String", "principalname:String", "principaltype:String", "resourcetype:String", "resourceaccount:String", "action:String", "condition:String", "ispublic:String", "status:String", "~label"]
        export_dynamodb_to_s3("AriaIdCExternalAAFindings", s3_bucket, "AriaIdCExternalAAFindings.csv", table_headers, csv_headers, label="ExternalAccessFinding")

        # Export the external principals (the entities OUTSIDE the zone of trust) as
        # ExternalPrincipal nodes, deduped on Principal so each external entity
        # appears once regardless of how many resources it can reach.
        table_headers = ["Principal", "PrincipalName", "PrincipalType", "Label"]
        csv_headers = ["~id", "principalname:String", "principaltype:String", "~label"]
        export_dynamodb_to_s3("AriaIdCExternalAAFindings", s3_bucket, "AriaIdCExternalPrincipals.csv", table_headers, csv_headers, label="ExternalPrincipal", dedup_fields=["Principal"])

        # Export externally exposed non-role resources as CriticalResources.
        # IAM roles retain their normal RoleName identity and are excluded here
        # to prevent duplicate graph nodes with the same ARN and two labels.
        table_headers = ["ResourceARN", "ResourceType", "Label"]
        csv_headers = ["~id", "resourcetype:String", "~label"]
        export_dynamodb_to_s3(
            "AriaIdCExternalAAFindings",
            s3_bucket,
            "AriaIdCExternalResources.csv",
            table_headers,
            csv_headers,
            label="CriticalResources",
            dedup_fields=["ResourceARN"],
            exclude_field_values={"ResourceType": {"AWS::IAM::Role"}},
        )

    # Only export Account Access Manager (AAM) data if the table has items
    if check_table_has_items("AriaIdCAccountAccessAssignments"):
        # Export AAM-entitled IAM roles as RoleName nodes, deduped on IamRoleArn so each
        # role appears once. The source:String property records AAM provenance.
        table_headers = ["IamRoleArn", "AccountId", "RoleName", "Source", "Label"]
        csv_headers = ["~id", "accountid:String", "rolename:String", "source:String", "~label"]
        export_dynamodb_to_s3(
            "AriaIdCAccountAccessAssignments",
            s3_bucket,
            "AriaIdCAccountAccessRoles.csv",
            table_headers,
            csv_headers,
            label="RoleName",
            dedup_fields=["IamRoleArn"]
        )

    
#EDGES

    # Modified Users to Groups (GroupMembership) - EDGE
    table_headers = ["UniqueId", "GroupId", "UserId", "Label"]
    csv_headers = ["~id", "~from", "~to", "~label"]
    export_dynamodb_to_s3(
        "AriaIdCGroupMembership", 
        s3_bucket, 
        "AriaIdCGroupMembership_Edge.csv", 
        table_headers, 
        csv_headers,
        generate_uuid=True,
        label="HAS_MEMBERS"
    )

    # Export User to PermissionsSets to csv file - EDGE
    table_headers = ["UniqueId", "UserId", "PermissionSetArn", "Label"]
    csv_headers = ["~id", "~from", "~to", "~label"]
    export_dynamodb_to_s3(
        "AriaIdCUserAccountAssignments", 
        s3_bucket, 
        "AriaIdCUserAssignments_Edge.csv", 
        table_headers, 
        csv_headers,
        generate_uuid=True,
        dedup_fields=["UserId", "PermissionSetArn"],
        label="ASSIGNED_PERMISSIONSET"
        )
    
    # Export Group to PermissionsSets to csv file - EDGE
    table_headers = ["UniqueId", "GroupId", "PermissionSetArn", "Label"]
    csv_headers = ["~id", "~from", "~to", "~label"]
    export_dynamodb_to_s3(
        "AriaIdCGroupAccountAssignments", 
        s3_bucket, 
        "AriaIdCGroupAssignments_Edge.csv", 
        table_headers, 
        csv_headers,
        generate_uuid=True,
        label="ASSIGNED_PERMISSIONSET",
        dedup_fields=["GroupId", "PermissionSetArn"]
        )

    # Export User to Accounts to csv file - EDGE
    # The source table now holds one row per (user, account, permission set), so a
    # user with several permission sets in an account yields multiple rows. Dedup on
    # (UserId, AccountId) to emit a single User -> Account edge per pair.
    table_headers = ["UniqueId", "UserId", "AccountId", "Label"]
    csv_headers = ["~id", "~from", "~to", "~label"]
    export_dynamodb_to_s3(
        "AriaIdCUserAccountAssignments", 
        s3_bucket, 
        "AriaIdCUserAccount_Edge.csv", 
        table_headers, 
        csv_headers,
        generate_uuid=True,
        label="ASSIGNED_ACCOUNT",
        dedup_fields=["UserId", "AccountId"]
        )
    
    # Export Groups to Accounts to csv file - EDGE
    # The source table now holds one row per (group, account, permission set), so a
    # group with several permission sets in an account yields multiple rows. Dedup on
    # (GroupId, AccountId) to emit a single Group -> Account edge per pair.
    table_headers = ["UniqueId", "GroupId", "AccountId", "Label"]
    csv_headers = ["~id", "~from", "~to", "~label"]
    export_dynamodb_to_s3(
        "AriaIdCGroupAccountAssignments", 
        s3_bucket, 
        "AriaIdCGroupAccount_Edge.csv", 
        table_headers, 
        csv_headers,
        generate_uuid=True,
        label="ASSIGNED_ACCOUNT",
        dedup_fields=["GroupId", "AccountId"]
        )

    # Export Account to PermissionSets to csv file - EDGE
    table_headers = ["UniqueId", "PermissionSetArn", "AccountId", "Label"]
    csv_headers = ["~id", "~from", "~to", "~label"]
    export_dynamodb_to_s3(
        "AriaIdCProvisionedPermissionSets", 
        s3_bucket, 
        "AriaIdCProvisionedPermissionSets_Edge.csv", 
        table_headers, 
        csv_headers,
        generate_uuid=True,
        label="PROVISIONED_INTO"
        )

    #Export Roles to Accounts to csv file - EDGE
    table_headers = ["UniqueId", "IamRoleArn", "AccountId", "Label"]
    csv_headers = ["~id", "~from", "~to", "~label"]
    export_dynamodb_to_s3(
        "AriaIdCIAMRoles",
        s3_bucket,
        "AriaIdCIAMRoles_Account_Edge.csv",
        table_headers,
        csv_headers,
        generate_uuid=True,
        label="CREATED_IN"
        )

    #Export PermissionsSets to Roles to csv file - EDGE
    table_headers = ["UniqueId", "PermissionSetArn", "IamRoleArn", "Label"]
    csv_headers = ["~id", "~from", "~to", "~label"]
    export_dynamodb_to_s3(
        "AriaIdCIAMRoles",
        s3_bucket,
        "AriaIdCRole_PS_Edge.csv",
        table_headers,
        csv_headers,
        generate_uuid=True,
        label="CREATED_AS",
        skip_if_missing=["PermissionSetArn"]
        )
    
    # Only export Account Access Manager (AAM) data if the table has items
    if check_table_has_items("AriaIdCAccountAccessAssignments"):
        # Export principal-to-role edge (User|Group) -> Role as ASSIGNED_ROLE.
        # ~from is the principal id and ~to is the role ARN; deduped on
        # (PrincipalId, IamRoleArn) so each entitlement yields a single edge.
        table_headers = ["UniqueId", "PrincipalId", "IamRoleArn", "Label"]
        csv_headers = ["~id", "~from", "~to", "~label"]
        export_dynamodb_to_s3(
            "AriaIdCAccountAccessAssignments",
            s3_bucket,
            "AriaIdCAccountAccess_Principal_Role_Edge.csv",
            table_headers,
            csv_headers,
            generate_uuid=True,
            label="ASSIGNED_ROLE",
            dedup_fields=["PrincipalId", "IamRoleArn"]
        )

        # Export role-to-account edge Role -> Account as EXISTS_IN.
        # ~from is the role ARN and ~to is the account id; deduped on
        # (IamRoleArn, AccountId) so each entitled role links to its account once.
        table_headers = ["UniqueId", "IamRoleArn", "AccountId", "Label"]
        csv_headers = ["~id", "~from", "~to", "~label"]
        export_dynamodb_to_s3(
            "AriaIdCAccountAccessAssignments",
            s3_bucket,
            "AriaIdCAccountAccessRole_Account_Edge.csv",
            table_headers,
            csv_headers,
            generate_uuid=True,
            label="EXISTS_IN",
            dedup_fields=["IamRoleArn", "AccountId"]
        )

    # Only export trust-policy CAN_ASSUME edges if the table has items
    if check_table_has_items("AriaIdCRoleTrustPolicies"):
        # Principal -> Role edge. ~from is the trusting principal ARN, ~to is the
        # trusted role ARN, so the edge attaches into existing RoleName nodes.
        # Deduped on (PrincipalArn, RoleArn) so each principal-to-role relationship
        # yields a single edge.
        table_headers = ["UniqueId", "PrincipalArn", "RoleArn", "Label"]
        csv_headers = ["~id", "~from", "~to", "~label"]
        export_dynamodb_to_s3(
            "AriaIdCRoleTrustPolicies",
            s3_bucket,
            "AriaIdCRoleTrustPolicies_CanAssume_Edge.csv",
            table_headers,
            csv_headers,
            generate_uuid=True,
            label="CAN_ASSUME",
            dedup_fields=["PrincipalArn", "RoleArn"]
        )

    # Only export Internal Access Analyzer Findings if the table has items
    if check_table_has_items("AriaIdCInternalAAFindings"):

        #Export Internal Access Analyzer Findings to Roles csv file - EDGE
        table_headers = ["UniqueId", "FindingId", "Principal", "Label"]
        csv_headers = ["~id", "~from", "~to", "~label"]
        export_dynamodb_to_s3(
            "AriaIdCInternalAAFindings",
            s3_bucket,
            "AriaIdCInternalAAFindingsRole_Edge.csv",
            table_headers,
            csv_headers,
            generate_uuid=True,
            label="LINKED_TO"
            )

        #Export Internal Access Analyzer Findings to Resource csv file - EDGE
        table_headers = ["UniqueId", "FindingId", "ResourceARN", "Label"]
        csv_headers = ["~id", "~from", "~to", "~label"]
        export_dynamodb_to_s3(
            "AriaIdCInternalAAFindings",
            s3_bucket,
            "AriaIdCInternalAAFindingsResource_Edge.csv",
            table_headers,
            csv_headers,
            generate_uuid=True,
            label="LINKED_TO"
            )    

        #Export Internal Access Analyzer Findings Principal to Resource csv file - EDGE
        table_headers = ["UniqueId", "Principal", "ResourceARN", "Label"]
        csv_headers = ["~id", "~from", "~to", "~label"]
        export_dynamodb_to_s3(
            "AriaIdCInternalAAFindings",
            s3_bucket,
            "AriaIdCInternalAAF_Principal_Resource_Edge.csv",
            table_headers,
            csv_headers,
            generate_uuid=True,
            label="GRANTS_ACCESS_TO",
            dedup_fields=["Principal", "ResourceARN"]
            )

        #Export Internal Access Analyzer Findings Resource to Account csv file - EDGE
        table_headers = ["UniqueId", "ResourceARN", "ResourceAccount", "Label"]
        csv_headers = ["~id", "~from", "~to", "~label"]
        export_dynamodb_to_s3(
            "AriaIdCInternalAAFindings",
            s3_bucket,
            "AriaIdCInternalAAFindingsResource_Account_Edge.csv",
            table_headers,
            csv_headers,
            generate_uuid=True,
            label="BELONGS_TO",
            dedup_fields=["ResourceARN", "ResourceAccount"]
            )

    # Only export External Access Analyzer Findings if the table has items
    if check_table_has_items("AriaIdCExternalAAFindings"):

        # Export External Access Analyzer Finding to Resource csv file - EDGE
        table_headers = ["UniqueId", "FindingId", "ResourceARN", "Label"]
        csv_headers = ["~id", "~from", "~to", "~label"]
        export_dynamodb_to_s3(
            "AriaIdCExternalAAFindings",
            s3_bucket,
            "AriaIdCExternalAAFindingsResource_Edge.csv",
            table_headers,
            csv_headers,
            generate_uuid=True,
            label="LINKED_TO"
            )

        # Export External Access Analyzer Finding to External Principal csv file - EDGE
        table_headers = ["UniqueId", "FindingId", "Principal", "Label"]
        csv_headers = ["~id", "~from", "~to", "~label"]
        export_dynamodb_to_s3(
            "AriaIdCExternalAAFindings",
            s3_bucket,
            "AriaIdCExternalAAFindingsPrincipal_Edge.csv",
            table_headers,
            csv_headers,
            generate_uuid=True,
            label="LINKED_TO"
            )

        # Export External Principal to Resource csv file - EDGE
        # The external entity has access to the internal resource; dedup on
        # (Principal, ResourceARN) so a single access relationship yields one edge.
        table_headers = ["UniqueId", "Principal", "ResourceARN", "Label"]
        csv_headers = ["~id", "~from", "~to", "~label"]
        export_dynamodb_to_s3(
            "AriaIdCExternalAAFindings",
            s3_bucket,
            "AriaIdCExternal_Principal_Resource_Edge.csv",
            table_headers,
            csv_headers,
            generate_uuid=True,
            label="HAS_EXTERNAL_ACCESS_TO",
            dedup_fields=["Principal", "ResourceARN"]
            )

        # Export External Finding Resource to Account csv file - EDGE
        table_headers = ["UniqueId", "ResourceARN", "ResourceAccount", "Label"]
        csv_headers = ["~id", "~from", "~to", "~label"]
        export_dynamodb_to_s3(
            "AriaIdCExternalAAFindings",
            s3_bucket,
            "AriaIdCExternalResource_Account_Edge.csv",
            table_headers,
            csv_headers,
            generate_uuid=True,
            label="BELONGS_TO",
            dedup_fields=["ResourceARN", "ResourceAccount"]
            )

    # Only export Unused Access Analyzer Findings if the table has items
    if check_table_has_items("AriaIdCUnusedAAFindings"):

        # Modified Unused Finding to Roles - EDGE
        table_headers = ["UniqueId", "ResourceARN", "FindingId", "Label"]
        csv_headers = ["~id", "~from", "~to", "~label"]
        export_dynamodb_to_s3(
            "AriaIdCUnusedAAFindings", 
            s3_bucket, 
            "AriaUnusedAAFindings_Edge.csv", 
            table_headers, 
            csv_headers,
            generate_uuid=True,
            label="HAS_UNUSED_ACCESS"
        )

    return {
        'statusCode': 200,
        'body': json.dumps('Data exported to S3')
    }
