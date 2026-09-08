import json
import boto3
from botocore.config import Config

# Reuse the DynamoDB resource across warm invocations. This Lambda is now a pure
# DynamoDB scan-and-write transform: it reads the enriched AriaIdCIAMRoles table
# and derives (RoleArn, PrincipalArn) trust pairs. No STS, no cross-account IAM,
# no chain-capable permission test.
BOTO_CONFIG = Config(
    retries={'max_attempts': 10, 'mode': 'adaptive'},
    max_pool_connections=50
)
dynamodb = boto3.resource('dynamodb')

# Stop writing once fewer than this many milliseconds remain, so the open
# batch_writer can flush buffered rows before the Lambda timeout.
RUNTIME_SAFETY_BUFFER_MS = 30_000

# Destination table holding one item per (trusted role, trusting principal) pair.
TRUST_POLICIES_TABLE = 'AriaIdCRoleTrustPolicies'


def _scan_all(table, **kwargs):
    # Scan a table fully, following pagination. A plain table.scan() only returns
    # the first 1 MB page, which silently drops data on larger tables.
    items = []
    response = table.scan(**kwargs)
    items.extend(response.get('Items', []))
    while 'LastEvaluatedKey' in response:
        response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'], **kwargs)
        items.extend(response.get('Items', []))
    return items


def empty_trust_policies_table():
    # Empty AriaIdCRoleTrustPolicies before repopulation, deleting by the full
    # composite key {RoleArn, PrincipalArn}. Supplies both key
    # components, matching the RoleArn (HASH) + PrincipalArn (RANGE) schema.
    table = dynamodb.Table(TRUST_POLICIES_TABLE)
    with table.batch_writer() as batch:
        for item in _scan_all(table, ProjectionExpression='RoleArn, PrincipalArn'):
            batch.delete_item(Key={
                'RoleArn': item['RoleArn'],
                'PrincipalArn': item['PrincipalArn']
            })


def lambda_handler(event, context):
    # Pure DynamoDB scan-and-write transform. Scan the enriched AriaIdCIAMRoles
    # table, read each role's stored TrustedPrincipals list, and write one
    # AriaIdCRoleTrustPolicies row per (IamRoleArn, principal) pair. The source
    # table is read-only here and never modified.
    #
    # Returns {statusCode:200, body:{message, rowsWritten, complete}} on success,
    # and wraps the whole run in a 500 handler so an unexpected failure surfaces
    # as an error response rather than an unhandled exception.
    try:
        roles_table = dynamodb.Table('AriaIdCIAMRoles')
        trust_table = dynamodb.Table(TRUST_POLICIES_TABLE)

        # Empty-then-rebuild the destination so revoked trust relationships do
        # not linger.
        empty_trust_policies_table()

        items = _scan_all(roles_table, ProjectionExpression='IamRoleArn, TrustedPrincipals')
        written = 0
        complete = True

        # Single main-thread batch_writer. overwrite_by_pkeys de-duplicates the
        # buffer on the full composite key so a repeated (RoleArn, PrincipalArn)
        # within a flush window cannot trigger a BatchWriteItem duplicate-key
        # error.
        with trust_table.batch_writer(overwrite_by_pkeys=['RoleArn', 'PrincipalArn']) as batch:
            for item in items:
                # Stop before the deadline so the open batch_writer can flush the
                # rows written so far (timeout guard).
                if context is not None and context.get_remaining_time_in_millis() < RUNTIME_SAFETY_BUFFER_MS:
                    print("Approaching Lambda timeout; stopping trust-policy derivation early")
                    complete = False
                    break

                role_arn = item.get('IamRoleArn')
                for principal in (item.get('TrustedPrincipals') or []):
                    batch.put_item(Item={'RoleArn': role_arn, 'PrincipalArn': principal})
                    written += 1

        message = f"Wrote {written} trust-policy rows"
        print(message)
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': message,
                'rowsWritten': written,
                'complete': complete
            })
        }
    except Exception as e:
        print(f"Error deriving trust policies: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error deriving trust policies: {str(e)}")
        }
