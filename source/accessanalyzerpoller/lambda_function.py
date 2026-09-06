import json
import os
import re
import time
import boto3
from datetime import datetime
from botocore.config import Config
from botocore.exceptions import ClientError

# Reuse clients/resources across warm invocations rather than recreating them
# per invocation - this Lambda calls sts:AssumeRole and the Access Analyzer
# API once per Polling_Cycle, so adaptive retries absorb any throttling from
# those calls without needing per-call backoff plumbing.
BOTO_CONFIG = Config(
    retries={'max_attempts': 5, 'mode': 'adaptive'},
    max_pool_connections=25
)

# Fixed pacing delay applied between GetFindingV2 calls in reconcile_family's
# per-finding loop, to stay under Access Analyzer's undocumented, per-account
# throttle. Expressed as requests per second (default 0.5 RPS = 1 request
# every 2 seconds) and set via accessAnalyzerPoller.requestsPerSecond in
# config.yaml (see templates/lambda-functions.yaml's
# AccessAnalyzerPollerRequestsPerSecond parameter, which sets the
# FINDING_FETCH_RATE_LIMIT_RPS environment variable read here).
FINDING_FETCH_RATE_LIMIT_RPS = float(os.environ.get('FINDING_FETCH_RATE_LIMIT_RPS', '0.5'))
FINDING_FETCH_DELAY_SECONDS = 1.0 / FINDING_FETCH_RATE_LIMIT_RPS

# Reserved for the stale-finding delete pass and response wrap-up once the
# per-finding fetch loop in reconcile_family stops. Checked against
# context.get_remaining_time_in_millis() so the fetch loop bails out early
# (reporting more_work=True) instead of running until Lambda kills the
# invocation mid-call, which would drop the whole family's progress for this
# Polling_Cycle instead of the partial progress already made.
FETCH_LOOP_TIME_BUDGET_BUFFER_MS = 60_000

# Upper bound on how many times the Step Functions state machine re-invokes
# the same family's Task while it keeps reporting more_work=True (see
# templates/step-functions.yaml). Caps a single family's catch-up at roughly
# MAX_POLL_ATTEMPTS_PER_FAMILY * 15 minutes; any findings still unprocessed
# after that are simply picked up on the next scheduled Polling_Cycle rather
# than looping indefinitely. Overridable via the MAX_POLL_ATTEMPTS_PER_FAMILY
# environment variable (see templates/lambda-functions.yaml's
# AccessAnalyzerPollerMaxPollAttempts parameter) so a large initial backfill
# (e.g. 10k+ findings) can be given more attempts - and therefore more wall-
# clock time - within one Step Functions execution than routine steady-state
# polling needs, without a code change.
MAX_POLL_ATTEMPTS_PER_FAMILY = int(os.environ.get('MAX_POLL_ATTEMPTS_PER_FAMILY', '6'))

# Diagnostic-logging thresholds/knobs. A single fetch or write that exceeds
# its threshold gets its own log line called out explicitly (searchable via
# "SLOW_FETCH"/"SLOW_WRITE" in CloudWatch Logs Insights) instead of scanning
# through a line for every finding to spot the outlier that is actually
# causing an invocation to run long.
SLOW_FETCH_THRESHOLD_MS = 2000
SLOW_WRITE_THRESHOLD_MS = 500

# How often (in findings processed) to emit a progress heartbeat while
# working through a large fetch backlog, so a long-running invocation shows
# visible, timestamped progress in CloudWatch Logs instead of going quiet
# between the "summary" line at the very start and end of the loop.
PROGRESS_LOG_INTERVAL = 50


def _is_throttling_error(client_error):
    """True if a ClientError represents Access Analyzer throttling.

    Access Analyzer's boto3 error code for throttling is
    ThrottlingException; TooManyRequestsException is also matched since it
    has been observed in this Lambda's own CloudWatch logs for the same
    condition (botocore's retry classifier treats both as throttling-class
    errors for adaptive-mode purposes) and it costs nothing to accept both.
    """
    code = client_error.response.get('Error', {}).get('Code', '')
    return code in ('ThrottlingException', 'TooManyRequestsException')


sts_client = boto3.client('sts', config=BOTO_CONFIG)
# Shares BOTO_CONFIG's adaptive retries/larger pool with the Access Analyzer
# client - without this, DynamoDB calls fell back to botocore's default
# 'legacy' retry mode and a small connection pool, which is a poor fit for
# the batch writes reconcile_family issues per Polling_Cycle.
dynamodb = boto3.resource('dynamodb', config=BOTO_CONFIG)

# Delegated administrator account/role this Lambda assumes into before it can
# call the Access Analyzer API against the organization-scoped analyzers.
DELEGATED_ADMIN_ACCOUNT_ID = os.environ['DELEGATED_ADMIN_ACCOUNT_ID']
POLLER_ROLE_NAME = os.environ.get('POLLER_ROLE_NAME', 'AriaAccessAnalyzerPollerRole')

# Analyzer ARNs are operator-supplied (never discovered via ListAnalyzers) so
# the poller only ever queries the exact analyzer designated for each finding
# family, and never an auto-created analyzer of the same type.
INTERNAL_ACCESS_ANALYZER_ARN = os.environ['INTERNAL_ACCESS_ANALYZER_ARN']
EXTERNAL_ACCESS_ANALYZER_ARN = os.environ['EXTERNAL_ACCESS_ANALYZER_ARN']
UNUSED_ACCESS_ANALYZER_ARN = os.environ['UNUSED_ACCESS_ANALYZER_ARN']


def get_delegated_admin_client(current_account_id):
    """Return an accessanalyzer client scoped to the delegated administrator account.

    If the delegated administrator account is the same account this Lambda
    runs in, no cross-account assumption is needed or possible (a role
    cannot usefully assume itself across accounts) - the Lambda's own
    execution-role credentials already have direct access, granted by
    AccessAnalyzerPollerManagedPolicy alongside the cross-account AssumeRole
    grant. Only when the two accounts differ does this assume
    AriaAccessAnalyzerPollerRole (mirrors the ROLE_TO_ASSUME pattern in
    source/getiamroles/lambda_function.py) in the Delegated_Administrator_Account.
    Credentials are re-assumed per invocation; this Lambda runs infrequently
    (once per Polling_Cycle) so no warm-start cache.
    """
    if current_account_id == DELEGATED_ADMIN_ACCOUNT_ID:
        print("get_delegated_admin_client: same-account fast path, no AssumeRole")
        return boto3.client('accessanalyzer', config=BOTO_CONFIG)

    role_arn = f"arn:aws:iam::{DELEGATED_ADMIN_ACCOUNT_ID}:role/{POLLER_ROLE_NAME}"
    start = time.monotonic()
    creds = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='AccessAnalyzerPollerSession'
    )['Credentials']
    print(f"get_delegated_admin_client: AssumeRole took {(time.monotonic() - start) * 1000:.0f} ms")
    return boto3.client(
        'accessanalyzer',
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
        config=BOTO_CONFIG
    )


def list_active_finding_ids(client, analyzer_arn):
    """Return a mapping of ACTIVE finding id -> its current updatedAt timestamp.

    Requirement 3.1/3.3: filters on status=ACTIVE and fully paginates via
    the list_findings_v2 paginator so every page for this analyzer is
    aggregated before returning. FindingSummaryV2 already carries updatedAt
    at no extra API cost beyond the list call itself, so reconcile_family
    can diff it against what is already stored to skip re-fetching (via
    GetFindingV2) any finding that has not changed since the last
    Polling_Cycle - see reconcile_family for why that matters.
    """
    start = time.monotonic()
    active = {}
    page_count = 0
    paginator = client.get_paginator('list_findings_v2')
    for page in paginator.paginate(
        analyzerArn=analyzer_arn,
        filter={'status': {'eq': ['ACTIVE']}}
    ):
        page_count += 1
        for finding in page['findings']:
            active[finding['id']] = _iso(finding.get('updatedAt'))
    elapsed_ms = (time.monotonic() - start) * 1000
    print(
        f"list_active_finding_ids: {len(active)} active finding(s) across "
        f"{page_count} page(s) in {elapsed_ms:.0f} ms ({analyzer_arn})"
    )
    return active


def fetch_finding_detail(client, analyzer_arn, finding_id):
    """Fetch the full finding detail for a finding id from the same analyzer.

    Requirement 3.2: full detail is retrieved before any table row is
    populated for that finding id. Returns (finding_v2, elapsed_ms) so
    reconcile_family can track per-call latency without a second timer at
    every call site; a call that individually exceeds
    SLOW_FETCH_THRESHOLD_MS is logged immediately so a single slow
    GetFinding call is visible instead of only showing up as an average.
    """
    start = time.monotonic()
    result = client.get_finding_v2(analyzerArn=analyzer_arn, id=finding_id)
    elapsed_ms = (time.monotonic() - start) * 1000
    if elapsed_ms >= SLOW_FETCH_THRESHOLD_MS:
        print(f"SLOW_FETCH: GetFinding for {finding_id} took {elapsed_ms:.0f} ms")
    return result, elapsed_ms


def _iso(value):
    """Return an ISO 8601 string for a datetime, or pass through unchanged.

    botocore deserializes GetFindingV2/ListFindingsV2 timestamp fields
    (createdAt/updatedAt/analyzedAt) as native datetime.datetime objects,
    whereas the legacy EventBridge Access Analyzer finding events always
    carried these as ISO 8601 strings. DynamoDB's Table resource serializer
    has no support for datetime.datetime, so any raw datetime reaching
    put_item() raises. Converting here keeps the timestamp values string-
    shaped exactly as the parse_* functions expect. Defensive no-op for
    anything that is not a datetime (already a string, a test double, or
    None).
    """
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def to_legacy_detail(family, finding_v2):
    """Adapt a GetFindingV2 response into the legacy EventBridge detail shape.

    The three parsing functions (parse_internalaccess_finding,
    parse_unusedaccess_finding, parse_externalaccess_finding) were written
    against the flat 'detail' dict carried by EventBridge Access Analyzer
    finding events. GetFindingV2 instead returns top-level fields plus a
    findingDetails list holding family-specific nested detail objects. This
    adapter reconstructs the legacy shape so the parsing functions can be
    invoked unchanged (Requirements 3.4, 4.1, 4.2, 4.3).
    """
    detail = {
        'id': finding_v2['id'],
        'status': finding_v2['status'],
        'createdAt': _iso(finding_v2['createdAt']),
        'updatedAt': _iso(finding_v2['updatedAt']),
        'resource': finding_v2.get('resource', 'N/A'),
        'resourceType': finding_v2.get('resourceType', 'N/A'),
        'accountId': finding_v2.get('resourceOwnerAccount', 'N/A'),
        'resourceOwnerAccount': finding_v2.get('resourceOwnerAccount', 'N/A'),
        'findingType': finding_v2.get('findingType'),
    }
    if 'error' in finding_v2:
        detail['error'] = finding_v2['error']
        return detail
    if 'analyzedAt' in finding_v2:
        detail['analyzedAt'] = _iso(finding_v2['analyzedAt'])

    finding_details = finding_v2.get('findingDetails', [])

    if family == 'internal':
        d = next((f['internalAccessDetails'] for f in finding_details
                   if 'internalAccessDetails' in f), {})
        principal_map = d.get('principal', {}) or {}
        detail['principal'] = {
            'AWS': principal_map.get('AWS') or next(iter(principal_map.values()), 'N/A')
        }
        detail['principalType'] = d.get('principalType', 'N/A')
        detail['principalOwnerAccount'] = d.get('principalOwnerAccount', 'N/A')
        detail['resourceControlPolicyRestrictionType'] = d.get('resourceControlPolicyRestriction', 'N/A')
        detail['serviceControlPolicyRestrictionType'] = d.get('serviceControlPolicyRestriction', 'N/A')
        detail['accessType'] = d.get('accessType', 'N/A')
        detail['action'] = d.get('action', [])

    elif family == 'unused':
        unused_permission_entries = [
            f['unusedPermissionDetails'] for f in finding_details
            if 'unusedPermissionDetails' in f
        ]
        namespaces = {e.get('serviceNamespace') for e in unused_permission_entries if e.get('serviceNamespace')}
        detail['numberOfUnusedServices'] = len(namespaces)
        detail['numberOfUnusedActions'] = sum(len(e.get('actions', [])) for e in unused_permission_entries)

    elif family == 'external':
        d = next((f['externalAccessDetails'] for f in finding_details
                   if 'externalAccessDetails' in f), {})
        detail['principal'] = d.get('principal', {})
        detail['isPublic'] = d.get('isPublic', False)
        detail['action'] = d.get('action', [])
        detail['condition'] = d.get('condition', {})

    return detail


def poll_analyzer_with_retry(fn, *args, max_attempts=4, **kwargs):
    """Call fn with a bounded, exponential-backoff retry policy.

    Requirement 9.1: bounded retry with backoff before a call is treated
    as failed. Reuses the retryable-error set already applied via BOTO_CONFIG
    for throttling; this wrapper additionally retries transient errors that
    adaptive retries inside botocore do not cover (e.g. connection resets)
    at the family level so one bad call does not abort the whole family.
    """
    delay = 1
    last_error = None
    for attempt in range(1, max_attempts + 1):
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            last_error = e
            if attempt == max_attempts:
                break
            time.sleep(delay)
            delay *= 2
    raise last_error


# Roles provisioned by IAM Identity Center live under this reserved path. The
# poller scopes internal/unused access findings to "roles we visualize": an
# IdC/SSO role or an Account Access Manager (AAM) entitled role. NOTE: this
# matches the standard 'aws' partition only, mirroring the previous
# EventBridge-based ingestion Lambda; broaden the partition segment (e.g.
# arn:[^:]+:iam::) for GovCloud/China.
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

    start = time.monotonic()
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
    elapsed_ms = (time.monotonic() - start) * 1000
    print(f"get_aam_role_arns: refreshed cache with {len(role_arns)} role(s) in {elapsed_ms:.0f} ms")
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


def internal_scope_filter(detail):
    """Scope filter for internal access findings (Requirement 6.1, 6.3, 6.5).

    Only IAM_ROLE principals are eligible, and the principal role ARN must
    be a Tracked_Role (an IdC/SSO role or an AAM-entitled role).
    """
    if detail.get('principalType') != 'IAM_ROLE':
        return False
    return is_tracked_role(detail.get('principal', {}).get('AWS', ''))


def unused_scope_filter(detail):
    """Scope filter for unused access findings (Requirement 6.2, 6.3, 6.5).

    Only AWS::IAM::Role resources are eligible, and the resource role ARN
    must be a Tracked_Role (an IdC/SSO role or an AAM-entitled role).
    """
    if detail.get('resourceType') != 'AWS::IAM::Role':
        return False
    return is_tracked_role(detail.get('resource', ''))


def get_finding_id(detail):
    """Return the finding identifier, tolerating both event schemas.

    IAM Access Analyzer uses different keys per finding family: internal and
    external (Access Analyzer Finding) events carry 'id', while unused-access
    events carry 'findingId'. Accept either so no family throws a KeyError.
    """
    return detail.get('id') or detail.get('findingId')


def extract_role_name(arn):
    # Split by '/' and get the last element
    role_name = arn.split('/')[-1]
    return role_name


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


def _scan_all(table, **kwargs):
    # Scan a table fully, following pagination. A plain table.scan() only returns
    # the first 1 MB page, which silently drops data on larger tables. Mirrors
    # the _scan_all helper in source/listaccountaccessassignments/lambda_function.py
    # and source/gettrustpolicies/lambda_function.py.
    items = []
    response = table.scan(**kwargs)
    items.extend(response.get('Items', []))
    while 'LastEvaluatedKey' in response:
        response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'], **kwargs)
        items.extend(response.get('Items', []))
    return items


# Maps a finding family name to the existing parsing function that upserts its
# adapted detail into the family's finding table (Requirement 4.1, 4.2, 4.3).
PARSERS = {
    'internal': parse_internalaccess_finding,
    'unused': parse_unusedaccess_finding,
    'external': parse_externalaccess_finding,
}


def reconcile_family(family, client, analyzer_arn, table, context, scope_filter=None):
    """Reconcile one finding family's table against its analyzer's Active_Finding set.

    For every ACTIVE finding that is new or has changed (updatedAt differs
    from the value already stored for that FindingId), fetch its full
    detail, adapt it to the legacy shape, apply the optional scope filter,
    and upsert a row (Requirements 4.4, 4.5, 6.x). A finding whose stored
    UpdatedAt already matches the analyzer's current updatedAt is skipped
    entirely - no GetFindingV2 call, no write - since Access Analyzer
    findings stay ACTIVE indefinitely until resolved, so most findings on
    any given Polling_Cycle are unchanged since the last one.

    Both the upsert loop and the stale-delete pass write through a
    `table.batch_writer()` rather than one put_item/delete_item call per
    finding. BatchWriter buffers up to 25 items and flushes them in a single
    BatchWriteItem request (retrying any UnprocessedItems itself), which was
    the main driver of "slow to update DynamoDB after parsing a finding" -
    one HTTP round trip per finding vs. one per ~25. The `PARSERS[family]`
    functions are unchanged: BatchWriter exposes the same `put_item(Item=...)`
    signature as Table, so passing the batch writer in place of the table
    is a drop-in swap. One tradeoff: BatchWriteItem has no ConditionExpression
    support, so the stale-delete pass no longer distinguishes "deleted" from
    "was already gone" the way the old per-item
    `ConditionExpression='attribute_exists(FindingId)'` delete did - deleting
    an already-absent id is now a silent no-op rather than a logged
    already-deleted message, and `deleted` below counts attempted deletes
    rather than confirmed ones.

    If the fetch loop is still working through changed/new findings when
    the Lambda is close to running out of time, it stops early rather than
    risk being killed mid-call, and reports more_work=True so the caller
    (lambda_handler, and in turn the Step Functions state machine) knows to
    re-invoke this same family. Because the skip check above is keyed off
    each finding's stored UpdatedAt, a re-invocation naturally resumes where
    the last one left off: everything already upserted this cycle is now
    "current" and gets skipped again, so only the remaining changed/new
    findings are fetched. No separate continuation cursor is needed. The
    stale-finding delete pass only runs once the fetch loop has gone through
    every changed/new finding (more_work is False), so a family working
    through a large backlog does not repeat a full table scan on every
    re-invocation.
    """
    family_start = time.monotonic()

    active = list_active_finding_ids(client, analyzer_arn)
    active_ids = set(active)

    scan_start = time.monotonic()
    existing_items = _scan_all(table, ProjectionExpression='FindingId, UpdatedAt')
    scan_ms = (time.monotonic() - scan_start) * 1000
    existing_updated_at = {item['FindingId']: item.get('UpdatedAt') for item in existing_items}
    existing_ids = set(existing_updated_at)
    print(
        f"reconcile_family[{family}]: table scan returned {len(existing_items)} "
        f"existing row(s) in {scan_ms:.0f} ms"
    )

    to_fetch = [
        finding_id for finding_id in active_ids
        if existing_updated_at.get(finding_id) != active[finding_id]
    ]
    already_current = len(active_ids) - len(to_fetch)
    print(
        f"reconcile_family[{family}]: {len(to_fetch)} finding(s) to fetch this "
        f"cycle, {already_current} already current"
    )

    upserted = 0
    skipped_out_of_scope = 0
    skipped_errors = 0
    parse_errors = 0
    more_work = False

    # Cumulative time spent in each phase of the loop below, so the final
    # summary line can show where the invocation's wall-clock time actually
    # went (GetFinding calls, the pacing sleep, or parse-and-queue) instead
    # of just the loop's total elapsed time.
    fetch_total_ms = 0.0
    write_total_ms = 0.0
    processed = 0
    throttle_count = 0

    with table.batch_writer(overwrite_by_pkeys=['FindingId']) as batch:
        for finding_id in to_fetch:
            if context.get_remaining_time_in_millis() < FETCH_LOOP_TIME_BUDGET_BUFFER_MS:
                print(
                    f"Time budget nearly exhausted for {family}; stopping early with "
                    f"{len(to_fetch) - upserted - skipped_out_of_scope - skipped_errors - parse_errors} "
                    "changed/new finding(s) still to fetch this cycle."
                )
                more_work = True
                break

            # Fixed pacing: one GetFindingV2 call per FINDING_FETCH_DELAY_SECONDS
            # (i.e. FINDING_FETCH_RATE_LIMIT_RPS requests per second), applied
            # before every call regardless of whether the previous one
            # succeeded or was throttled.
            time.sleep(FINDING_FETCH_DELAY_SECONDS)

            try:
                finding_v2, fetch_ms = fetch_finding_detail(client, analyzer_arn, finding_id)
                fetch_total_ms += fetch_ms
            except ClientError as e:
                if _is_throttling_error(e):
                    throttle_count += 1
                    print(f"Throttled fetching {family} finding {finding_id}")
                else:
                    print(f"Error fetching {family} finding {finding_id}: {e}")
                parse_errors += 1
                continue

            detail = to_legacy_detail(family, finding_v2)
            if 'error' in detail:
                # Requirement 3.4: error-finding detail, no row to write.
                skipped_errors += 1
                continue

            if scope_filter is not None and not scope_filter(detail):
                skipped_out_of_scope += 1
                continue

            try:
                write_start = time.monotonic()
                PARSERS[family]({'detail': detail}, batch)
                write_ms = (time.monotonic() - write_start) * 1000
                write_total_ms += write_ms
                if write_ms >= SLOW_WRITE_THRESHOLD_MS:
                    # A batch_writer put_item is normally just a local buffer
                    # append (sub-millisecond); a slow one here almost always
                    # means the buffer just hit its 25-item flush and the
                    # actual BatchWriteItem call landed inside this put_item.
                    print(f"SLOW_WRITE: queuing {finding_id} for {family} took {write_ms:.0f} ms")
                upserted += 1
            except Exception as e:
                # Requirement 9.4: log and continue past a single malformed finding.
                print(f"Error parsing {family} finding {finding_id}: {e}")
                parse_errors += 1

            processed += 1
            if processed % PROGRESS_LOG_INTERVAL == 0:
                elapsed_ms = (time.monotonic() - family_start) * 1000
                print(
                    f"reconcile_family[{family}]: progress {processed}/{len(to_fetch)} - "
                    f"fetch_total={fetch_total_ms:.0f} ms write_total={write_total_ms:.0f} ms "
                    f"elapsed={elapsed_ms:.0f} ms remaining_time={context.get_remaining_time_in_millis()} ms"
                )

    delete_start = time.monotonic()
    deleted = 0
    if not more_work:
        stale_ids = existing_ids - active_ids
        with table.batch_writer() as batch:
            for stale_id in stale_ids:
                batch.delete_item(Key={'FindingId': str(stale_id)})
                deleted += 1
    delete_ms = (time.monotonic() - delete_start) * 1000

    total_ms = (time.monotonic() - family_start) * 1000
    print(
        f"reconcile_family[{family}] timing: total={total_ms:.0f} ms "
        f"scan={scan_ms:.0f} ms fetch_total={fetch_total_ms:.0f} ms "
        f"write_total={write_total_ms:.0f} ms delete={delete_ms:.0f} ms "
        f"({processed} finding(s) fetched, {deleted} deleted, "
        f"{throttle_count} throttle(s), pacing delay={FINDING_FETCH_DELAY_SECONDS:.2f}s)"
    )

    return {
        'family': family,
        'upserted': upserted,
        'deleted': deleted,
        'already_current': already_current,
        'skipped_out_of_scope': skipped_out_of_scope,
        'skipped_errors': skipped_errors,
        'parse_errors': parse_errors,
        'more_work': more_work,
    }


def lambda_handler(event, context):
    """Entry point for one Polling_Cycle across internal and external families.

    The unused IAM-role family is intentionally not handled here. Its summary
    dispatcher and strict-global-RPS SQS detail worker live in
    unused_role_pipeline.py, so an unused backlog cannot consume this
    function's 15-minute polling budget.

    Builds the internal/external family list from the operator-supplied
    analyzer ARNs, assumes the delegated-admin role once, and reconciles each
    family in turn. A family whose retries are exhausted is recorded in
    family_failures and the remaining family is still processed.

    Supports two invocation modes:
    - Single-family: when `event` carries a supported 'family' key (for
      example, {"family": "internal"}), Step Functions invokes only that
      family.
    - All-supported-families: when `event` has no 'family' key, manual or
      console invocations reconcile internal and external in turn.

    `event` may also carry a 'poll_attempt' integer (default 1). When
    reconcile_family reports more_work=True, the returned body's
    'more_work'/'next_poll_attempt' fields tell the caller to re-invoke the
    same Lambda. Once poll_attempt reaches MAX_POLL_ATTEMPTS_PER_FAMILY,
    more_work is forced to False so the loop terminates and the remaining
    backlog is deferred to the next scheduled cycle.
    """
    # Unused IAM-role findings are dispatched to SQS by
    # unused_role_pipeline.unused_role_dispatcher_handler and processed by its
    # strict-global-RPS worker. This legacy Step Functions handler therefore
    # retains only the internal and external families.
    families = [
        ('internal', INTERNAL_ACCESS_ANALYZER_ARN, 'AriaIdCInternalAAFindings', internal_scope_filter),
        ('external', EXTERNAL_ACCESS_ANALYZER_ARN, 'AriaIdCExternalAAFindings', None),
    ]

    requested_family = event.get('family') if isinstance(event, dict) else None
    if requested_family is not None:
        families = [f for f in families if f[0] == requested_family]
        if not families:
            raise ValueError(f"Unknown finding family '{requested_family}'")

    poll_attempt = event.get('poll_attempt', 1) if isinstance(event, dict) else 1

    invocation_start = time.monotonic()
    print(
        f"lambda_handler: starting invocation for families={[f[0] for f in families]} "
        f"poll_attempt={poll_attempt} remaining_time={context.get_remaining_time_in_millis()} ms"
    )

    current_account_id = context.invoked_function_arn.split(':')[4]
    client = get_delegated_admin_client(current_account_id)
    results = []
    family_failures = []

    for family, analyzer_arn, table_name, scope_filter in families:
        table = dynamodb.Table(table_name)
        family_start = time.monotonic()
        try:
            result = poll_analyzer_with_retry(
                reconcile_family, family, client, analyzer_arn, table, context, scope_filter
            )
            if result['more_work'] and poll_attempt >= MAX_POLL_ATTEMPTS_PER_FAMILY:
                print(
                    f"Family '{family}' still has unfetched changed/new findings after "
                    f"{poll_attempt} poll attempts; deferring the remainder to the next "
                    "scheduled Polling_Cycle instead of looping further."
                )
                result['more_work'] = False
            results.append(result)
            family_elapsed_ms = (time.monotonic() - family_start) * 1000
            print(
                f"Polling_Cycle summary [{family}]: upserted={result['upserted']} "
                f"deleted={result['deleted']} already_current={result['already_current']} "
                f"skipped_out_of_scope={result['skipped_out_of_scope']} "
                f"skipped_errors={result['skipped_errors']} parse_errors={result['parse_errors']} "
                f"more_work={result['more_work']} elapsed={family_elapsed_ms:.0f} ms"
            )
        except ClientError as e:
            print(f"Finding family '{family}' failed after retries: {e}")
            family_failures.append(family)
            # Requirement 2.5/9.2: continue with the remaining families.
            continue

    status_code = 200 if not family_failures else 500
    total_elapsed_ms = (time.monotonic() - invocation_start) * 1000
    print(
        f"lambda_handler: invocation complete in {total_elapsed_ms:.0f} ms, "
        f"remaining_time={context.get_remaining_time_in_millis()} ms, statusCode={status_code}"
    )
    return {
        'statusCode': status_code,
        'body': {
            'families_processed': [r['family'] for r in results],
            'families_failed': family_failures,
            'results': results,
            'more_work': any(r['more_work'] for r in results),
            'poll_attempt': poll_attempt,
            'next_poll_attempt': poll_attempt + 1,
        }
    }
