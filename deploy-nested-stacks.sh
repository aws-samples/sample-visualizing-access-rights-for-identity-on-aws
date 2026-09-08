#!/bin/bash

# Deploy nested CloudFormation stacks for Access Rights for Identity on AWS
# This script uploads templates to S3 and deploys the main stack

set -e

# Configuration
STACK_NAME="aria-gv-setup"
REGION="us-east-1"
DEPLOY_NEPTUNE="true"
DEPLOY_NEPTUNE_NOTEBOOK="true"
PUBLIC_IP="0.0.0.0/0"

# MCP Server (AgentCore) Configuration
DEPLOY_MCP_SERVER="false"
MCP_CONTAINER_IMAGE_URI=""
MCP_AGENT_RUNTIME_NAME="aria_gv_mcp"

# Data Collection Scheduling Configuration
ENABLE_DATA_COLLECTION_SCHEDULING="false"
DATA_COLLECTION_SCHEDULE_EXPRESSION="rate(6 hours)"
DATA_COLLECTION_SCHEDULE_DESCRIPTION="Automated ARIA identity data collection every 6 hours"
DATA_COLLECTION_SCHEDULE_TIMEZONE="UTC"

# Graph Export Scheduling Configuration
ENABLE_GRAPH_EXPORT_SCHEDULING="false"
GRAPH_EXPORT_SCHEDULE_EXPRESSION="rate(1 day)"
GRAPH_EXPORT_SCHEDULE_DESCRIPTION="Daily execution of ARIA graph export and import"
GRAPH_EXPORT_SCHEDULE_TIMEZONE="UTC"

# Access Analyzer Scheduling Configuration - AriaAccessAnalyzerStateMachine
# runs on its own schedule, independent of data collection, so findings can
# be polled more frequently.
ENABLE_ACCESS_ANALYZER_SCHEDULING="false"
ACCESS_ANALYZER_SCHEDULE_EXPRESSION="rate(15 minutes)"
ACCESS_ANALYZER_SCHEDULE_DESCRIPTION="Automated ARIA Access Analyzer findings polling every 15 minutes"
ACCESS_ANALYZER_SCHEDULE_TIMEZONE="UTC"

# Access Analyzer Poller Configuration
INTERNAL_ACCESS_ANALYZER_ARN=""
EXTERNAL_ACCESS_ANALYZER_ARN=""
UNUSED_ACCESS_ANALYZER_ARN=""
DELEGATED_ADMIN_ACCOUNT_ID=""
ACCESS_ANALYZER_POLLER_ROLE_NAME="AriaAccessAnalyzerPollerRole"
ACCESS_ANALYZER_POLLER_MAX_POLL_ATTEMPTS="6"
ACCESS_ANALYZER_POLLER_REQUESTS_PER_SECOND="0.5"
ACCESS_ANALYZER_DISPATCHER_ROLE_NAME="AriaAccessAnalyzerDispatcherRole"
ACCESS_ANALYZER_WORKER_ROLE_NAME="AriaAccessAnalyzerWorkerRole"
UNUSED_ROLE_WORKER_REQUESTS_PER_SECOND="0.5"
UNUSED_ROLE_WORKER_BATCH_SIZE="10"
UNUSED_ROLE_QUEUE_VISIBILITY_TIMEOUT_SECONDS="600"
UNUSED_ROLE_QUEUE_MAX_RECEIVE_COUNT="5"
UNUSED_ROLE_DISPATCHER_LEASE_SECONDS="900"

# Shared role filtering for Access Analyzer and trust-chain processing.
ROLE_FILTER_INCLUDE_PERMISSION_SETS="true"
ROLE_FILTER_INCLUDE_AAM_ROLES="true"
ROLE_FILTER_INCLUDE_ROLE_NAME_PATTERNS="[]"
# Exclude patterns are a denylist that wins over every include selector: a role
# whose name matches one is dropped even if it is a permission-set or AAM role
# or matches an include pattern.
ROLE_FILTER_EXCLUDE_ROLE_NAME_PATTERNS="[]"

# Debug output configuration. When DEBUG is "true", AWS CLI stdout/stderr that
# is normally sent to /dev/null is surfaced instead, so failures are no longer
# silent. When DEBUG_LOG_FILE is set that output is also appended to the file.
DEBUG="false"
DEBUG_LOG_FILE=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Emit a debug line to stderr (and the debug log file, if configured) but only
# when --debug is enabled. Normal runs stay quiet.
echo_debug() {
    if [[ "$DEBUG" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $1" >&2
        if [[ -n "$DEBUG_LOG_FILE" ]]; then
            echo "[DEBUG] $1" >> "$DEBUG_LOG_FILE"
        fi
    fi
}

# Run a command, suppressing its output on normal runs (preserving the previous
# `> /dev/null 2>&1` behavior) but surfacing full stdout/stderr when --debug is
# enabled. With --debug-log-file set, that output is also appended to the log
# file. The command's own exit status is always preserved, so `set -e` and `if`
# predicates behave exactly as they did before.
run_cmd() {
    if [[ "$DEBUG" == "true" ]]; then
        echo_debug "Running: $*"
        if [[ -n "$DEBUG_LOG_FILE" ]]; then
            "$@" 2>&1 | tee -a "$DEBUG_LOG_FILE"
            return "${PIPESTATUS[0]}"
        fi
        "$@"
        return $?
    fi
    "$@" > /dev/null 2>&1
}

# Function to parse the YAML config file into shell variable assignments.
# Emits `YAML_KEY=value` lines (one per recognized setting) that the caller
# evaluates with `eval "$(parse_yaml_config "$CONFIG_FILE")"`. Missing keys
# emit nothing, so a partial YAML file leaves those variables at whatever
# value they already held (their hardcoded default).
# On a missing PyYAML dependency or a YAML syntax error, a single
# `YAML_PARSE_ERROR=<description>` line is emitted instead.
parse_yaml_config() {
    local config_file=$1
    python3 - "$config_file" <<'PYEOF'
import sys
import shlex
import json

try:
    import yaml
except ImportError:
    print("YAML_PARSE_ERROR=PyYAML is required to read --config-file; install it with: pip3 install pyyaml")
    sys.exit(1)

path = sys.argv[1]
try:
    with open(path, "r") as fh:
        config = yaml.safe_load(fh) or {}
except yaml.YAMLError as e:
    print(f"YAML_PARSE_ERROR={shlex.quote(str(e))}")
    sys.exit(1)
except Exception as e:
    print(f"YAML_PARSE_ERROR={shlex.quote(str(e))}")
    sys.exit(1)

if not isinstance(config, dict):
    print("YAML_PARSE_ERROR=top-level YAML content must be a mapping of settings")
    sys.exit(1)

def emit(var_name, value):
    if value is None:
        return
    if isinstance(value, bool):
        value = "true" if value else "false"
    print(f"{var_name}={shlex.quote(str(value))}")

def emit_json_array(var_name, value):
    if value is None:
        return
    if not isinstance(value, list) or any(
        not isinstance(entry, str) or not entry for entry in value
    ):
        print(
            "YAML_PARSE_ERROR="
            + shlex.quote(f"{var_name} must be a YAML list of non-empty strings")
        )
        sys.exit(1)
    print(f"{var_name}={shlex.quote(json.dumps(value))}")


mcp = config.get("mcpServer", {}) or {}
dcs = config.get("dataCollectionScheduling", {}) or {}
ges = config.get("graphExportScheduling", {}) or {}
aas = config.get("accessAnalyzerScheduling", {}) or {}
aap = config.get("accessAnalyzerPoller", {}) or {}
role_filters = config.get("roleFiltering", {}) or {}
if not isinstance(role_filters, dict):
    print("YAML_PARSE_ERROR=roleFiltering must be a mapping")
    sys.exit(1)

emit("YAML_STACK_NAME", config.get("stackName"))
emit("YAML_TEMPLATES_BUCKET", config.get("templatesBucket"))
emit("YAML_REGION", config.get("region"))
emit("YAML_DEPLOY_NEPTUNE", config.get("deployNeptune"))
emit("YAML_DEPLOY_NEPTUNE_NOTEBOOK", config.get("deployNeptuneNotebook"))
emit("YAML_PUBLIC_IP", config.get("publicIp"))
emit("YAML_DEPLOY_MCP_SERVER", mcp.get("deploy"))
emit("YAML_MCP_CONTAINER_IMAGE_URI", mcp.get("containerImageUri"))
emit("YAML_MCP_AGENT_RUNTIME_NAME", mcp.get("agentRuntimeName"))
emit("YAML_ENABLE_DATA_COLLECTION_SCHEDULING", dcs.get("enabled"))
emit("YAML_DATA_COLLECTION_SCHEDULE_EXPRESSION", dcs.get("scheduleExpression"))
emit("YAML_DATA_COLLECTION_SCHEDULE_DESCRIPTION", dcs.get("scheduleDescription"))
emit("YAML_DATA_COLLECTION_SCHEDULE_TIMEZONE", dcs.get("scheduleTimezone"))
emit("YAML_ENABLE_GRAPH_EXPORT_SCHEDULING", ges.get("enabled"))
emit("YAML_GRAPH_EXPORT_SCHEDULE_EXPRESSION", ges.get("scheduleExpression"))
emit("YAML_GRAPH_EXPORT_SCHEDULE_DESCRIPTION", ges.get("scheduleDescription"))
emit("YAML_GRAPH_EXPORT_SCHEDULE_TIMEZONE", ges.get("scheduleTimezone"))
emit("YAML_ENABLE_ACCESS_ANALYZER_SCHEDULING", aas.get("enabled"))
emit("YAML_ACCESS_ANALYZER_SCHEDULE_EXPRESSION", aas.get("scheduleExpression"))
emit("YAML_ACCESS_ANALYZER_SCHEDULE_DESCRIPTION", aas.get("scheduleDescription"))
emit("YAML_ACCESS_ANALYZER_SCHEDULE_TIMEZONE", aas.get("scheduleTimezone"))
emit("YAML_INTERNAL_ACCESS_ANALYZER_ARN", aap.get("internalAccessAnalyzerArn"))
emit("YAML_EXTERNAL_ACCESS_ANALYZER_ARN", aap.get("externalAccessAnalyzerArn"))
emit("YAML_UNUSED_ACCESS_ANALYZER_ARN", aap.get("unusedAccessAnalyzerArn"))
emit("YAML_DELEGATED_ADMIN_ACCOUNT_ID", aap.get("delegatedAdminAccountId"))
emit("YAML_ACCESS_ANALYZER_POLLER_ROLE_NAME", aap.get("accessAnalyzerPollerRoleName"))
emit("YAML_ACCESS_ANALYZER_POLLER_MAX_POLL_ATTEMPTS", aap.get("maxPollAttempts"))
emit("YAML_ACCESS_ANALYZER_POLLER_REQUESTS_PER_SECOND", aap.get("requestsPerSecond"))
emit("YAML_ACCESS_ANALYZER_DISPATCHER_ROLE_NAME", aap.get("accessAnalyzerDispatcherRoleName"))
emit("YAML_ACCESS_ANALYZER_WORKER_ROLE_NAME", aap.get("accessAnalyzerWorkerRoleName"))
emit("YAML_UNUSED_ROLE_WORKER_REQUESTS_PER_SECOND", aap.get("unusedRoleWorkerRequestsPerSecond"))
emit("YAML_UNUSED_ROLE_WORKER_BATCH_SIZE", aap.get("unusedRoleWorkerBatchSize"))
emit("YAML_UNUSED_ROLE_QUEUE_VISIBILITY_TIMEOUT_SECONDS", aap.get("unusedRoleQueueVisibilityTimeoutSeconds"))
emit("YAML_UNUSED_ROLE_QUEUE_MAX_RECEIVE_COUNT", aap.get("unusedRoleQueueMaxReceiveCount"))
emit("YAML_UNUSED_ROLE_DISPATCHER_LEASE_SECONDS", aap.get("unusedRoleDispatcherLeaseSeconds"))
emit("YAML_ROLE_FILTER_INCLUDE_PERMISSION_SETS", role_filters.get("includePermissionSets"))
emit("YAML_ROLE_FILTER_INCLUDE_AAM_ROLES", role_filters.get("includeAamRoles"))
emit_json_array("YAML_ROLE_FILTER_INCLUDE_ROLE_NAME_PATTERNS", role_filters.get("includeRoleNamePatterns"))
emit_json_array("YAML_ROLE_FILTER_EXCLUDE_ROLE_NAME_PATTERNS", role_filters.get("excludeRoleNamePatterns"))
emit("YAML_DEBUG", config.get("debug"))
emit("YAML_DEBUG_LOG_FILE", config.get("debugLogFile"))
PYEOF
}

# Function to check if S3 bucket exists
check_bucket() {
    local bucket_name=$1
    if run_cmd aws s3api head-bucket --bucket "$bucket_name"; then
        echo_info "S3 bucket $bucket_name exists"
        return 0
    else
        echo_error "S3 bucket $bucket_name does not exist"
        return 1
    fi
}

# Function to create S3 bucket if it doesn't exist
create_bucket() {
    local bucket_name=$1
    echo_info "Creating S3 bucket: $bucket_name"
    
    if [ "$REGION" = "us-east-1" ]; then
        run_cmd aws s3api create-bucket --bucket "$bucket_name"
    else
        run_cmd aws s3api create-bucket --bucket "$bucket_name" --region "$REGION" \
            --create-bucket-configuration LocationConstraint="$REGION"
    fi
    
    # Enable versioning
    run_cmd aws s3api put-bucket-versioning --bucket "$bucket_name" \
        --versioning-configuration Status=Enabled
    
    echo_info "S3 bucket $bucket_name created successfully"
    
    # Store the bucket name in SSM parameter store for future reference
    if [ "$bucket_name" = "$TEMPLATES_BUCKET" ]; then
        run_cmd aws ssm put-parameter --name "aria-templates-bucket" --value "$bucket_name" --type "String" --overwrite --region "$REGION"
        echo_info "Templates bucket name stored in SSM parameter store"
    fi
}

# Function to upload templates to S3
upload_templates() {
    echo_info "Uploading CloudFormation templates to S3..."
    
    # Upload all template files
    run_cmd aws s3 cp templates/ s3://"$TEMPLATES_BUCKET"/ --recursive
    
    echo_info "Templates uploaded successfully"
}

# Function to validate CloudFormation template
validate_template() {
    local template_file=$1
    echo_info "Validating template: $template_file"
    
    run_cmd aws cloudformation validate-template --template-body file://"$template_file"
    
    echo_info "Template $template_file is valid"
}

# Function to validate scheduling parameters
validate_scheduling_parameters() {
    # Require the unused access analyzer ARN when a config file was supplied.
    # A deployment configuration file must explicitly
    # specify accessAnalyzerPoller.unusedAccessAnalyzerArn (or the operator
    # must override it with --unused-access-analyzer-arn); flags-only
    # invocations (no --config-file) are unaffected.
    if [[ -n "$CONFIG_FILE" && -z "$UNUSED_ACCESS_ANALYZER_ARN" ]]; then
        echo_error "The unused access analyzer ARN must be specified via the 'accessAnalyzerPoller.unusedAccessAnalyzerArn' YAML key in the config file or the '--unused-access-analyzer-arn' flag."
        exit 1
    fi

    # Validate boolean values
    if [[ "$ENABLE_DATA_COLLECTION_SCHEDULING" != "true" && "$ENABLE_DATA_COLLECTION_SCHEDULING" != "false" ]]; then
        echo_error "Invalid value for --enable-data-collection-scheduling: $ENABLE_DATA_COLLECTION_SCHEDULING (must be 'true' or 'false')"
        exit 1
    fi
    
    if [[ "$ENABLE_GRAPH_EXPORT_SCHEDULING" != "true" && "$ENABLE_GRAPH_EXPORT_SCHEDULING" != "false" ]]; then
        echo_error "Invalid value for --enable-graph-export-scheduling: $ENABLE_GRAPH_EXPORT_SCHEDULING (must be 'true' or 'false')"
        exit 1
    fi

    if [[ "$ENABLE_ACCESS_ANALYZER_SCHEDULING" != "true" && "$ENABLE_ACCESS_ANALYZER_SCHEDULING" != "false" ]]; then
        echo_error "Invalid value for --enable-access-analyzer-scheduling: $ENABLE_ACCESS_ANALYZER_SCHEDULING (must be 'true' or 'false')"
        exit 1
    fi

    if ! awk -v value="$UNUSED_ROLE_WORKER_REQUESTS_PER_SECOND" 'BEGIN { exit !(value + 0 > 0) }'; then
        echo_error "--unused-role-worker-requests-per-second must be greater than zero"
        exit 1
    fi
    if [[ ! "$UNUSED_ROLE_WORKER_BATCH_SIZE" =~ ^([1-9]|10)$ ]]; then
        echo_error "--unused-role-worker-batch-size must be an integer from 1 through 10"
        exit 1
    fi
    if [[ ! "$UNUSED_ROLE_QUEUE_VISIBILITY_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || (( UNUSED_ROLE_QUEUE_VISIBILITY_TIMEOUT_SECONDS < 120 )); then
        echo_error "--unused-role-queue-visibility-timeout-seconds must be an integer of at least 120"
        exit 1
    fi
    if [[ ! "$UNUSED_ROLE_QUEUE_MAX_RECEIVE_COUNT" =~ ^[0-9]+$ ]] || (( UNUSED_ROLE_QUEUE_MAX_RECEIVE_COUNT < 1 )); then
        echo_error "--unused-role-queue-max-receive-count must be an integer of at least 1"
        exit 1
    fi
    if [[ ! "$UNUSED_ROLE_DISPATCHER_LEASE_SECONDS" =~ ^[0-9]+$ ]] || (( UNUSED_ROLE_DISPATCHER_LEASE_SECONDS < 60 )); then
        echo_error "--unused-role-dispatcher-lease-seconds must be an integer of at least 60"
        exit 1
    fi
    if [[ -z "$ACCESS_ANALYZER_DISPATCHER_ROLE_NAME" || -z "$ACCESS_ANALYZER_WORKER_ROLE_NAME" ]]; then
        echo_error "The dispatcher and worker role names must not be empty"
        exit 1
    fi
    
    # Validate schedule expressions (basic validation)
    if [[ "$ENABLE_DATA_COLLECTION_SCHEDULING" == "true" ]]; then
        if [[ ! "$DATA_COLLECTION_SCHEDULE_EXPRESSION" =~ ^(rate\(|cron\() ]]; then
            echo_error "Invalid data collection schedule expression: $DATA_COLLECTION_SCHEDULE_EXPRESSION"
            echo_error "Must start with 'rate(' or 'cron('"
            exit 1
        fi
    fi
    
    if [[ "$ENABLE_GRAPH_EXPORT_SCHEDULING" == "true" ]]; then
        if [[ ! "$GRAPH_EXPORT_SCHEDULE_EXPRESSION" =~ ^(rate\(|cron\() ]]; then
            echo_error "Invalid graph export schedule expression: $GRAPH_EXPORT_SCHEDULE_EXPRESSION"
            echo_error "Must start with 'rate(' or 'cron('"
            exit 1
        fi
    fi

    if [[ "$ENABLE_ACCESS_ANALYZER_SCHEDULING" == "true" ]]; then
        if [[ ! "$ACCESS_ANALYZER_SCHEDULE_EXPRESSION" =~ ^(rate\(|cron\() ]]; then
            echo_error "Invalid Access Analyzer schedule expression: $ACCESS_ANALYZER_SCHEDULE_EXPRESSION"
            echo_error "Must start with 'rate(' or 'cron('"
            exit 1
        fi
    fi
    
    echo_info "Scheduling parameters validated successfully"

    # Validate Neptune notebook parameters
    if [[ "$DEPLOY_NEPTUNE_NOTEBOOK" != "true" && "$DEPLOY_NEPTUNE_NOTEBOOK" != "false" ]]; then
        echo_error "Invalid value for --deploy-neptune-notebook: $DEPLOY_NEPTUNE_NOTEBOOK (must be 'true' or 'false')"
        exit 1
    fi
    if [[ "$DEPLOY_NEPTUNE_NOTEBOOK" == "true" && "$DEPLOY_NEPTUNE" != "true" ]]; then
        echo_error "--deploy-neptune-notebook true requires --deploy-neptune true (the notebook connects to the Neptune graph)"
        exit 1
    fi

    # Validate MCP server parameters
    if [[ "$DEPLOY_MCP_SERVER" != "true" && "$DEPLOY_MCP_SERVER" != "false" ]]; then
        echo_error "Invalid value for --deploy-mcp-server: $DEPLOY_MCP_SERVER (must be 'true' or 'false')"
        exit 1
    fi
    if [[ "$DEPLOY_MCP_SERVER" == "true" ]]; then
        if [[ "$DEPLOY_NEPTUNE" != "true" ]]; then
            echo_error "--deploy-mcp-server true requires --deploy-neptune true (the MCP server queries the Neptune graph)"
            exit 1
        fi
        if [[ -z "$MCP_CONTAINER_IMAGE_URI" ]]; then
            echo_error "--deploy-mcp-server true requires --mcp-container-image-uri <ECR image URI>"
            echo_error "Build and push the image first: cd mcp-server && ./build-and-push.sh -r $REGION"
            exit 1
        fi
        echo_info "MCP server parameters validated successfully"
    fi
}

# Function to deploy CloudFormation stack
deploy_stack() {
    echo_info "Deploying CloudFormation stack: $STACK_NAME"

    # Check if stack exists
    if run_cmd aws cloudformation describe-stacks --stack-name "$STACK_NAME"; then
        echo_info "Stack exists, updating..."
        OPERATION="update-stack"
    else
        echo_info "Stack does not exist, creating..."
        OPERATION="create-stack"
    fi
    
    # Build the --parameters argument as JSON rather than the AWS CLI
    # shorthand (ParameterKey=...,ParameterValue=...). The shorthand parser
    # treats any value that begins with "[" as a list, which corrupts
    # JSON-array string parameters such as RoleFilterIncludeRoleNamePatterns
    # (e.g. ["waddeam-*"] would be parsed as a list and rejected because the
    # parameter is a String). Emitting proper JSON keeps every value a string
    # and is robust to brackets, quotes, and spaces. Values are streamed to
    # python NUL-delimited so no value needs shell or JSON escaping.
    local -a stack_parameters=(
        TemplatesBucketName "$TEMPLATES_BUCKET"
        DeployNeptune "$DEPLOY_NEPTUNE"
        DeployNeptuneNotebook "$DEPLOY_NEPTUNE_NOTEBOOK"
        PublicIPAddress "$PUBLIC_IP"
        EnableDataCollectionScheduling "$ENABLE_DATA_COLLECTION_SCHEDULING"
        DataCollectionScheduleExpression "$DATA_COLLECTION_SCHEDULE_EXPRESSION"
        DataCollectionScheduleDescription "$DATA_COLLECTION_SCHEDULE_DESCRIPTION"
        DataCollectionScheduleTimezone "$DATA_COLLECTION_SCHEDULE_TIMEZONE"
        EnableScheduling "$ENABLE_GRAPH_EXPORT_SCHEDULING"
        ScheduleExpression "$GRAPH_EXPORT_SCHEDULE_EXPRESSION"
        ScheduleDescription "$GRAPH_EXPORT_SCHEDULE_DESCRIPTION"
        ScheduleTimezone "$GRAPH_EXPORT_SCHEDULE_TIMEZONE"
        EnableAccessAnalyzerScheduling "$ENABLE_ACCESS_ANALYZER_SCHEDULING"
        AccessAnalyzerScheduleExpression "$ACCESS_ANALYZER_SCHEDULE_EXPRESSION"
        AccessAnalyzerScheduleDescription "$ACCESS_ANALYZER_SCHEDULE_DESCRIPTION"
        AccessAnalyzerScheduleTimezone "$ACCESS_ANALYZER_SCHEDULE_TIMEZONE"
        ManagementAccountId "$MANAGEMENT_ACCOUNT_ID"
        DeployMcpServer "$DEPLOY_MCP_SERVER"
        McpContainerImageUri "$MCP_CONTAINER_IMAGE_URI"
        McpAgentRuntimeName "$MCP_AGENT_RUNTIME_NAME"
        InternalAccessAnalyzerArn "$INTERNAL_ACCESS_ANALYZER_ARN"
        ExternalAccessAnalyzerArn "$EXTERNAL_ACCESS_ANALYZER_ARN"
        UnusedAccessAnalyzerArn "$UNUSED_ACCESS_ANALYZER_ARN"
        DelegatedAdminAccountId "$DELEGATED_ADMIN_ACCOUNT_ID"
        AccessAnalyzerPollerRoleName "$ACCESS_ANALYZER_POLLER_ROLE_NAME"
        AccessAnalyzerPollerMaxPollAttempts "$ACCESS_ANALYZER_POLLER_MAX_POLL_ATTEMPTS"
        AccessAnalyzerPollerRequestsPerSecond "$ACCESS_ANALYZER_POLLER_REQUESTS_PER_SECOND"
        AccessAnalyzerDispatcherRoleName "$ACCESS_ANALYZER_DISPATCHER_ROLE_NAME"
        AccessAnalyzerWorkerRoleName "$ACCESS_ANALYZER_WORKER_ROLE_NAME"
        UnusedRoleWorkerRequestsPerSecond "$UNUSED_ROLE_WORKER_REQUESTS_PER_SECOND"
        UnusedRoleWorkerBatchSize "$UNUSED_ROLE_WORKER_BATCH_SIZE"
        UnusedRoleQueueVisibilityTimeoutSeconds "$UNUSED_ROLE_QUEUE_VISIBILITY_TIMEOUT_SECONDS"
        UnusedRoleQueueMaxReceiveCount "$UNUSED_ROLE_QUEUE_MAX_RECEIVE_COUNT"
        UnusedRoleDispatcherLeaseSeconds "$UNUSED_ROLE_DISPATCHER_LEASE_SECONDS"
        RoleFilterIncludePermissionSets "$ROLE_FILTER_INCLUDE_PERMISSION_SETS"
        RoleFilterIncludeAamRoles "$ROLE_FILTER_INCLUDE_AAM_ROLES"
        RoleFilterIncludeRoleNamePatterns "$ROLE_FILTER_INCLUDE_ROLE_NAME_PATTERNS"
        RoleFilterExcludeRoleNamePatterns "$ROLE_FILTER_EXCLUDE_ROLE_NAME_PATTERNS"
    )

    local parameters_json
    parameters_json=$(printf '%s\0' "${stack_parameters[@]}" | python3 -c '
import json
import sys

tokens = sys.stdin.buffer.read().split(b"\0")
# printf appends a trailing NUL after the final value, leaving one empty
# token at the end; drop exactly that one.
if tokens and tokens[-1] == b"":
    tokens = tokens[:-1]
if len(tokens) % 2 != 0:
    sys.stderr.write("stack parameter list must be key/value pairs\n")
    sys.exit(1)
params = [
    {"ParameterKey": tokens[i].decode(), "ParameterValue": tokens[i + 1].decode()}
    for i in range(0, len(tokens), 2)
]
print(json.dumps(params))
')

    # Deploy the stack
    run_cmd aws cloudformation "$OPERATION" \
        --stack-name "$STACK_NAME" \
        --template-body file://templates/main-stack.yaml \
        --parameters "$parameters_json" \
        --capabilities CAPABILITY_IAM
    
    echo_info "Stack deployment initiated. Waiting for completion..."
    
    # Wait for stack operation to complete
    if [ "$OPERATION" = "create-stack" ]; then
        run_cmd aws cloudformation wait stack-create-complete --stack-name "$STACK_NAME"
    else
        run_cmd aws cloudformation wait stack-update-complete --stack-name "$STACK_NAME"
    fi
    
    echo_info "Stack deployment completed successfully"
}

# Function to show stack outputs
show_outputs() {
    echo_info "Stack outputs:"
    aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
        --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' --output table 
}

# Function to set common scheduling presets
set_scheduling_preset() {
    local preset=$1
    case $preset in
        "daily-collection-and-export")
            ENABLE_DATA_COLLECTION_SCHEDULING="true"
            DATA_COLLECTION_SCHEDULE_EXPRESSION="rate(1 day)"
            DATA_COLLECTION_SCHEDULE_DESCRIPTION="Daily ARIA identity data collection with graph export"
            ENABLE_GRAPH_EXPORT_SCHEDULING="false"
            echo_info "Applied preset: Daily ARIA identity data collection and graph export"
            ;;
        "frequent-collection-daily-export")
            ENABLE_DATA_COLLECTION_SCHEDULING="true"
            DATA_COLLECTION_SCHEDULE_EXPRESSION="rate(6 hours)"
            DATA_COLLECTION_SCHEDULE_DESCRIPTION="Frequent ARIA identity data collection every 6 hours"
            ENABLE_GRAPH_EXPORT_SCHEDULING="true"
            GRAPH_EXPORT_SCHEDULE_EXPRESSION="rate(1 day)"
            GRAPH_EXPORT_SCHEDULE_DESCRIPTION="Daily ARIA graph export and import"
            echo_info "Applied preset: Frequent data collection (6 hours) with daily graph export"
            ;;
        "business-hours")
            ENABLE_DATA_COLLECTION_SCHEDULING="true"
            DATA_COLLECTION_SCHEDULE_EXPRESSION="cron(0 9 ? * MON-FRI *)"
            DATA_COLLECTION_SCHEDULE_DESCRIPTION="Business hours ARIA identity data collection"
            DATA_COLLECTION_SCHEDULE_TIMEZONE="America/New_York"
            ENABLE_GRAPH_EXPORT_SCHEDULING="true"
            GRAPH_EXPORT_SCHEDULE_EXPRESSION="cron(0 18 ? * MON-FRI *)"
            GRAPH_EXPORT_SCHEDULE_DESCRIPTION="End of business day ARIA graph export"
            GRAPH_EXPORT_SCHEDULE_TIMEZONE="America/New_York"
            echo_info "Applied preset: Business hours scheduling (9 AM data collection, 6 PM graph export, EST)"
            ;;
        "disabled")
            ENABLE_DATA_COLLECTION_SCHEDULING="false"
            ENABLE_GRAPH_EXPORT_SCHEDULING="false"
            ENABLE_ACCESS_ANALYZER_SCHEDULING="false"
            echo_info "Applied preset: All scheduling disabled"
            ;;
        *)
            echo_error "Unknown scheduling preset: $preset"
            echo_info "Available presets:"
            echo_info "  daily-collection-and-export    - Daily data collection and graph export"
            echo_info "  frequent-collection-daily-export - 6-hour data collection, daily graph export"
            echo_info "  business-hours                 - Business hours scheduling (EST)"
            echo_info "  disabled                       - Disable all scheduling"
            exit 1
            ;;
    esac
}

# Function to show scheduling summary
show_scheduling_summary() {
    echo_info "Scheduling Summary:"
    
    if [[ "$ENABLE_DATA_COLLECTION_SCHEDULING" == "true" ]]; then
        echo_info "  ✅ Data Collection & Export Scheduling: ENABLED"
        echo_info "     Expression: $DATA_COLLECTION_SCHEDULE_EXPRESSION"
        echo_info "     Timezone: $DATA_COLLECTION_SCHEDULE_TIMEZONE"
    else
        echo_info "  ❌ Data Collection Scheduling: DISABLED"
    fi
    
    if [[ "$ENABLE_GRAPH_EXPORT_SCHEDULING" == "true" ]]; then
        echo_info "  ✅ Graph Export Independent Scheduling: ENABLED"
        echo_info "     Expression: $GRAPH_EXPORT_SCHEDULE_EXPRESSION"
        echo_info "     Timezone: $GRAPH_EXPORT_SCHEDULE_TIMEZONE"
    else
        echo_info "  ❌ Graph Export Independent Scheduling: DISABLED"
    fi

    if [[ "$ENABLE_ACCESS_ANALYZER_SCHEDULING" == "true" ]]; then
        echo_info "  ✅ Access Analyzer Scheduling: ENABLED"
        echo_info "     Expression: $ACCESS_ANALYZER_SCHEDULE_EXPRESSION"
        echo_info "     Timezone: $ACCESS_ANALYZER_SCHEDULE_TIMEZONE"
    else
        echo_info "  ❌ Access Analyzer Scheduling: DISABLED"
    fi
    
    if [[ "$ENABLE_DATA_COLLECTION_SCHEDULING" == "false" && "$ENABLE_GRAPH_EXPORT_SCHEDULING" == "false" && "$ENABLE_ACCESS_ANALYZER_SCHEDULING" == "false" ]]; then
        echo_warn "All scheduling options are disabled. You will need to manually execute state machines."
    fi
    
    echo ""
}

# Generate unique templates bucket name
ACCOUNTID=$(aws sts get-caller-identity --output json | grep Account | awk -F ': "' '{print$2}' | sed 's/\".*//')
ACCOUNTIDSHORT=$(echo "$ACCOUNTID" | cut -c 9-12)

# Resolve the management account ID from AWS Organizations
echo_info "Resolving management account ID from AWS Organizations..."
MANAGEMENT_ACCOUNT_ID=$(aws organizations describe-organization --query 'Organization.MasterAccountId' --output text 2>/dev/null || echo "")
if [ -z "$MANAGEMENT_ACCOUNT_ID" ]; then
    echo_warn "Could not resolve management account ID from Organizations API."
    echo_warn "Falling back to current account ID: $ACCOUNTID"
    MANAGEMENT_ACCOUNT_ID="$ACCOUNTID"
else
    echo_info "Management account ID: $MANAGEMENT_ACCOUNT_ID"
fi

# Check SSM parameter store to see if the templates bucket name has already been generated
TEMPLATES_BUCKET=$(aws ssm get-parameter --name "aria-templates-bucket" --region "$REGION" --query "Parameter.Value" --output text 2>/dev/null || echo "")

# Check if the parameter store value exists, if not then set the variable (will be stored in SSM parameter store later)
if [ -z "$TEMPLATES_BUCKET" ]; then
    echo_info "Templates Bucket variable not set...creating..."
    RANDOMSTRING="$(mktemp -u XXXXXXXX | tr 'A-Z' 'a-z')"
    TEMPLATES_BUCKET="aria-templates-$ACCOUNTIDSHORT-$RANDOMSTRING"
fi
    

# Main execution
main() {
    echo_info "Starting deployment of nested CloudFormation stacks"
    if [[ "$DEBUG" == "true" ]]; then
        if [[ -n "$DEBUG_LOG_FILE" ]]; then
            echo_info "Debug output enabled (also appending to $DEBUG_LOG_FILE)"
            echo "=== ARIA-gv deployment debug log - $(date) ===" >> "$DEBUG_LOG_FILE"
        else
            echo_info "Debug output enabled"
        fi
    fi
    echo_info "Stack Name: $STACK_NAME"
    echo_info "Templates Bucket: $TEMPLATES_BUCKET"
    echo_info "Region: $REGION"
    echo_info "Deploy Neptune Graph: $DEPLOY_NEPTUNE"
    echo_info "Deploy Neptune Notebook: $DEPLOY_NEPTUNE_NOTEBOOK"
    echo_info "Public IP: $PUBLIC_IP"
    echo_info "Deploy MCP Server (AgentCore): $DEPLOY_MCP_SERVER"
    if [[ "$DEPLOY_MCP_SERVER" == "true" ]]; then
        echo_info "  MCP Container Image: $MCP_CONTAINER_IMAGE_URI"
        echo_info "  MCP Runtime Name: $MCP_AGENT_RUNTIME_NAME"
    fi
    echo ""
    echo_info "Data Collection and Export Scheduling Configuration:"
    echo_info "  Enable Data Collection and Export Scheduling: $ENABLE_DATA_COLLECTION_SCHEDULING"
    echo_info "  Data Collection Schedule Expression: $DATA_COLLECTION_SCHEDULE_EXPRESSION"
    echo_info "  Data Collection Schedule Timezone: $DATA_COLLECTION_SCHEDULE_TIMEZONE"
    echo ""
    echo_info "Graph Export Independent Scheduling Configuration:"
    echo_info "  Enable Graph Export Independent Scheduling: $ENABLE_GRAPH_EXPORT_SCHEDULING"
    echo_info "  Graph Export Schedule Expression: $GRAPH_EXPORT_SCHEDULE_EXPRESSION"
    echo_info "  Graph Export Schedule Timezone: $GRAPH_EXPORT_SCHEDULE_TIMEZONE"
    echo ""
    echo_info "Access Analyzer Scheduling Configuration:"
    echo_info "  Enable Access Analyzer Scheduling: $ENABLE_ACCESS_ANALYZER_SCHEDULING"
    echo_info "  Access Analyzer Schedule Expression: $ACCESS_ANALYZER_SCHEDULE_EXPRESSION"
    echo_info "  Access Analyzer Schedule Timezone: $ACCESS_ANALYZER_SCHEDULE_TIMEZONE"
    echo ""
    
    # Show scheduling summary
    show_scheduling_summary
    
    # Validate scheduling parameters
    validate_scheduling_parameters
    
    # Check if templates bucket exists, create if not
    if ! check_bucket "$TEMPLATES_BUCKET"; then
        create_bucket "$TEMPLATES_BUCKET"
    fi
    
    # Validate main template
    validate_template "templates/main-stack.yaml"
    
    # Upload templates to S3
    upload_templates
    
    # Deploy the stack
    deploy_stack
    
    # Show outputs
    show_outputs
    
    echo_info "Deployment completed successfully!"
}

# Pre-scan for --config-file/-c so YAML values load before the flag-parsing
# loop below applies CLI overrides on top of them. This
# scan does not consume "$@" - the flag-parsing loop still needs to see
# every original argument, including this flag itself (handled there as a
# no-op, since it has already been applied here).
CONFIG_FILE=""
config_scan_args=("$@")
for ((config_scan_i = 0; config_scan_i < ${#config_scan_args[@]}; config_scan_i++)); do
    case "${config_scan_args[$config_scan_i]}" in
        --config-file=*)
            CONFIG_FILE="${config_scan_args[$config_scan_i]#--config-file=}"
            break
            ;;
        --config-file|-c)
            CONFIG_FILE="${config_scan_args[$((config_scan_i + 1))]}"
            break
            ;;
    esac
done
unset config_scan_args config_scan_i

if [[ -n "$CONFIG_FILE" ]]; then
    if [[ ! -f "$CONFIG_FILE" || ! -r "$CONFIG_FILE" ]]; then
        echo_error "Config file not found or not readable: $CONFIG_FILE"
        exit 1
    fi

    # Guard against `set -e` treating a non-zero parse_yaml_config exit
    # (e.g. the missing-PyYAML or YAML-syntax-error cases) as a reason to
    # abort the whole script before we get a chance to inspect the emitted
    # YAML_PARSE_ERROR= line and print a proper message.
    YAML_OUTPUT=$(parse_yaml_config "$CONFIG_FILE") || true

    if echo "$YAML_OUTPUT" | grep -q '^YAML_PARSE_ERROR='; then
        PARSE_ERROR=$(echo "$YAML_OUTPUT" | sed -n 's/^YAML_PARSE_ERROR=//p')
        echo_error "Invalid YAML in config file $CONFIG_FILE: $PARSE_ERROR"
        exit 1
    fi

    eval "$YAML_OUTPUT"

    # Apply loaded YAML values on top of the hardcoded/auto-generated
    # defaults already established above. Each is only applied if the YAML
    # actually set it, so an omitted key leaves the existing default in
    # place - the flag-parsing loop further below can
    # still override any of these.
    [[ -n "${YAML_STACK_NAME:-}" ]] && STACK_NAME="$YAML_STACK_NAME"
    [[ -n "${YAML_TEMPLATES_BUCKET:-}" ]] && TEMPLATES_BUCKET="$YAML_TEMPLATES_BUCKET"
    [[ -n "${YAML_REGION:-}" ]] && REGION="$YAML_REGION"
    [[ -n "${YAML_DEPLOY_NEPTUNE:-}" ]] && DEPLOY_NEPTUNE="$YAML_DEPLOY_NEPTUNE"
    [[ -n "${YAML_DEPLOY_NEPTUNE_NOTEBOOK:-}" ]] && DEPLOY_NEPTUNE_NOTEBOOK="$YAML_DEPLOY_NEPTUNE_NOTEBOOK"
    [[ -n "${YAML_PUBLIC_IP:-}" ]] && PUBLIC_IP="$YAML_PUBLIC_IP"
    [[ -n "${YAML_DEPLOY_MCP_SERVER:-}" ]] && DEPLOY_MCP_SERVER="$YAML_DEPLOY_MCP_SERVER"
    [[ -n "${YAML_MCP_CONTAINER_IMAGE_URI:-}" ]] && MCP_CONTAINER_IMAGE_URI="$YAML_MCP_CONTAINER_IMAGE_URI"
    [[ -n "${YAML_MCP_AGENT_RUNTIME_NAME:-}" ]] && MCP_AGENT_RUNTIME_NAME="$YAML_MCP_AGENT_RUNTIME_NAME"
    [[ -n "${YAML_ENABLE_DATA_COLLECTION_SCHEDULING:-}" ]] && ENABLE_DATA_COLLECTION_SCHEDULING="$YAML_ENABLE_DATA_COLLECTION_SCHEDULING"
    [[ -n "${YAML_DATA_COLLECTION_SCHEDULE_EXPRESSION:-}" ]] && DATA_COLLECTION_SCHEDULE_EXPRESSION="$YAML_DATA_COLLECTION_SCHEDULE_EXPRESSION"
    [[ -n "${YAML_DATA_COLLECTION_SCHEDULE_DESCRIPTION:-}" ]] && DATA_COLLECTION_SCHEDULE_DESCRIPTION="$YAML_DATA_COLLECTION_SCHEDULE_DESCRIPTION"
    [[ -n "${YAML_DATA_COLLECTION_SCHEDULE_TIMEZONE:-}" ]] && DATA_COLLECTION_SCHEDULE_TIMEZONE="$YAML_DATA_COLLECTION_SCHEDULE_TIMEZONE"
    [[ -n "${YAML_ENABLE_GRAPH_EXPORT_SCHEDULING:-}" ]] && ENABLE_GRAPH_EXPORT_SCHEDULING="$YAML_ENABLE_GRAPH_EXPORT_SCHEDULING"
    [[ -n "${YAML_GRAPH_EXPORT_SCHEDULE_EXPRESSION:-}" ]] && GRAPH_EXPORT_SCHEDULE_EXPRESSION="$YAML_GRAPH_EXPORT_SCHEDULE_EXPRESSION"
    [[ -n "${YAML_GRAPH_EXPORT_SCHEDULE_DESCRIPTION:-}" ]] && GRAPH_EXPORT_SCHEDULE_DESCRIPTION="$YAML_GRAPH_EXPORT_SCHEDULE_DESCRIPTION"
    [[ -n "${YAML_GRAPH_EXPORT_SCHEDULE_TIMEZONE:-}" ]] && GRAPH_EXPORT_SCHEDULE_TIMEZONE="$YAML_GRAPH_EXPORT_SCHEDULE_TIMEZONE"
    [[ -n "${YAML_ENABLE_ACCESS_ANALYZER_SCHEDULING:-}" ]] && ENABLE_ACCESS_ANALYZER_SCHEDULING="$YAML_ENABLE_ACCESS_ANALYZER_SCHEDULING"
    [[ -n "${YAML_ACCESS_ANALYZER_SCHEDULE_EXPRESSION:-}" ]] && ACCESS_ANALYZER_SCHEDULE_EXPRESSION="$YAML_ACCESS_ANALYZER_SCHEDULE_EXPRESSION"
    [[ -n "${YAML_ACCESS_ANALYZER_SCHEDULE_DESCRIPTION:-}" ]] && ACCESS_ANALYZER_SCHEDULE_DESCRIPTION="$YAML_ACCESS_ANALYZER_SCHEDULE_DESCRIPTION"
    [[ -n "${YAML_ACCESS_ANALYZER_SCHEDULE_TIMEZONE:-}" ]] && ACCESS_ANALYZER_SCHEDULE_TIMEZONE="$YAML_ACCESS_ANALYZER_SCHEDULE_TIMEZONE"
    [[ -n "${YAML_INTERNAL_ACCESS_ANALYZER_ARN:-}" ]] && INTERNAL_ACCESS_ANALYZER_ARN="$YAML_INTERNAL_ACCESS_ANALYZER_ARN"
    [[ -n "${YAML_EXTERNAL_ACCESS_ANALYZER_ARN:-}" ]] && EXTERNAL_ACCESS_ANALYZER_ARN="$YAML_EXTERNAL_ACCESS_ANALYZER_ARN"
    [[ -n "${YAML_UNUSED_ACCESS_ANALYZER_ARN:-}" ]] && UNUSED_ACCESS_ANALYZER_ARN="$YAML_UNUSED_ACCESS_ANALYZER_ARN"
    [[ -n "${YAML_DELEGATED_ADMIN_ACCOUNT_ID:-}" ]] && DELEGATED_ADMIN_ACCOUNT_ID="$YAML_DELEGATED_ADMIN_ACCOUNT_ID"
    [[ -n "${YAML_ACCESS_ANALYZER_POLLER_ROLE_NAME:-}" ]] && ACCESS_ANALYZER_POLLER_ROLE_NAME="$YAML_ACCESS_ANALYZER_POLLER_ROLE_NAME"
    [[ -n "${YAML_ACCESS_ANALYZER_POLLER_MAX_POLL_ATTEMPTS:-}" ]] && ACCESS_ANALYZER_POLLER_MAX_POLL_ATTEMPTS="$YAML_ACCESS_ANALYZER_POLLER_MAX_POLL_ATTEMPTS"
    [[ -n "${YAML_ACCESS_ANALYZER_POLLER_REQUESTS_PER_SECOND:-}" ]] && ACCESS_ANALYZER_POLLER_REQUESTS_PER_SECOND="$YAML_ACCESS_ANALYZER_POLLER_REQUESTS_PER_SECOND"
    [[ -n "${YAML_ACCESS_ANALYZER_DISPATCHER_ROLE_NAME:-}" ]] && ACCESS_ANALYZER_DISPATCHER_ROLE_NAME="$YAML_ACCESS_ANALYZER_DISPATCHER_ROLE_NAME"
    [[ -n "${YAML_ACCESS_ANALYZER_WORKER_ROLE_NAME:-}" ]] && ACCESS_ANALYZER_WORKER_ROLE_NAME="$YAML_ACCESS_ANALYZER_WORKER_ROLE_NAME"
    [[ -n "${YAML_UNUSED_ROLE_WORKER_REQUESTS_PER_SECOND:-}" ]] && UNUSED_ROLE_WORKER_REQUESTS_PER_SECOND="$YAML_UNUSED_ROLE_WORKER_REQUESTS_PER_SECOND"
    [[ -n "${YAML_UNUSED_ROLE_WORKER_BATCH_SIZE:-}" ]] && UNUSED_ROLE_WORKER_BATCH_SIZE="$YAML_UNUSED_ROLE_WORKER_BATCH_SIZE"
    [[ -n "${YAML_UNUSED_ROLE_QUEUE_VISIBILITY_TIMEOUT_SECONDS:-}" ]] && UNUSED_ROLE_QUEUE_VISIBILITY_TIMEOUT_SECONDS="$YAML_UNUSED_ROLE_QUEUE_VISIBILITY_TIMEOUT_SECONDS"
    [[ -n "${YAML_UNUSED_ROLE_QUEUE_MAX_RECEIVE_COUNT:-}" ]] && UNUSED_ROLE_QUEUE_MAX_RECEIVE_COUNT="$YAML_UNUSED_ROLE_QUEUE_MAX_RECEIVE_COUNT"
    [[ -n "${YAML_UNUSED_ROLE_DISPATCHER_LEASE_SECONDS:-}" ]] && UNUSED_ROLE_DISPATCHER_LEASE_SECONDS="$YAML_UNUSED_ROLE_DISPATCHER_LEASE_SECONDS"
    [[ -n "${YAML_ROLE_FILTER_INCLUDE_PERMISSION_SETS:-}" ]] && ROLE_FILTER_INCLUDE_PERMISSION_SETS="$YAML_ROLE_FILTER_INCLUDE_PERMISSION_SETS"
    [[ -n "${YAML_ROLE_FILTER_INCLUDE_AAM_ROLES:-}" ]] && ROLE_FILTER_INCLUDE_AAM_ROLES="$YAML_ROLE_FILTER_INCLUDE_AAM_ROLES"
    [[ -n "${YAML_ROLE_FILTER_INCLUDE_ROLE_NAME_PATTERNS:-}" ]] && ROLE_FILTER_INCLUDE_ROLE_NAME_PATTERNS="$YAML_ROLE_FILTER_INCLUDE_ROLE_NAME_PATTERNS"
    [[ -n "${YAML_ROLE_FILTER_EXCLUDE_ROLE_NAME_PATTERNS:-}" ]] && ROLE_FILTER_EXCLUDE_ROLE_NAME_PATTERNS="$YAML_ROLE_FILTER_EXCLUDE_ROLE_NAME_PATTERNS"
    [[ -n "${YAML_DEBUG:-}" ]] && DEBUG="$YAML_DEBUG"
    [[ -n "${YAML_DEBUG_LOG_FILE:-}" ]] && DEBUG_LOG_FILE="$YAML_DEBUG_LOG_FILE"

    echo_info "Loaded deployment configuration from $CONFIG_FILE"
fi

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --config-file=*)
            # Already applied during the pre-scan pass above; consume here
            # only so the loop does not reject it as an unknown option.
            shift 1
            ;;
        --config-file|-c)
            # Already applied during the pre-scan pass above; consume the
            # flag and its value here only so the loop does not reject it
            # as an unknown option.
            shift 2
            ;;
        --stack-name)
            STACK_NAME="$2"
            shift 2
            ;;
        --templates-bucket)
            TEMPLATES_BUCKET="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --deploy-neptune)
            DEPLOY_NEPTUNE="$2"
            shift 2
            ;;
        --deploy-neptune-notebook)
            DEPLOY_NEPTUNE_NOTEBOOK="$2"
            shift 2
            ;;
        --public-ip)
            PUBLIC_IP="$2"
            shift 2
            ;;
        --enable-data-collection-scheduling)
            ENABLE_DATA_COLLECTION_SCHEDULING="$2"
            shift 2
            ;;
        --data-collection-schedule-expression)
            DATA_COLLECTION_SCHEDULE_EXPRESSION="$2"
            shift 2
            ;;
        --data-collection-schedule-description)
            DATA_COLLECTION_SCHEDULE_DESCRIPTION="$2"
            shift 2
            ;;
        --data-collection-schedule-timezone)
            DATA_COLLECTION_SCHEDULE_TIMEZONE="$2"
            shift 2
            ;;
        --enable-graph-export-scheduling)
            ENABLE_GRAPH_EXPORT_SCHEDULING="$2"
            shift 2
            ;;
        --graph-export-schedule-expression)
            GRAPH_EXPORT_SCHEDULE_EXPRESSION="$2"
            shift 2
            ;;
        --graph-export-schedule-description)
            GRAPH_EXPORT_SCHEDULE_DESCRIPTION="$2"
            shift 2
            ;;
        --graph-export-schedule-timezone)
            GRAPH_EXPORT_SCHEDULE_TIMEZONE="$2"
            shift 2
            ;;
        --enable-access-analyzer-scheduling)
            ENABLE_ACCESS_ANALYZER_SCHEDULING="$2"
            shift 2
            ;;
        --access-analyzer-schedule-expression)
            ACCESS_ANALYZER_SCHEDULE_EXPRESSION="$2"
            shift 2
            ;;
        --access-analyzer-schedule-description)
            ACCESS_ANALYZER_SCHEDULE_DESCRIPTION="$2"
            shift 2
            ;;
        --access-analyzer-schedule-timezone)
            ACCESS_ANALYZER_SCHEDULE_TIMEZONE="$2"
            shift 2
            ;;
        --scheduling-preset)
            set_scheduling_preset "$2"
            shift 2
            ;;
        --deploy-mcp-server)
            DEPLOY_MCP_SERVER="$2"
            shift 2
            ;;
        --mcp-container-image-uri)
            MCP_CONTAINER_IMAGE_URI="$2"
            shift 2
            ;;
        --mcp-agent-runtime-name)
            MCP_AGENT_RUNTIME_NAME="$2"
            shift 2
            ;;
        --internal-access-analyzer-arn)
            INTERNAL_ACCESS_ANALYZER_ARN="$2"
            shift 2
            ;;
        --external-access-analyzer-arn)
            EXTERNAL_ACCESS_ANALYZER_ARN="$2"
            shift 2
            ;;
        --unused-access-analyzer-arn)
            UNUSED_ACCESS_ANALYZER_ARN="$2"
            shift 2
            ;;
        --delegated-admin-account-id)
            DELEGATED_ADMIN_ACCOUNT_ID="$2"
            shift 2
            ;;
        --access-analyzer-poller-role-name)
            ACCESS_ANALYZER_POLLER_ROLE_NAME="$2"
            shift 2
            ;;
        --access-analyzer-poller-max-poll-attempts)
            ACCESS_ANALYZER_POLLER_MAX_POLL_ATTEMPTS="$2"
            shift 2
            ;;
        --access-analyzer-poller-requests-per-second)
            ACCESS_ANALYZER_POLLER_REQUESTS_PER_SECOND="$2"
            shift 2
            ;;
        --access-analyzer-dispatcher-role-name)
            ACCESS_ANALYZER_DISPATCHER_ROLE_NAME="$2"
            shift 2
            ;;
        --access-analyzer-worker-role-name)
            ACCESS_ANALYZER_WORKER_ROLE_NAME="$2"
            shift 2
            ;;
        --unused-role-worker-requests-per-second)
            UNUSED_ROLE_WORKER_REQUESTS_PER_SECOND="$2"
            shift 2
            ;;
        --unused-role-worker-batch-size)
            UNUSED_ROLE_WORKER_BATCH_SIZE="$2"
            shift 2
            ;;
        --unused-role-queue-visibility-timeout-seconds)
            UNUSED_ROLE_QUEUE_VISIBILITY_TIMEOUT_SECONDS="$2"
            shift 2
            ;;
        --unused-role-queue-max-receive-count)
            UNUSED_ROLE_QUEUE_MAX_RECEIVE_COUNT="$2"
            shift 2
            ;;
        --unused-role-dispatcher-lease-seconds)
            UNUSED_ROLE_DISPATCHER_LEASE_SECONDS="$2"
            shift 2
            ;;
        --debug)
            DEBUG="true"
            shift 1
            ;;
        --debug-log-file)
            DEBUG_LOG_FILE="$2"
            DEBUG="true"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Configuration File Options:"
            echo "  --config-file PATH, -c PATH       Path to a YAML deployment configuration file (see"
            echo "                                    README/design for schema). CLI flags override values"
            echo "                                    from this file."
            echo ""
            echo "Basic Options:"
            echo "  --stack-name STACK_NAME           CloudFormation stack name (default: aria-gv-setup)"
            echo "  --templates-bucket BUCKET_NAME    S3 bucket for templates (default: auto-generated unique name)"
            echo "                                    Note: Bucket names are automatically generated per account and stored in SSM"
            echo "  --region REGION                   AWS region (default: us-east-1)"
            echo "  --deploy-neptune true|false       Deploy the Neptune Analytics graph (default: true)"
            echo "  --deploy-neptune-notebook true|false"
            echo "                                    Deploy the Neptune notebook and Graph Explorer (default: true)."
            echo "                                    Requires --deploy-neptune true."
            echo "  --public-ip CIDR                  Public IP address in CIDR format (default: 0.0.0.0/0)"
            echo ""
            echo "Data Collection Scheduling Options:"
            echo "  --enable-data-collection-scheduling true|false"
            echo "                                    Enable automatic data collection scheduling (default: false)"
            echo "  --data-collection-schedule-expression EXPRESSION"
            echo "                                    Schedule expression for data collection (default: rate(6 hours))"
            echo "  --data-collection-schedule-description DESCRIPTION"
            echo "                                    Description for data collection schedule"
            echo "  --data-collection-schedule-timezone TIMEZONE"
            echo "                                    Timezone for data collection schedule (default: UTC)"
            echo ""
            echo "Graph Export Scheduling Options:"
            echo "  --enable-graph-export-scheduling true|false"
            echo "                                    Enable automatic graph export scheduling (default: false)"
            echo "  --graph-export-schedule-expression EXPRESSION"
            echo "                                    Schedule expression for graph export (default: rate(1 day))"
            echo "  --graph-export-schedule-description DESCRIPTION"
            echo "                                    Description for graph export schedule"
            echo "  --graph-export-schedule-timezone TIMEZONE"
            echo "                                    Timezone for graph export schedule (default: UTC)"
            echo ""
            echo "Access Analyzer Scheduling Options:"
            echo "  --enable-access-analyzer-scheduling true|false"
            echo "                                    Enable automatic scheduling of the AriaAccessAnalyzerStateMachine"
            echo "                                    (default: false). Runs independently of data collection so"
            echo "                                    Access Analyzer findings can be polled more frequently."
            echo "  --access-analyzer-schedule-expression EXPRESSION"
            echo "                                    Schedule expression for Access Analyzer polling"
            echo "                                    (default: rate(15 minutes))"
            echo "  --access-analyzer-schedule-description DESCRIPTION"
            echo "                                    Description for the Access Analyzer polling schedule"
            echo "  --access-analyzer-schedule-timezone TIMEZONE"
            echo "                                    Timezone for Access Analyzer polling schedule (default: UTC)"
            echo ""
            echo "Scheduling Presets:"
            echo "  --scheduling-preset PRESET       Apply a common scheduling configuration"
            echo "                                    Available presets:"
            echo "                                      daily-collection-and-export"
            echo "                                      frequent-collection-daily-export"
            echo "                                      business-hours"
            echo "                                      disabled"
            echo ""
            echo "MCP Server (AgentCore) Options:"
            echo "  --deploy-mcp-server true|false    Host the ARIA-gv MCP server on Bedrock AgentCore"
            echo "                                    Runtime (default: false). Requires --deploy-neptune true"
            echo "                                    and --mcp-container-image-uri."
            echo "  --mcp-container-image-uri URI     ECR image URI (with tag) of the ARM64 MCP server image."
            echo "                                    Build it first: cd mcp-server && ./build-and-push.sh"
            echo "  --mcp-agent-runtime-name NAME     AgentCore Runtime name (default: aria_gv_mcp)"
            echo ""
            echo "Access Analyzer Poller Options:"
            echo "  --internal-access-analyzer-arn ARN"
            echo "                                    ARN of the ORGANIZATION_INTERNAL_ACCESS analyzer in the"
            echo "                                    delegated administrator account"
            echo "  --external-access-analyzer-arn ARN"
            echo "                                    ARN of the ORGANIZATION analyzer in the delegated"
            echo "                                    administrator account"
            echo "  --unused-access-analyzer-arn ARN  ARN of the ORGANIZATION_UNUSED_ACCESS analyzer in the"
            echo "                                    delegated administrator account"
            echo "  --delegated-admin-account-id ID   AWS Account ID registered as the IAM Access Analyzer"
            echo "                                    delegated administrator"
            echo "  --access-analyzer-poller-role-name NAME"
            echo "                                    Name of the cross-account role assumed in the delegated"
            echo "                                    administrator account (default: AriaAccessAnalyzerPollerRole)"
            echo "  --access-analyzer-poller-max-poll-attempts N"
            echo "                                    Max re-invocations per finding family per polling cycle"
            echo "                                    while it still has unfetched findings (default: 6)."
            echo "                                    Raise temporarily (e.g. 20-30) for a large initial"
            echo "                                    backfill (10k+ findings on first run), then lower back"
            echo "                                    down once the backlog clears."
            echo "  --access-analyzer-poller-requests-per-second N"
            echo "                                    Fixed rate limit for internal/external GetFinding calls"
            echo "                                    (default: 0.5, i.e. 1 request every 2 seconds)."
            echo "  --access-analyzer-dispatcher-role-name NAME"
            echo "                                    Cross-account list-only role for the unused-role dispatcher"
            echo "                                    (default: AriaAccessAnalyzerDispatcherRole)."
            echo "  --access-analyzer-worker-role-name NAME"
            echo "                                    Cross-account get-only role for the unused-role worker"
            echo "                                    (default: AriaAccessAnalyzerWorkerRole)."
            echo "  --unused-role-worker-requests-per-second N"
            echo "                                    Strict global RPS limit for queued unused IAM-role details"
            echo "                                    (default: 0.5). The worker has one concurrent execution."
            echo "  --unused-role-worker-batch-size N"
            echo "                                    SQS messages per unused-role worker invocation, 1-10"
            echo "                                    (default: 10)."
            echo "  --unused-role-queue-visibility-timeout-seconds N"
            echo "                                    Work-message visibility timeout in seconds (default: 600)."
            echo "  --unused-role-queue-max-receive-count N"
            echo "                                    Receives before failed work moves to the DLQ (default: 5)."
            echo "  --unused-role-dispatcher-lease-seconds N"
            echo "                                    Prevent overlapping unused-role dispatch runs (default: 900)."
            echo ""
            echo "Other Options:"
            echo "  --debug                           Write verbose debug output, including the full AWS CLI"
            echo "                                    stdout/stderr that is normally suppressed. Use this to"
            echo "                                    diagnose deployments that otherwise fail silently."
            echo "  --debug-log-file PATH             Also append debug output to PATH (implies --debug)"
            echo "  --help                            Show this help message"
            echo ""
            echo "Examples:"
            echo "  # Deploy from a YAML config file, overriding just the region"
            echo "  $0 --config-file aria-deploy-config.yaml --region us-west-2"
            echo ""
            echo "  # Deploy with daily scheduling preset"
            echo "  $0 --scheduling-preset daily-collection-and-export"
            echo ""
            echo "  # Deploy with business hours preset"
            echo "  $0 --scheduling-preset business-hours"
            echo ""
            echo "  # Deploy with custom data collection scheduling"
            echo "  $0 --enable-data-collection-scheduling true \\"
            echo "     --data-collection-schedule-expression 'rate(4 hours)' \\"
            echo "     --enable-graph-export-scheduling false"
            echo ""
            echo "  # Deploy with custom business hours scheduling"
            echo "  $0 --enable-data-collection-scheduling true \\"
            echo "     --data-collection-schedule-expression 'cron(0 9 ? * MON-FRI *)' \\"
            echo "     --data-collection-schedule-timezone 'America/New_York' \\"
            echo "     --enable-graph-export-scheduling true \\"
            echo "     --graph-export-schedule-expression 'cron(0 18 ? * MON-FRI *)' \\"
            echo "     --graph-export-schedule-timezone 'America/New_York'"
            exit 0
            ;;
        *)
            echo_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# A debug log file implies debug output is enabled. Confirm the file is
# writable now so a later run_cmd tee does not fail mid-deployment.
if [[ -n "$DEBUG_LOG_FILE" ]]; then
    DEBUG="true"
    if ! touch "$DEBUG_LOG_FILE" 2>/dev/null; then
        echo_error "Debug log file is not writable: $DEBUG_LOG_FILE"
        exit 1
    fi
fi

# Run main function
main