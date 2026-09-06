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

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Function to parse the YAML config file into shell variable assignments.
# Emits `YAML_KEY=value` lines (one per recognized setting) that the caller
# evaluates with `eval "$(parse_yaml_config "$CONFIG_FILE")"`. Missing keys
# emit nothing, so a partial YAML file leaves those variables at whatever
# value they already held (their hardcoded default, per Requirement 10.4).
# On a missing PyYAML dependency or a YAML syntax error, a single
# `YAML_PARSE_ERROR=<description>` line is emitted instead.
parse_yaml_config() {
    local config_file=$1
    python3 - "$config_file" <<'PYEOF'
import sys
import shlex

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

mcp = config.get("mcpServer", {}) or {}
dcs = config.get("dataCollectionScheduling", {}) or {}
ges = config.get("graphExportScheduling", {}) or {}
aas = config.get("accessAnalyzerScheduling", {}) or {}
aap = config.get("accessAnalyzerPoller", {}) or {}

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
PYEOF
}

# Function to check if S3 bucket exists
check_bucket() {
    local bucket_name=$1
    if aws s3api head-bucket --bucket "$bucket_name" > /dev/null 2>&1; then
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
        aws s3api create-bucket --bucket "$bucket_name" > /dev/null 2>&1
    else
        aws s3api create-bucket --bucket "$bucket_name" --region "$REGION" \
            --create-bucket-configuration LocationConstraint="$REGION" > /dev/null 2>&1
    fi
    
    # Enable versioning
    aws s3api put-bucket-versioning --bucket "$bucket_name" \
        --versioning-configuration Status=Enabled > /dev/null 2>&1
    
    echo_info "S3 bucket $bucket_name created successfully"
    
    # Store the bucket name in SSM parameter store for future reference
    if [ "$bucket_name" = "$TEMPLATES_BUCKET" ]; then
        aws ssm put-parameter --name "aria-templates-bucket" --value "$bucket_name" --type "String" --overwrite --region "$REGION" > /dev/null 2>&1
        echo_info "Templates bucket name stored in SSM parameter store"
    fi
}

# Function to upload templates to S3
upload_templates() {
    echo_info "Uploading CloudFormation templates to S3..."
    
    # Upload all template files
    aws s3 cp templates/ s3://"$TEMPLATES_BUCKET"/ --recursive > /dev/null 2>&1
    
    echo_info "Templates uploaded successfully"
}

# Function to validate CloudFormation template
validate_template() {
    local template_file=$1
    echo_info "Validating template: $template_file"
    
    aws cloudformation validate-template --template-body file://"$template_file"  > /dev/null 2>&1
    
    echo_info "Template $template_file is valid"
}

# Function to validate scheduling parameters
validate_scheduling_parameters() {
    # Require the unused access analyzer ARN when a config file was supplied.
    # Requirement 10.8: a Deployment_Configuration_File must explicitly
    # specify accessAnalyzerPoller.unusedAccessAnalyzerArn (or the operator
    # must override it with --unused-access-analyzer-arn); flags-only
    # invocations (no --config-file) are unaffected, per Requirement 10.5.
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
    if aws cloudformation describe-stacks --stack-name "$STACK_NAME" > /dev/null 2>&1; then
        echo_info "Stack exists, updating..."
        OPERATION="update-stack"
    else
        echo_info "Stack does not exist, creating..."
        OPERATION="create-stack"
    fi
    
    # Deploy the stack
    aws cloudformation "$OPERATION" \
        --stack-name "$STACK_NAME" \
        --template-body file://templates/main-stack.yaml \
        --parameters \
            ParameterKey=TemplatesBucketName,ParameterValue="$TEMPLATES_BUCKET" \
            ParameterKey=DeployNeptune,ParameterValue="$DEPLOY_NEPTUNE" \
            ParameterKey=DeployNeptuneNotebook,ParameterValue="$DEPLOY_NEPTUNE_NOTEBOOK" \
            ParameterKey=PublicIPAddress,ParameterValue="$PUBLIC_IP" \
            ParameterKey=EnableDataCollectionScheduling,ParameterValue="$ENABLE_DATA_COLLECTION_SCHEDULING" \
            ParameterKey=DataCollectionScheduleExpression,ParameterValue="$DATA_COLLECTION_SCHEDULE_EXPRESSION" \
            ParameterKey=DataCollectionScheduleDescription,ParameterValue="$DATA_COLLECTION_SCHEDULE_DESCRIPTION" \
            ParameterKey=DataCollectionScheduleTimezone,ParameterValue="$DATA_COLLECTION_SCHEDULE_TIMEZONE" \
            ParameterKey=EnableScheduling,ParameterValue="$ENABLE_GRAPH_EXPORT_SCHEDULING" \
            ParameterKey=ScheduleExpression,ParameterValue="$GRAPH_EXPORT_SCHEDULE_EXPRESSION" \
            ParameterKey=ScheduleDescription,ParameterValue="$GRAPH_EXPORT_SCHEDULE_DESCRIPTION" \
            ParameterKey=ScheduleTimezone,ParameterValue="$GRAPH_EXPORT_SCHEDULE_TIMEZONE" \
            ParameterKey=EnableAccessAnalyzerScheduling,ParameterValue="$ENABLE_ACCESS_ANALYZER_SCHEDULING" \
            ParameterKey=AccessAnalyzerScheduleExpression,ParameterValue="$ACCESS_ANALYZER_SCHEDULE_EXPRESSION" \
            ParameterKey=AccessAnalyzerScheduleDescription,ParameterValue="$ACCESS_ANALYZER_SCHEDULE_DESCRIPTION" \
            ParameterKey=AccessAnalyzerScheduleTimezone,ParameterValue="$ACCESS_ANALYZER_SCHEDULE_TIMEZONE" \
            ParameterKey=ManagementAccountId,ParameterValue="$MANAGEMENT_ACCOUNT_ID" \
            ParameterKey=DeployMcpServer,ParameterValue="$DEPLOY_MCP_SERVER" \
            ParameterKey=McpContainerImageUri,ParameterValue="$MCP_CONTAINER_IMAGE_URI" \
            ParameterKey=McpAgentRuntimeName,ParameterValue="$MCP_AGENT_RUNTIME_NAME" \
            ParameterKey=InternalAccessAnalyzerArn,ParameterValue="$INTERNAL_ACCESS_ANALYZER_ARN" \
            ParameterKey=ExternalAccessAnalyzerArn,ParameterValue="$EXTERNAL_ACCESS_ANALYZER_ARN" \
            ParameterKey=UnusedAccessAnalyzerArn,ParameterValue="$UNUSED_ACCESS_ANALYZER_ARN" \
            ParameterKey=DelegatedAdminAccountId,ParameterValue="$DELEGATED_ADMIN_ACCOUNT_ID" \
            ParameterKey=AccessAnalyzerPollerRoleName,ParameterValue="$ACCESS_ANALYZER_POLLER_ROLE_NAME" \
            ParameterKey=AccessAnalyzerPollerMaxPollAttempts,ParameterValue="$ACCESS_ANALYZER_POLLER_MAX_POLL_ATTEMPTS" \
            ParameterKey=AccessAnalyzerPollerRequestsPerSecond,ParameterValue="$ACCESS_ANALYZER_POLLER_REQUESTS_PER_SECOND" \
            ParameterKey=AccessAnalyzerDispatcherRoleName,ParameterValue="$ACCESS_ANALYZER_DISPATCHER_ROLE_NAME" \
            ParameterKey=AccessAnalyzerWorkerRoleName,ParameterValue="$ACCESS_ANALYZER_WORKER_ROLE_NAME" \
            ParameterKey=UnusedRoleWorkerRequestsPerSecond,ParameterValue="$UNUSED_ROLE_WORKER_REQUESTS_PER_SECOND" \
            ParameterKey=UnusedRoleWorkerBatchSize,ParameterValue="$UNUSED_ROLE_WORKER_BATCH_SIZE" \
            ParameterKey=UnusedRoleQueueVisibilityTimeoutSeconds,ParameterValue="$UNUSED_ROLE_QUEUE_VISIBILITY_TIMEOUT_SECONDS" \
            ParameterKey=UnusedRoleQueueMaxReceiveCount,ParameterValue="$UNUSED_ROLE_QUEUE_MAX_RECEIVE_COUNT" \
            ParameterKey=UnusedRoleDispatcherLeaseSeconds,ParameterValue="$UNUSED_ROLE_DISPATCHER_LEASE_SECONDS" \
        --capabilities CAPABILITY_IAM > /dev/null 2>&1
    
    echo_info "Stack deployment initiated. Waiting for completion..."
    
    # Wait for stack operation to complete
    if [ "$OPERATION" = "create-stack" ]; then
        aws cloudformation wait stack-create-complete --stack-name "$STACK_NAME" > /dev/null 2>&1
    else
        aws cloudformation wait stack-update-complete --stack-name "$STACK_NAME" > /dev/null 2>&1
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
# loop below applies CLI overrides on top of them (Requirement 10.3). This
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
    # place (Requirement 10.4) - the flag-parsing loop further below can
    # still override any of these (Requirement 10.3).
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
            echo "                                    Max re-invocations per finding family per Polling_Cycle"
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

# Run main function
main