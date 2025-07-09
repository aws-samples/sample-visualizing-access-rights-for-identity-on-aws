#!/bin/bash

# Deploy nested CloudFormation stacks for Access Rights for Identity on AWS
# This script uploads templates to S3 and deploys the main stack

set -e

# Configuration
STACK_NAME="aria-gv-setup"
REGION="us-east-1"
DEPLOY_NEPTUNE="true"
PUBLIC_IP="0.0.0.0/0"

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

# Function to check if S3 bucket exists
check_bucket() {
    local bucket_name=$1
    if aws s3api head-bucket --bucket "$bucket_name" 2>/dev/null; then
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
        aws s3api create-bucket --bucket "$bucket_name" 
    else
        aws s3api create-bucket --bucket "$bucket_name" --region "$REGION" \
            --create-bucket-configuration LocationConstraint="$REGION" 
    fi
    
    # Enable versioning
    aws s3api put-bucket-versioning --bucket "$bucket_name" \
        --versioning-configuration Status=Enabled 
    
    echo_info "S3 bucket $bucket_name created successfully"
    
    # Store the bucket name in SSM parameter store for future reference
    if [ "$bucket_name" = "$TEMPLATES_BUCKET" ]; then
        aws ssm put-parameter --name "aria-templates-bucket" --value "$bucket_name" --type "String" --overwrite --region "$REGION" > /dev/null
        echo_info "Templates bucket name stored in SSM parameter store"
    fi
}

# Function to upload templates to S3
upload_templates() {
    echo_info "Uploading CloudFormation templates to S3..."
    
    # Upload all template files
    aws s3 cp templates/ s3://"$TEMPLATES_BUCKET"/ --recursive 
    
    echo_info "Templates uploaded successfully"
}

# Function to validate CloudFormation template
validate_template() {
    local template_file=$1
    echo_info "Validating template: $template_file"
    
    aws cloudformation validate-template --template-body file://"$template_file"  > /dev/null
    
    echo_info "Template $template_file is valid"
}

# Function to validate scheduling parameters
validate_scheduling_parameters() {
    # Validate boolean values
    if [[ "$ENABLE_DATA_COLLECTION_SCHEDULING" != "true" && "$ENABLE_DATA_COLLECTION_SCHEDULING" != "false" ]]; then
        echo_error "Invalid value for --enable-data-collection-scheduling: $ENABLE_DATA_COLLECTION_SCHEDULING (must be 'true' or 'false')"
        exit 1
    fi
    
    if [[ "$ENABLE_GRAPH_EXPORT_SCHEDULING" != "true" && "$ENABLE_GRAPH_EXPORT_SCHEDULING" != "false" ]]; then
        echo_error "Invalid value for --enable-graph-export-scheduling: $ENABLE_GRAPH_EXPORT_SCHEDULING (must be 'true' or 'false')"
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
    
    echo_info "Scheduling parameters validated successfully"
}

# Function to deploy CloudFormation stack
deploy_stack() {
    echo_info "Deploying CloudFormation stack: $STACK_NAME"

    # Check if stack exists
    if aws cloudformation describe-stacks --stack-name "$STACK_NAME" 2>/dev/null; then
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
            ParameterKey=PublicIPAddress,ParameterValue="$PUBLIC_IP" \
            ParameterKey=EnableDataCollectionScheduling,ParameterValue="$ENABLE_DATA_COLLECTION_SCHEDULING" \
            ParameterKey=DataCollectionScheduleExpression,ParameterValue="$DATA_COLLECTION_SCHEDULE_EXPRESSION" \
            ParameterKey=DataCollectionScheduleDescription,ParameterValue="$DATA_COLLECTION_SCHEDULE_DESCRIPTION" \
            ParameterKey=DataCollectionScheduleTimezone,ParameterValue="$DATA_COLLECTION_SCHEDULE_TIMEZONE" \
            ParameterKey=EnableScheduling,ParameterValue="$ENABLE_GRAPH_EXPORT_SCHEDULING" \
            ParameterKey=ScheduleExpression,ParameterValue="$GRAPH_EXPORT_SCHEDULE_EXPRESSION" \
            ParameterKey=ScheduleDescription,ParameterValue="$GRAPH_EXPORT_SCHEDULE_DESCRIPTION" \
            ParameterKey=ScheduleTimezone,ParameterValue="$GRAPH_EXPORT_SCHEDULE_TIMEZONE" \
        --capabilities CAPABILITY_IAM
    
    echo_info "Stack deployment initiated. Waiting for completion..."
    
    # Wait for stack operation to complete
    if [ "$OPERATION" = "create-stack" ]; then
        aws cloudformation wait stack-create-complete --stack-name "$STACK_NAME" 
    else
        aws cloudformation wait stack-update-complete --stack-name "$STACK_NAME" 
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
    
    if [[ "$ENABLE_DATA_COLLECTION_SCHEDULING" == "false" && "$ENABLE_GRAPH_EXPORT_SCHEDULING" == "false" ]]; then
        echo_warn "Both scheduling options are disabled. You will need to manually execute state machines."
    fi
    
    echo ""
}

# Generate unique templates bucket name
ACCOUNTID=$(aws sts get-caller-identity --output json | grep Account | awk -F ': "' '{print$2}' | sed 's/\".*//')
ACCOUNTIDSHORT=$(echo "$ACCOUNTID" | cut -c 9-12)

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
    echo_info "Deploy Neptune: $DEPLOY_NEPTUNE"
    echo_info "Public IP: $PUBLIC_IP"
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

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
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
        --scheduling-preset)
            set_scheduling_preset "$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Basic Options:"
            echo "  --stack-name STACK_NAME           CloudFormation stack name (default: aria-gv-setup)"
            echo "  --templates-bucket BUCKET_NAME    S3 bucket for templates (default: auto-generated unique name)"
            echo "                                    Note: Bucket names are automatically generated per account and stored in SSM"
            echo "  --region REGION                   AWS region (default: us-east-1)"
            echo "  --deploy-neptune true|false       Deploy Neptune Analytics and Notebook (default: true)"
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
            echo "Scheduling Presets:"
            echo "  --scheduling-preset PRESET       Apply a common scheduling configuration"
            echo "                                    Available presets:"
            echo "                                      daily-collection-and-export"
            echo "                                      frequent-collection-daily-export"
            echo "                                      business-hours"
            echo "                                      disabled"
            echo ""
            echo "Other Options:"
            echo "  --help                            Show this help message"
            echo ""
            echo "Examples:"
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