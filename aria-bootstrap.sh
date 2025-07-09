#!/bin/bash
# This script sets up the necessary AWS resources for the Aria application
# It creates S3 buckets for source code and exports, and prepares Lambda function zip files

echo "+---------------------------------------------------+"
echo "|  Aria Bootstrap Script                            |"
echo "+---------------------------------------------------+"

# Set the region - NOTE CHANGE THIS TO DESIRED REGION
REGION=us-east-1

# Get account id and get the last 4 digits
ACCOUNTID=$(aws sts get-caller-identity --output json |grep Account |awk -F ': "' '{print$2}' |sed 's/\".*//')
ACCOUNTIDSHORT=$(echo "$ACCOUNTID" | cut -c 9-12)

# Generate a random 8 character string in lower case
RANDOMSTRING="$(mktemp -u XXXXXXXX | tr 'A-Z' 'a-z')"

# Check SSM parameter store to see if the source bucket name has already been generated
SOURCE_BUCKET=$(aws ssm get-parameter --name "aria-source-bucket" --region "$REGION" --query "Parameter.Value" --output text)

# Check if the parameter store value exists, if not then set the variable (will be stored in SSM parameter store later)
if [ -z "$SOURCE_BUCKET" ]; then
    echo "Source Bucket variable not set...creating..."
    SOURCE_BUCKET="aria-source-$ACCOUNTIDSHORT-$RANDOMSTRING"
fi

# Define the local directory for storing zip files temporarily
SOURCE_DIR="./zip/"

# Check if the source directory exists
if [ ! -d "$SOURCE_DIR" ]; then
    echo "Creating temporary local source directory..."
    mkdir zip
fi

# Check SSM parameter store to see if the export bucket name has already been generated
EXPORT_BUCKET=$(aws ssm get-parameter --name "aria-export-bucket" --region "$REGION" --query "Parameter.Value" --output text)

# Check if the parameter store value exists, if not then set the variable (will be stored in SSM parameter store later)
if [ -z "$EXPORT_BUCKET" ]; then
    echo "Export Bucket variable not set...creating..."
    EXPORT_BUCKET="aria-export-$ACCOUNTIDSHORT-$RANDOMSTRING"
fi

echo "Aria Source Bucket is : $SOURCE_BUCKET"

# Check if aria SOURCE_BUCKET exists - create if missing, add configure bucket for EventBridge notifications
if aws s3api head-bucket --bucket "$SOURCE_BUCKET" 2>/dev/null; then
    echo "Source Bucket does not exist...creating..."
    aws s3api create-bucket \
        --bucket "$SOURCE_BUCKET" \
        --region "$REGION" \
        $(if [ "$REGION" != "us-east-1" ]; then echo "--create-bucket-configuration LocationConstraint=$REGION"; fi)
fi

# Configure EventBridge notifications (done once regardless of bucket existence)
aws s3api put-bucket-notification-configuration \
    --bucket "$SOURCE_BUCKET" \
    --notification-configuration '{"EventBridgeConfiguration": {}}'

echo "Aria Export Bucket is : $EXPORT_BUCKET"

# Check if aria EXPORT_BUCKET exists
if aws s3api head-bucket --bucket "$EXPORT_BUCKET" 2>/dev/null; then
    echo "Export Bucket already exists"
else
    echo "Export Bucket does not exist...creating..."
    aws s3api create-bucket \
        --bucket "$EXPORT_BUCKET" \
        --region "$REGION" \
        $(if [ "$REGION" != "us-east-1" ]; then echo "--create-bucket-configuration LocationConstraint=$REGION"; fi)
fi
# Create Lambda function zip files
echo "Creating directories and zip files..."

# Define the list of Lambda functions
LAMBDA_FUNCTIONS=(
  "createtables"
  "listusers"
  "listgroups"
  "listgroupmembership"
  "listpermissionsets"
  "listprovisionedpermissionsets"
  "listaccounts"
  "listuseraccountassignments"
  "listgroupaccountassignments"
  "getiamroles"
  "accessanalyzerfindingingestion"
  "s3export"
  "updatefunctioncode"
)

# Remove existing zip files
rm -f ./zip/*.zip

# Create directories and zip files in a loop
for func in "${LAMBDA_FUNCTIONS[@]}"; do
  echo "Processing ${func}..."
  mkdir -p "./source/${func}"
  zip -j "./zip/${func}.zip" "./source/${func}/lambda_function.py"
done

echo "Zip files created successfully!"

# Copy files to SOURCE_BUCKET
echo "Uploading zip files to S3 bucket: $SOURCE_BUCKET"
aws s3 rm "s3://$SOURCE_BUCKET/" --recursive
aws s3 cp "$SOURCE_DIR" "s3://$SOURCE_BUCKET/" --recursive --exclude "*" --include "*.zip"

# Delete files from zip bucket
echo "Cleaning up..."
rm -rf "$SOURCE_DIR"*.zip
rmdir "$SOURCE_DIR"

echo "-----"
echo "Storing generated bucket names in SSM parameter store..."
# Save the bucket names to SSM parameter store for future reference
aws ssm put-parameter --name "aria-source-bucket" --value "$SOURCE_BUCKET" --type "String" --overwrite > /dev/null
aws ssm put-parameter --name "aria-export-bucket" --value "$EXPORT_BUCKET" --type "String" --overwrite > /dev/null
echo "Source Bucket: $SOURCE_BUCKET"
echo "Export Bucket: $EXPORT_BUCKET"
echo "-----"
echo "Pre-requisites setup complete."