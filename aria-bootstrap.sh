#!/bin/bash
echo "+---------------------------------------------------+"
echo "|  Aria Bootstrap Script                            |"
echo "+---------------------------------------------------+"

# Set the region - NOTE CHANGE THIS TO DESIRED REGION
REGION=us-east-1

# Get account id and get the last 4 digits
ACCOUNTID=$(aws sts get-caller-identity --output json |grep Account |awk -F ': "' '{print$2}' |sed 's/\".*//')
ACCOUNTIDSHORT=$(echo $ACCOUNTID| cut -c 9-12)

# Generate a random 8 character string in lower case
RANDOMSTRING="$(echo $(mktemp -u XXXXXXXX) | tr '[A-Z]' '[a-z]')"

# Check SSM parameter store to see if the source bucket name has already been generated
SOURCE_BUCKET=$(aws ssm get-parameter --name "aria-source-bucket" --region "$REGION" --query "Parameter.Value" --output text)

# Check if the parameter store value exists, if not then set the variable (will be stored in SSM parameter store later)
if [ -z "$SOURCE_BUCKET" ]; then
    echo "Source Bucket variable not set...creating..."
    SOURCE_BUCKET="aria-source-$ACCOUNTIDSHORT-$RANDOMSTRING"
fi

SOURCE_DIR="./zip/"

# Check if the source directory exists
if [ ! -d "$SOURCE_DIR" ]; then
    echo "Error: Source directory does not exist...creating..."
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

# Check if aria SOURCE_BUCKET exists
response=$(aws s3api head-bucket --bucket "$SOURCE_BUCKET")
if [ $? -eq 0 ]; then
    echo "Source Bucket already exists"
else
    echo "Source Bucket does not exist...creating..."
    aws s3api create-bucket \
        --bucket "$SOURCE_BUCKET" \
        --region "$REGION" \
        $(if [ "$REGION" != "us-east-1" ]; then echo "--create-bucket-configuration LocationConstraint=$REGION"; fi)
fi

echo "Aria Export Bucket is : $EXPORT_BUCKET"

# Check if aria EXPORT_BUCKET exists
response=$(aws s3api head-bucket --bucket "$EXPORT_BUCKET")
if [ $? -eq 0 ]; then
    echo "Export Bucket already exists"
else
    echo "Export Bucket does not exist...creating..."
    aws s3api create-bucket \
        --bucket "$EXPORT_BUCKET" \
        --region "$REGION" \
        $(if [ "$REGION" != "us-east-1" ]; then echo "--create-bucket-configuration LocationConstraint=$REGION"; fi)
fi

sh ./createzips.sh

# Copy files to SOURCE_BUCKET
echo "Uploading zip files to S3 bucket: $SOURCE_BUCKET"
aws s3 rm s3://$SOURCE_BUCKET/ --recursive
aws s3 sync "$SOURCE_DIR" "s3://$SOURCE_BUCKET" --exclude "*" --include "*.zip"

# Delete files from zip bucket
echo "Cleaning up..."
rm -rf "$SOURCE_DIR"*.zip
rmdir "$SOURCE_DIR"

echo "-----"
echo "Storing generated bucket names in SSM parameter store..."
aws ssm put-parameter --name "aria-source-bucket" --value "$SOURCE_BUCKET" --type "String" --overwrite > /dev/null
aws ssm put-parameter --name "aria-export-bucket" --value "$EXPORT_BUCKET" --type "String" --overwrite > /dev/null
echo "Source Bucket: $SOURCE_BUCKET"
echo "Export Bucket: $EXPORT_BUCKET"
echo "-----"
echo "Pre-requisites setup complete."