import boto3
import json
import os
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    try:
        # Get S3 bucket and key from the event
        bucket = event['detail']['bucket']['name']
        key = event['detail']['object']['key']

        # Remove .zip extension to get SSM parameter name
        parameter_name = "/aria/lambda/" + os.path.splitext(key)[0]
        
        # Initialize AWS clients
        ssm = boto3.client('ssm')
        lambda_client = boto3.client('lambda')
        s3 = boto3.client('s3')
        
        # Get the Lambda ARN from Parameter Store using the S3 object key as parameter name
        try:
            parameter = ssm.get_parameter(
                Name=parameter_name,
                WithDecryption=True
            )
            target_lambda_arn = parameter['Parameter']['Value']
        except ClientError as e:
            print(f"Error getting parameter {key}: {str(e)}")
            raise
        
        # Update the Lambda function code
        try:
            response = lambda_client.update_function_code(
                FunctionName=target_lambda_arn,
                S3Bucket=bucket,
                S3Key=key,
                Publish=True  # Create new version
            )
            
            print(f"Successfully updated Lambda function: {target_lambda_arn}")
            print(f"New version: {response['Version']}")
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Lambda function updated successfully',
                    'functionArn': target_lambda_arn,
                    'version': response['Version']
                })
            }
            
        except ClientError as e:
            print(f"Error updating Lambda function: {str(e)}")
            raise
            
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': f'Error occurred: {str(e)}'
            })
        }
