### Creating and deploying IAM role to enable cross-account IAM role for collection of IAM Identity Center provisioned IAM roles

Run this in the Management account to deploy a CloudFormation stackset that will create the IAM role needed to allow inventory of IAM roles in all accounts

*Caveat: Skip step 1 if your AWS IAM Identity Center is running in your management account and you have NOT delegated the administration to a member account*

#### 1. Create stackset

**NOTE:**
* Replace `<delegated-IdC-management-account-id>` with the 12-digit account ID that you have nominated as the administration account for AWS IAM Identity Center
* Replace `<arn-getiamroles-lambda-execution-role>` with the IAM Role Arn for the GetIamRoles Lambda function - see the CloudFormation output of the Aria-Setup stack for the required Arn

```
aws cloudformation create-stack-set \
  --stack-set-name aria-orglevel-iamlistroles \
  --template-body file://idc-iam-inventory-role.yaml \
  --parameters ParameterKey=TrustedAccountId,ParameterValue=<delegated-IdC-management-account-id> ParameterKey=IAMRolesLambdaCrossAccountRole,ParameterValue=<arn-getiamroles-lambda-execution-role> \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM
```

#### 2. Create stack instances in all member accounts

**NOTE:**
* This will ONLY create stack instances in *Member* accounts - it will NOT create a stack instance in the Management account as we are using service managed permissions. See step 3 for how to address that
* Replace `<root-ou-id>` with the Organizations root OU - you can programmatically retrieve this using `aws organizations list-roots | jq '.Roots[0].Id'`

```
aws cloudformation create-stack-instances \
  --stack-set-name aria-orglevel-iamlistroles \
  --regions us-east-1 \
  --deployment-targets OrganizationalUnitIds=<root-ou-id>
```

#### 3. Deploy the stack in the management account

In the management account you must manually deploy the cloudformation stack using file `idc-iam-inventory-role.yaml`

**Note:**
* Replace `arn:aws:iam::<01234567890>:role/<stack-name>-GetIAMRolesLambdaExecutionRole-<randomchars>` in the CloudFormation parameter screen with the IAM Role Arn for the GetIamRoles Lambda function - see the CloudFormation output of the Aria-Setup stack for the required Arn

