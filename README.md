# Welcome to ARIA-gv (Access Rights for Identity on AWS - graph visualization)

## Getting started

#### 0. Pre-requisites

* At the command line, obtain temporary credentials and run `aria-bootstrap.sh`
* This script will create 2 S3 buckets in your specified region (change the REGION parameter in `prereq-setup.sh` if required) named as follows:
    * `aria-source-<accountid>` - this will contain the zipped source files needed by cloudformation
    * `aria-export-<accountid>` - used to export data used by Neptune graph analytics & Neptune notebooks
* The script will then create zip files from the `source` folder and upload them from the `zip` folder to the `aria-source-<accountid>` S3 bucket

#### 1. Cloudformation - ARIA Code Setup

* Deploy a Cloudformation stack in the *same account* and *region* as your delegated Identity Center using the `aria-setup.yaml` template.
  * Give the stack a name, something like `aria-setup`
  * Make sure you update the `S3SourceBucketName` and `S3ExportBucketName` parameters with the correct AWS Account ID
  * Leave all other parameters as they are - no changes required
  
Once this completes be sure to check the output tab for ARN information that you may need in subsequent steps.

#### 2. Create cross-account IAM roles in your AWS organization

For ARIA-gv to retrieve the IAM policies associated with IAM roles deployed by AWS IAM Identity Center into each of your AWS Accounts, you must deploy a cloudformation stackset and stack as follows:

__Organization-wide Stackset Deployment__

Run the following in your Management account to deploy a stackset that will create the required IAM role to allow inventory of IAM roles in accounts:

*Caveat: Skip step 1 if your IDC is running in your management account*

1. Create stackset
 
```
aws cloudformation create-stack-set \
  --stack-set-name aria-orglevel-iamlistroles \
  --template-body file://idc-iam-inventory-role.yaml \
  --parameters ParameterKey=TrustedAccountId,ParameterValue=<delegated-IdC-management-account-id>,ParameterKey=IAMRolesLambdaCrossAccountRole,ParameterValue=<arn-getiamroles-lambda-execution-role> \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM
```

NOTES:
* Replace `<delegated-IdC-management-account-id>` with the account ID that you have delegated the administration of your AWS IAM Identity Center.
* Replace `<arn-getiamroles-lambda-execution-role>` with the ARN of the Lambda Execution Role for the `getiamroles` function that the initial Cloudformation stack created (see the stack output for the required ARN)
  
2. Create the stack instances in the entire org

```
aws cloudformation create-stack-instances \
  --stack-set-name aria-orglevel-iamlistroles \
  --regions us-east-1 \
  --deployment-targets OrganizationalUnitIds=<root-ou-id>
```

3. In the management account create a Cloudformation stack using the `idc-iam-inventory-role.yaml` YAML template in the `source\idciaminventoryrole` folder

#### 3. Cloudformation - ARIA Neptune Analytics Setup

* Deploy a Cloudformation stack in the *same account* and *region* as your delegated Identity Center using the `aria-neptune-analytics.yaml` template.
  * Give the stack a name, something like `aria-neptune-analytics`
  * Make sure you update the `AriaSetupStackName` parameter with the name of the Cloudformation stack you created in step 1 above
  * Make sure you update the `S3ExportBucketName` parameter with the name of the S3 Export Bucket created in Step 0 and used in Step 1 above
  * Leave all other parameters as they are - no changes required


#### 4. Cloudformation - ARIA Neptune Notebook Setup

* Deploy a Cloudformation stack in the *same account* and *region* as your `aria-neptune-analytics.yaml` template.
  * Give the stack a name, like `aria-neptune-notebook`
  * Make sure you update the following parameters:
    * GraphPort: `8182`
    * GraphSecurityGroup: `sg-xx` *Add the network config if you have vpc setup*
    * GraphSubnet: `subnet-xx`
    * GraphVPC: `vpc-xx`
    * NotebookInstanceType: `ml.t2.medium` *Best to take the smallest size for inital testing purposes*
    * NotebookName: `Aria-Neptune-Notebook`

This will take some time, so its worth moving to step 5. while the notebook stack finishes creating. 

#### 5: ARIA Execution 

Navigate to AWS Step Functions and execute the state machines in the following order:

1. AriaStateMachine
2. AriaExportGraphStateMachine


#### 6: Visualizing workforce identities - ARIA Neptune Grah

* Navigate to Amazon Neptine, and click on Notebooks
  * You should have a notebook named `aws-neptune-analytics-Aria-Neptune-Notebook` or something similar
  * Click on radio button > Actions > Open Graph Explorer
  * Make sure you add all the nodes and edges and experiment away! 


