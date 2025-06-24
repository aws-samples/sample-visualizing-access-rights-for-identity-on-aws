# Welcome to ARIA-gv (Access Rights for Identity on AWS - graph visualization)

## Getting started

#### 0. Pre-requisites

At the command line:
* Obtain temporary credentials for the AWS Account that you have designated as the delegated Administration account for AWS IAM Identity Center
* Run `aria-bootstrap.sh`

This script will use AWS CLI commands to create two S3 buckets in your specified region named as follows: (NOTE: change the REGION parameter in `aria-bootstrap.sh` if required - default is set to `us-east-1`):
  * `aria-source-<last-4-digits-of-account-id>-<8-random-characters>` - this will contain the zipped source files needed by cloudformation
  * `aria-export-<last-4-digits-of-account-id>-<8-random-characters>` - used to export data used by Neptune graph analytics & Neptune notebooks
* The script will then create zip files from the `source` folder and upload them from the `zip` folder to the `aria-source-<last-4-digits-of-account-id>-<8-random-characters>` S3 bucket

#### 1. Cloudformation - Initial Code Setup

* Deploy a Cloudformation stack in the ==same account== and ==region== as your delegated AWS IAM Identity Center using the `aria-setup.yaml` template
* Give the stack a name, something like `aria-setup`
* Leave all parameters as they are - no changes required
  
Once this completes be sure to check the output tab for Arn information that you may need in subsequent steps.

#### 2. Create cross-account IAM roles in your AWS organization

For the Lambda `getiamroles` function to retrieve IAM roles deployed by AWS IAM Identity Center into each of your AWS Accounts, you must deploy a cloudformation stackset and stack as described [here](./idciaminventoryrole.stack-set-creation.md).


#### 3. Cloudformation - Neptune Analytics Setup

* Deploy a Cloudformation stack in the ==same account== and ==region== as your delegated Identity Center using the `aria-neptune-analytics.yaml` template
  * Give the stack a name, something like `aria-neptune-analytics`
  * Make sure you update the `AriaSetupStackName` parameter with the name of the Cloudformation stack you created in step 1 above
  * Make sure you update the `S3ExportBucketName` parameter with the name of the S3 Export Bucket created in Step 0 and used in Step 1 above
  * Leave all other parameters as they are - no changes required


#### 4. Cloudformation - Neptune Notebook Setup

* Deploy a Cloudformation stack in the ==same account== and ==region== as your `aria-neptune-analytics.yaml` template
  * Give the stack a name, like `aria-neptune-notebook`
  * Make sure you update the following parameters:
    * GraphPort: `8182`
    * GraphSecurityGroup: `sg-xx` (*Select the Security Group created ib Step 3 above*)
    * GraphSubnet: `subnet-xx` (*Select one of the Graph subnets created in Step 3 above*)
    * GraphVPC: `vpc-xx` (*Select the VPC created in Step 3 above*)
    * NotebookInstanceType: `ml.t2.medium` (*Best to take the smallest size for inital testing purposes and scale to your needs*)
    * NotebookName: `Aria-Neptune-Notebook`

This will take some time, so its worth moving to step 5. while the notebook stack finishes creating. 

#### 5: Execution 

Navigate to AWS Step Functions and execute the state machines in the following order:

1. AriaStateMachine
2. AriaExportGraphStateMachine


#### 6: Visualizing workforce identities - Neptune Grah

* Navigate to Amazon Neptune, and click on Notebooks
  * You should have a notebook named `aws-neptune-analytics-Aria-Neptune-Notebook` or something similar
  * Click on `radio button > Actions > Open Graph Explorer`
  * Make sure you add all the nodes and edges and experiment away! 

Got an idea for how this could be extended and improved? Let us know!
