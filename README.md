# Welcome to ARIA-gv (Access Rights for Identity on AWS - graph visualization)

**NOTE:** This sample code was shown at AWS re:Inforce 2025 in Code Talk session IAM341, presented by Meg Peddada and Alex Waddell. Watch the session recording here: [https://www.youtube.com/watch?v=JsPug0rh7BM](https://www.youtube.com/watch?v=JsPug0rh7BM).

## What are the challenges we are trying to solve?
Customers connect their Identity Provider (IdP) to AWS IAM Identity Center to enable easier management of access to AWS applications and accounts. This single connection then allows users & groups from the IdP to be easily synchronised to Identity Center and used to provide access to (for example) AWS Accounts.

![AWS IAM Identity Center](/img/idc.png)

This helps Identity administrators to manage AWS access more simply through IdP group membership. However those same Identity teams are also being asked questions like

*“Who in our company can access our cloud resources and what can they do to them?”*

*“Can you show me how Bob was able to update the customer data in our production account?”*

*“Do users with access to our cloud resources have access rights that follow least privilege?”*

*“Can you give me a report of everything that Alice has access to in our production account?”*

Some challenges when attempting to answer those questions are:

* Basing resource access assumptions on IdP group membership doesn’t tell the whole story
* Resource access may be granted using a combination of
  * Identity-based policies
  * Resource-based policies
  * Service Control Policies (SCPs)
  * Resource Control Policies (RCPs)
  * Permissions Boundaries
  * Session Policies
* Teams might deploy custom IAM roles & policies into accounts
* Providing AWS account & resource access visibility to teams beyond just CloudOps

## So what can we do?

We need to get data from AWS Identity and Access Management, AWS IAM Identity Center and also AWS IAM Access Analyzer. Fortunately there are APIs that we can use to get most of it. Then, we can process and enrich that data and put it into the right format for visualizing it.

We can most information from two different sets of Identity Center APIs:
1. [Identity Store](https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/welcome.html) 
2. [Identity Center](https://docs.aws.amazon.com/singlesignon/latest/APIReference/welcome.html)

Lastly we also want to bring in Unused Access findings and Internal Access findings from IAM Access Analyzer, which we will do using EventBridge. To achieve this, we need to setup [Unused Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-create-unused.html) and [Internal Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-create-internal.html) in order to ingest findings. 

However, there are also things we need to build the relationships, such as the relation between principals and permission sets, and, are provisioned into each account part of the AWS IAM Identity Center deployments. 


In order to understand these relationships, lets conceptualize the relationships we need to build in this diagram.

![Relationships](/img/relationships.png)

So we finally have an idea of how our graph needs to be built. Using the power of automation, lets actually build something that can help us put all this together. 

![Our Architecture](/img/architecture.png)

## Let's build!

#### 0. Pre-requisites

At the command line:
* Obtain temporary credentials for the AWS Account that you have designated as the delegated Administration account for AWS IAM Identity Center
* Run `aria-bootstrap.sh`

This script will use AWS CLI commands to create two S3 buckets in your specified region named as follows: (NOTE: change the REGION parameter in `aria-bootstrap.sh` if required - default is set to `us-east-1`):
  * `aria-source-<last-4-digits-of-account-id>-<8-random-characters>` - this will contain the zipped source files needed by cloudformation
  * `aria-export-<last-4-digits-of-account-id>-<8-random-characters>` - used to export data used by Neptune graph analytics & Neptune notebooks
* The script will then create zip files from the `source` folder and upload them from the `zip` folder to the `aria-source-<last-4-digits-of-account-id>-<8-random-characters>` S3 bucket

#### 1. Cloudformation - Initial Code Setup

* Deploy a Cloudformation stack in the *same account and region* as your delegated AWS IAM Identity Center using the `aria-setup.yaml` template
* Give the stack a name, something like `aria-setup`
* Leave all parameters as they are - no changes required
  
Once this completes be sure to check the output tab for Arn information that you may need in subsequent steps.

#### 2. Create cross-account IAM roles in your AWS organization

For the Lambda `getiamroles` function to retrieve IAM roles deployed by AWS IAM Identity Center into each of your AWS Accounts, you must deploy a cloudformation stackset and stack as described [here](source/idciaminventoryrole/stack-set-creation.md).


#### 3. Cloudformation - Neptune Analytics Setup

* Deploy a Cloudformation stack in the *same account and region* as your delegated Identity Center using the `aria-neptune-analytics.yaml` template
  * Give the stack a name, something like `aria-neptune-analytics`
  * Make sure you update the `AriaSetupStackName` parameter with the name of the Cloudformation stack you created in step 1 above
  * Make sure you update the `S3ExportBucketName` parameter with the name of the S3 Export Bucket created in Step 0 and used in Step 1 above
  * Leave all other parameters as they are - no changes required


#### 4. Cloudformation - Neptune Notebook Setup

* Deploy a Cloudformation stack in the *same account and region* as your `aria-neptune-analytics.yaml` template
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
