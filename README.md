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

What if we were able to get various data sets and understand the relationships between those? Then perhaps we could visualize in ways that could help Identity administrators have a better understanding of the potential access that principals (users & roles) have to critical resources like Amazon Simple Storage Service (S3) buckets, Amazon DynamoDB tables, and in addition it could help you on your journey to implementing Least Privilege.

As a side effect if we can create csv exports then the data could be used in other solutions that may have additional company-specific context to provide even greater value and improved fidelity.

To achieve this will require acquisition and storage of Identity-related data from a number of AWS services - primarily AWS Identity and Access Management, AWS IAM Identity Center and AWS IAM Access Analyzer. Fortunately we can use APIs to get the majority of this data, which we can then process, enrich and finally put it into the right format to create csv exports and to visualize it.

We will get most of the required data from two different Identity Center APIs:
1. [Identity Store](https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/welcome.html) 
2. [Identity Center](https://docs.aws.amazon.com/singlesignon/latest/APIReference/welcome.html)

We also need to ingest Unused Access findings and Internal Access findings from IAM Access Analyzer, which we will do using EventBridge. To achieve this, this solution expects that you have setup [Unused Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-create-unused.html) and [Internal Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-create-internal.html) to create the necessary findings. 

However we also need to build relationships between different entities, such as the relation between principals and permission sets, and understand what AWS IAM Identity Center permission sets are provisioned as IAM Roles into each account.

In order to understand these relationships, lets conceptualize the relationships we need to build using this diagram.

![Relationships](/img/relationships.png)

So we finally have an idea of how our graph needs to be built. Using the power of automation, lets construct an architecture that can help us put all this together. 

![Our Architecture](/img/architecture.png)

As shown above, this solution will use AWS Step Functions, AWS Lambda and Amazon EventBridge to orchestrate the processing of data capture, enrichment and processing to enable it to be visualized in Amazon Neptune. Amazon DynamoDB will be used to store the data to enable more efficient processing and reduce the need to repeatedly call APIs.

NOTE:
* This solution provides a snapshot into access rights at a moment in time (based on when the data was acquired from IAM Identity Center, IAM and IAM Access Analyzer). 
* This solution does **not** factor in contextual data from third-party IdPs or IAM trust policy statements that may affect access to your critical resources.

## Scheduling Automation

The ARIA-gv solution supports **intelligent automatic scheduling** with event-driven execution chaining:

1. **Data Collection**: Automatically runs the `AriaStateMachine` to collect fresh identity data
2. **Automatic Graph Export**: When data collection completes successfully, the `AriaExportGraphStateMachine` automatically triggers to refresh your Neptune Analytics graph  
3. **Independent Scheduling**: Optional time-based scheduling for additional graph export runs

This intelligent approach helps your Neptune graph to reflect the most current data while optimizing costs and execution efficiency.

## Let's build!

**IMPORTANT:** If you are deploying this solution and have ALREADY deployed prior to July 9th 2025, you must manually delete the old cloudformation stacks in this order:
* aria-neptune-notebook
* aria-neptune-analytics
* aria-setup

Once you deploy the updated solution as described below, ensure that you update the `aria-orglevel-iamlistroles` stackset and the cloudformation stack you created in your Management account with the Arn of the `GetIamRoles` Lambda function - see Quick Start step 2 below.

The ARIA-gv solution supports **intelligent automatic scheduling** with event-driven execution chaining:

1. **Data Collection**: Automatically runs the `AriaStateMachine` to collect fresh identity data
2. **Automatic Graph Export**: When data collection completes successfully, the `AriaExportGraphStateMachine` automatically triggers to refresh your Neptune Analytics graph  
3. **Independent Scheduling**: Optional time-based scheduling for additional graph export runs

This intelligent approach ensures your Neptune graph has 'fresh' data while optimizing costs and execution efficiency.

### Quick Start

The fastest way to deploy ARIA-gv is using the enhanced deployment script:

#### 1. Pre-requisites

Once you have cloned this repository locally:
* Obtain temporary credentials for the AWS Account that you have designated as the delegated Administration account for AWS IAM Identity Center
* Run `aria-bootstrap.sh` to create required S3 buckets and upload Lambda code

#### 2. Create cross-account IAM roles

Deploy the cross-account IAM roles in your AWS organization as described [here](source/idciaminventoryrole/stack-set-creation.md). This allows the solution to collect IAM role information from all accounts.

#### 3. Deploy everything using the Enhanced Deployment Script (Recommended)

The easiest way to deploy with optional scheduling is using the enhanced deployment script with presets:

```bash
# Deploy with daily data collection and graph export
./deploy-nested-stacks.sh --scheduling-preset daily-collection-and-export

# Deploy with business hours scheduling
./deploy-nested-stacks.sh --scheduling-preset business-hours

# Deploy with frequent data collection (6 hours) and daily graph export
./deploy-nested-stacks.sh --scheduling-preset frequent-collection-daily-export

# Or deploy basic setup without scheduling
./deploy-nested-stacks.sh --deploy-neptune true
```

#### Using CloudFormation Directly

Alternatively, deploy directly with CloudFormation:

```bash
aws cloudformation deploy \
  --template-file templates/main-stack.yaml \
  --stack-name aria-gv-setup \
  --parameter-overrides \
    EnableDataCollectionScheduling=true \
    DataCollectionScheduleExpression="rate(6 hours)" \
    EnableScheduling=true \
    ScheduleExpression="rate(1 day)" \
  --capabilities CAPABILITY_IAM
```

NOTE: To disable scheduling you would set `EnableScheduling=false` in the above.

#### 4. Visualizing workforce identities

* Navigate to Amazon Neptune in the AWS Console
* Click on **Notebooks** and find your notebook (e.g., `aws-neptune-analytics-Aria-Neptune-Notebook`)
* Click **Actions > Open Graph Explorer**
* Add all nodes and edges to explore your identity relationships!

### Manual Deployment (Alternative)

If you prefer manual control over the deployment process:

#### 1. Deploy Core Infrastructure
```bash
aws cloudformation deploy \
  --template-file templates/main-stack.yaml \
  --stack-name aria-gv-setup \
  --parameter-overrides DeployNeptune=true \
  --capabilities CAPABILITY_IAM
```

#### 2. Create cross-account IAM roles

Deploy the cross-account IAM roles in your AWS organization as described [here](source/idciaminventoryrole/stack-set-creation.md). This allows the solution to collect IAM role information from all accounts.

#### 3. Execute State Machines

Navigate to AWS Step Functions and execute the state machines:
1. **AriaStateMachine** (collects identity data)
2. **AriaExportGraphStateMachine** (exports to Neptune)

Or enable automatic scheduling to run these automatically.


### Scheduling Options

#### Data Collection (AriaStateMachine)
- **Frequent Updates**: `rate(6 hours)` - Collect fresh identity data every 6 hours
- **Daily Updates**: `rate(1 day)` - Collect data once per day
- **Business Hours**: `cron(0 9 ? * MON-FRI *)` - Collect data at 9 AM on weekdays

#### Graph Export (AriaExportGraphStateMachine)  
- **Daily Export**: `rate(1 day)` - Update Neptune graph daily
- **Weekly Export**: `rate(1 week)` - Update Neptune graph weekly
- **End of Business**: `cron(0 18 ? * MON-FRI *)` - Update graph at 6 PM on weekdays

#### Deployment Script Presets
- **daily-collection-and-export**: Daily data collection and graph export
- **frequent-collection-daily-export**: 6-hour data collection, daily graph export
- **business-hours**: 9 AM data collection, 6 PM graph export (EST)
- **disabled**: All scheduling disabled (manual execution only)

### Features

✅ **Event-Driven Execution**: Graph export automatically triggers after data collection completes  
✅ **Intelligent Chaining**: Ensures graph always uses the freshest data  
✅ **Dual-Trigger System**: Event-driven + optional time-based scheduling  
✅ **Flexible Scheduling**: Rate-based or cron-based expressions  
✅ **Timezone Support**: Configure schedules for your local timezone  
✅ **Error Handling**: Dead letter queues for failed executions  
✅ **Monitoring**: CloudWatch logs and metrics  
✅ **Cost Optimization**: Only runs graph export when there's new data  
✅ **Easy Deployment**: Enhanced script with common presets  
✅ **Validation**: Built-in parameter validation and configuration summary  

For detailed scheduling configuration, see the [Scheduling Guide](SCHEDULING_GUIDE.md).

**NOTE:** Consider how often to run the scheduled updates to keep your data 'fresh' while managing costs effectively.

### Deployment Architecture

#### 1. Deployment Approach
After running the `aria-boostrap.sh` script to prepare your environment, the solution uses a **single-step deployment** approach with:
- **Nested CloudFormation stacks** for modular architecture
- **Direct stack output references** (no export dependencies)
- **Automatic parameter passing** between stacks
- **Built-in validation** and error handling

#### 2. Architecture Benefits
- ✅ Eliminates CloudFormation export conflicts
- ✅ Enables reliable, repeatable deployments
- ✅ Simplifies updates and maintenance
- ✅ Provides cleaner dependency management

#### 3. What Gets Deployed

The solution creates:
- **Lambda Functions**: Data collection and processing
- **Step Functions**: Orchestration workflows  
- **DynamoDB Tables**: Identity data storage
- **Neptune Analytics**: Graph database and visualization
- **EventBridge Rules**: Automatic scheduling (optional)
- **IAM Roles**: Least-privilege access controls

### Execution Flow

1. **Data Collection**: Gathers identity data from IAM Identity Center
2. **Data Processing**: Enriches and stores data in DynamoDB
3. **Graph Export**: Converts data to Neptune-compatible format
4. **Visualization**: Creates interactive graph in Neptune Analytics

* Navigate to Amazon Neptune, and click on Notebooks
  * You should have a notebook named `aws-neptune-analytics-Aria-Neptune-Notebook` or something similar
  * Click on `radio button > Actions > Open Graph Explorer`
  * Make sure you add all the nodes and edges and experiment away! 

Here is an example of a graph visualization that you can create that looks very similar to the relationships diagram shown above.

![Example Graph](/img/graph-example.png)

## Updating the solution

This solution is under active development so there will be various updates and improvements that you may want to take advantage of over time. To keep your implementation up to date:

1. Perform a `git pull` to get your local copy up to date
2. Obtain credentials for the account that you originally deployed the solution into
3. At the command line run the `aria-bootstrap.sh` script
   * This script will upload the latest code to the S3 bucket in your account
   * A lambda function will then be triggered following the S3 upload to update the Lambda code for the various Lambda functions, ensuring that each of them are running the latest code
4. Once the Lambda functions are updated, re-run the deployment script (`deploy-nested-stacks.sh`) using the same command line as you used previously.

**NOTE:** If you have made *any* changes to the solution then performing this update **will overwrite** your changes - take note!

## Troubleshooting

### Common Deployment Issues

#### 1. Resource Name Length Limits
If you encounter errors about resource names being too long:
- Use shorter stack names (recommended: 20 characters or less)
- The deployment script automatically handles name length optimization

#### 2. CloudFormation Export Conflicts
**Issue Resolved**: Templates updated to eliminate all export dependencies.

**Common Error Messages:**
- "No export named NeptuneGraphEndpoint found"
- "Cannot delete export as it is in use"

**Solution**: The architecture has been improved to use direct parameter passing instead of exports.

**For New Deployments:**
```bash
./deploy-nested-stacks.sh --deploy-neptune true
```

**For Existing Deployments with Conflicts:**
```bash
# Recommended: Clean deployment
aws cloudformation delete-stack --stack-name aria-gv-setup
aws cloudformation wait stack-delete-complete --stack-name aria-gv-setup
./deploy-nested-stacks.sh --deploy-neptune true
```

**Why This Happens**: Existing deployments use the old export-based architecture. The new parameter-based architecture eliminates these conflicts permanently.

#### 3. EventBridge Rule Creation Failures
If EventBridge rules fail to create:
- Verify that both data collection and graph export scheduling are properly configured
- Check that the AriaStateMachine ARN is correctly passed between stacks

#### 4. Security Group Updates
If security group updates fail due to custom naming:
- The templates now use CloudFormation-generated names to avoid replacement conflicts
- Existing deployments will automatically migrate to the new naming approach

### Deployment Best Practices

1. **Use the Enhanced Script**: `./deploy-nested-stacks.sh` handles most common issues automatically
2. **Choose Appropriate Scheduling**: Match your scheduling frequency to your data change patterns
3. **Monitor Costs**: Frequent scheduling increases Lambda and Step Functions costs
4. **Test Scheduling**: Start with manual execution before enabling automatic scheduling

### Getting Help

- Check the [Scheduling Guide](SCHEDULING_GUIDE.md) for detailed configuration options
- Review CloudFormation stack events for specific error details
- Ensure all prerequisites are met (IAM permissions, cross-account roles)

Got an idea for how this solution could be extended and improved? Let us know!