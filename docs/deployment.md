# Deployment

[← Back to README](../README.md)

This guide covers deploying ARIA-gv. For how the solution works, see
[Overview](overview.md). For scheduling, see [Scheduling](scheduling.md).

> **Migrating from a pre-July 9th 2025 deployment?** You must manually delete the
> old CloudFormation stacks in this order first: `aria-neptune-notebook`,
> `aria-neptune-analytics`, `aria-setup`. After deploying the updated solution,
> update the `aria-orglevel-iamlistroles` stack set and the CloudFormation stack
> in your Management account with the ARN of the `GetIamRoles` Lambda function
> (see step 2 below).

## Prerequisites

1. Clone this repository locally.
2. Obtain temporary credentials for the AWS account you designated as the delegated administration account for AWS IAM Identity Center.
3. Run `aria-bootstrap.sh` to create the required S3 buckets and upload the Lambda code.

## Step 1 - Create cross-account IAM roles

Deploy the cross-account IAM roles across your AWS organization as described in [stack-set-creation.md](../source/idciaminventoryrole/stack-set-creation.md). This lets the solution collect IAM role information from all accounts.

## Step 2 - Deploy

### Recommended: the enhanced deployment script

The easiest way to deploy, with optional scheduling presets:

```bash
# Daily data collection and graph export
./deploy-nested-stacks.sh --scheduling-preset daily-collection-and-export

# Business hours scheduling
./deploy-nested-stacks.sh --scheduling-preset business-hours

# Frequent data collection (6 hours) and daily graph export
./deploy-nested-stacks.sh --scheduling-preset frequent-collection-daily-export

# Basic setup without scheduling
./deploy-nested-stacks.sh --deploy-neptune true
```

See [Scheduling](scheduling.md) for all presets and options.

### Alternative: CloudFormation directly

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

To disable scheduling, set `EnableScheduling=false`.

The Neptune notebook (SageMaker instance + Graph Explorer) is deployed by
default alongside the graph. To deploy the graph without it, set
`DeployNeptuneNotebook=false` (or pass `--deploy-neptune-notebook false` to the
deployment script). The notebook requires the graph, so it is only deployed when
`DeployNeptune=true`.

To also host the natural-language MCP server, first build the image, then add
`DeployMcpServer=true` and `McpContainerImageUri=<image-uri>` to
`--parameter-overrides`. See
[Hosting on Amazon Bedrock AgentCore Runtime](../mcp-server/README.md#hosting-on-amazon-bedrock-agentcore-runtime).

### Manual deployment

If you prefer manual control:

1. **Deploy core infrastructure:**
   ```bash
   aws cloudformation deploy \
     --template-file templates/main-stack.yaml \
     --stack-name aria-gv-setup \
     --parameter-overrides DeployNeptune=true \
     --capabilities CAPABILITY_IAM
   ```
2. **Create cross-account IAM roles** (see step 1 above).
3. **Execute the state machines** in AWS Step Functions:
   1. `AriaStateMachine` (collects identity data)
   2. `AriaExportGraphStateMachine` (exports to Neptune)

   Or enable automatic scheduling to run these for you.

## Step 3 - Visualize

> Requires the Neptune notebook (deployed by default; skipped if you set `DeployNeptuneNotebook=false`). If you deployed the graph only, use the MCP server (Step 4) or the Neptune Graph Explorer directly.

- Navigate to Amazon Neptune in the AWS Console.
- Open **Notebooks** and find your notebook (e.g. `aws-neptune-analytics-Aria-Neptune-Notebook`).
- Click **Actions > Open Graph Explorer**.
- Add all nodes and edges to explore your identity relationships.

## Step 4 (optional) - Ask questions in natural language

Beyond the visual Graph Explorer, you can query the graph in plain English using the included MCP server. See the [MCP server README](../mcp-server/README.md).

## What gets deployed

- **Lambda functions** - data collection and processing
- **Step Functions** - orchestration workflows
- **DynamoDB tables** - identity data storage
- **Neptune Analytics** - graph database
- **Neptune notebook** (optional, on by default) - SageMaker notebook and Graph Explorer for visualization
- **EventBridge rules** - automatic scheduling (optional)
- **IAM roles** - least-privilege access controls
- **MCP server on Bedrock AgentCore Runtime** (optional) - a natural-language query interface to the graph, with Cognito JWT authentication

## Deployment architecture

After `aria-bootstrap.sh` prepares your environment, the solution uses a **single-step deployment** built on:

- Nested CloudFormation stacks for a modular architecture
- Direct stack output references (no export dependencies)
- Automatic parameter passing between stacks
- Built-in validation and error handling

This design eliminates CloudFormation export conflicts, enables reliable and repeatable deployments, and simplifies updates and maintenance.

## Updating the solution

This solution is under active development. To keep your implementation current:

1. `git pull` to update your local copy.
2. Obtain credentials for the account you originally deployed into.
3. Run `aria-bootstrap.sh` - this uploads the latest code to your S3 bucket, then a Lambda function updates the code for all the solution's Lambda functions.
4. Re-run `deploy-nested-stacks.sh` with the same arguments you used previously.

> **Note:** if you have made *any* changes to the solution, updating **will overwrite** them.

## Troubleshooting

Deployment or runtime issues? See [Troubleshooting](troubleshooting.md).
