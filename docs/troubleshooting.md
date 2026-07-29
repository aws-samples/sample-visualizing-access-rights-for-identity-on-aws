# Troubleshooting

[← Back to README](../README.md)

Jump to a section:

- [Core deployment](#core-deployment-issues)
  - [Resource name length limits](#resource-name-length-limits)
  - [CloudFormation export conflicts](#cloudformation-export-conflicts)
  - [EventBridge rule creation failures](#eventbridge-rule-creation-failures)
  - [Security group updates](#security-group-updates)
- [MCP server / AgentCore](#mcp-server--agentcore-issues)
  - [Unsupported availability zone](#unsupported-availability-zone)
  - [Recovering from a failed deployment](#recovering-from-a-failed-deployment)
  - [Runtime times out / never becomes healthy](#runtime-times-out--never-becomes-healthy)
  - [SECRET_HASH error](#secret_hash-error)
- [Best practices](#deployment-best-practices)
- [Getting help](#getting-help)

## Core deployment issues

### Resource name length limits

If you hit errors about resource names being too long:

- Use shorter stack names (20 characters or fewer recommended).
- The deployment script automatically handles name length optimization.

### CloudFormation export conflicts

**Resolved:** templates were updated to eliminate all export dependencies.

Common error messages:

- "No export named NeptuneGraphEndpoint found"
- "Cannot delete export as it is in use"

The architecture now uses direct parameter passing instead of exports. For new
deployments:

```bash
./deploy-nested-stacks.sh --deploy-neptune true
```

For existing deployments with conflicts, a clean redeploy is recommended:

```bash
aws cloudformation delete-stack --stack-name aria-gv-setup
aws cloudformation wait stack-delete-complete --stack-name aria-gv-setup
./deploy-nested-stacks.sh --deploy-neptune true
```

### EventBridge rule creation failures

If EventBridge rules fail to create:

- Verify that both data collection and graph export scheduling are configured.
- Check that the `AriaStateMachine` ARN is correctly passed between stacks.

### Security group updates

If security group updates fail due to custom naming, the templates now use
CloudFormation-generated names to avoid replacement conflicts; existing
deployments migrate automatically.

## MCP server / AgentCore issues

### Unsupported availability zone

**Error (during `AgentCoreMcpStack` creation):**

```
Agent runtime creation failed ... The following subnets are in unsupported
availability zones in region us-east-1: subnet-xxxx in us-east-1c (ID: use1-az6).
Supported availability zones are: use1-az4, use1-az1, use1-az2
```

**Why:** Bedrock AgentCore Runtime is only available in a subset of availability
zones, identified by stable **AZ IDs** (`use1-azN`) that map to different AZ
names (`us-east-1a`, etc.) in each account. The MCP stack creates dedicated
runtime subnets pinned to AZ IDs, but the defaults (`use1-az1`, `use1-az2`) must
be in the supported list for your region.

**Fix:** check the supported AZ IDs in the error, then set
`McpRuntimeSubnet1AzId` and `McpRuntimeSubnet2AzId` to two of them. To confirm AZ
IDs:

```bash
aws ec2 describe-availability-zones --region us-east-1 \
  --query 'AvailabilityZones[].[ZoneName,ZoneId]' --output table
```

Then redeploy:

```bash
aws cloudformation deploy \
  --template-file templates/main-stack.yaml \
  --stack-name aria-gv-setup \
  --parameter-overrides \
    DeployMcpServer=true \
    McpContainerImageUri="$IMAGE_URI" \
    McpRuntimeSubnet1AzId=use1-az1 \
    McpRuntimeSubnet2AzId=use1-az2 \
  --capabilities CAPABILITY_IAM
```

(The defaults `use1-az1`/`use1-az2` already work for the standard us-east-1
deployment.)

### Recovering from a failed deployment

If the `AgentCoreMcpStack` nested stack fails, the parent stack rolls back:

- If the parent is in `UPDATE_ROLLBACK_COMPLETE`, fix the cause (e.g. the AZ IDs
  above) and redeploy - the update applies in place.
- If it is in `ROLLBACK_COMPLETE` (a failed first-time create), delete it before
  redeploying:
  ```bash
  aws cloudformation delete-stack --stack-name aria-gv-setup
  aws cloudformation wait stack-delete-complete --stack-name aria-gv-setup
  ```
- If a redeploy is blocked by the nested stack being stuck in `DELETE_FAILED` or
  `UPDATE_ROLLBACK_FAILED`:
  ```bash
  aws cloudformation continue-update-rollback --stack-name aria-gv-setup
  ```
- You do **not** need to rebuild the container image to retry; reuse the same
  `McpContainerImageUri`.

### Runtime times out / never becomes healthy

**Symptoms:** the runtime deploys but invoking it hangs and times out with no
response (e.g. a raw MCP `initialize` returns nothing), and there are few or no
logs under `/aws/bedrock-agentcore/runtimes/aria_gv_mcp-*`.

**Why:** a VPC-mode container runtime with no internet egress must reach ECR, S3,
and CloudWatch Logs through VPC endpoints. Without them, AgentCore cannot pull
the container image or ship logs, so the microVM never becomes healthy and
invocations time out. This solution's Neptune VPC has no NAT gateway, so the
endpoints are mandatory.

**Fix:** `templates/agentcore-mcp.yaml` now provisions the required endpoints in
the runtime subnets automatically:

- ECR interface endpoints: `com.amazonaws.<region>.ecr.api` and `...ecr.dkr`
- CloudWatch Logs interface endpoint: `com.amazonaws.<region>.logs`
- S3 **gateway** endpoint (ECR stores image layers in S3), on the runtime route
  table

If you deployed an earlier version, redeploy to add them (no image rebuild
needed):

```bash
./deploy-nested-stacks.sh --deploy-neptune true \
  --deploy-mcp-server true --mcp-container-image-uri <existing IMAGE_URI>
```

See the AWS guidance on
[AgentCore VPC configuration](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html).

### SECRET_HASH error

**Error:** `Client ... is configured with secret but SECRET_HASH was not received`

**Why:** the invoking client is authenticating with a Cognito *user-login* flow
(`USER_PASSWORD_AUTH`), but this deployment uses a *machine-to-machine* app
client (the OAuth2 `client_credentials` grant). A secret-bearing client requires
a `SECRET_HASH` for user-login flows, hence the error.

**Fix:** invoke with a `client_credentials` bearer token instead - this is what
`mcp-server/connect-kiro.sh` and the Kiro remote config do. Do not use a Cognito
username/password (`initiate_auth`) invoke path against this runtime.

## Deployment best practices

1. **Use the enhanced script** - `./deploy-nested-stacks.sh` handles most common
   issues automatically.
2. **Choose appropriate scheduling** - match frequency to your data change
   patterns.
3. **Monitor costs** - frequent scheduling increases Lambda and Step Functions
   costs.
4. **Test scheduling** - start with manual execution before enabling automatic
   scheduling.

## Getting help

- See the [Scheduling Guide](../SCHEDULING_GUIDE.md) for detailed configuration.
- Review CloudFormation stack events for specific error details.
- Ensure all prerequisites are met (IAM permissions, cross-account roles).

Got an idea for how this solution could be extended and improved? Let us know!
