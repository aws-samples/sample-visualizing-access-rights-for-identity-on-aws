# ARIA-gv (Access Rights for Identity on AWS - graph visualization)

> This solution was initially shown at AWS re:Inforce 2025 in Code Talk session IAM341, presented by Meg
> Peddada and Alex Waddell. [Watch the recording](https://www.youtube.com/watch?v=JsPug0rh7BM).

ARIA-gv collects identity data from AWS IAM Identity Center, IAM, and IAM Access Analyzer, builds the relationships between users, groups, permission sets, roles, accounts, and resources, and loads it into an Amazon Neptune Analytics graph you can **visualize** and **query in plain English**.

It helps identity teams answer questions like:

- *"Who can access our cloud resources and what can they do to them?"*
- *"How was Bob able to update the customer data in our production account?"*
- *"Do access rights follow least privilege?"*
- *"What does Alice have access to in our production account?"*

![Example graph](img/graph-example.png)

## Documentation

| Guide                                      | What's in it                                                |
| ------------------------------------------ | ----------------------------------------------------------- |
| [Overview](docs/overview.md)               | The problem, the approach, architecture, and how it works   |
| [Deployment](docs/deployment.md)           | Prerequisites, deploy options, what gets deployed, updating |
| [Scheduling](docs/scheduling.md)           | Automatic data collection and graph export scheduling       |
| [Troubleshooting](docs/troubleshooting.md) | Common deployment and MCP/AgentCore issues                  |
| [Scheduling Guide](SCHEDULING_GUIDE.md)    | Full scheduling configuration reference                     |
| [MCP server README](mcp-server/README.md)  | MCP tools, hosting, and Kiro connection detail              |

## Quick start

1. **Prerequisites** - clone the repo, get credentials for your IAM Identity Center delegated admin account, and run `aria-bootstrap.sh`.
2. **Cross-account roles** - deploy the roles described in [stack-set-creation.md](source/idciaminventoryrole/stack-set-creation.md), and the `AriaAccessAnalyzerPollerRole` described in [delegated-admin-role-setup.md](source/accessanalyzerpoller/delegated-admin-role-setup.md) (only needed if your IAM Access Analyzer delegated administrator account differs from your ARIA-gv account).
3. **Deploy:**
   ```bash
   ./deploy-nested-stacks.sh --scheduling-preset daily-collection-and-export
   ```
4. **Visualize** - open the Neptune notebook (if you chose to deploy it) and launch Graph Explorer, or **query in plain English** with the [MCP server](mcp-server/README.md).

Full instructions are in the [Deployment guide](docs/deployment.md).

## Recent updates

- **YAML deployment configuration file** - `deploy-nested-stacks.sh` accepts `--config-file` (or `-c`) pointing at a YAML file that centralizes deployment settings, including Access Analyzer role names, queue recovery controls, dispatcher lease duration, and strict worker RPS. CLI flags still override YAML values. See the [Deployment guide](docs/deployment.md).
- **Access Analyzer polling is independently scheduled** - `AriaAccessAnalyzerStateMachine` runs independently of `AriaStateMachine` identity collection and can be scheduled more frequently through `accessAnalyzerScheduling` in `config.yaml`. Its unused-role dispatcher starts immediately instead of waiting for internal or external poll backfills. See the [Scheduling guide](docs/scheduling.md).
- **Access Analyzer findings are polled, not pushed via EventBridge** - the old `AccessAnalyzerFindingIngestion` Lambda and per-account EventBridge rules are retired. ARIA-gv queries only the three explicit analyzer ARNs you configure and never calls `ListAnalyzers`. See the [Deployment guide](docs/deployment.md).
- **No cross-account role needed for same-account delegated administrators** - the poller detects at runtime whether the account registered as the IAM Access Analyzer delegated administrator is the same account ARIA-gv is deployed into. When it is, it calls the Access Analyzer API directly using its own execution role instead of assuming `AriaAccessAnalyzerPollerRole`, so the standalone cross-account role setup ([delegated-admin-role-setup.md](source/accessanalyzerpoller/delegated-admin-role-setup.md)) becomes entirely unnecessary for that setup. This is automatic based on your `DelegatedAdminAccountId` setting - no additional configuration needed.
- **IAM trust policy ingestion (role chaining)** - added a collector that reads IAM role trust policies (`AssumeRolePolicyDocument`) and graphs which principals can assume which roles as `CAN_ASSUME` edges, enabling role-chaining and role-assumption-path queries. The shared `roleFiltering` configuration now selects the permission-set roles, AAM roles, and any role-name patterns to inventory, so this collector derives edges from the same scope as internal and unused Access Analyzer findings. Only IAM role and user principals are graphed (service, account-root, wildcard, and federated/SAML/OIDC principals are excluded), and STS assumed-role ARNs are normalized back to their IAM role. The edges attach to existing role nodes so chains connect end to end. This adds read actions (`iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListRolePolicies`, `iam:GetRolePolicy`) to the cross-account inventory role, so redeploy the inventory-role StackSet to all member accounts before enabling it - see [stack-set-creation.md](source/idciaminventoryrole/stack-set-creation.md).
- **AWS Account Access Manager support** - added a collector that discovers the Account Access Manager application and gathers its entitlements per principal, mapping them to IAM roles and accounts so Account Access Manager-granted access shows up in the graph alongside IAM Identity Center assignments. The [MCP server](mcp-server/README.md) was also updated to surface this Account Access Manager data in natural-language queries.
- **MCP server on Python MCP SDK 2.0** - the [ARIA-gv MCP server](mcp-server/README.md) now targets the [v2 line](https://py.sdk.modelcontextprotocol.io/v2/whats-new/) of the Python MCP SDK, which brings:
  - a stateless protocol core (the 2026-07-28 MCP revision) that drops the connection handshake, session IDs, and server-initiated requests for better reliability and scalability;
  - a reworked SDK engine;
  - a first-class `Client` object that connects and negotiates the protocol version in one step.
- **Faster data collection** - the IAM role and account-assignment collectors now process accounts, users, and groups concurrently, write to DynamoDB in batches, and fully paginate the source APIs. Collection Lambdas also run with more memory (1024 MB) and a longer timeout (15 min).
- **Faster, more reliable graph refresh** - the graph export/import state machine now polls the graph reset and import-task status instead of waiting fixed time windows, so runs advance as soon as each step completes and surface a real failure if the import doesn't succeed.
- **Natural-language querying** - added the ARIA-gv MCP server for asking questions in plain English, hosted on Amazon Bedrock AgentCore Runtime. See the [MCP server README](mcp-server/README.md).
- **More accurate assignments** - user and group account-assignment tables use composite sort keys, so a principal with multiple permission sets in the same account is captured correctly.
- **Managed IAM policies for Lambda roles** - each data-collection Lambda role now attaches a standalone customer-managed policy instead of an embedded inline policy, making permissions easier to review, reuse, and audit. No change to the effective (least-privilege) permissions.
- **Optional Neptune notebook** - the graph and the notebook now deploy independently. The notebook (SageMaker + Graph Explorer) is still on by default, but you can deploy the graph alone with `DeployNeptuneNotebook=false` (or `--deploy-neptune-notebook false`) - handy when you only need the [MCP server](mcp-server/README.md). See the [Deployment guide](docs/deployment.md).
- **Fixes and cleanup** - bug fixes for Access Analyzer finding ingestion, Lambda execution-role updates for IAM Identity Center KMS, streamlined deployment scripts, and removal of redundant CloudFormation.

## Important notes

- ARIA-gv provides a **snapshot** of access rights at a moment in time, based on when data was acquired from IAM Identity Center, IAM, and IAM Access Analyzer.
- ARIA-gv now ingests IAM role **trust policy** statements to graph role-assumption relationships (see Recent updates), currently for IAM role and user principals. It does **not** yet factor in contextual data from third-party IdPs, or trust-policy conditions and non-IAM (service, federated/SAML/OIDC) principals, that may affect access to your critical resources.

## Contributing and security

- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security](SECURITY.md)
- [License](LICENSE)
