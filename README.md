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
2. **Cross-account roles** - deploy the roles described in [stack-set-creation.md](source/idciaminventoryrole/stack-set-creation.md).
3. **Deploy:**
   ```bash
   ./deploy-nested-stacks.sh --scheduling-preset daily-collection-and-export
   ```
4. **Visualize** - open the Neptune notebook (if you chose to deploy it) and launch Graph Explorer, or **query in plain English** with the [MCP server](mcp-server/README.md).

Full instructions are in the [Deployment guide](docs/deployment.md).

## Recent updates

- **Faster data collection** - the IAM role and account-assignment collectors now process accounts, users, and groups concurrently, write to DynamoDB in batches, and fully paginate the source APIs. Collection Lambdas also run with more memory (1024 MB) and a longer timeout (15 min).
- **Faster, more reliable graph refresh** - the graph export/import state machine now polls the graph reset and import-task status instead of waiting fixed time windows, so runs advance as soon as each step completes and surface a real failure if the import doesn't succeed.
- **Natural-language querying** - added the ARIA-gv MCP server for asking questions in plain English, hosted on Amazon Bedrock AgentCore Runtime. See the [MCP server README](mcp-server/README.md).
- **More accurate assignments** - user and group account-assignment tables use composite sort keys, so a principal with multiple permission sets in the same account is captured correctly.
- **Managed IAM policies for Lambda roles** - each data-collection Lambda role now attaches a standalone customer-managed policy instead of an embedded inline policy, making permissions easier to review, reuse, and audit. No change to the effective (least-privilege) permissions.
- **Optional Neptune notebook** - the graph and the notebook now deploy independently. The notebook (SageMaker + Graph Explorer) is still on by default, but you can deploy the graph alone with `DeployNeptuneNotebook=false` (or `--deploy-neptune-notebook false`) - handy when you only need the [MCP server](mcp-server/README.md). See the [Deployment guide](docs/deployment.md).
- **Fixes and cleanup** - bug fixes for Access Analyzer finding ingestion, Lambda execution-role updates for IAM Identity Center KMS, streamlined deployment scripts, and removal of redundant CloudFormation.

## Important notes

- ARIA-gv provides a **snapshot** of access rights at a moment in time, based on when data was acquired from IAM Identity Center, IAM, and IAM Access Analyzer.
- It does **not** factor in contextual data from third-party IdPs or IAM trust policy statements that may affect access to your critical resources - we **are** working on trust policy statement data!

## Contributing and security

- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security](SECURITY.md)
- [License](LICENSE)
