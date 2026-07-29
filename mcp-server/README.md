# ARIA-gv MCP server

An [MCP](https://modelcontextprotocol.io) server that exposes the ARIA-gv (Access Rights for Identity on AWS) Neptune Analytics identity access graph as callable tools. It lets an MCP client (Kiro, Claude Desktop, etc.) answer natural-language questions such as:

- "Show me how Bob was able to update this critical resource."
- "Who can delete our production S3 bucket?"
- "What does Alice have access to in the Production account?"
- "Which roles have unused access (least-privilege violations)?"

The server turns those questions into read-only [openCypher](https://opencypher.org/) queries, runs them against the graph via the `neptune-graph` data plane, and returns structured results the model narrates as an access path.

It runs as a managed, remote endpoint on **Amazon Bedrock AgentCore Runtime**, deployed as part of the solution. See [Hosting on Amazon Bedrock AgentCore Runtime](#hosting-on-amazon-bedrock-agentcore-runtime) to deploy and connect.

## Tools

| Tool                    | Purpose                                                              |
| ----------------------- | -------------------------------------------------------------------- |
| `describe_graph_schema` | Return the node/edge model and property names                        |
| `find_access_paths`     | How a user reaches a resource (optional action filter)               |
| `who_can_access`        | Every principal that can reach a resource                            |
| `get_principal_access`  | Full access report for one user                                      |
| `find_unused_access`    | Roles with unused-access findings, worst first                       |
| `list_entities`         | List users / groups / permission sets / accounts / roles / resources |
| `graph_summary`         | Node counts per label (also a connectivity check)                    |
| `execute_cypher`        | Run an arbitrary read-only openCypher query                          |

All tools are read-only. Mutating clauses (`CREATE`, `MERGE`, `SET`, `DELETE`,`REMOVE`, `DETACH`, `DROP`, `LOAD`) are rejected, and user values are passed as openCypher parameters rather than string-interpolated.

## Requirements

- The core solution deployed with Neptune (`--deploy-neptune true`).
- A running container engine (Docker Desktop, Colima, or Rancher Desktop) and the AWS CLI, to build and push the ARM64 image.
- AWS credentials that can deploy CloudFormation and, at connect time, read the Cognito app client (`cognito-idp:DescribeUserPoolClient`).

The runtime's execution role is least-privilege and read-only (`neptune-graph:ReadDataViaQuery` scoped to the graph ARN). If the graph is ever unreachable, every tool still returns the generated `query`, which you can paste into Neptune Graph Explorer.

## Configuration

The server reads these environment variables (the runtime resolves them automatically; you rarely need to set them):

| Variable        | Meaning                                                                                                                                                       |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ARIA_GRAPH_ID` | Graph id (e.g. `g-abc123`). If unset, it is auto-discovered by name (`aria` / `identitycenter`), or used directly when the account/region has a single graph. |
| `AWS_REGION`    | Region of the graph.                                                                                                                                          |

## Hosting on Amazon Bedrock AgentCore Runtime

The server runs as a remote, managed endpoint on Amazon Bedrock AgentCore Runtime, with Cognito JWT inbound auth. Because the Neptune graph is private (`PublicConnectivity: false`), the runtime is deployed in **VPC mode** and attached to the same private subnets as the graph, reaching it through the existing `neptune-graph` interface endpoint.

Infrastructure is defined in `templates/agentcore-mcp.yaml` and wired into the solution's `main-stack.yaml` (gated by `DeployMcpServer`). It provisions:

- an AgentCore Runtime (MCP protocol, ARM64 container, VPC network mode);
- a Cognito user pool + machine-to-machine (client credentials) app client for JWT inbound auth;
- a runtime security group and an ingress rule on the Neptune endpoint SG;
- a least-privilege execution role - read-only `neptune-graph:ReadDataViaQuery` scoped to the graph ARN, plus the standard ECR/logs/X-Ray/metrics permissions.

### Deploy (three steps)

The container image must exist before the runtime is created, so deploy in this order:

1. **Build and push the ARM64 image:**

   ```bash
   cd mcp-server
   IMAGE_URI=$(./build-and-push.sh -r us-east-1)
   echo "$IMAGE_URI"
   ```

2. **Deploy (or update) the solution with the MCP server enabled**, passing the
   image URI. With the nested stack:

   ```
   DeployNeptune          = true
   DeployMcpServer        = true
   McpContainerImageUri   = <IMAGE_URI from step 1>
   ```

   The MCP server queries the graph directly and does not require the Neptune
   notebook. If you only want the natural-language interface, you can set
   `DeployNeptuneNotebook = false` to skip the notebook.

   (Or deploy `templates/agentcore-mcp.yaml` on its own, passing the Neptune VPC id, the Neptune endpoint security group id, the graph id/ARN, and two AgentCore-supported AZ IDs - all available from the main stack's outputs.)  
       
3. **Read the stack outputs** for `McpRuntimeArn`, `McpCognitoAppClientId`, `McpCognitoTokenEndpoint`, and `McpScope`. Retrieve the app client secret from Cognito (console, or `aws cognito-idp describe-user-pool-client`).

### Quickest path: generate the Kiro config automatically

`generate-kiro-config.sh` does the next three sections for you - it reads the stack outputs, fetches the app client secret and a bearer token, builds the runtime endpoint URL, and prints ready-to-paste Kiro config for both connection options:

```bash
cd mcp-server
./generate-kiro-config.sh -s aria-gv-setup -r us-east-1
```

Copy whichever block it prints (Option A or B) into your `mcp.json`. Pass `-o aria-gv-mcp.json` to also write the recommended (Option B) entry to a file. Its output includes a live token and the client secret, so treat it as sensitive. The manual steps below explain what it does under the hood.

### Get a token

Obtain a bearer token with the client-credentials grant. Using the stack outputs from step 3 (and the app client secret):

```bash
TOKEN_ENDPOINT="<McpCognitoTokenEndpoint>"   # stack output
CLIENT_ID="<McpCognitoAppClientId>"          # stack output
CLIENT_SECRET="<from Cognito>"

export ARIA_MCP_TOKEN=$(curl -s -X POST "$TOKEN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials&scope=aria-gv-mcp/invoke" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

echo "$ARIA_MCP_TOKEN"
```

> The access token expires after `AccessTokenValidityHours` (default **12 hours**, configurable 1-24 via the `McpAccessTokenValidityHours` stack parameter). When it expires, refresh it and reconnect - or skip manual refresh entirely with the `connect-kiro.sh` launcher (Option B below).

### Build the runtime endpoint URL

Kiro connects to the AgentCore data-plane endpoint for the runtime. The runtime ARN must be URL-encoded and placed in the path:

```bash
RUNTIME_ARN="<McpRuntimeArn>"                # stack output
REGION="us-east-1"
ENCODED_ARN=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1], safe=''))" "$RUNTIME_ARN")
MCP_URL="https://bedrock-agentcore.${REGION}.amazonaws.com/runtimes/${ENCODED_ARN}/invocations?qualifier=DEFAULT"
echo "$MCP_URL"
```

The result looks like:

```
https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/arn%3Aaws%3Abedrock-agentcore%3Aus-east-1%3A123456789012%3Aruntime%2Faria_gv_mcp-abc123/invocations?qualifier=DEFAULT
```

### Connect Kiro to the hosted server

Both options below add an entry to `.kiro/settings/mcp.json` (workspace) or `~/.kiro/settings/mcp.json` (global). Changes apply on save; you can also reconnect from Kiro's MCP Server view.

#### Option A - remote entry with a bearer token (no extra tooling)

Kiro supports remote MCP servers directly (a `url` entry with `headers`). Use the `MCP_URL` from above:

```json
{
  "mcpServers": {
    "aria-gv-remote": {
      "url": "https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/<ENCODED_ARN>/invocations?qualifier=DEFAULT",
      "headers": {
        "Authorization": "Bearer ${ARIA_MCP_TOKEN}"
      },
      "disabled": false,
      "autoApprove": [
        "describe_graph_schema", "find_access_paths", "who_can_access",
        "get_principal_access", "find_unused_access", "list_entities", "graph_summary"
      ]
    }
  }
}
```

- `${ARIA_MCP_TOKEN}` is expanded from the environment Kiro runs in, so export the token (see "Get a token") before launching Kiro, then reconnect. You can instead paste the raw token, but avoid committing it.
- When the token expires you must refresh it and reconnect - simplest, but needs a periodic manual step. For hands-off refresh, use Option B.

#### Option B - auto-refreshing launcher (recommended)

`connect-kiro.sh` is a small stdio launcher that mints a **fresh** token on every connect and proxies to the runtime via [`mcp-remote`](https://www.npmjs.com/package/mcp-remote), so you never manually refresh. It needs `curl`, `python3`, and Node.js (for `npx`).

```json
{
  "mcpServers": {
    "aria-gv-remote": {
      "command": "/absolute/path/to/mcp-server/connect-kiro.sh",
      "env": {
        "ARIA_TOKEN_ENDPOINT": "<McpCognitoTokenEndpoint>",
        "ARIA_CLIENT_ID": "<McpCognitoAppClientId>",
        "ARIA_USER_POOL_ID": "<McpCognitoUserPoolId>",
        "ARIA_RUNTIME_ARN": "<McpRuntimeArn>",
        "AWS_REGION": "us-east-1"
      },
      "disabled": false,
      "autoApprove": [
        "describe_graph_schema", "find_access_paths", "who_can_access",
        "get_principal_access", "find_unused_access", "list_entities", "graph_summary"
      ]
    }
  }
}
```

- **No secret is stored.** With `ARIA_USER_POOL_ID` set (and no `ARIA_CLIENT_SECRET`), the launcher fetches the app client secret from Cognito at connect time using your AWS credentials, so nothing sensitive is written to `mcp.json`. This needs valid AWS creds and `cognito-idp:DescribeUserPoolClient` when Kiro connects (the default chain reads `~/.aws`, which GUI apps can use).
- Do **not** use `${ARIA_CLIENT_SECRET}` here: Kiro runs as a GUI app and does not inherit your shell `export`s, so `${VAR}` resolves to empty and the launcher exits (Kiro shows *"connection closed: initialize response"*).
- Fallback only (no AWS creds at connect time): add `"ARIA_CLIENT_SECRET": "<literal secret>"` to the `env`. Put it in the **user-level** `~/.kiro/settings/mcp.json` (not committed) - never in the repo's workspace `.kiro/settings/mcp.json`.
- `generate-kiro-config.sh` (above) prints this block fully populated (no secret).
- On each connect the launcher mints a fresh token, builds the endpoint URL, and execs `npx -y mcp-remote`; all diagnostics go to stderr so the MCP channel stays clean.

#### Troubleshooting: "connection closed: initialize response"

This means the launcher process exited before the MCP handshake. Most common causes:

- `ARIA_CLIENT_SECRET` is a `${...}` reference that resolved to empty (Kiro does not inherit shell exports) - use a literal secret, or set `ARIA_USER_POOL_ID` for runtime fetch (see Option B notes above).
- `ARIA_USER_POOL_ID` fetch was used but AWS credentials are missing/expired - refresh them (`aws sts get-caller-identity` should succeed).
- Node.js is not installed - the launcher needs `npx` for `mcp-remote`.

Run the launcher by hand to see the real error (it prints diagnostics to stderr) with the same env values from your `mcp.json`, for example:

```bash
ARIA_TOKEN_ENDPOINT=... ARIA_CLIENT_ID=... ARIA_CLIENT_SECRET=... \
ARIA_RUNTIME_ARN=... AWS_REGION=us-east-1 \
  ./connect-kiro.sh </dev/null
```

#### Notes for both options

- Missing, invalid, or expired auth returns `401`.
- All eight tools are exposed. `execute_cypher` is left out of `autoApprove` so free-form queries still prompt for approval.
- Kiro's built-in `oauth` config is not used here: it supports only public (PKCE) clients, whereas this deployment uses a confidential machine-to-machine client, so the bearer-token header is the most appropriate approach today.

### Updating the server

Rebuild and push a new image (step 1), then update the runtime to the new image tag. The server speaks streamable-HTTP on `0.0.0.0:8000` at `/mcp`.

## Notes and limits

The graph is a point-in-time snapshot built from IAM Identity Center, IAM, and IAM Access Analyzer data. It shows *potential* access; it does not model IdP context, IAM trust-policy conditions, SCPs/RCPs, or session policies, and it is not proof that an action occurred.

## License

MIT-0.
