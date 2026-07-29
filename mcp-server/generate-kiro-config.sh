#!/usr/bin/env bash
#
# generate-kiro-config.sh - read the ARIA-gv AgentCore MCP stack outputs, obtain
# a Cognito bearer token, build the runtime endpoint URL, and print recommended
# Kiro (.kiro/settings/mcp.json) configuration.
#
# It prints TWO ready-to-use options:
#   A) a remote `url` entry with a freshly-minted bearer token inline;
#   B) the auto-refreshing `connect-kiro.sh` launcher (recommended - never
#      expires because it mints a fresh token on each connect).
#
# Usage:
#   ./generate-kiro-config.sh [-s stack-name] [-r region] [-o out-file] [--no-token]
#
# Defaults: stack-name = aria-gv-setup; region = AWS_REGION or us-east-1.
#   -o out-file   also write the Option B server entry (JSON) to this file.
#   --no-token    don't call the token endpoint; emit Option A with a
#                 ${ARIA_MCP_TOKEN} placeholder instead of a live token.
#
# Requirements: aws CLI, python3, curl. Credentials must be able to read the
# stack outputs and describe the Cognito user pool client.
#
# SECURITY: this prints a client secret and (by default) a live bearer token to
# your terminal so you can paste them into a local config. Treat the output as
# sensitive; do not commit it.

set -euo pipefail

STACK_NAME="aria-gv-setup"
REGION="${AWS_REGION:-us-east-1}"
OUT_FILE=""
FETCH_TOKEN=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    -s|--stack-name) STACK_NAME="$2"; shift 2 ;;
    -r|--region) REGION="$2"; shift 2 ;;
    -o|--output-file) OUT_FILE="$2"; shift 2 ;;
    --no-token) FETCH_TOKEN=0; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -- read a single stack output by key -------------------------------------
get_output() {
  aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" --region "$REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" \
    --output text 2>/dev/null
}

echo "info: reading outputs from stack '${STACK_NAME}' in ${REGION}..." >&2
RUNTIME_ARN="$(get_output McpRuntimeArn)"
TOKEN_ENDPOINT="$(get_output McpCognitoTokenEndpoint)"
CLIENT_ID="$(get_output McpCognitoAppClientId)"
USER_POOL_ID="$(get_output McpCognitoUserPoolId)"
SCOPE="$(get_output McpScope)"
[[ -z "$SCOPE" || "$SCOPE" == "None" ]] && SCOPE="aria-gv-mcp/invoke"

if [[ -z "$RUNTIME_ARN" || "$RUNTIME_ARN" == "None" || -z "$CLIENT_ID" || "$CLIENT_ID" == "None" ]]; then
  echo "error: could not find MCP outputs on stack '${STACK_NAME}'." >&2
  echo "       Is the MCP server deployed (DeployMcpServer=true) and the stack name/region correct?" >&2
  exit 1
fi

# -- app client secret ------------------------------------------------------
echo "info: fetching Cognito app client secret..." >&2
CLIENT_SECRET="$(aws cognito-idp describe-user-pool-client \
  --user-pool-id "$USER_POOL_ID" --client-id "$CLIENT_ID" --region "$REGION" \
  --query 'UserPoolClient.ClientSecret' --output text 2>/dev/null || true)"
if [[ -z "$CLIENT_SECRET" || "$CLIENT_SECRET" == "None" ]]; then
  echo "error: could not read the app client secret. Check permissions." >&2
  exit 1
fi

# -- runtime endpoint URL ---------------------------------------------------
ENCODED_ARN="$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1], safe=''))" "$RUNTIME_ARN")"
MCP_URL="https://bedrock-agentcore.${REGION}.amazonaws.com/runtimes/${ENCODED_ARN}/invocations?qualifier=DEFAULT"

# -- bearer token -----------------------------------------------------------
TOKEN=""
EXPIRES_IN=""
if [[ "$FETCH_TOKEN" -eq 1 ]]; then
  echo "info: requesting a bearer token (client_credentials)..." >&2
  TOKEN_JSON="$(curl -s -X POST "$TOKEN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    -d "grant_type=client_credentials&scope=${SCOPE}")"
  TOKEN="$(printf '%s' "$TOKEN_JSON" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || true)"
  EXPIRES_IN="$(printf '%s' "$TOKEN_JSON" | python3 -c "import sys,json;print(json.load(sys.stdin).get('expires_in',''))" 2>/dev/null || true)"
  if [[ -z "$TOKEN" ]]; then
    echo "warn: token request failed; emitting Option A with a placeholder instead." >&2
    echo "      Response: $TOKEN_JSON" >&2
  fi
fi

# -- render config via python3 (valid JSON, correct escaping) ---------------
AUTHZ_VALUE="Bearer \${ARIA_MCP_TOKEN}"
if [[ -n "$TOKEN" ]]; then
  AUTHZ_VALUE="Bearer ${TOKEN}"
fi

LAUNCHER="${SCRIPT_DIR}/connect-kiro.sh"

APPROVE='["describe_graph_schema","find_access_paths","who_can_access","get_principal_access","find_unused_access","list_entities","graph_summary"]'

render_option_a() {
  MCP_URL="$MCP_URL" AUTHZ_VALUE="$AUTHZ_VALUE" APPROVE="$APPROVE" python3 - <<'PY'
import json, os
cfg = {"mcpServers": {"aria-gv-remote": {
    "url": os.environ["MCP_URL"],
    "headers": {"Authorization": os.environ["AUTHZ_VALUE"]},
    "disabled": False,
    "autoApprove": json.loads(os.environ["APPROVE"]),
}}}
print(json.dumps(cfg, indent=2))
PY
}

render_option_b() {
  LAUNCHER="$LAUNCHER" TOKEN_ENDPOINT="$TOKEN_ENDPOINT" CLIENT_ID="$CLIENT_ID" \
  USER_POOL_ID="$USER_POOL_ID" \
  RUNTIME_ARN="$RUNTIME_ARN" REGION="$REGION" APPROVE="$APPROVE" python3 - <<'PY'
import json, os
# No client secret is stored. The launcher fetches it at connect time from
# Cognito using ARIA_USER_POOL_ID and the caller's AWS credentials, so nothing
# sensitive is written to mcp.json.
cfg = {"mcpServers": {"aria-gv-remote": {
    "command": os.environ["LAUNCHER"],
    "env": {
        "ARIA_TOKEN_ENDPOINT": os.environ["TOKEN_ENDPOINT"],
        "ARIA_CLIENT_ID": os.environ["CLIENT_ID"],
        "ARIA_USER_POOL_ID": os.environ["USER_POOL_ID"],
        "ARIA_RUNTIME_ARN": os.environ["RUNTIME_ARN"],
        "AWS_REGION": os.environ["REGION"],
    },
    "disabled": False,
    "autoApprove": json.loads(os.environ["APPROVE"]),
}}}
print(json.dumps(cfg, indent=2))
PY
}

# -- output -----------------------------------------------------------------
cat >&2 <<EOF

Resolved from stack '${STACK_NAME}' (${REGION}):
  Runtime ARN     : ${RUNTIME_ARN}
  MCP endpoint URL: ${MCP_URL}
  Token endpoint  : ${TOKEN_ENDPOINT}
  App client id   : ${CLIENT_ID}
  Scope           : ${SCOPE}
EOF
if [[ -n "$TOKEN" ]]; then
  echo "  Token          : obtained (expires in ${EXPIRES_IN}s)" >&2
fi

echo "" >&2
echo "=== Option A: remote entry (bearer token) ===" >&2
if [[ -n "$TOKEN" ]]; then
  echo "(token embedded below; it expires - regenerate with this script, or use Option B)" >&2
else
  echo "(export the token first: export ARIA_MCP_TOKEN=... , then reconnect in Kiro)" >&2
fi
render_option_a

echo "" >&2
echo "=== Option B: auto-refreshing launcher (recommended) ===" >&2
echo "No secret is stored: the launcher fetches it from Cognito at connect time" >&2
echo "using ARIA_USER_POOL_ID and your AWS credentials. Requires valid AWS creds" >&2
echo "and cognito-idp:DescribeUserPoolClient permission when Kiro connects." >&2
render_option_b

if [[ -n "$OUT_FILE" ]]; then
  render_option_b > "$OUT_FILE"
  echo "" >&2
  echo "info: wrote Option B server entry to ${OUT_FILE} (merge it into your mcp.json)" >&2
fi

echo "" >&2
echo "Add the chosen block to .kiro/settings/mcp.json (workspace) or ~/.kiro/settings/mcp.json (global), then reconnect from Kiro's MCP Server view." >&2
