#!/usr/bin/env bash
#
# connect-kiro.sh - stdio launcher that bridges Kiro (or any stdio MCP client)
# to the ARIA-gv MCP server hosted on Bedrock AgentCore Runtime, fetching a
# FRESH Cognito bearer token on every launch. This avoids the "token expired,
# reconnect" friction of putting a static token in mcp.json.
#
# How it works: it mints a client-credentials access token, builds the runtime
# endpoint URL, then execs `mcp-remote` (npm) which proxies stdio <-> the remote
# streamable-HTTP endpoint, injecting the Authorization header.
#
# Requirements:
#   - curl, python3
#   - Node.js (the script runs `npx -y mcp-remote`)
#
# Required environment variables (set these in mcp.json "env"):
#   ARIA_TOKEN_ENDPOINT   Cognito token endpoint  (stack output McpCognitoTokenEndpoint)
#   ARIA_CLIENT_ID        Cognito app client id   (stack output McpCognitoAppClientId)
#   ARIA_RUNTIME_ARN      AgentCore runtime ARN   (stack output McpRuntimeArn)
#
# Secret handling (recommended: do NOT store the secret):
#   ARIA_USER_POOL_ID     Cognito user pool id (stack output McpCognitoUserPoolId).
#                         When set, the launcher fetches the app client secret
#                         from Cognito at runtime using your AWS credentials, so
#                         no secret is written to mcp.json. This is preferred.
#   ARIA_CLIENT_SECRET    Optional fallback: the literal app client secret. Only
#                         use when AWS creds are not available at connect time.
# Optional:
#   AWS_REGION            defaults to us-east-1
#   ARIA_MCP_SCOPE        defaults to aria-gv-mcp/invoke
#
# All diagnostics go to stderr so stdout stays a clean MCP channel.

set -euo pipefail

: "${ARIA_TOKEN_ENDPOINT:?set ARIA_TOKEN_ENDPOINT (McpCognitoTokenEndpoint output)}"
: "${ARIA_CLIENT_ID:?set ARIA_CLIENT_ID (McpCognitoAppClientId output)}"
: "${ARIA_RUNTIME_ARN:?set ARIA_RUNTIME_ARN (McpRuntimeArn output)}"

REGION="${AWS_REGION:-us-east-1}"
SCOPE="${ARIA_MCP_SCOPE:-aria-gv-mcp/invoke}"

# Resolve the app client secret. Preferred path: fetch it from Cognito at
# runtime using ARIA_USER_POOL_ID + the caller's AWS credentials, so no secret
# is stored in mcp.json. The default credential chain reads ~/.aws, which a
# GUI-launched process (Kiro) can use. ARIA_CLIENT_SECRET is only a fallback for
# environments without AWS credentials at connect time.
if [[ -z "${ARIA_CLIENT_SECRET:-}" && -n "${ARIA_USER_POOL_ID:-}" ]]; then
  echo "info: fetching app client secret from Cognito pool ${ARIA_USER_POOL_ID} (nothing stored)..." >&2
  ARIA_CLIENT_SECRET="$(aws cognito-idp describe-user-pool-client \
    --user-pool-id "${ARIA_USER_POOL_ID}" --client-id "${ARIA_CLIENT_ID}" \
    --region "${REGION}" --query 'UserPoolClient.ClientSecret' --output text 2>/dev/null || true)"
  [[ "${ARIA_CLIENT_SECRET}" == "None" ]] && ARIA_CLIENT_SECRET=""
  if [[ -z "${ARIA_CLIENT_SECRET:-}" ]]; then
    echo "error: could not fetch the client secret from Cognito." >&2
    echo "       Ensure your AWS credentials are valid (aws sts get-caller-identity)" >&2
    echo "       and allow cognito-idp:DescribeUserPoolClient, and that" >&2
    echo "       ARIA_USER_POOL_ID / ARIA_CLIENT_ID are correct." >&2
    exit 1
  fi
fi

if [[ -z "${ARIA_CLIENT_SECRET:-}" ]]; then
  echo "error: no way to obtain the client secret." >&2
  echo "       Recommended: set ARIA_USER_POOL_ID so the secret is fetched from" >&2
  echo "       Cognito at runtime (needs valid AWS creds; nothing is stored)." >&2
  echo "       Fallback only: set ARIA_CLIENT_SECRET to the literal secret." >&2
  exit 1
fi

echo "info: requesting a fresh Cognito access token..." >&2
TOKEN="$(curl -s -X POST "${ARIA_TOKEN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "${ARIA_CLIENT_ID}:${ARIA_CLIENT_SECRET}" \
  -d "grant_type=client_credentials&scope=${SCOPE}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")"

if [[ -z "${TOKEN}" ]]; then
  echo "error: failed to obtain an access token. Check ARIA_CLIENT_ID/SECRET," >&2
  echo "       ARIA_TOKEN_ENDPOINT, and that the scope '${SCOPE}' is allowed." >&2
  exit 1
fi

ENCODED_ARN="$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1], safe=''))" "${ARIA_RUNTIME_ARN}")"
MCP_URL="https://bedrock-agentcore.${REGION}.amazonaws.com/runtimes/${ENCODED_ARN}/invocations?qualifier=DEFAULT"
echo "info: connecting to ${MCP_URL}" >&2

# Compose the header value first to avoid mcp-remote splitting on the space
# after the colon (it parses --header by the first ':').
AUTH_HEADER="Bearer ${TOKEN}"

exec npx -y mcp-remote "${MCP_URL}" --header "Authorization:${AUTH_HEADER}"
