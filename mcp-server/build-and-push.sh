#!/usr/bin/env bash
#
# build-and-push.sh - build the ARIA-gv MCP server as an ARM64 image and push it
# to Amazon ECR, ready to be referenced by the AgentCore Runtime CloudFormation
# stack (templates/agentcore-mcp.yaml).
#
# The ECR repository is created if it does not already exist, so this can run
# before any CloudFormation is deployed. On success it prints the full image
# URI to pass as the ContainerImageUri parameter.
#
# Usage:
#   ./build-and-push.sh [-r region] [-n repo-name] [-t tag]
#
# Defaults: region = AWS_REGION or the CLI default; repo = aria-gv-mcp; tag = latest.
#
# Requirements: docker (with buildx) and the AWS CLI, with credentials that can
# create/push to ECR.

set -euo pipefail

REPO_NAME="aria-gv-mcp"
TAG="latest"
REGION="${AWS_REGION:-$(aws configure get region 2>/dev/null || true)}"

while getopts "r:n:t:h" opt; do
  case "$opt" in
    r) REGION="$OPTARG" ;;
    n) REPO_NAME="$OPTARG" ;;
    t) TAG="$OPTARG" ;;
    h)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "invalid option" >&2; exit 64 ;;
  esac
done

if [[ -z "${REGION}" ]]; then
  echo "error: no region. Pass -r <region> or set AWS_REGION." >&2
  exit 64
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
REGISTRY="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
IMAGE_URI="${REGISTRY}/${REPO_NAME}:${TAG}"

echo "info: region=${REGION} account=${ACCOUNT_ID} repo=${REPO_NAME} tag=${TAG}" >&2

# 1. Ensure the ECR repository exists (idempotent).
if ! aws ecr describe-repositories --region "${REGION}" \
      --repository-names "${REPO_NAME}" >/dev/null 2>&1; then
  echo "info: creating ECR repository ${REPO_NAME}" >&2
  aws ecr create-repository \
    --region "${REGION}" \
    --repository-name "${REPO_NAME}" \
    --image-scanning-configuration scanOnPush=true \
    --image-tag-mutability MUTABLE >/dev/null
fi

# 2. Preflight: a container engine must be installed and its daemon reachable.
if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker CLI not found on PATH." >&2
  echo "       Install a container engine with a running daemon, e.g. Docker" >&2
  echo "       Desktop, Colima ('brew install colima && colima start'), or" >&2
  echo "       Rancher Desktop. A CLI-only 'brew install docker' is not enough." >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "error: cannot connect to the Docker daemon." >&2
  echo "       Start your container engine first (e.g. open Docker Desktop, or" >&2
  echo "       run 'colima start'), then re-run this script." >&2
  exit 1
fi

# 3. Log in to ECR.
aws ecr get-login-password --region "${REGION}" \
  | docker login --username AWS --password-stdin "${REGISTRY}" >/dev/null

# 4. Build for ARM64 (required by AgentCore) and push.
#    Prefer buildx (works cross-arch, pushes in one step). Fall back to the
#    classic builder + a separate push when buildx is not installed - fine on an
#    arm64 host (e.g. Apple Silicon), where linux/arm64 is the native platform.
# Docker build/push output is sent to stderr (1>&2) so that stdout carries only
# the final image URI - this keeps `IMAGE_URI=$(./build-and-push.sh ...)` clean.
if docker buildx version >/dev/null 2>&1; then
  echo "info: building with buildx (--platform linux/arm64)" >&2
  docker buildx build \
    --platform linux/arm64 \
    --tag "${IMAGE_URI}" \
    --push \
    "${SCRIPT_DIR}" 1>&2
else
  HOST_ARCH="$(uname -m)"
  if [[ "${HOST_ARCH}" != "arm64" && "${HOST_ARCH}" != "aarch64" ]]; then
    echo "error: docker buildx is not installed and this host is ${HOST_ARCH}, not arm64." >&2
    echo "       Cross-building a linux/arm64 image reliably needs buildx." >&2
    echo "       Install it (Docker Desktop includes it, or 'brew install docker-buildx')" >&2
    echo "       and re-run, or build on an arm64 host." >&2
    exit 1
  fi
  echo "info: buildx not found; building natively for linux/arm64 with the classic builder" >&2
  docker build --platform linux/arm64 --tag "${IMAGE_URI}" "${SCRIPT_DIR}" 1>&2
  docker push "${IMAGE_URI}" 1>&2
fi
echo >&2
echo "Pushed: ${IMAGE_URI}" >&2
echo >&2
echo "Pass this as the ContainerImageUri parameter:" >&2
# The image URI is the only thing printed on stdout, for easy capture in scripts.
echo "${IMAGE_URI}"
