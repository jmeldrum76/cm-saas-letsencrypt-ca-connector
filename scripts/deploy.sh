#!/usr/bin/env bash
# Build the connector image with ko (no Docker daemon) and push it to AWS ECR, then generate the
# CM SaaS deployment manifest. Does NOT register the connector in the tenant — review the image
# and confirm the vSatellite can pull from ECR first (see DEPLOY.md prerequisite #1).
#
# Usage:
#   AWS_PROFILE=Venafi-SE-Basic-Access-427380916706 AWS_REGION=us-east-1 scripts/deploy.sh
# (Or export temp creds first; see the e2e-staging-run memory for the SSO workaround.)
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
REPO="${ECR_REPO:-cm-saas-letsencrypt-ca-connector}"

cd "$(dirname "$0")/.."

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
echo ">> account=${ACCOUNT} region=${REGION} repo=${REPO}"

echo ">> ensuring ECR repository exists"
aws ecr create-repository --repository-name "$REPO" --region "$REGION" >/dev/null 2>&1 || true

echo ">> logging ko into ECR"
aws ecr get-login-password --region "$REGION" | ko login "$REGISTRY" --username AWS --password-stdin

echo ">> building + pushing image with ko (linux/amd64)"
export KO_DOCKER_REPO="${REGISTRY}/${REPO}"
export KO_DEFAULTBASEIMAGE="${KO_DEFAULTBASEIMAGE:-cgr.dev/chainguard/static:latest}"
IMAGE="$(ko build --bare --platform=linux/amd64 ./cmd/cm-saas-letsencrypt-ca-connector)"
echo ">> pushed: ${IMAGE}"

echo ">> generating manifest.create.json"
PLUGIN_TYPE="$(jq -r .pluginType manifest.json)"
jq --arg img "$IMAGE" '.deployment.image = $img | .deployment.executionTarget = "vsat"' manifest.json > manifest_with_image.json
jq '{manifest: .}' manifest_with_image.json > manifest.update.json
jq --arg pt "$PLUGIN_TYPE" '.pluginType = $pt' manifest.update.json > manifest.create.json

echo ">> done. Image: ${IMAGE}"
echo ">> Next (manual): confirm the vSatellite can pull ${IMAGE}, then register manifest.create.json"
echo "   in CM SaaS (Integrations → Certificate Authorities) and configure a CA account (see DEPLOY.md)."
