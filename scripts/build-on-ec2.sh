#!/bin/bash
# Runs ON the build EC2 (Amazon Linux 2023) via SSM. Clones this connector's PUBLIC repo,
# builds the linux/amd64 image with buildx (--provenance=false, required for vSat pulls), and
# pushes it to a SEPARATE ECR Public repo (distinct from any other connector). Prints the image
# referenced by its canonical manifest digest.
#
# ECR Public's API is us-east-1 only; the image is global under the namespace.
set -euxo pipefail

REGISTRY="public.ecr.aws/v3y9q2u6"
IMAGE_NAME="tls-protect-letsencrypt-dnspersist"
REPO_URL="https://github.com/jmeldrum76/cm-saas-letsencrypt-ca-connector"
ECR_REGION="us-east-1"

# 1) Toolchain (idempotent)
dnf -y install docker golang make jq git tar gzip >/dev/null 2>&1 || true
systemctl enable --now docker >/dev/null 2>&1 || true
docker buildx version >/dev/null 2>&1 || dnf -y install docker-buildx-plugin >/dev/null 2>&1 || true

# 2) Fresh source from the public repo
mkdir -p /opt/build && cd /opt/build
rm -rf cm-saas-letsencrypt-ca-connector
git clone --depth 1 "$REPO_URL"
cd cm-saas-letsencrypt-ca-connector

# 3) ECR Public login (us-east-1 only)
aws ecr-public get-login-password --region "$ECR_REGION" \
  | docker login --username AWS --password-stdin public.ecr.aws

# 4) Create the SEPARATE repo if absent
aws ecr-public create-repository --region "$ECR_REGION" --repository-name "$IMAGE_NAME" \
  --catalog-data 'description=Venafi CA connector for Lets Encrypt via ACME dns-persist-01 (persistent DNS validation)' \
  2>&1 | head -5 || true

# 5) Build + push (buildx --provenance=false comes from the Makefile).
#    SSM RunShellScript has no HOME/GOPATH; set Go env so `go mod download` works.
export HOME=/root GOPATH=/root/go GOMODCACHE=/root/go/pkg/mod GOCACHE=/root/.cache/go-build
make push CONTAINER_REGISTRY="$REGISTRY" IMAGE_NAME="$IMAGE_NAME"

# 6) Resolve the canonical MANIFEST digest (buildx's containerimage.digest can be the config
#    digest, which breaks vSat pulls — inspect the pushed tag instead).
MANIFEST_DIGEST=$(docker buildx imagetools inspect "${REGISTRY}/${IMAGE_NAME}:latest" | awk '/^Digest:/ {print $2; exit}')
[[ "$MANIFEST_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "ERROR: no manifest digest" >&2; exit 1; }

echo "IMAGE_BY_DIGEST=${REGISTRY}/${IMAGE_NAME}@${MANIFEST_DIGEST}"
