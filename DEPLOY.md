# Deploying to CyberArk Certificate Manager SaaS (vSatellite)

This connector runs as a container on a **vSatellite** in your CM SaaS tenant. Deployment is:
build image → push to a registry the vSatellite can pull from → generate the deployment manifest
→ register the connector in CM SaaS → configure a CA account → issue.

## ⚠️ Prerequisite #1 (the #1 cause of deploy failures): registry pull access
The vSatellite must be able to **pull** the connector image. Confirm this BEFORE anything else:
- Pick a registry the vSatellite can reach: Docker Hub, GHCR, or **AWS ECR** (the tenant already
  uses AWS account `427380916706`; the vSatellite may already have ECR pull access).
- On the vSatellite host: `sudo crictl pull <registry>/<image>:<tag>` must succeed.

If the vSatellite can't pull, fix that first — a registered connector with an unpullable image
just fails `testConnection` in CM with no useful error.

## Customer distribution (recommended: GitHub + GHCR)
For customers to run this connector they need two things: the **container image** and the
**manifest.json**. The simplest model:
- **Image:** published automatically to **`ghcr.io/<owner>/cm-saas-letsencrypt-ca-connector`** by
  the `publish-image` GitHub Actions workflow (`.github/workflows/publish-image.yml`) on every
  push to `main` and on `v*` tags. **Make the GHCR package PUBLIC once** (repo/org → Packages →
  package settings → change visibility) so any customer's vSatellite can pull it with **no
  credentials**.
- **Manifest:** the customer registers `manifest.json` (with `deployment.image` set to the public
  GHCR image) in their own CM SaaS tenant and configures a CA account.

So a customer's flow is just: register the manifest → set Directory URL + ACME account key + DCV
mode → issue. No image build on their side. The sections below cover building/pushing yourself
(e.g. to a private registry) if you don't use the GHCR workflow.

## 1. Build + push the image

### Option A — Docker (the framework default; needs Docker/buildx)
```bash
export CONTAINER_REGISTRY=<your-registry>     # e.g. 427380916706.dkr.ecr.us-east-1.amazonaws.com
make push                                     # build linux/amd64 + push
make manifests                                # writes manifest.create.json (image + executionTarget=vsat)
```

### Option B — ko (no Docker daemon; what this environment supports)
Verified: `ko` builds the linux/amd64 image here (digest `sha256:f60248b1…`). To push to ECR:
```bash
REGION=us-east-1
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REPO=cm-saas-letsencrypt-ca-connector
aws ecr create-repository --repository-name "$REPO" --region "$REGION" 2>/dev/null || true
aws ecr get-login-password --region "$REGION" \
  | ko login "$ACCOUNT.dkr.ecr.$REGION.amazonaws.com" --username AWS --password-stdin
export KO_DOCKER_REPO="$ACCOUNT.dkr.ecr.$REGION.amazonaws.com/$REPO"
IMAGE=$(ko build --bare --platform=linux/amd64 ./cmd/cm-saas-letsencrypt-ca-connector)   # pushes; prints image@digest
# Generate the deployment manifest by hand (make manifests needs Docker):
jq --arg img "$IMAGE" '.deployment.image=$img | .deployment.executionTarget="vsat"' manifest.json > manifest_with_image.json
jq '{manifest: .}' manifest_with_image.json > manifest.update.json
jq --arg pt "$(jq -r .pluginType manifest.json)" '.pluginType=$pt' manifest.update.json > manifest.create.json
```
`scripts/deploy.sh` automates Option B end to end (set `AWS_PROFILE`/`AWS_REGION` first; see the
SSO creds note in the Claude memory `e2e-staging-run`).

> ko builds only the Go binary into a distroless base. The running connector does NOT read
> manifest.json (it's platform metadata uploaded to CM separately), so a ko image is functional.
> For a byte-for-byte match with `build/Dockerfile` (which also COPYs manifest.json), use Option A.

## 2. Register the connector in CM SaaS
- **UI:** Integrations → Certificate Authorities → add a connector, upload `manifest.create.json`.
- **API:** `POST` the manifest to the tenant connectors endpoint with header `tppl-api-key: <key>`
  (base `https://api.venafi.cloud`). The tenant + key are in `.env.local` (gitignored).

## 3. Configure a CA account (the connector's connection)
Fill the manifest-driven fields:
- **ACME Directory URL** = `https://acme-staging-v02.api.letsencrypt.org/directory` (staging; flip to
  production when dns-persist-01 is GA there).
- **Issuer Domain** = `letsencrypt.org`.
- **ACME Account Key** = a PEM ECDSA P-256 key (generate: `openssl ecparam -genkey -name prime256v1 -noout`).
- **DCV Mode** = `manual` (customer publishes the record — zero DNS access) or `auto` (Route 53).
  For `auto`, also set Hosted Zone ID + AWS Access Key/Secret.

Run **Test Connection** → it registers/reuses the ACME account and logs the account URI + the
standing `_validation-persist` record template (visible in the vSatellite container logs).

## 4. Issue
Create an issuing template using this CA + the "Let's Encrypt (dns-persist-01)" product, then
request a certificate for a domain whose `_validation-persist` record is published (or let auto
mode publish it). For the Route 53 test zone, use a name under `jmcmsandbox.mimlab.io`.

## Repo → org transfer (when the org exists)
The repo is currently `jmeldrum76/cm-saas-letsencrypt-ca-connector` (private). After you create the
`cmsaas-connectors` org:
```bash
gh api -X POST repos/jmeldrum76/cm-saas-letsencrypt-ca-connector/transfer -f new_owner=cmsaas-connectors
```
The Go module path already uses `github.com/cmsaas-connectors/...`, so no code change is needed.
