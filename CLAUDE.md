# cm-saas-letsencrypt-ca-connector

A CyberArk Certificate Manager **SaaS CA Connector** (Venafi CA Connector Framework) that issues
certificates from **Let's Encrypt** using the ACME **`dns-persist-01`** challenge
(`draft-ietf-acme-dns-persist`). Domain control is established by a persistent
`_validation-persist` TXT record validated just-in-time, so issuance collapses to a
**submit-CSR → retrieve-cert** flow and **never depends on DNS access**.

## The non-negotiable invariant
The ACME protocol engine (`internal/acme`) is **DNS-free and publisher-free** — it only ever
*validates* against an already-present standing record. It MUST NOT import `internal/publisher`
or any DNS/cloud SDK. Enforced by: `go list -deps ./internal/acme/... | grep -iE 'aws-sdk-go|/internal/publisher'`
(must be empty). Record *generation* (`internal/record`) is DNS-free and importable anywhere.
Record *publishing* (`internal/publisher`, AWS SDK) is used ONLY from the service layer, ONLY in
auto mode.

## Two DCV modes
- **manual** (default, the differentiator): connector generates the record; the customer
  publishes it on any DNS provider. Connector makes **zero** DNS calls.
- **auto**: connector publishes the standing record **once** (idempotent `EnsureRecord`) via a
  DNS provider (Route 53 first), then issues. Renewals find the record present → JIT validation,
  no further DNS writes.

## Layout
```
cmd/cm-saas-letsencrypt-ca-connector/   entry point + fx wiring (app.go)
internal/handler/web/                   Echo server, 8 CA routes, payload-encryption middleware
internal/app/letsencrypt/               8 webhook handlers + service interfaces
internal/app/service/                   business logic: adapts framework ops onto the ACME engine
internal/acme/                          DNS-free ACME client (jws, account, order, dnspersist, revoke)
internal/record/                        Capability A: generate the _validation-persist record
internal/publisher/ + /route53/         Capability B: auto-mode DNS publishing (AWS SDK lives here only)
test/e2e/                               gated staging+Route53 end-to-end issuance test
manifest.json                           framework manifest (UI + 8 hooks)
```

## Endpoint mapping (ACME ↔ framework)
- testconnection → register/reuse ACME account; logs account URI + standing-record template
- getoptions/validateproduct → single "Let's Encrypt (dns-persist-01)" profile
- requestcertificate → parse CSR (BYO, never regenerate key); auto mode publishes record once;
  newOrder → resolve authz (JIT or accept) → finalize; returns ACME order URL as the request ID
- checkorder / checkcertificate → poll order; download PEM chain → **base64 DER** leaf+chain
- importcertificates → no-op (ACME accounts don't enumerate certs) → empty COMPLETED page
- revokecertificate → ACME revokeCert (needs certificateContent)

## Build / test / run
```
go build ./...                 # compile
go test ./...                  # offline unit tests (record generator, etc.)
make build                     # linux/amd64 vSatellite binary -> output/bin/
go run ./cmd/cm-saas-letsencrypt-ca-connector   # local HTTP server on :8080 (no encryption locally)

# Staging integration (real CA). Needs the AWS SSO creds workaround for Route 53:
P=Venafi-SE-Basic-Access-427380916706
eval "$(aws configure export-credentials --profile "$P" --format env)"; unset AWS_PROFILE; export AWS_REGION=us-east-1
ACME_STAGING=1 go test ./test/e2e/ -run TestEndToEndIssuance -v -timeout 360s
ACME_STAGING=1 go test ./internal/acme/ -run TestStaging -v        # account/order/challenge only
```

## Status
- Phases 1–4 done. **Proven: a real LE staging certificate issued e2e via dns-persist-01**
  (`test/e2e`), with the cert key matching the BYO-CSR. `dns-persist-01` is live on **LE staging**
  now (verified) — default directory targets staging; flip to production when GA (targeted Q2 2026).
- Issuer-domain-names on LE = `letsencrypt.org` (staging + prod).
- TODO: Phase 5 renewal/JIT zero-write test + Pebble offline tier; Phase 6 vSatellite deploy;
  CI dependency-isolation check + manual-mode zero-DNS test; route fx logging through zap;
  manifest conditional UI (`x-rule` to show auto-mode fields only when dcvMode=auto) — validate in
  the Dev Central manifest editor.

## Phase 0 prerequisite (before deploy)
Set `CONTAINER_REGISTRY` and confirm the vSatellite can pull from it before `make push` / Phase 6.

## Test environment
CM SaaS tenant `api.venafi.cloud` (admin `administrator@mimlab.io`); existing native ACME "LE CA"
is the per-issuance dns-01 baseline this connector improves on. Route 53 test zone
`Z07101631Q7ZZTRCPJ6YR` = `jmcmsandbox.mimlab.io`. Tenant API key + IDs are in `.env.local`
(gitignored). See the Claude memory files for details.
