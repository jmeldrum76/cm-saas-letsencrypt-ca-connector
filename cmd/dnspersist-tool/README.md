# dnspersist — Let's Encrypt dns-persist-01 onboarding utility

Manual-path companion to the CA connector. It generates/loads a per-customer ACME account, emits
the standing `_validation-persist` records to hand a customer, validates those records are live, and
turns an existing certificate's SANs into a minimal record plan. It imports the connector's own
`internal/record` and `internal/acme`, so its output is exactly what the connector validates and
issues against.

> Not needed for **AWS Route 53 (auto)** mode — there the connector publishes records itself.
> This tool is for the **Manual** path: you generate the account + records, the customer publishes,
> the connector's Test Connection gate confirms.

## CLI

```
dnspersist new-account [-out key.pem] [-contact mailto:you@ex.com] [-prod]
dnspersist records     -key key.pem -domains a.com,b.com [-wildcard] [-prod]
dnspersist add-domains -key key.pem -domains c.com        [-wildcard] [-prod]   # alias of records
dnspersist validate    -key key.pem -domains a.com,b.com [-prod]
dnspersist plan        -cert leaf.pem -key key.pem [-validate] [-prod]
dnspersist serve       [-addr 127.0.0.1:8088]
```

`-prod` targets Let's Encrypt production; default is staging.

Typical lifecycle:
1. `new-account` (or `plan -cert` from the customer's current cert) → account key + URI.
2. `records` → send the customer the TXT records to publish.
3. Customer publishes them in their DNS.
4. `validate` (or the connector's Test Connection) → confirm all live.
5. In CM: paste the **PEM** + the domain list → green → issue. Growth: `add-domains` → re-validate.

## Web UI

```
dnspersist serve            # http://127.0.0.1:8088
```

Same four operations in a browser. Build a single static binary and drop it on a host:

```
go build -o dnspersist ./cmd/dnspersist-tool
./dnspersist serve -addr 127.0.0.1:8088
```

### Security
- Account **private keys are generated/used in memory per request and never written server-side**;
  `new-account` returns the PEM to the browser for the operator to save.
- The server **binds to `127.0.0.1` by default**. If you expose it (e.g. an internal AWS host),
  put it behind **TLS and authentication** — it mints account keys.
- Back up account keys: regenerating a key starts a new ACME account (new URI) and orphans every
  record already published under the old one.
