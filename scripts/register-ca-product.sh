#!/usr/bin/env bash
# Register the product option for a Connector CA account so it becomes selectable in CM Issuing
# Templates.
#
# Why this is needed: CM calls the connector's getOptions and CACHES the product on every new CA
# account, but it does NOT auto-promote that to a *registered* product option — which is what the
# Issuing Template's "Certificate Authority" picker requires. CM exposes no UI button for this on
# Connector CAs, so it must be done via one API call. Run this once per CA you create in the UI.
# (Idempotent: it no-ops if the CA already has a product option.)
#
# Usage:
#   TPPL_KEY=<cm-api-key> scripts/register-ca-product.sh "<CA account name>"
#   # optional: PRODUCT_NAME="Let's Encrypt (dns-persist-01)"  VENAFI_CLOUD_BASE=https://api.venafi.cloud
set -euo pipefail

B="${VENAFI_CLOUD_BASE:-https://api.venafi.cloud}"
K="${TPPL_KEY:?set TPPL_KEY to your CM API key}"
NAME="${1:?usage: register-ca-product.sh \"<CA account name>\"}"
PRODUCT="${PRODUCT_NAME:-Let's Encrypt (dns-persist-01)}"
H=(-H "tppl-api-key: $K" -H "Content-Type: application/json")

ACCTS=$(curl -s "$B/v1/certificateauthorities/CONNECTOR/accounts" "${H[@]}")
AID=$(jq -r --arg n "$NAME" '.accounts[] | select(.account.key==$n) | .account.id' <<<"$ACCTS")
if [ -z "$AID" ] || [ "$AID" = "null" ]; then
  echo "CA account '$NAME' not found. Existing Connector CA accounts:" >&2
  jq -r '.accounts[] | "  - " + .account.key' <<<"$ACCTS" >&2
  exit 1
fi

HAVE=$(jq -r --arg n "$NAME" '.accounts[] | select(.account.key==$n) | (.productOptions|length)' <<<"$ACCTS")
if [ "${HAVE:-0}" -gt 0 ]; then
  echo "'$NAME' already has $HAVE product option(s) — already usable in Issuing Templates."
  exit 0
fi

POID=$(curl -s -X POST "$B/v1/certificateauthorities/CONNECTOR/accounts/$AID/productoptions" "${H[@]}" \
  -d "$(jq -nc --arg pn "$PRODUCT" '{caProduct:{certificateAuthority:"CONNECTOR",productName:$pn}}')" \
  | jq -r '.id')
if [ -z "$POID" ] || [ "$POID" = "null" ]; then
  echo "failed to register product option for '$NAME'" >&2
  exit 1
fi
echo "Registered product option $POID for '$NAME'."
echo "It will now appear in the Issuing Template > Certificate Authority picker (refresh the page)."
