#!/usr/bin/env bash
# Register the product option for a Connector CA account so it becomes selectable in CM Issuing
# Templates. In the CM UI this is done in the "New Certificate Authority" wizard at Step 3
# "Issuance" -> Product Options (select the connector's product); that step is optional and easy to
# skip, which leaves the CA out of the Issuing Template picker. This script is the API equivalent for
# automated / API-driven onboarding (it POSTs the same caProduct registration).
# Idempotent: no-ops if the CA already has a product option.
#
# Usage: TPPL_KEY=<cm-api-key> scripts/register-ca-product.sh "<CA account name>"
set -euo pipefail

B="${VENAFI_CLOUD_BASE:-https://api.venafi.cloud}"
K="${TPPL_KEY:?set TPPL_KEY to your CM API key}"
NAME="${1:?provide the CA account name as the first argument}"
PRODUCT="${PRODUCT_NAME:-}"
[ -z "$PRODUCT" ] && PRODUCT="Let's Encrypt (dns-persist-01)"
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
  echo "'$NAME' already has $HAVE product option, already usable in Issuing Templates."
  exit 0
fi

BODY=$(jq -nc --arg pn "$PRODUCT" '{caProduct:{certificateAuthority:"CONNECTOR",productName:$pn}}')
RESP=$(curl -s -X POST "$B/v1/certificateauthorities/CONNECTOR/accounts/$AID/productoptions" "${H[@]}" -d "$BODY")
POID=$(jq -r '.id // empty' <<<"$RESP")
if [ -z "$POID" ]; then
  echo "failed to register product option for '$NAME': $RESP" >&2
  exit 1
fi
echo "Registered product option $POID for '$NAME'. Refresh the Issuing Template page to select it."
