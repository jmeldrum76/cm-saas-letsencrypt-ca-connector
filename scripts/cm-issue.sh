#!/usr/bin/env bash
# Drive a full cert issuance through CM SaaS for the deployed CONNECTOR CA, end-to-end via the
# API. Assumes the connector is registered (plugin) and a CA account exists (see
# register-ca-account.py). Proven 2026-06-18: issues a real LE staging cert via dns-persist-01.
#
# Env: TPPL_KEY (CM API key), AID (CONNECTOR CA account id), ACCT_URI (connector ACME account URI),
#      DOMAIN (cert CN/SAN, under the Route53 zone), ZONE_ID (Route53 hosted zone).
# AWS creds must be exported for the Route53 step (see e2e-staging-run memory for the SSO note).
set -euo pipefail
B=https://api.venafi.cloud
H=(-H "tppl-api-key: ${TPPL_KEY}" -H "Content-Type: application/json")
PN="Let's Encrypt (dns-persist-01)"
WORK="${WORK:-/c/temp}"; mkdir -p "$WORK"; cd "$WORK"

echo "==> 1. Register product option (the UI 'Products' tab call)"
POID=$(curl -s -X POST "$B/v1/certificateauthorities/CONNECTOR/accounts/$AID/productoptions" "${H[@]}" \
  -d "$(jq -nc --arg pn "$PN" '{caProduct:{certificateAuthority:"CONNECTOR",productName:$pn}}')" | jq -r '.id')
echo "    productOptionId=$POID"

echo "==> 2. Create issuing template (both CSR modes allowed; validityPeriod under product)"
jq -nc --arg pn "$PN" --arg poid "$POID" '{name:"LE-dnspersist-90d",certificateAuthority:"CONNECTOR",certificateAuthorityProductOptionId:$poid,product:{certificateAuthority:"CONNECTOR",productName:$pn,validityPeriod:"P90D"},keyTypes:[{keyType:"RSA",keyLengths:[2048,3072,4096]}],keyReuse:false,csrUploadAllowed:true,keyGeneratedByVenafiAllowed:true,subjectCNRegexes:[".*"],subjectORegexes:[".*"],subjectOURegexes:[".*"],subjectLRegexes:[".*"],subjectSTRegexes:[".*"],subjectCValues:[".*"],sanRegexes:[".*"]}' > cit.json
curl -s -X POST "$B/v1/certificateissuingtemplates" "${H[@]}" -d @cit.json >/dev/null
CITID=$(curl -s "$B/v1/certificateissuingtemplates" "${H[@]}" | jq -r '.certificateIssuingTemplates[]|select(.name=="LE-dnspersist-90d")|.id' | head -1)
echo "    templateId=$CITID"

echo "==> 3. Create application holding the template"
TEAM=$(curl -s "$B/v1/teams" "${H[@]}" | jq -r '.teams[0].id')
APPID=$(curl -s -X POST "$B/outagedetection/v1/applications" "${H[@]}" \
  -d "$(jq -nc --arg t "$TEAM" --arg cit "$CITID" '{name:"LE-dnspersist-app",ownerIdsAndTypes:[{ownerId:$t,ownerType:"TEAM"}],certificateIssuingTemplateAliasIdMap:{"LE-dnspersist-90d":$cit}}')" \
  | jq -r '.applications[0].id // .id')
echo "    appId=$APPID"

echo "==> 4. Publish standing _validation-persist record (manual-mode DCV)"
jq -nc --arg n "_validation-persist.$DOMAIN" --arg v "\"letsencrypt.org; accounturi=$ACCT_URI\"" \
  '{Changes:[{Action:"UPSERT",ResourceRecordSet:{Name:$n,Type:"TXT",TTL:60,ResourceRecords:[{Value:$v}]}}]}' > cb.json
CHID=$(aws route53 change-resource-record-sets --hosted-zone-id "$ZONE_ID" --change-batch "file://$(pwd -W 2>/dev/null || pwd)/cb.json" --query ChangeInfo.Id --output text)
aws route53 wait resource-record-sets-changed --id "$CHID"; echo "    record INSYNC"

echo "==> 5. Generate BYO-CSR + request cert through CM"
printf '[req]\ndistinguished_name=dn\nreq_extensions=ext\nprompt=no\n[dn]\nCN=%s\n[ext]\nsubjectAltName=DNS:%s\n' "$DOMAIN" "$DOMAIN" > csr.cnf
openssl req -new -newkey rsa:2048 -nodes -keyout cert.key -out cert.csr -config csr.cnf 2>/dev/null
REQID=$(curl -s -X POST "$B/outagedetection/v1/certificaterequests" "${H[@]}" \
  -d "$(jq -nc --arg app "$APPID" --arg cit "$CITID" --rawfile csr cert.csr '{isVaaSGenerated:false,applicationId:$app,certificateIssuingTemplateId:$cit,validityPeriod:"P90D",reuseCSR:false,certificateSigningRequest:$csr}')" \
  | jq -r '.certificateRequests[0].id // .id')
echo "    requestId=$REQID — polling..."
for i in $(seq 1 30); do sleep 8; ST=$(curl -s "$B/outagedetection/v1/certificaterequests/$REQID" "${H[@]}" | jq -r '.status'); echo "    [$((i*8))s] $ST"; case "$ST" in ISSUED|FAILED|REJECTED) break;; esac; done
CERTID=$(curl -s "$B/outagedetection/v1/certificaterequests/$REQID" "${H[@]}" | jq -r '.certificateIds[0]')
curl -s "$B/outagedetection/v1/certificates/$CERTID/contents?format=PEM" "${H[@]}" -o cm-cert.pem
echo "==> DONE. Issued cert:"; openssl x509 -in cm-cert.pem -noout -subject -issuer -enddate 2>/dev/null
