#!/usr/bin/env python3
"""Probe v4: caAccountConfiguration={certificateAuthority, configuration:{...}} and
credentials={certificateAuthority, accountKey:sealed}. Stops at first 2xx.
Usage: python probe-ca-account.py <API_KEY> <ACCOUNT_KEY_PEM_FILE>
"""
import base64, json, sys, requests
from nacl.public import PublicKey, SealedBox
from nacl.encoding import Base64Encoder

API_KEY, PEM_FILE = sys.argv[1], sys.argv[2]
PLUGIN_ID = "37ec5f37-6b75-11f1-9ea5-20c33ba661e3"
DIR_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
H = {"Content-Type": "application/json", "Accept": "application/json", "tppl-api-key": API_KEY}
B = "https://api.venafi.cloud/"
account_key = open(PEM_FILE).read()

edges = requests.get(B + "v1/edgeinstances", headers=H, timeout=20).json()["edgeInstances"]
edge = next((e for e in edges if e.get("encryptionKeyId")), edges[0])
edge_id, key_id = edge["id"], edge["encryptionKeyId"]
pub = requests.get(B + f"v1/edgeencryptionkeys/{key_id}", headers=H, timeout=15).json()["key"]
def seal(s): return base64.b64encode(SealedBox(PublicKey(pub, encoder=Base64Encoder)).encrypt(s.encode())).decode()

base = {"pluginId": PLUGIN_ID, "key": "LE dns-persist (staging)", "dekId": key_id, "edgeInstanceId": edge_id}
cfg = {"directoryUrl": DIR_URL, "issuerDomain": "letsencrypt.org", "dcvMode": "manual"}
ca = "CONNECTOR"

variants = {
    "A cfg-in-caCfg + creds-typed": {**base,
        "caAccountConfiguration": {"certificateAuthority": ca, "configuration": cfg},
        "credentials": {"certificateAuthority": ca, "accountKey": seal(account_key)}},
    "B config-omitted (defaults)": {**base,
        "caAccountConfiguration": {"certificateAuthority": ca},
        "credentials": {"certificateAuthority": ca, "accountKey": seal(account_key)}},
    "C creds-nested": {**base,
        "caAccountConfiguration": {"certificateAuthority": ca, "configuration": cfg},
        "credentials": {"certificateAuthority": ca, "credentials": {"accountKey": seal(account_key)}}},
    "D caCfg.connection": {**base,
        "caAccountConfiguration": {"certificateAuthority": ca, "connection": {"configuration": cfg}},
        "credentials": {"certificateAuthority": ca, "accountKey": seal(account_key)}},
}

for name, payload in variants.items():
    r = requests.post(B + "v1/certificateauthorities/CONNECTOR/accounts", headers=H, json=payload, timeout=30)
    try:
        msg = r.json().get("errors", [{}])[0].get("message", r.text[:200])
    except Exception:
        msg = r.text[:200]
    print(f"[{r.status_code}] {name}: {msg}")
    if r.status_code in (200, 201):
        j = r.json(); acc = (j.get("accounts") or [j])[0]; acc = acc.get("account", acc)
        print("  >>> SUCCESS  CA_ACCOUNT_ID=" + str(acc.get("id")))
        break
