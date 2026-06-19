#!/usr/bin/env python3
"""Create a CONNECTOR CA account for the Let's Encrypt dns-persist connector.

Mirrors the Oracle machine-registration pattern: the ACME account key (an x-encrypted
credential) must be SEALED with the vSatellite's encryption public key (libsodium SealedBox)
before POSTing — the platform's arguments-decrypter unseals it at runtime. Plaintext credentials
are rejected as unparseable.

Usage: python register-ca-account.py <API_KEY> <ACCOUNT_KEY_PEM_FILE> [DIRECTORY_URL] [PLUGIN_ID]
"""
import base64, json, sys
import requests
from nacl.public import PublicKey, SealedBox
from nacl.encoding import Base64Encoder

API_KEY = sys.argv[1]
PEM_FILE = sys.argv[2]
DIRECTORY_URL = sys.argv[3] if len(sys.argv) > 3 else "https://acme-staging-v02.api.letsencrypt.org/directory"
PLUGIN_ID = sys.argv[4] if len(sys.argv) > 4 else "37ec5f37-6b75-11f1-9ea5-20c33ba661e3"

H = {"Content-Type": "application/json", "Accept": "application/json", "tppl-api-key": API_KEY}
B = "https://api.venafi.cloud/"
account_key = open(PEM_FILE).read()

# 1) Edge instance + its encryption (DEK) public key
edges = requests.get(B + "v1/edgeinstances", headers=H, timeout=20).json()["edgeInstances"]
edge = next((e for e in edges if e.get("encryptionKeyId")), edges[0])
edge_id, key_id = edge["id"], edge["encryptionKeyId"]
pub = requests.get(B + f"v1/edgeencryptionkeys/{key_id}", headers=H, timeout=15).json()["key"]
def seal(s: str) -> str:
    return base64.b64encode(SealedBox(PublicKey(pub, encoder=Base64Encoder)).encrypt(s.encode())).decode()
print(f"edge={edge.get('name')} id={edge_id} dek={key_id[:12]}...")

# 2) Owning team
teams = requests.get(B + "v1/teams", headers=H, timeout=15).json().get("teams", [])
team_id = teams[0]["id"] if teams else None

# 3) Create the CONNECTOR CA account with SEALED credentials.
payload = {
    "pluginId": PLUGIN_ID,
    "key": "LE dns-persist (staging)",
    "dekId": key_id,
    "edgeInstanceId": edge_id,
    # Both caAccountConfiguration and credentials are typed/discriminated (certificateAuthority),
    # the connector config nests under .configuration, the sealed creds under credentials.credentials.
    "caAccountConfiguration": {
        "certificateAuthority": "CONNECTOR",
        "configuration": {
            "directoryUrl": DIRECTORY_URL,
            "issuerDomain": "letsencrypt.org",
            "dcvMode": "manual",
        },
    },
    "credentials": {
        "certificateAuthority": "CONNECTOR",
        "credentials": {"accountKey": seal(account_key)},
    },
}
r = requests.post(B + "v1/certificateauthorities/CONNECTOR/accounts", headers=H, json=payload, timeout=30)
print(f"POST CONNECTOR/accounts -> HTTP {r.status_code}")
print(r.text[:1200])
if r.status_code in (200, 201):
    j = r.json()
    acc = (j.get("accounts") or [j])[0]
    acc = acc.get("account", acc)
    print("\nCA_ACCOUNT_ID=" + str(acc.get("id")))
