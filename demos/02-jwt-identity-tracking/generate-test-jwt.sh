#!/usr/bin/env bash
# Generate test RSA keypair, JWKS, and signed JWTs for nullfield identity demos.
# Usage: bash generate-test-jwt.sh
#
# Produces:
#   test-key.pem           RSA 2048 private key
#   test-key-pub.pem       RSA public key
#   jwks.json              JWKS file serving the public key
#   human-token.txt        JWT: identity_type=human, groups=[mcp-writers]
#   agent-token.txt        JWT: identity_type=agent
#   autonomous-token.txt   JWT: identity_type=autonomous

set -euo pipefail
cd "$(dirname "$0")"

echo "Generating RSA 2048 keypair..."
openssl genrsa -out test-key.pem 2048 2>/dev/null
openssl rsa -in test-key.pem -pubout -out test-key-pub.pem 2>/dev/null

echo "Building JWKS..."
python3 - <<'PYSCRIPT'
import json, base64, struct
from cryptography.hazmat.primitives.serialization import load_pem_public_key

with open("test-key-pub.pem", "rb") as f:
    pub = load_pem_public_key(f.read())

numbers = pub.public_numbers()

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")

jwks = {
    "keys": [{
        "kty": "RSA",
        "kid": "test-key-1",
        "use": "sig",
        "alg": "RS256",
        "n": b64url(n_bytes),
        "e": b64url(e_bytes),
    }]
}

with open("jwks.json", "w") as f:
    json.dump(jwks, f, indent=2)
print("  wrote jwks.json")
PYSCRIPT

sign_jwt() {
  local payload="$1" output="$2"

  local header='{"alg":"RS256","typ":"JWT","kid":"test-key-1"}'
  local h_b64=$(echo -n "$header" | base64 | tr '+/' '-_' | tr -d '=\n')
  local p_b64=$(echo -n "$payload" | base64 | tr '+/' '-_' | tr -d '=\n')
  local unsigned="${h_b64}.${p_b64}"
  local sig=$(echo -n "$unsigned" | openssl dgst -sha256 -sign test-key.pem | base64 | tr '+/' '-_' | tr -d '=\n')

  echo "${unsigned}.${sig}" > "$output"
}

NOW=$(date +%s)
EXP=$((NOW + 3600))

echo "Generating tokens..."

sign_jwt "{\"sub\":\"alice@example.com\",\"iss\":\"nullfield-test\",\"aud\":\"nullfield\",\"iat\":$NOW,\"exp\":$EXP,\"identity_type\":\"human\",\"groups\":[\"mcp-writers\",\"developers\"],\"scope\":\"openid profile\",\"jti\":\"human-$(date +%s)\"}" \
  "human-token.txt"
echo "  wrote human-token.txt (identity_type=human, groups=[mcp-writers])"

sign_jwt "{\"sub\":\"ops-agent-svc\",\"iss\":\"nullfield-test\",\"aud\":\"nullfield\",\"iat\":$NOW,\"exp\":$EXP,\"identity_type\":\"agent\",\"scope\":\"read\",\"jti\":\"agent-$(date +%s)\"}" \
  "agent-token.txt"
echo "  wrote agent-token.txt (identity_type=agent)"

sign_jwt "{\"sub\":\"cron-scheduler\",\"iss\":\"nullfield-test\",\"aud\":\"nullfield\",\"iat\":$NOW,\"exp\":$EXP,\"identity_type\":\"autonomous\",\"jti\":\"auto-$(date +%s)\"}" \
  "autonomous-token.txt"
echo "  wrote autonomous-token.txt (identity_type=autonomous)"

echo ""
echo "Done. Serve JWKS with: python3 -m http.server 8888"
echo "Tokens expire in 1 hour."
