#!/usr/bin/env bash
# Generate a throwaway RSA keypair, a JWKS document, and signed JWTs for the
# identity demos. Requires openssl and python3 -- no pip packages.
#
# Everything lands in .generated/, which is gitignored. Nothing here is a real
# key and nothing here should outlive the demo: the keypair is regenerated on
# every run and the tokens expire in an hour.
#
# The earlier version needed the `cryptography` package to turn the public key
# into a JWK. openssl already prints the modulus, and the exponent is checked
# rather than assumed, so the dependency is gone and this runs in CI.
set -euo pipefail
cd "$(dirname "$0")"

out=".generated"
mkdir -p "$out"

openssl genrsa -out "$out/test-key.pem" 2048 2>/dev/null

# A second key that is never published in the JWKS, used to sign a token that
# should be rejected. Without it "the signature is checked" is unprovable.
openssl genrsa -out "$out/wrong-key.pem" 2048 2>/dev/null

exponent="$(openssl rsa -in "$out/test-key.pem" -noout -text 2>/dev/null \
  | sed -n 's/.*publicExponent: \([0-9]*\).*/\1/p')"
if [[ "$exponent" != "65537" ]]; then
  echo "unexpected public exponent $exponent; this script assumes 65537 (AQAB)" >&2
  exit 1
fi

modulus="$(openssl rsa -in "$out/test-key.pem" -noout -modulus 2>/dev/null | sed 's/^Modulus=//')"

MODULUS_HEX="$modulus" python3 - "$out/jwks.json" <<'PY'
import base64, json, os, sys

n = bytes.fromhex(os.environ["MODULUS_HEX"])
jwk = {
    "keys": [{
        "kty": "RSA",
        "kid": "test-key-1",
        "use": "sig",
        "alg": "RS256",
        "n": base64.urlsafe_b64encode(n).rstrip(b"=").decode(),
        "e": "AQAB",
    }]
}
with open(sys.argv[1], "w") as f:
    json.dump(jwk, f, indent=2)
PY

# base64url without padding, which is what JWT uses and `base64` does not do.
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

sign_jwt() {
  local payload="$1" output="$2" key="${3:-$out/test-key.pem}" kid="${4:-test-key-1}"
  local header="{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"$kid\"}"
  local unsigned
  unsigned="$(printf '%s' "$header" | b64url).$(printf '%s' "$payload" | b64url)"
  local sig
  sig="$(printf '%s' "$unsigned" | openssl dgst -sha256 -sign "$key" -binary | b64url)"
  printf '%s.%s' "$unsigned" "$sig" > "$out/$output"
}

now=$(date +%s)
exp=$((now + 3600))
past=$((now - 7200))

sign_jwt "{\"sub\":\"alice@example.com\",\"iss\":\"nullfield-test\",\"aud\":\"nullfield\",\"iat\":$now,\"exp\":$exp,\"identity_type\":\"human\",\"groups\":[\"mcp-writers\",\"developers\"]}" \
  human-token.txt

sign_jwt "{\"sub\":\"ops-agent-svc\",\"iss\":\"nullfield-test\",\"aud\":\"nullfield\",\"iat\":$now,\"exp\":$exp,\"identity_type\":\"agent\"}" \
  agent-token.txt

sign_jwt "{\"sub\":\"cron-scheduler\",\"iss\":\"nullfield-test\",\"aud\":\"nullfield\",\"iat\":$now,\"exp\":$exp,\"identity_type\":\"autonomous\"}" \
  autonomous-token.txt

# Four tokens that must be refused, one per reason.
sign_jwt "{\"sub\":\"alice@example.com\",\"iss\":\"nullfield-test\",\"aud\":\"nullfield\",\"iat\":$past,\"exp\":$((past + 60)),\"identity_type\":\"human\",\"groups\":[\"mcp-writers\"]}" \
  expired-token.txt

sign_jwt "{\"sub\":\"alice@example.com\",\"iss\":\"some-other-idp\",\"aud\":\"nullfield\",\"iat\":$now,\"exp\":$exp,\"identity_type\":\"human\",\"groups\":[\"mcp-writers\"]}" \
  wrong-issuer-token.txt

sign_jwt "{\"sub\":\"alice@example.com\",\"iss\":\"nullfield-test\",\"aud\":\"someone-else\",\"iat\":$now,\"exp\":$exp,\"identity_type\":\"human\",\"groups\":[\"mcp-writers\"]}" \
  wrong-audience-token.txt

# Correct claims, correct kid, signed by a key the JWKS has never heard of.
sign_jwt "{\"sub\":\"alice@example.com\",\"iss\":\"nullfield-test\",\"aud\":\"nullfield\",\"iat\":$now,\"exp\":$exp,\"identity_type\":\"human\",\"groups\":[\"mcp-writers\"]}" \
  forged-token.txt "$out/wrong-key.pem"

echo "wrote $out/: jwks.json and 7 tokens (valid for 1 hour)"
