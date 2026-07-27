#!/usr/bin/env bash
# Mint the keypair, JWKS and tokens this demo needs. Requires openssl and
# python3 only.
#
# Deliberately self-contained rather than borrowing demo 02's keys: a demo that
# only runs after another demo has been run is a demo that does not run.
#
# Replay detection keys on the jti claim, so this mints several tokens for the
# same subject differing only in jti, plus one with no jti at all.
set -euo pipefail
cd "$(dirname "$0")"

out=".generated"
mkdir -p "$out"

openssl genrsa -out "$out/test-key.pem" 2048 2>/dev/null

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
with open(sys.argv[1], "w") as f:
    json.dump({"keys": [{
        "kty": "RSA", "kid": "test-key-1", "use": "sig", "alg": "RS256",
        "n": base64.urlsafe_b64encode(n).rstrip(b"=").decode(), "e": "AQAB",
    }]}, f, indent=2)
PY

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

now=$(date +%s)
exp=$((now + 3600))

# mint <subject> <jti-or-empty> <output-file>
mint() {
  local sub="$1" jti="$2" output="$3"
  local claims="\"sub\":\"$sub\",\"iss\":\"nullfield-test\",\"aud\":\"nullfield\",\"iat\":$now,\"exp\":$exp"
  [[ -n "$jti" ]] && claims="$claims,\"jti\":\"$jti\""

  local header='{"alg":"RS256","typ":"JWT","kid":"test-key-1"}'
  local unsigned
  unsigned="$(printf '%s' "$header" | b64url).$(printf '{%s}' "$claims" | b64url)"
  local sig
  sig="$(printf '%s' "$unsigned" | openssl dgst -sha256 -sign "$out/test-key.pem" -binary | b64url)"
  printf '%s.%s' "$unsigned" "$sig" > "$out/$output"
}

# Two principals, for session binding.
mint "alice@example.com" "alice-1" alice-1.txt
mint "alice@example.com" "alice-2" alice-2.txt
mint "alice@example.com" "alice-3" alice-3.txt
mint "mallory@example.com" "mallory-1" mallory-1.txt

# Same subject, no jti. Replay detection has nothing to key on and skips it.
mint "alice@example.com" "" alice-no-jti.txt

# A burst for the velocity assertion, each with its own jti so replay detection
# does not refuse them first.
for i in $(seq 1 12); do
  mint "burst@example.com" "burst-$i" "burst-$i.txt"
done

echo "wrote $out/: jwks.json and 17 tokens (valid for 1 hour)"
