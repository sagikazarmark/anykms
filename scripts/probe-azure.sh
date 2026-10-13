#!/usr/bin/env bash
# Probes the Azure Key Vault (and, with --mhsm, Managed HSM) behavior anykms-azure depends on
# and prints normalized output: versions, key ids, signatures, ciphertexts, request ids, tenant
# and object ids, client IPs and the per-run key prefix are masked, so runs against the same
# service diff cleanly against a committed baseline (tasks T3 and T13 of docs/cloud/azure.md).
#
# Usage:
#   scripts/probe-azure.sh [run] VAULT_URL [--mhsm]          print the normalized output
#   scripts/probe-azure.sh record VAULT_URL [--mhsm] [NAME]  write scripts/probe-baseline-azure/NAME.txt
#                                                            (default NAME: vault or mhsm)
#   scripts/probe-azure.sh diff VAULT_URL [--mhsm] [NAME]    diff against that baseline; exits 1
#                                                            when the behavior differs
#
# VAULT_URL is https://<vault>.vault.azure.net (or https://<pool>.managedhsm.azure.net with
# --mhsm). The caller (see TOKEN below: a token, an app secret or `az login`) needs Key Vault
# Crypto Officer (Managed HSM: Crypto
# Officer and Crypto User, local RBAC) on it: the probe creates keys named probe-<time>-<pid>-*,
# and deletes (and, where allowed, purges) them on exit. Needs az, curl, jq and openssl.
#
# What it pins (each block prints status, error code chain and the message):
#   - versionless operations (POST /keys/<name>/sign without a version);
#   - ECDSA signature size (raw r||s), RSA signature size, verify true/false/malformed;
#   - missing key, missing version (GET, sign, verify, unwrap);
#   - disabled key and version, not-yet-valid (nbf) and expired (exp) keys, for get, sign,
#     verify, wrapkey and unwrapkey;
#   - key_ops that exclude the operation; algorithm/key mismatches (RS256 on EC, A256KW on RSA);
#   - RSA-OAEP-256 input limit, a damaged wrapped key;
#   - the 401 challenge (no token), Retry-After on 429 when one happens;
#   - Managed HSM: A256GCM iv/tag sizes, plaintext limits, AAD, a damaged tag; A256KW; HS256 on an
#     imported HMAC key compared with a local HMAC of the message and of its SHA-256 (azure.md Q4).
set -euo pipefail

BASELINE_DIR="$(cd "$(dirname "$0")" && pwd)/probe-baseline-azure"

usage() {
  sed -n '7,13p' "$0" >&2
  exit 2
}

mode=run
case "${1:-}" in
  run | record | diff) mode=$1; shift ;;
  "" | -h | --help) usage ;;
esac
[ $# -ge 1 ] || usage
URL=${1%/}
shift
MHSM=0
if [ "${1:-}" = "--mhsm" ]; then
  MHSM=1
  shift
fi
NAME=${1:-$([ "$MHSM" = 1 ] && echo mhsm || echo vault)}

for tool in curl jq openssl; do
  command -v "$tool" >/dev/null || { echo "probe-azure: $tool is required" >&2; exit 2; }
done

HOST=${URL#https://}
SUFFIX=${HOST#*.}
RESOURCE="https://$SUFFIX"
API="api-version=2025-07-01"
PREFIX="probe-$(date +%s)-$$"
# The token: ANYKMS_AZURE_TOKEN, else a client-credentials grant for AZURE_TENANT_ID,
# AZURE_CLIENT_ID and AZURE_CLIENT_SECRET (no az login needed), else `az account get-access-token`.
if [ -n "${ANYKMS_AZURE_TOKEN:-}" ]; then
  TOKEN=$ANYKMS_AZURE_TOKEN
elif [ -n "${AZURE_CLIENT_SECRET:-}" ]; then
  TOKEN=$(curl -sS "https://login.microsoftonline.com/$AZURE_TENANT_ID/oauth2/v2.0/token" \
    -d grant_type=client_credentials --data-urlencode "client_id=$AZURE_CLIENT_ID" \
    --data-urlencode "client_secret=$AZURE_CLIENT_SECRET" \
    --data-urlencode "scope=$RESOURCE/.default" | jq -er .access_token)
else
  TOKEN=$(az account get-access-token --resource "$RESOURCE" --query accessToken -o tsv)
fi
TMP=$(mktemp -d)
CREATED=()

cleanup() {
  for k in "${CREATED[@]}"; do
    curl -sS -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" "$URL/keys/$k?$API" || true
    curl -sS -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" "$URL/deletedkeys/$k?$API" || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

b64u() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
unb64u() {
  local s
  s=$(tr -- '-_' '+/')
  while [ $((${#s} % 4)) -ne 0 ]; do s="$s="; done
  printf '%s' "$s" | openssl base64 -d -A
}

# req METHOD PATH [JSON] [--no-auth]: prints "<status> <headers file> <body file>".
n=0
req() {
  n=$((n + 1))
  local auth=(-H "Authorization: Bearer $TOKEN")
  [ "${4:-}" = "--no-auth" ] && auth=()
  local args=(-sS -o "$TMP/b$n" -D "$TMP/h$n" -w '%{http_code}' -X "$1" "${auth[@]}"
    -H 'Content-Type: application/json' "$URL/$2?$API")
  [ -n "${3:-}" ] && args+=(--data-binary "$3")
  local status
  status=$(curl "${args[@]}")
  echo "$status $TMP/h$n $TMP/b$n"
}

# Masks values that differ between runs or identify the caller.
normalize() {
  sed -E \
    -e "s/$PREFIX/PREFIX/g" \
    -e 's/[0-9a-f]{32}/<version>/g' \
    -e 's/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/<uuid>/g' \
    -e 's/([0-9]{1,3}\.){3}[0-9]{1,3}/<ip>/g' \
    -e "s#$HOST#<host>#g"
}

# show LABEL METHOD PATH [JSON] [--no-auth]: status, error codes and message.
show() {
  local label=$1
  shift
  read -r status h b < <(req "$@")
  local codes msg
  codes=$(jq -r '[.error | recurse(.innererror // empty) | .code // empty] | join("/")' "$b" 2>/dev/null || true)
  msg=$(jq -r '.error.message // empty' "$b" 2>/dev/null || true)
  local extra=""
  grep -qi '^retry-after:' "$h" && extra=" retry-after=$(grep -i '^retry-after:' "$h" | cut -d' ' -f2 | tr -d '\r')"
  if [ "$status" = 401 ]; then
    extra="$extra challenge=$(grep -i '^www-authenticate:' "$h" | cut -d' ' -f2- | tr -d '\r')"
  fi
  printf '%-40s %s %s %s%s\n' "$label" "$status" "${codes:--}" "${msg:--}" "$extra" | normalize
  LAST_BODY=$b
}

create() { # create NAME JSON: the new version
  CREATED+=("$PREFIX-$1")
  read -r status _ b < <(req POST "keys/$PREFIX-$1/create" "$2")
  [ "$status" = 200 ] || { echo "create $1 failed: $status $(cat "$b")" >&2; exit 1; }
  jq -r '.key.kid' "$b" | sed 's#.*/##'
}

DIGEST=$(printf 'probe' | openssl dgst -sha256 -binary | b64u)
hsm=""
[ "$MHSM" = 1 ] && hsm="-HSM"

run() {
  echo "# anykms-azure probe ($([ "$MHSM" = 1 ] && echo "Managed HSM" || echo "key vault"), api 2025-07-01)"
  show "no token: get" GET "keys/$PREFIX-none" "" --no-auth
  show "missing key: get" GET "keys/$PREFIX-none"
  show "missing key: sign" POST "keys/$PREFIX-none/sign" "{\"alg\":\"ES256\",\"value\":\"$DIGEST\"}"

  local ec rsa kek
  ec=$(create ec "{\"kty\":\"EC$hsm\",\"crv\":\"P-256\",\"key_ops\":[\"sign\",\"verify\"]}")
  rsa=$(create rsa "{\"kty\":\"RSA$hsm\",\"key_size\":2048,\"key_ops\":[\"sign\",\"verify\"]}")
  kek=$(create kek "{\"kty\":\"RSA$hsm\",\"key_size\":2048,\"key_ops\":[\"wrapKey\",\"unwrapKey\"]}")

  echo "## signing"
  show "versionless sign ES256" POST "keys/$PREFIX-ec/sign" "{\"alg\":\"ES256\",\"value\":\"$DIGEST\"}"
  show "versioned sign ES256" POST "keys/$PREFIX-ec/$ec/sign" "{\"alg\":\"ES256\",\"value\":\"$DIGEST\"}"
  local sig
  sig=$(jq -r .value "$LAST_BODY")
  echo "ES256 signature bytes: $(printf '%s' "$sig" | unb64u | wc -c)"
  show "verify ok" POST "keys/$PREFIX-ec/$ec/verify" "{\"alg\":\"ES256\",\"digest\":\"$DIGEST\",\"value\":\"$sig\"}"
  jq -c . "$LAST_BODY"
  show "verify other digest" POST "keys/$PREFIX-ec/$ec/verify" "{\"alg\":\"ES256\",\"digest\":\"$(printf x | openssl dgst -sha256 -binary | b64u)\",\"value\":\"$sig\"}"
  jq -c . "$LAST_BODY"
  show "verify malformed signature" POST "keys/$PREFIX-ec/$ec/verify" "{\"alg\":\"ES256\",\"digest\":\"$DIGEST\",\"value\":\"AAAA\"}"
  show "verify missing version" POST "keys/$PREFIX-ec/00000000000000000000000000000000/verify" "{\"alg\":\"ES256\",\"digest\":\"$DIGEST\",\"value\":\"$sig\"}"
  show "sign RS256 with EC key" POST "keys/$PREFIX-ec/$ec/sign" "{\"alg\":\"RS256\",\"value\":\"$DIGEST\"}"
  show "sign PS256" POST "keys/$PREFIX-rsa/$rsa/sign" "{\"alg\":\"PS256\",\"value\":\"$DIGEST\"}"
  echo "PS256 signature bytes: $(jq -r .value "$LAST_BODY" | unb64u | wc -c)"
  show "sign with key_ops [wrapKey,unwrapKey]" POST "keys/$PREFIX-kek/$kek/sign" "{\"alg\":\"PS256\",\"value\":\"$DIGEST\"}"
  show "sign with a 20-byte digest" POST "keys/$PREFIX-rsa/$rsa/sign" "{\"alg\":\"PS256\",\"value\":\"$(head -c 20 /dev/zero | b64u)\"}"

  echo "## wrap"
  local dek
  dek=$(head -c 32 /dev/urandom | b64u)
  show "versionless wrapkey" POST "keys/$PREFIX-kek/wrapkey" "{\"alg\":\"RSA-OAEP-256\",\"value\":\"$dek\"}"
  local w
  w=$(jq -r .value "$LAST_BODY")
  echo "wrapped bytes: $(printf '%s' "$w" | unb64u | wc -c)"
  show "unwrapkey" POST "keys/$PREFIX-kek/$kek/unwrapkey" "{\"alg\":\"RSA-OAEP-256\",\"value\":\"$w\"}"
  [ "$(jq -r .value "$LAST_BODY")" = "$dek" ] && echo "unwrap round trip: ok"
  show "unwrapkey damaged" POST "keys/$PREFIX-kek/$kek/unwrapkey" "{\"alg\":\"RSA-OAEP-256\",\"value\":\"$(head -c 256 /dev/zero | b64u)\"}"
  show "unwrapkey missing version" POST "keys/$PREFIX-kek/00000000000000000000000000000000/unwrapkey" "{\"alg\":\"RSA-OAEP-256\",\"value\":\"$w\"}"
  show "wrapkey 191 bytes (limit 190)" POST "keys/$PREFIX-kek/$kek/wrapkey" "{\"alg\":\"RSA-OAEP-256\",\"value\":\"$(head -c 191 /dev/zero | b64u)\"}"
  show "wrapkey A256KW on RSA" POST "keys/$PREFIX-kek/$kek/wrapkey" "{\"alg\":\"A256KW\",\"value\":\"$dek\"}"

  echo "## key state"
  show "disable version" PATCH "keys/$PREFIX-ec/$ec" '{"attributes":{"enabled":false}}' >/dev/null
  show "disabled: get" GET "keys/$PREFIX-ec"
  show "disabled: get version" GET "keys/$PREFIX-ec/$ec"
  show "disabled: sign" POST "keys/$PREFIX-ec/$ec/sign" "{\"alg\":\"ES256\",\"value\":\"$DIGEST\"}"
  show "disabled: verify" POST "keys/$PREFIX-ec/$ec/verify" "{\"alg\":\"ES256\",\"digest\":\"$DIGEST\",\"value\":\"$sig\"}"
  local now
  now=$(date +%s)
  create nbf "{\"kty\":\"RSA$hsm\",\"key_size\":2048,\"key_ops\":[\"wrapKey\",\"unwrapKey\",\"sign\",\"verify\"],\"attributes\":{\"nbf\":$((now + 86400))}}" >/dev/null
  show "not yet valid: get" GET "keys/$PREFIX-nbf"
  show "not yet valid: sign" POST "keys/$PREFIX-nbf/sign" "{\"alg\":\"PS256\",\"value\":\"$DIGEST\"}"
  show "not yet valid: wrapkey" POST "keys/$PREFIX-nbf/wrapkey" "{\"alg\":\"RSA-OAEP-256\",\"value\":\"$dek\"}"
  local exp
  exp=$(create exp "{\"kty\":\"RSA$hsm\",\"key_size\":2048,\"key_ops\":[\"wrapKey\",\"unwrapKey\",\"sign\",\"verify\"]}")
  show "wrap before expiry" POST "keys/$PREFIX-exp/$exp/wrapkey" "{\"alg\":\"RSA-OAEP-256\",\"value\":\"$dek\"}"
  local we
  we=$(jq -r .value "$LAST_BODY")
  show "expire" PATCH "keys/$PREFIX-exp/$exp" "{\"attributes\":{\"exp\":$((now - 60))}}" >/dev/null
  show "expired: sign" POST "keys/$PREFIX-exp/$exp/sign" "{\"alg\":\"PS256\",\"value\":\"$DIGEST\"}"
  show "expired: wrapkey" POST "keys/$PREFIX-exp/$exp/wrapkey" "{\"alg\":\"RSA-OAEP-256\",\"value\":\"$dek\"}"
  show "expired: unwrapkey" POST "keys/$PREFIX-exp/$exp/unwrapkey" "{\"alg\":\"RSA-OAEP-256\",\"value\":\"$we\"}"

  if [ "$MHSM" = 1 ]; then
    echo "## Managed HSM AES-GCM and A256KW"
    local aes
    aes=$(create aes '{"kty":"oct-HSM","key_size":256,"key_ops":["encrypt","decrypt","wrapKey","unwrapKey"]}')
    show "encrypt A256GCM with aad" POST "keys/$PREFIX-aes/$aes/encrypt" "{\"alg\":\"A256GCM\",\"value\":\"$(printf hello | b64u)\",\"aad\":\"$(printf ctx | b64u)\"}"
    local ct iv tag
    ct=$(jq -r .value "$LAST_BODY")
    iv=$(jq -r .iv "$LAST_BODY")
    tag=$(jq -r .tag "$LAST_BODY")
    echo "iv bytes: $(printf '%s' "$iv" | unb64u | wc -c) tag bytes: $(printf '%s' "$tag" | unb64u | wc -c) ct bytes: $(printf '%s' "$ct" | unb64u | wc -c)"
    show "decrypt" POST "keys/$PREFIX-aes/$aes/decrypt" "{\"alg\":\"A256GCM\",\"value\":\"$ct\",\"iv\":\"$iv\",\"tag\":\"$tag\",\"aad\":\"$(printf ctx | b64u)\"}"
    jq -r .value "$LAST_BODY" | unb64u; echo
    show "decrypt wrong aad" POST "keys/$PREFIX-aes/$aes/decrypt" "{\"alg\":\"A256GCM\",\"value\":\"$ct\",\"iv\":\"$iv\",\"tag\":\"$tag\",\"aad\":\"$(printf other | b64u)\"}"
    show "decrypt damaged tag" POST "keys/$PREFIX-aes/$aes/decrypt" "{\"alg\":\"A256GCM\",\"value\":\"$ct\",\"iv\":\"$iv\",\"tag\":\"$(head -c 16 /dev/zero | b64u)\"}"
    show "encrypt with a client iv" POST "keys/$PREFIX-aes/$aes/encrypt" "{\"alg\":\"A256GCM\",\"value\":\"$(printf hello | b64u)\",\"iv\":\"$(head -c 12 /dev/zero | b64u)\"}"
    show "encrypt empty plaintext" POST "keys/$PREFIX-aes/$aes/encrypt" "{\"alg\":\"A256GCM\",\"value\":\"\"}"
    for size in 4096 65536 262144 1048576; do
      head -c "$size" /dev/zero | b64u > "$TMP/pt"
      show "encrypt $size bytes" POST "keys/$PREFIX-aes/$aes/encrypt" "{\"alg\":\"A256GCM\",\"value\":\"$(cat "$TMP/pt")\"}"
    done
    show "wrapkey A256KW" POST "keys/$PREFIX-aes/$aes/wrapkey" "{\"alg\":\"A256KW\",\"value\":\"$dek\"}"
    echo "A256KW bytes: $(jq -r .value "$LAST_BODY" | unb64u | wc -c)"
    show "describe oct-HSM (key_size reported?)" GET "keys/$PREFIX-aes/$aes"
    jq -c '.key | {kty, key_size, key_ops}' "$LAST_BODY"

    echo "## Managed HSM HMAC (Q4: message or digest?)"
    local k
    k=$(head -c 32 /dev/urandom)
    local khex kb64
    khex=$(printf '%s' "$k" | od -An -tx1 | tr -d ' \n')
    kb64=$(printf '%s' "$k" | b64u)
    CREATED+=("$PREFIX-hmac")
    show "import HMAC key" PUT "keys/$PREFIX-hmac" "{\"key\":{\"kty\":\"oct-HSM\",\"k\":\"$kb64\",\"key_ops\":[\"sign\",\"verify\"]}}"
    local msg="the quick brown fox"
    show "HS256 sign of a message" POST "keys/$PREFIX-hmac/sign" "{\"alg\":\"HS256\",\"value\":\"$(printf '%s' "$msg" | b64u)\"}"
    local got
    got=$(jq -r .value "$LAST_BODY")
    local of_msg of_digest
    of_msg=$(printf '%s' "$msg" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$khex" -binary | b64u)
    of_digest=$(printf '%s' "$msg" | openssl dgst -sha256 -binary | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$khex" -binary | b64u)
    if [ "$got" = "$of_msg" ]; then echo "HS256 = HMAC(message)";
    elif [ "$got" = "$of_digest" ]; then echo "HS256 = HMAC(SHA-256(message))";
    else echo "HS256 = neither (got ${#got} chars)"; fi
    show "HS256 sign of 1 MiB" POST "keys/$PREFIX-hmac/sign" "{\"alg\":\"HS256\",\"value\":\"$(head -c 1048576 /dev/zero | b64u)\"}"
    show "HS256 verify" POST "keys/$PREFIX-hmac/verify" "{\"alg\":\"HS256\",\"digest\":\"$(printf '%s' "$msg" | b64u)\",\"value\":\"$got\"}"
    jq -c . "$LAST_BODY"
  fi
}

case $mode in
  run) run ;;
  record)
    mkdir -p "$BASELINE_DIR"
    run > "$BASELINE_DIR/$NAME.txt"
    echo "wrote $BASELINE_DIR/$NAME.txt" >&2
    ;;
  diff)
    run > "$TMP/now.txt"
    diff -u "$BASELINE_DIR/$NAME.txt" "$TMP/now.txt"
    ;;
esac
