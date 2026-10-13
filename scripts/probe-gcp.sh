#!/usr/bin/env bash
# Probes the Cloud KMS behavior anykms-gcp depends on (task T1 in docs/cloud/gcp.md): limits,
# empty inputs, error statuses and messages (checksum, purpose, digest, version state, missing
# keys, bad tokens), RequestInfo/RetryInfo presence and disable propagation. Prints normalized
# output: ciphertexts, signatures, MACs, timestamps, request ids, the project and the per-run
# key names are masked, so runs diff cleanly against a committed baseline.
#
# Usage:
#   scripts/probe-gcp.sh [run]               print the normalized probe output
#   scripts/probe-gcp.sh record [NAME]       write scripts/probe-baseline/gcp/NAME.txt
#                                            (default NAME: gcp-<yyyy-mm>)
#   scripts/probe-gcp.sh diff [BASELINE]     diff against BASELINE (a file or a NAME; default:
#                                            the newest gcp baseline); exits 1 on differences
#
# Uses the pooled keys of scripts/gcp-test-setup.sh in ANYKMS_GCP_KEY_RING
# (projects/<p>/locations/<l>/keyRings/<r>) and creates two probe keys (probe-<ts>-*) whose
# versions `gcp-test-setup.sh sweep` destroys later. Key management (create, disable, destroy)
# uses ANYKMS_GCP_TOKEN or `gcloud auth print-access-token` (roles/cloudkms.admin on the ring);
# cryptographic calls use ANYKMS_GCP_DATA_TOKEN, else a token minted from the service-account
# key in GOOGLE_APPLICATION_CREDENTIALS (cryptoKeyEncrypterDecrypter and signerVerifier on the
# ring), else the admin token. Needs curl, jq and base64 (and openssl to mint a token).
set -euo pipefail

BASELINE_DIR="$(cd "$(dirname "$0")" && pwd)/probe-baseline/gcp"

usage() {
  sed -n '8,14p' "$0" >&2
  exit 2
}

mode=run
case "${1:-}" in
  run | record | diff) mode=$1; shift ;;
  -h | --help) usage ;;
esac
ARG=${1:-}

for tool in curl jq base64; do
  command -v "$tool" >/dev/null || { echo "probe-gcp: $tool is required" >&2; exit 2; }
done
RING=${ANYKMS_GCP_KEY_RING:?set ANYKMS_GCP_KEY_RING}
PROJECT=$(cut -d/ -f2 <<<"$RING")
TOKEN=${ANYKMS_GCP_TOKEN:-$(gcloud auth print-access-token)}
API=${ANYKMS_GCP_API:-https://cloudkms.googleapis.com/v1}

# sa_token FILE: an access token for the service-account key FILE (JWT bearer grant).
sa_token() {
  local email aud now hdr claims sig
  email=$(jq -r .client_email "$1")
  aud=$(jq -r '.token_uri // "https://oauth2.googleapis.com/token"' "$1")
  now=$(date +%s)
  url64() { base64 -w0 2>/dev/null | tr '+/' '-_' | tr -d '=\n'; }
  hdr=$(printf '{"alg":"RS256","typ":"JWT"}' | url64)
  claims=$(jq -cn --arg iss "$email" --arg aud "$aud" --argjson now "$now" \
    '{iss:$iss,aud:$aud,iat:$now,exp:($now+3600),scope:"https://www.googleapis.com/auth/cloudkms"}' | url64)
  # The private key goes to openssl through a pipe, never to a file.
  sig=$(printf '%s.%s' "$hdr" "$claims" |
    openssl dgst -sha256 -sign <(jq -r .private_key "$1") | url64)
  curl -sS "$aud" -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
    -d "assertion=$hdr.$claims.$sig" | jq -er .access_token
}

if [ -n "${ANYKMS_GCP_DATA_TOKEN:-}" ]; then
  DATA=$ANYKMS_GCP_DATA_TOKEN
elif [ -f "${GOOGLE_APPLICATION_CREDENTIALS:-}" ] &&
  [ "$(jq -r .type "$GOOGLE_APPLICATION_CREDENTIALS")" = service_account ]; then
  DATA=$(sa_token "$GOOGLE_APPLICATION_CREDENTIALS")
else
  DATA=$TOKEN
fi
RUN="probe-$(date +%s)"

b64() { printf '%s' "$1" | base64 -w0 2>/dev/null || printf '%s' "$1" | base64; }
zeros() { head -c "$1" /dev/zero | base64 -w0 2>/dev/null || head -c "$1" /dev/zero | base64; }

# CRC32C of stdin, in pure bash (small inputs only).
crc32c() {
  local -i crc=0xFFFFFFFF b k
  local hex
  hex=$(od -An -v -tu1)
  for b in $hex; do
    crc=$((crc ^ b))
    for k in 1 2 3 4 5 6 7 8; do
      if ((crc & 1)); then crc=$(((crc >> 1) ^ 0x82F63B78)); else crc=$((crc >> 1)); fi
    done
  done
  echo $((crc ^ 0xFFFFFFFF))
}

# call METHOD PATH [JSON] [TOKEN] (default: the data token): prints "<status> <normalized body>".
call() {
  local out status body tok=${4:-$DATA}
  out=$(mktemp)
  status=$(curl -sS -o "$out" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $tok" \
    -H 'Content-Type: application/json' "$API/$2" ${3:+--data-binary "$3"})
  body=$(cat "$out")
  rm -f "$out"
  echo "$status $(normalize <<<"$body")"
}

normalize() {
  jq -cS --arg p "$PROJECT" --arg run "$RUN" '
    def mask: if type == "string" then
        gsub($p; "<project>") | gsub($run + "-[a-z0-9-]+"; "<probe-key>")
        | gsub("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z"; "<time>")
      else . end;
    walk(if type == "object" then
        with_entries(
          if (.key | test("^(ciphertext|signature|mac|pem|requestId|plaintext|error_info_id|troubleshooter_url)$"))
            then .value = "<\(.key)>"
          elif (.key | test("Crc32c$")) then .value = "<crc>"
          else .value |= mask end)
      else mask end)' 2>/dev/null || echo "<non-JSON body>"
}

probe() {
  echo "== $1"
  shift
  call "$@"
}

key() { echo "$RING/cryptoKeys/$1"; }

run() {
  local aead ec ed hmac p ct v
  aead=$(key aead)
  ec=$(key ec-p256)/cryptoKeyVersions/1
  ed=$(key ed25519)/cryptoKeyVersions/1
  hmac=$(key hmac-sha256)/cryptoKeyVersions/1

  echo "# encrypt limits and empty input"
  probe "encrypt empty plaintext" POST "$aead:encrypt" '{"plaintext":""}'
  probe "encrypt 65536" POST "$aead:encrypt" "{\"plaintext\":\"$(zeros 65536)\"}"
  probe "encrypt 65537" POST "$aead:encrypt" "{\"plaintext\":\"$(zeros 65537)\"}"
  probe "encrypt aad 65537" POST "$aead:encrypt" \
    "{\"plaintext\":\"$(b64 x)\",\"additionalAuthenticatedData\":\"$(zeros 65537)\"}"
  p=$(b64 hello)
  probe "encrypt wrong plaintextCrc32c" POST "$aead:encrypt" \
    "{\"plaintext\":\"$p\",\"plaintextCrc32c\":\"1\"}"
  probe "encrypt with crc" POST "$aead:encrypt" \
    "{\"plaintext\":\"$p\",\"plaintextCrc32c\":\"$(printf hello | crc32c)\"}"

  echo "# decrypt failures"
  ct=$(curl -sS -X POST -H "Authorization: Bearer $DATA" -H 'Content-Type: application/json' \
    "$API/$aead:encrypt" --data-binary "{\"plaintext\":\"$p\",\"additionalAuthenticatedData\":\"$(b64 aad)\"}" |
    jq -r .ciphertext)
  probe "decrypt right aad" POST "$aead:decrypt" \
    "{\"ciphertext\":\"$ct\",\"additionalAuthenticatedData\":\"$(b64 aad)\"}"
  probe "decrypt wrong aad" POST "$aead:decrypt" \
    "{\"ciphertext\":\"$ct\",\"additionalAuthenticatedData\":\"$(b64 other)\"}"
  probe "decrypt with another key" POST "$(key hmac-sha256):decrypt" "{\"ciphertext\":\"$ct\"}"
  probe "decrypt wrong ciphertextCrc32c" POST "$aead:decrypt" \
    "{\"ciphertext\":\"$ct\",\"ciphertextCrc32c\":\"1\"}"
  probe "decrypt garbage" POST "$aead:decrypt" "{\"ciphertext\":\"$(b64 garbage)\"}"

  echo "# purpose and algorithm mismatches"
  probe "asymmetricSign on an AEAD key" POST "$aead/cryptoKeyVersions/1:asymmetricSign" \
    "{\"digest\":{\"sha256\":\"$(zeros 32)\"}}"
  probe "encrypt on a signing key" POST "$(key ec-p256):encrypt" "{\"plaintext\":\"$p\"}"
  probe "getPublicKey on an AEAD key" GET "$aead/cryptoKeyVersions/1/publicKey"
  probe "macSign on a signing key" POST "$ec:macSign" "{\"data\":\"$p\"}"
  probe "sha384 digest on P-256" POST "$ec:asymmetricSign" "{\"digest\":{\"sha384\":\"$(zeros 48)\"}}"
  probe "data on P-256" POST "$ec:asymmetricSign" "{\"data\":\"$p\"}"
  probe "wrong digestCrc32c" POST "$ec:asymmetricSign" \
    "{\"digest\":{\"sha256\":\"$(zeros 32)\"},\"digestCrc32c\":\"1\"}"

  echo "# message and MAC sizes"
  for n in 0 4096 8192 16384 32768 65536 65537; do
    probe "Ed25519 data $n" POST "$ed:asymmetricSign" "{\"data\":\"$(zeros "$n")\"}"
  done
  for n in 0 65536 65537; do
    probe "macSign data $n" POST "$hmac:macSign" "{\"data\":\"$(zeros "$n")\"}"
  done
  probe "macVerify wrong tag" POST "$hmac:macVerify" "{\"data\":\"$p\",\"mac\":\"$(zeros 32)\"}"

  echo "# missing keys, versions and bad tokens"
  probe "encrypt missing key" POST "$(key does-not-exist):encrypt" "{\"plaintext\":\"$p\"}"
  probe "getPublicKey missing version" GET "$(key ec-p256)/cryptoKeyVersions/999/publicKey"
  probe "encrypt with a bad token" POST "$aead:encrypt" "{\"plaintext\":\"$p\"}" "ya29.invalid"
  probe "encrypt in another project" POST \
    "projects/anykms-probe-nonexistent/locations/global/keyRings/r/cryptoKeys/k:encrypt" \
    "{\"plaintext\":\"$p\"}"

  echo "# disabled versions (probe keys)"
  local sym sig
  sym=$(call POST "$RING/cryptoKeys?cryptoKeyId=$RUN-sym" \
    '{"purpose":"ENCRYPT_DECRYPT","destroyScheduledDuration":"86400s"}' "$TOKEN")
  echo "create symmetric: ${sym%% *}"
  sig=$(call POST "$RING/cryptoKeys?cryptoKeyId=$RUN-sig" \
    '{"purpose":"ASYMMETRIC_SIGN","versionTemplate":{"algorithm":"EC_SIGN_P256_SHA256"},"destroyScheduledDuration":"86400s"}' "$TOKEN")
  echo "create signing: ${sig%% *}"
  local skey="$RING/cryptoKeys/$RUN-sym" gkey="$RING/cryptoKeys/$RUN-sig"
  for _ in $(seq 60); do
    [ "$(call GET "$gkey/cryptoKeyVersions/1" "" "$TOKEN" | cut -d' ' -f2- | jq -r .state)" = ENABLED ] && break
    sleep 2
  done
  ct=$(curl -sS -X POST -H "Authorization: Bearer $DATA" -H 'Content-Type: application/json' \
    "$API/$skey:encrypt" --data-binary "{\"plaintext\":\"$p\"}" | jq -r .ciphertext)
  call PATCH "$skey/cryptoKeyVersions/1?updateMask=state" '{"state":"DISABLED"}' "$TOKEN" >/dev/null
  call PATCH "$gkey/cryptoKeyVersions/1?updateMask=state" '{"state":"DISABLED"}' "$TOKEN" >/dev/null
  local t0=$SECONDS waited=none
  for _ in $(seq 40); do
    if [ "$(call POST "$skey:encrypt" "{\"plaintext\":\"$p\"}" | cut -d' ' -f1)" != 200 ]; then
      waited=$(((SECONDS - t0) / 15 * 15))
      break
    fi
    sleep 3
  done
  echo "disable propagation: refused after ~${waited}s (15 s buckets)"
  probe "encrypt, primary disabled" POST "$skey:encrypt" "{\"plaintext\":\"$p\"}"
  probe "decrypt, version disabled" POST "$skey:decrypt" "{\"ciphertext\":\"$ct\"}"
  probe "sign, version disabled" POST "$gkey/cryptoKeyVersions/1:asymmetricSign" \
    "{\"digest\":{\"sha256\":\"$(zeros 32)\"}}"
  probe "getPublicKey, version disabled" GET "$gkey/cryptoKeyVersions/1/publicKey"
  call POST "$skey/cryptoKeyVersions/1:destroy" '{}' "$TOKEN" >/dev/null
  call POST "$gkey/cryptoKeyVersions/1:destroy" '{}' "$TOKEN" >/dev/null
}

case "$mode" in
  run) run ;;
  record)
    mkdir -p "$BASELINE_DIR"
    name=${ARG:-gcp-$(date +%Y-%m)}
    run >"$BASELINE_DIR/$name.txt"
    echo "wrote $BASELINE_DIR/$name.txt"
    ;;
  diff)
    if [ -n "$ARG" ] && [ -f "$ARG" ]; then base=$ARG
    elif [ -n "$ARG" ]; then base=$BASELINE_DIR/$ARG.txt
    else base=$(ls -1 "$BASELINE_DIR"/gcp-*.txt 2>/dev/null | sort | tail -1)
    fi
    [ -n "${base:-}" ] && [ -f "$base" ] || { echo "probe-gcp: no baseline" >&2; exit 2; }
    diff -u "$base" <(run)
    ;;
esac
