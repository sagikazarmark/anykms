#!/usr/bin/env bash
# Probes transit semantics that anykms depends on (AAD, data keys, rotation, error codes, signing
# options, key metadata) and prints normalized output: random values (ciphertexts, signatures,
# HMACs, random bytes) and the per-run mount name are masked, so runs against the same server
# version are identical and runs against a new release diff cleanly against a committed baseline.
#
# Usage:
#   scripts/probe-transit.sh [run] ADDR              print the normalized probe output
#   scripts/probe-transit.sh record ADDR [NAME]      write scripts/probe-baseline/NAME.txt
#                                                    (default NAME: <flavor>-<version>)
#   scripts/probe-transit.sh diff ADDR [BASELINE]    diff against BASELINE (a file or a NAME;
#                                                    default: the newest baseline of the same
#                                                    flavor); exits 1 when semantics differ
#
# ADDR is e.g. http://127.0.0.1:8200. The root token comes from ANYKMS_ROOT_TOKEN (default
# "root"). Every run mounts transit at a fresh path (with disable_upsert, like the dev setup) and
# unmounts it on exit, so shared servers are not disturbed. Needs curl and jq.
set -euo pipefail

BASELINE_DIR="$(cd "$(dirname "$0")" && pwd)/probe-baseline"

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
A=${1%/}
ARG=${2:-}
TOKEN=${ANYKMS_ROOT_TOKEN:-root}

for tool in curl jq; do
  command -v "$tool" >/dev/null || { echo "probe-transit: $tool is required" >&2; exit 2; }
done

health=$(curl -sS "$A/v1/sys/health")
version=$(jq -r .version <<<"$health")
# Vault reports an `enterprise` field; OpenBao does not.
flavor=$(jq -r 'if has("enterprise") then "vault" else "openbao" end' <<<"$health")

TMP=$(mktemp -d)
MOUNT="probe-$(date +%s)-$$"

hdr=(-H "X-Vault-Token: $TOKEN")

# call METHOD PATH [JSON]: the response body.
call() {
  if [ $# -ge 3 ]; then
    curl -sS -X "$1" "${hdr[@]}" "$A/v1/$2" --data-binary "$3"
  else
    curl -sS -X "$1" "${hdr[@]}" "$A/v1/$2"
  fi
}

# code METHOD PATH [JSON]: the HTTP status.
code() {
  if [ $# -ge 3 ]; then
    curl -sS -o /dev/null -w '%{http_code}' -X "$1" "${hdr[@]}" "$A/v1/$2" --data-binary "$3"
  else
    curl -sS -o /dev/null -w '%{http_code}' -X "$1" "${hdr[@]}" "$A/v1/$2"
  fi
}

# j FILTER: compact jq over stdin; tolerates empty and non-JSON bodies.
j() {
  local in
  in=$(cat)
  if [ -z "$in" ]; then
    echo "<no body>"
  else
    jq -c "$1" <<<"$in" 2>/dev/null || echo "<non-json body>"
  fi
}

cleanup() {
  curl -sS -o /dev/null -X DELETE "${hdr[@]}" "$A/v1/sys/mounts/$MOUNT" || true
  rm -rf "$TMP"
}
trap cleanup EXIT

probe() {
  local T=$MOUNT
  echo "# server: $flavor $version"
  call POST "sys/mounts/$T" '{"type":"transit"}' >/dev/null
  call POST "$T/config/keys" '{"disable_upsert":true}' >/dev/null

  echo "-- create keys"
  for spec in 'aes {"type":"aes256-gcm96"}' 'ec {"type":"ecdsa-p256"}' 'ed {"type":"ed25519"}' \
    'rsa {"type":"rsa-2048"}' 'hm {"type":"hmac","key_size":32}'; do
    printf '%s ' "${spec%% *}"
    call POST "$T/keys/${spec%% *}" "${spec#* }" | j '.errors // "ok"'
  done

  local PT AD AD2 CT DK DKCT DG SIG MAC
  PT=$(printf 'hello' | base64)
  AD=$(printf 'ctx1' | base64)
  AD2=$(printf 'ctx2' | base64)

  echo "-- encrypt with associated_data"
  CT=$(call POST "$T/encrypt/aes" "{\"plaintext\":\"$PT\",\"associated_data\":\"$AD\"}" | jq -r .data.ciphertext)
  echo "$CT"
  echo "-- decrypt, right AD"
  call POST "$T/decrypt/aes" "{\"ciphertext\":\"$CT\",\"associated_data\":\"$AD\"}" | j '.data // .errors'
  echo "-- decrypt, wrong AD"
  code POST "$T/decrypt/aes" "{\"ciphertext\":\"$CT\",\"associated_data\":\"$AD2\"}"
  echo
  call POST "$T/decrypt/aes" "{\"ciphertext\":\"$CT\",\"associated_data\":\"$AD2\"}" | j '.errors'
  echo "-- decrypt, no AD"
  call POST "$T/decrypt/aes" "{\"ciphertext\":\"$CT\"}" | j '.data // .errors'
  echo "-- decrypt, tampered ciphertext"
  call POST "$T/decrypt/aes" "{\"ciphertext\":\"${CT%??}AA\",\"associated_data\":\"$AD\"}" | j '.errors'

  echo "-- datakey with associated_data"
  DK=$(call POST "$T/datakey/plaintext/aes" "{\"associated_data\":\"$AD\",\"bits\":256}")
  j '{warnings:.warnings,errors:.errors,ciphertext:.data.ciphertext,plaintext_len:(.data.plaintext // "" | length)}' <<<"$DK"
  DKCT=$(jq -r .data.ciphertext <<<"$DK")
  echo "   decrypt datakey with AD"
  call POST "$T/decrypt/aes" "{\"ciphertext\":\"$DKCT\",\"associated_data\":\"$AD\"}" | j 'if .data then (.data|keys) else .errors end'
  echo "   decrypt datakey without AD"
  call POST "$T/decrypt/aes" "{\"ciphertext\":\"$DKCT\"}" | j 'if .data then (.data|keys) else .errors end'
  echo "-- datakey wrapped"
  call POST "$T/datakey/wrapped/aes" '{}' | j 'if .data then (.data|keys) else .errors end'

  echo "-- rotate, then decrypt the v1 ciphertext"
  call POST "$T/keys/aes/rotate" '' | j '.data.latest_version // .errors // "ok"'
  call POST "$T/decrypt/aes" "{\"ciphertext\":\"$CT\",\"associated_data\":\"$AD\"}" | j '.data // .errors'
  echo "-- encrypt with key_version=1 after rotation"
  call POST "$T/encrypt/aes" "{\"plaintext\":\"$PT\",\"key_version\":1}" | j '.data.ciphertext // .errors'
  echo "-- min_decryption_version=2, then decrypt v1"
  call POST "$T/keys/aes/config" '{"min_decryption_version":2}' | j '.errors // "ok"'
  code POST "$T/decrypt/aes" "{\"ciphertext\":\"$CT\",\"associated_data\":\"$AD\"}"
  echo
  call POST "$T/decrypt/aes" "{\"ciphertext\":\"$CT\",\"associated_data\":\"$AD\"}" | j '.errors'

  echo "-- encrypt to a missing key (disable_upsert)"
  code POST "$T/encrypt/nope" "{\"plaintext\":\"$PT\"}"
  echo
  call POST "$T/encrypt/nope" "{\"plaintext\":\"$PT\"}" | j '.errors // .data'
  echo "-- decrypt with a missing key"
  code POST "$T/decrypt/nope2" "{\"ciphertext\":\"$CT\"}"
  echo
  call POST "$T/decrypt/nope2" "{\"ciphertext\":\"$CT\"}" | j '.errors'
  echo "-- bad token"
  curl -sS -o /dev/null -w '%{http_code}\n' -X POST -H "X-Vault-Token: bad" "$A/v1/$T/encrypt/aes" --data-binary "{\"plaintext\":\"$PT\"}"

  DG=$(printf 'msg' | sha256sum | cut -d' ' -f1 | xxd -r -p | base64)
  echo "-- sign ecdsa, prehashed"
  SIG=$(call POST "$T/sign/ec" "{\"input\":\"$DG\",\"prehashed\":true,\"hash_algorithm\":\"sha2-256\",\"marshaling_algorithm\":\"asn1\"}" | jq -r '.data.signature // .errors')
  echo "$SIG"
  echo "   verify"
  call POST "$T/verify/ec" "{\"input\":\"$DG\",\"prehashed\":true,\"hash_algorithm\":\"sha2-256\",\"signature\":\"$SIG\"}" | j '.data // .errors'
  echo "   verify another input"
  call POST "$T/verify/ec" "{\"input\":\"$PT\",\"prehashed\":true,\"hash_algorithm\":\"sha2-256\",\"signature\":\"$SIG\"}" | j '.data // .errors'
  echo "-- sign ecdsa, jws marshaling"
  call POST "$T/sign/ec" "{\"input\":\"$DG\",\"prehashed\":true,\"hash_algorithm\":\"sha2-256\",\"marshaling_algorithm\":\"jws\"}" | j '.data.signature // .errors'
  echo "-- sign rsa pss, prehashed"
  call POST "$T/sign/rsa" "{\"input\":\"$DG\",\"prehashed\":true,\"hash_algorithm\":\"sha2-256\",\"signature_algorithm\":\"pss\"}" | j '.data.signature // .errors'
  echo "-- sign rsa pkcs1v15, prehashed"
  call POST "$T/sign/rsa" "{\"input\":\"$DG\",\"prehashed\":true,\"hash_algorithm\":\"sha2-256\",\"signature_algorithm\":\"pkcs1v15\"}" | j '.data.signature // .errors'
  echo "-- sign ed25519, prehashed"
  call POST "$T/sign/ed" "{\"input\":\"$DG\",\"prehashed\":true}" | j '.data.signature // .errors'
  echo "-- sign ed25519, raw message"
  call POST "$T/sign/ed" "{\"input\":\"$PT\"}" | j '.data.signature // .errors'

  echo "-- hmac"
  MAC=$(call POST "$T/hmac/hm/sha2-256" "{\"input\":\"$PT\"}" | jq -r '.data.hmac // .errors')
  echo "$MAC"
  echo "   verify hmac"
  call POST "$T/verify/hm/sha2-256" "{\"input\":\"$PT\",\"hmac\":\"$MAC\"}" | j '.data // .errors'
  echo "   hmac with an aes key"
  call POST "$T/hmac/aes/sha2-256" "{\"input\":\"$PT\"}" | j '.data.hmac // .errors'

  echo "-- sign/verify/hmac error messages (pinned in anykms-transit src/errors.rs)"
  local V
  V="\"input\":\"$DG\",\"prehashed\":true,\"hash_algorithm\":\"sha2-256\",\"marshaling_algorithm\":\"asn1\""
  for c in \
    "sign-missing-key sign/nope {$V}" \
    "verify-missing-key verify/nope {$V,\"signature\":\"vault:v1:AAAA\"}" \
    "hmac-missing-key hmac/nope/sha2-256 {\"input\":\"$PT\"}" \
    "verify-non-der-signature verify/ec {$V,\"signature\":\"vault:v1:AAAA\"}" \
    "verify-bad-base64-signature verify/ec {$V,\"signature\":\"vault:v1:!!!\"}" \
    "verify-signature-no-prefix verify/ec {$V,\"signature\":\"AAAA\"}" \
    "verify-signature-too-new verify/ec {$V,\"signature\":\"vault:v9:AAAA\"}" \
    "verify-ed25519-garbage verify/ed {\"input\":\"$PT\",\"signature\":\"vault:v1:AAAA\"}" \
    "verify-hmac-garbage verify/hm/sha2-256 {\"input\":\"$PT\",\"hmac\":\"vault:v1:AAAA\"}" \
    "verify-hmac-bad-base64 verify/hm/sha2-256 {\"input\":\"$PT\",\"hmac\":\"vault:v1:!!!\"}" \
    "verify-hmac-no-prefix verify/hm/sha2-256 {\"input\":\"$PT\",\"hmac\":\"AAAA\"}" \
    "verify-hmac-too-new verify/hm/sha2-256 {\"input\":\"$PT\",\"hmac\":\"vault:v9:AAAA\"}" \
    "verify-hmac-too-old verify/hm/sha2-256 {\"input\":\"$PT\",\"hmac\":\"vault:v0:AAAA\"}"; do
    set -- $c
    printf '%s %s ' "$1" "$(code POST "$T/$2" "$3")"
    call POST "$T/$2" "$3" | j '.errors // .data'
  done

  echo "-- random"
  call POST "$T/random/32" '{"format":"base64"}' | j '(.data.random_bytes | length) // .errors'
  echo "   sys/tools/random"
  call POST sys/tools/random/32 '{}' | j '(.data.random_bytes | length) // .errors'

  echo "-- read key ec"
  call GET "$T/keys/ec" | j '.data | {type,latest_version,min_decryption_version,min_encryption_version,deletion_allowed,exportable,supports_encryption,supports_signing,supports_decryption,supports_derivation, kv: (.keys|to_entries|map({k:.key,v:(.value|keys)}))}'
  echo "-- read key aes"
  call GET "$T/keys/aes" | j '.data | {type,latest_version,min_decryption_version,versions:(.keys|keys)}'
  echo "-- read key hmac"
  call GET "$T/keys/hm" | j '.data | {type,latest_version,keys}'
  echo "-- export public key"
  call GET "$T/export/public-key/ec" | j '(.data.keys | keys) // .errors'
  echo "-- cmac"
  call POST "$T/cmac/aes" '{"input":"aGVsbG8="}' | j 'if .errors then .errors else (.data|keys) end'
  echo "-- delete a key without deletion_allowed"
  call DELETE "$T/keys/hm" | j '.errors // "deleted"'
  echo "-- encrypt with an ed25519 key"
  call POST "$T/encrypt/ed" "{\"plaintext\":\"$PT\"}" | j '.errors // .data'
  echo "-- large plaintext (2 MB)"
  head -c 2000000 /dev/urandom | base64 -w0 >"$TMP/big.b64"
  printf '{"plaintext":"%s"}' "$(cat "$TMP/big.b64")" >"$TMP/big.json"
  curl -sS -o /dev/null -w '%{http_code}\n' -X POST "${hdr[@]}" "$A/v1/$T/encrypt/aes" --data-binary "@$TMP/big.json"
  echo "-- chacha20-poly1305 key"
  call POST "$T/keys/cc" '{"type":"chacha20-poly1305"}' | j '.errors // "ok"'
  call POST "$T/encrypt/cc" "{\"plaintext\":\"$PT\",\"associated_data\":\"$AD\"}" | j '.data.ciphertext // .errors'
  echo "-- ml-dsa key"
  call POST "$T/keys/pq" '{"type":"ml-dsa","parameter_set":"44"}' | j '.errors // "ok"'
  echo "-- list keys"
  call LIST "$T/keys" | j '.data.keys'
  echo "-- reserved (non-transit) paths shaped like <mount>/keys/<name>"
  for m in sys auth/token identity cubbyhole; do
    printf '%s %s\n' "$m" "$(code GET "$m/keys/k")"
  done
}

# Masks values that differ between runs.
normalize() {
  sed -E \
    -e "s#$MOUNT#<mount>#g" \
    -e 's#([a-z]+:v[0-9]+:)[A-Za-z0-9+/=_-]+#\1<b64>#g'
}

case $mode in
  run)
    probe | normalize
    ;;
  record)
    mkdir -p "$BASELINE_DIR"
    out="$BASELINE_DIR/${ARG:-$flavor-$version}.txt"
    probe | normalize >"$out"
    echo "wrote $out" >&2
    ;;
  diff)
    if [ -z "$ARG" ]; then
      base=$(ls "$BASELINE_DIR/$flavor"-*.txt 2>/dev/null | sort -V | tail -n1)
      [ -n "$base" ] || { echo "probe-transit: no $flavor baseline in $BASELINE_DIR" >&2; exit 2; }
    elif [ -f "$ARG" ]; then
      base=$ARG
    else
      base="$BASELINE_DIR/$ARG.txt"
    fi
    echo "comparing $flavor $version with $base" >&2
    probe | normalize >"$TMP/current.txt"
    # The header names the server version, which is expected to differ.
    diff -u --label "$base" --label "$flavor-$version" -I '^# server:' "$base" "$TMP/current.txt"
    ;;
esac
