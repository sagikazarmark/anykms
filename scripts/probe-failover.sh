#!/usr/bin/env bash
# Records what transit data-plane requests get back while an integrated-storage (raft) cluster
# changes leader, so the transient-error mapping in crates/anykms-transit/src/errors.rs rests on
# observed responses rather than on guessed messages.
#
# Usage:
#   scripts/probe-failover.sh [run] FLAVOR VERSION      print the observed non-200 responses
#   scripts/probe-failover.sh record FLAVOR VERSION     add to scripts/failover-baseline/FLAVOR-VERSION.txt
#   scripts/probe-failover.sh diff FLAVOR VERSION       exit 1 if a response not in the baseline appears
#
# FLAVOR is vault or openbao. The script starts a three-node raft cluster (scripts/ha/compose.yaml,
# ports 8401-8403), initializes and unseals it, creates transit keys, and then sends a mix of
# data-plane requests (encrypt, decrypt, rewrap, datakey, sign, verify, hmac, key read) to every
# node while it forces leader changes: STEPDOWNS graceful step-downs (default 6), then KILLS hard
# kills of the active node (default 2), each restarted and unsealed. The cluster is removed on exit.
#
# Output is one line per distinct "<op> <status> <message>" (sorted, without counts, addresses
# masked). The longest per-node outage after each leader change is printed to stderr (a killed
# node's own outage is the script's restart time, not a client-visible failover). RAW=FILE also writes every non-200 response and failover event, timestamped and with
# the node's port, to FILE for investigation. Failover is timing-dependent, so a run can see fewer lines than the baseline; diff only
# fails on lines the baseline does not have, which are responses to classify in errors.rs.
# Not run in CI (timing-dependent); rerun it when bumping server versions. Needs docker, curl, jq.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE_DIR="$ROOT/scripts/failover-baseline"
COMPOSE=(docker compose -f "$ROOT/scripts/ha/compose.yaml" -p anykms-failover)
PORTS=(8401 8402 8403)
STEPDOWNS=${STEPDOWNS:-6}
KILLS=${KILLS:-2}

usage() {
  sed -n '6,9p' "$0" >&2
  exit 2
}

mode=run
case "${1:-}" in
  run | record | diff) mode=$1; shift ;;
  "" | -h | --help) usage ;;
esac
[ $# -eq 2 ] || usage
FLAVOR=$1
VERSION=$2
# Images are pinned by digest as well as tag. Bumping a version means adding its digest here
# (multi-arch index digest: `docker buildx imagetools inspect <image>:<tag>`, or the registry's
# docker-content-digest header), as in compose.yaml and the CI matrix.
case "$FLAVOR:$VERSION" in
  vault:1.20.4) digest=sha256:268bb80aa9c6d13d65fcfa05c0c268caca068952240a8087291a6ce0b66e3a10 ;;
  vault:2.1.1) digest=sha256:47f14a6acb98f48d798a07df7c83f23a6e636e1cf724c5f8ff165cb32667a1e2 ;;
  openbao:2.4.4) digest=sha256:595c83b42614a4d2b044608e4593c05b019c5db25bc9c185d8fff3ac96c03ddd ;;
  openbao:2.7.1) digest=sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf ;;
  vault:* | openbao:*)
    echo "probe-failover: no pinned digest for $FLAVOR $VERSION; add it to $0" >&2
    exit 2
    ;;
  *) usage ;;
esac
case "$FLAVOR" in
  vault) export HA_IMAGE="hashicorp/vault:$VERSION@$digest" ;;
  openbao) export HA_IMAGE="openbao/openbao:$VERSION@$digest" ;;
esac

for tool in docker curl jq; do
  command -v "$tool" >/dev/null || { echo "probe-failover: $tool is required" >&2; exit 2; }
done

TMP=$(mktemp -d)
cleanup() {
  jobs -p | xargs -r kill 2>/dev/null || true
  "${COMPOSE[@]}" down -v -t 1 >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

log() {
  echo "probe-failover: $*" >&2
  echo "$(date +%s.%3N) event $*" >>"$TMP/raw"
}

# api PORT METHOD PATH [JSON]: response body (token from $TOKEN when set).
api() {
  local args=(-sS -m "${MAXTIME:-5}" -X "$2")
  [ -n "${TOKEN:-}" ] && args+=(-H "X-Vault-Token: $TOKEN")
  [ $# -ge 4 ] && args+=(--data-binary "$4")
  curl "${args[@]}" "http://127.0.0.1:$1/v1/$3"
}

# wait_for DESCRIPTION COMMAND...: retry COMMAND for up to 60 s.
wait_for() {
  local what=$1
  shift
  for _ in $(seq 60); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 1
  done
  log "timed out waiting for $what"
  exit 1
}

unsealed() { [ "$(api "$1" GET sys/seal-status | jq -r .sealed)" = false ]; }
unseal() {
  wait_for "node $1 to answer" api "$1" GET sys/seal-status
  for _ in $(seq 60); do
    api "$1" PUT sys/unseal "{\"key\":\"$UNSEAL_KEY\"}" >/dev/null 2>&1 || true
    unsealed "$1" && return 0
    sleep 1
  done
  log "node $1 did not unseal"
  exit 1
}
active_port() {
  for p in "${PORTS[@]}"; do
    [ "$(api "$p" GET sys/leader 2>/dev/null | jq -r .is_self 2>/dev/null)" = true ] && { echo "$p"; return 0; }
  done
  return 1
}
all_voters() {
  [ "$(api "${PORTS[0]}" GET sys/storage/raft/configuration |
    jq '[.data.config.servers[] | select(.voter)] | length')" = 3 ]
}
healthy() { active_port >/dev/null && for p in "${PORTS[@]}"; do unsealed "$p" || return 1; done; }

log "starting $HA_IMAGE cluster"
"${COMPOSE[@]}" down -v -t 1 >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d >/dev/null 2>&1
wait_for "node ${PORTS[0]}" api "${PORTS[0]}" GET sys/seal-status
init=$(MAXTIME=60 api "${PORTS[0]}" PUT sys/init '{"secret_shares":1,"secret_threshold":1}')
UNSEAL_KEY=$(jq -r '.keys_base64[0]' <<<"$init")
TOKEN=$(jq -r .root_token <<<"$init")
for p in "${PORTS[@]}"; do unseal "$p"; done
wait_for "three raft voters" all_voters
wait_for "an active node" active_port

A=$(active_port)
MAXTIME=30 api "$A" POST sys/mounts/transit '{"type":"transit"}' >/dev/null
api "$A" POST transit/keys/aes '{}' >/dev/null
api "$A" POST transit/keys/ec '{"type":"ecdsa-p256"}' >/dev/null
api "$A" POST transit/keys/mac '{"type":"hmac","key_size":32}' >/dev/null
CT=$(api "$A" POST transit/encrypt/aes '{"plaintext":"aGVsbG8="}' | jq -r .data.ciphertext)
DIGEST=$(printf 'hello' | sha256sum | cut -d' ' -f1 | xxd -r -p | base64)
SIG=$(api "$A" POST transit/sign/ec/sha2-256 \
  "{\"input\":\"$DIGEST\",\"prehashed\":true,\"marshaling_algorithm\":\"asn1\"}" | jq -r .data.signature)

# The same requests anykms makes (crates/anykms-transit/src/handles.rs), one of each per round.
OPS=(
  "encrypt POST transit/encrypt/aes {\"plaintext\":\"aGVsbG8=\"}"
  "decrypt POST transit/decrypt/aes {\"ciphertext\":\"$CT\"}"
  "rewrap POST transit/rewrap/aes {\"ciphertext\":\"$CT\"}"
  "datakey POST transit/datakey/wrapped/aes {\"bits\":256}"
  "sign POST transit/sign/ec/sha2-256 {\"input\":\"$DIGEST\",\"prehashed\":true,\"marshaling_algorithm\":\"asn1\"}"
  "verify POST transit/verify/ec/sha2-256 {\"input\":\"$DIGEST\",\"signature\":\"$SIG\",\"prehashed\":true,\"marshaling_algorithm\":\"asn1\"}"
  "hmac POST transit/hmac/mac/sha2-256 {\"input\":\"aGVsbG8=\"}"
  "keyread GET transit/keys/aes"
)

# load PORT: send OPS round-robin to PORT until $TMP/stop exists; record non-200 responses.
load() {
  local port=$1 out="$TMP/seen.$1" body="$TMP/body.$1" hdrs="$TMP/hdrs.$1"
  while [ ! -e "$TMP/stop" ]; do
    for op in "${OPS[@]}"; do
      read -r name method path json <<<"$op"
      local args=(-s -o "$body" -D "$hdrs" -w '%{http_code}' -m 5 -X "$method"
        -H "X-Vault-Token: $TOKEN")
      [ -n "${json:-}" ] && args+=(--data-binary "$json")
      : >"$hdrs"
      code=$(curl "${args[@]}" "http://127.0.0.1:$port/v1/$path" || true)
      if [ "$code" = 200 ]; then
        echo "$(date +%s.%3N) $port $name ok" >>"$TMP/raw"
        continue
      fi
      if [ "$code" = 000 ]; then
        msg="(no response)"
      elif [[ "$code" == 3* ]]; then
        msg="(redirect)"
      else
        msg=$(jq -c '.errors // .' "$body" 2>/dev/null || echo "(non-JSON body)")
      fi
      # A Retry-After on a failover response would change how Retry waits; record it if sent.
      ra=$(tr -d '\r' <"$hdrs" | awk 'tolower($1) == "retry-after:" { print $2 }')
      [ -n "$ra" ] && msg="$msg retry-after=$ra"
      echo "$name $code $msg" >>"$out"
      echo "$(date +%s.%3N) $port $name $code $msg" >>"$TMP/raw"
    done
  done
}

# Standbys can answer from their own copy of storage (OpenBao), so wait until every node sees the
# new keys: a 400 "encryption key not found" before that is replica lag, not failover.
serves_all() {
  for p in "${PORTS[@]}"; do
    for op in "${OPS[@]}"; do
      read -r _ method path json <<<"$op"
      local args=(-s -o /dev/null -w '%{http_code}' -m 5 -X "$method" -H "X-Vault-Token: $TOKEN")
      [ -n "${json:-}" ] && args+=(--data-binary "$json")
      [ "$(curl "${args[@]}" "http://127.0.0.1:$p/v1/$path")" = 200 ] || return 1
    done
  done
}
wait_for "every node to serve the new keys" serves_all

for p in "${PORTS[@]}"; do load "$p" & done
sleep 3

for i in $(seq "$STEPDOWNS"); do
  A=$(active_port) || { wait_for "an active node" active_port; A=$(active_port); }
  log "step-down $i/$STEPDOWNS (active: $A)"
  api "$A" PUT sys/step-down >/dev/null || true
  sleep 2
  wait_for "the cluster to recover" healthy
  sleep 3
done

for i in $(seq "$KILLS"); do
  A=$(active_port) || { wait_for "an active node" active_port; A=$(active_port); }
  svc="ha-$((A - 8400))"
  log "kill $i/$KILLS ($svc)"
  "${COMPOSE[@]}" kill "$svc" >/dev/null 2>&1
  sleep 8
  "${COMPOSE[@]}" start "$svc" >/dev/null 2>&1
  unseal "$A"
  wait_for "the cluster to recover" healthy
  sleep 3
done

touch "$TMP/stop"
wait
sort -n "$TMP/raw" >"$TMP/raw.sorted"
if [ -n "${RAW:-}" ]; then grep -v ' ok$' "$TMP/raw.sorted" >"$RAW" || true; fi

# Outages: per node, the longest run of failed requests, from the first failure to the next
# success (what a client that keeps retrying that node waits through), after each leader change.
# This is what Retry's defaults must ride through (crates/anykms-core/src/retry.rs).
awk '
  function flush() {
    if (kind != "") printf "%s: longest outage %.2fs (node %s)\n", label, worst, worst_port
    delete since; worst = 0; worst_port = "-"
  }
  $2 == "event" {
    flush(); kind = $3; label = $3 " " $4; killed = ""
    if (kind == "kill") { match($0, /ha-[0-9]/); killed = 8400 + substr($0, RSTART + 3, 1) }
    next
  }
  kind == "" || $2 == killed { next }
  $4 == "ok" {
    if ($2 in since) {
      d = $1 - since[$2]
      if (d > worst) { worst = d; worst_port = $2 }
      delete since[$2]
    }
    next
  }
  !($2 in since) { since[$2] = $1 }
  END { flush() }
' "$TMP/raw.sorted" | grep -v '^starting' | tee "$TMP/windows" | sed 's/^/probe-failover: /' >&2

# Mask addresses and request-specific values so runs compare.
result=$(cat "$TMP"/seen.* 2>/dev/null |
  sed -E 's/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?/<addr>/g; s/ha-[123](:[0-9]+)?/<node>/g' |
  sort -u || true)

case "$mode" in
  run) printf '%s\n' "$result" ;;
  record)
    mkdir -p "$BASELINE_DIR"
    # Union with the existing baseline: a single run can miss responses that are timing-dependent.
    base="$BASELINE_DIR/$FLAVOR-$VERSION.txt"
    { printf '%s\n' "$result"; [ -f "$base" ] && cat "$base"; } | grep -v '^$' | sort -u >"$base.new"
    mv "$base.new" "$base"
    log "wrote $BASELINE_DIR/$FLAVOR-$VERSION.txt"
    ;;
  diff)
    base="$BASELINE_DIR/$FLAVOR-$VERSION.txt"
    [ -f "$base" ] || { log "no baseline $base"; exit 2; }
    new=$(comm -13 <(sort -u "$base") <(printf '%s\n' "$result" | sort -u))
    if [ -n "$new" ]; then
      log "responses not in the baseline (classify them in crates/anykms-transit/src/errors.rs):"
      printf '%s\n' "$new"
      exit 1
    fi
    log "no new responses"
    ;;
esac
