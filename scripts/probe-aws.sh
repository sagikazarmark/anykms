#!/usr/bin/env bash
# The A0 live probe of docs/cloud/aws.md: records AWS KMS behaviors the anykms-aws backend pins
# (encryption-context size limit, KeyId formats through aliases, every error body and header of
# the mapping table, verification-failure shapes, input limits, clock skew) as raw JSON
# responses, for docs/research/aws-kms.md.
#
# Usage: scripts/probe-aws.sh [out-dir]          (real AWS: default credential chain)
#        ANYKMS_PROBE_ENDPOINT=http://127.0.0.1:4566 scripts/probe-aws.sh /tmp/floci-probe
#
# Needs AWS_REGION (or ANYKMS_PROBE_REGION) and credentials allowed to create, alias, disable,
# rotate and schedule deletion of keys. It cleans up after itself: every probe key, tagged
# anykms-probe, is scheduled for deletion with a 7-day window. Optional:
# ANYKMS_PROBE_DENIED_ACCESS_KEY_ID / ANYKMS_PROBE_DENIED_SECRET_ACCESS_KEY for AccessDenied.
# Never point it at a production account.
set -euo pipefail

out="${1:-docs/research/aws-probe}"
if [ -z "${ANYKMS_PROBE_ENDPOINT:-}" ] && [ -z "${AWS_REGION:-}${ANYKMS_PROBE_REGION:-}" ]; then
  echo "set AWS_REGION (or ANYKMS_PROBE_REGION), or ANYKMS_PROBE_ENDPOINT for an emulator" >&2
  exit 2
fi
export ANYKMS_PROBE_REGION="${ANYKMS_PROBE_REGION:-${AWS_REGION:-us-east-1}}"
if [ -n "${ANYKMS_PROBE_ENDPOINT:-}" ]; then
  # Emulators accept any credentials.
  export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}" AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
fi
mkdir -p "$out"
ANYKMS_PROBE_OUT="$out" cargo run -q -p anykms-aws --example probe
echo "Compare with docs/research/aws-kms.md and update the values marked 'to verify with A0'."
