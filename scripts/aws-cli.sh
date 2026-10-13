#!/usr/bin/env bash
# The AWS CLI v2 in Docker, for machines without it (setup scripts and probes). Forwards the
# AWS_* credential and region variables of the calling environment; mounts the current directory
# and $TMPDIR (default /tmp) so file:// arguments work. Usage: scripts/aws-cli.sh <aws args>
set -euo pipefail
tmp="${TMPDIR:-/tmp}"
exec docker run --rm -i -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
  -e AWS_REGION -e AWS_DEFAULT_REGION -v "$PWD:$PWD" -v "$tmp:$tmp" -w "$PWD" \
  "${AWS_CLI_IMAGE:-amazon/aws-cli:2.31.0@sha256:3b018ce74732c98acf6f1de59b3a89587cb7f9eb6ea0d1447d1779091b2bf057}" "$@"
