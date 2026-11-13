#!/usr/bin/env bash
# Build and start a fresh AWS Emulator (compose.yaml, profile aws-emulator) and wait until it is
# healthy. It keeps keys in memory and holds at most 500 (a full `just integration aws` run makes
# about 130), so it is recreated on every call. It writes its per-run credentials and the CA of
# its certificate to .dev/aws-emulator/9297/, readable by their owner only, so it runs as the
# calling user; creating the directory first keeps Docker from creating it owned by root.
#
# Usage: scripts/aws-emulator-up.sh
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p .dev/aws-emulator

AWS_EMULATOR_UID="$(id -u)" AWS_EMULATOR_GID="$(id -g)" \
  docker compose --profile aws-emulator up -d --build --force-recreate --wait aws-emulator
