#!/usr/bin/env bash
# Start the Vault and OpenBao dev servers and run their one-shot init (mount transit, disable upsert).
# `docker compose up --wait` with the init services included exits 1 once they finish, so run them separately.
#
# Usage: scripts/dev-up.sh [--sealed] [--tls]
set -euo pipefail
cd "$(dirname "$0")/.."

# compose.yaml pins images by tag and digest and no longer reads the old tag-only variables;
# fail instead of silently running the default version.
if [ -n "${VAULT_VERSION:-}${OPENBAO_VERSION:-}" ]; then
  echo "dev-up: VAULT_VERSION/OPENBAO_VERSION are no longer read; set" \
    "VAULT_IMAGE=hashicorp/vault:<tag>@sha256:<digest> / OPENBAO_IMAGE=openbao/openbao:<tag>@sha256:<digest>" >&2
  exit 2
fi

docker compose up -d --wait vault openbao
docker compose run --rm vault-init
docker compose run --rm openbao-init

for arg in "$@"; do
  case "$arg" in
    --sealed)
      docker compose --profile sealed up -d --wait vault-sealed
      docker compose --profile sealed run --rm vault-sealed-init
      ;;
    --tls)
      mkdir -p .dev/tls/vault .dev/tls/openbao
      chmod 0777 .dev/tls/vault .dev/tls/openbao
      docker compose --profile tls up -d --wait vault-tls openbao-tls
      ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done
