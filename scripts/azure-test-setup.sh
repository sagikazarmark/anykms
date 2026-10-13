#!/usr/bin/env bash
# Provisions what the live Azure tests and the probe need, with the Azure CLI (`az login` first).
#
# Usage:
#   scripts/azure-test-setup.sh vault-up        resource group, an RBAC key vault, pooled keys;
#                                               prints the environment for the live tests
#   scripts/azure-test-setup.sh oidc REPO       an Entra app with a GitHub OIDC federated
#                                               credential for REPO (owner/name, main branch and
#                                               workflow_dispatch/schedule runs), Key Vault Crypto
#                                               Officer on the vault; prints the repository
#                                               variables for the azure-live CI job
#   scripts/azure-test-setup.sh janitor         deletes and purges fixture keys (anykms-*,
#                                               probe-*) older than a day
#   scripts/azure-test-setup.sh mhsm-up         a Managed HSM: create, activate (security domain
#                                               with 3 generated RSA keys under .dev/azure-mhsm/),
#                                               local RBAC for the caller; ~$3.20/h until mhsm-down
#   scripts/azure-test-setup.sh mhsm-down       deletes and purges the Managed HSM
#   scripts/azure-test-setup.sh down            deletes the resource group (and purges the vault)
#
# Settings (environment): ANYKMS_AZURE_RG (default anykms-test), ANYKMS_AZURE_LOCATION (default
# westeurope), ANYKMS_AZURE_VAULT_NAME (default anykms-<subscription hash>),
# ANYKMS_AZURE_MHSM_NAME (default anykms-mhsm-<hash>), ANYKMS_AZURE_APP_NAME (default
# anykms-ci). Needs az and jq (and openssl for mhsm-up).
set -euo pipefail

usage() {
  sed -n '4,22p' "$0" >&2
  exit 2
}

[ $# -ge 1 ] || usage
cmd=$1
shift

for tool in az jq; do
  command -v "$tool" >/dev/null || { echo "azure-test-setup: $tool is required" >&2; exit 2; }
done

SUB=$(az account show --query id -o tsv)
HASH=$(printf '%s' "$SUB" | sha256sum | cut -c1-8)
RG=${ANYKMS_AZURE_RG:-anykms-test}
LOCATION=${ANYKMS_AZURE_LOCATION:-westeurope}
VAULT=${ANYKMS_AZURE_VAULT_NAME:-anykms-$HASH}
MHSM=${ANYKMS_AZURE_MHSM_NAME:-anykms-mhsm-$HASH}
APP=${ANYKMS_AZURE_APP_NAME:-anykms-ci}
VAULT_URL="https://$VAULT.vault.azure.net"
SCOPE="/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.KeyVault/vaults/$VAULT"

me() {
  az ad signed-in-user show --query id -o tsv 2>/dev/null \
    || az account show --query user.name -o tsv
}

vault_up() {
  az group create -n "$RG" -l "$LOCATION" -o none
  if ! az keyvault show -n "$VAULT" -o none 2>/dev/null; then
    # Purge protection stays off (the default; Azure refuses an explicit false) so the janitor
    # can purge test keys.
    az keyvault create -n "$VAULT" -g "$RG" -l "$LOCATION" --enable-rbac-authorization true \
      --retention-days 7 -o none
  fi
  az role assignment create --assignee "$(me)" --role "Key Vault Crypto Officer" --scope "$SCOPE" -o none || true
  echo "waiting for the role assignment to propagate..." >&2
  sleep 30
  # Pooled keys (long-lived; tests that need fresh keys create their own).
  az keyvault key show --vault-name "$VAULT" -n pool-kek -o none 2>/dev/null \
    || az keyvault key create --vault-name "$VAULT" -n pool-kek --kty RSA --size 2048 --ops wrapKey unwrapKey -o none
  az keyvault key show --vault-name "$VAULT" -n pool-ec -o none 2>/dev/null \
    || az keyvault key create --vault-name "$VAULT" -n pool-ec --kty EC --curve P-256 --ops sign verify -o none
  az keyvault key show --vault-name "$VAULT" -n pool-rsa -o none 2>/dev/null \
    || az keyvault key create --vault-name "$VAULT" -n pool-rsa --kty RSA --size 2048 --ops sign verify -o none
  cat <<EOF
export ANYKMS_AZURE_LIVE=1
export ANYKMS_AZURE_VAULT_URL=$VAULT_URL
export ANYKMS_AZURE_KEK_URI=azure-kv://$VAULT.vault.azure.net/keys/pool-kek
export ANYKMS_AZURE_EC_URI=azure-kv://$VAULT.vault.azure.net/keys/pool-ec
export ANYKMS_AZURE_RSA_URI=azure-kv://$VAULT.vault.azure.net/keys/pool-rsa
# Credentials (read from the environment): AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET
# for an app (the Azure CLI is not a built-in credential).
EOF
}

oidc() {
  local repo=${1:?repository owner/name}
  local app_id
  app_id=$(az ad app list --display-name "$APP" --query '[0].appId' -o tsv)
  if [ -z "$app_id" ]; then
    app_id=$(az ad app create --display-name "$APP" --query appId -o tsv)
    az ad sp create --id "$app_id" -o none
  fi
  local obj
  obj=$(az ad app show --id "$app_id" --query id -o tsv)
  for subject in "repo:$repo:ref:refs/heads/main"; do
    local name
    name=$(printf '%s' "$subject" | tr -c 'A-Za-z0-9-' '-' | cut -c1-120)
    az ad app federated-credential create --id "$obj" --parameters "$(jq -n \
      --arg n "$name" --arg s "$subject" \
      '{name: $n, issuer: "https://token.actions.githubusercontent.com", subject: $s, audiences: ["api://AzureADTokenExchange"]}')" \
      -o none 2>/dev/null || true
  done
  az role assignment create --assignee "$app_id" --role "Key Vault Crypto Officer" --scope "$SCOPE" -o none || true
  cat <<EOF
GitHub repository variables (Settings > Secrets and variables > Actions > Variables):
  AZURE_CLIENT_ID=$app_id
  AZURE_TENANT_ID=$(az account show --query tenantId -o tsv)
  ANYKMS_AZURE_VAULT_URL=$VAULT_URL
  ANYKMS_AZURE_KEK_URI=azure-kv://$VAULT.vault.azure.net/keys/pool-kek
  ANYKMS_AZURE_EC_URI=azure-kv://$VAULT.vault.azure.net/keys/pool-ec
  ANYKMS_AZURE_RSA_URI=azure-kv://$VAULT.vault.azure.net/keys/pool-rsa
Scheduled and manual runs on main get tokens for subject repo:$repo:ref:refs/heads/main.
EOF
}

janitor() {
  local vault=$VAULT
  if [ -n "${ANYKMS_AZURE_VAULT_URL:-}" ]; then
    vault=${ANYKMS_AZURE_VAULT_URL#https://}
    vault=${vault%%.*}
  fi
  local cutoff
  cutoff=$(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%S)
  az keyvault key list --vault-name "$vault" -o json \
    | jq -r --arg c "$cutoff" '.[] | select((.name | test("^(anykms|probe)-[0-9]")) and .attributes.created < $c) | .name' \
    | while read -r name; do
        echo "deleting $name" >&2
        az keyvault key delete --vault-name "$vault" -n "$name" -o none || true
      done
  az keyvault key list-deleted --vault-name "$vault" -o json \
    | jq -r '.[] | select(.name | test("^(anykms|probe)-[0-9]")) | .name' \
    | while read -r name; do
        az keyvault key purge --vault-name "$vault" -n "$name" -o none || true
      done
}

mhsm_up() {
  command -v openssl >/dev/null || { echo "azure-test-setup: openssl is required" >&2; exit 2; }
  az group create -n "$RG" -l "$LOCATION" -o none
  local admin
  admin=$(me)
  if ! az keyvault show --hsm-name "$MHSM" -o none 2>/dev/null; then
    az keyvault create --hsm-name "$MHSM" -g "$RG" -l "$LOCATION" --administrators "$admin" \
      --retention-days 7 -o none
  fi
  local dir=.dev/azure-mhsm
  mkdir -p "$dir"
  if [ ! -f "$dir/sd.json" ]; then
    for i in 0 1 2; do
      openssl req -newkey rsa:2048 -nodes -keyout "$dir/sd$i.key" -x509 -days 30 \
        -subj "/CN=anykms-sd-$i" -out "$dir/sd$i.cer" 2>/dev/null
    done
    az keyvault security-domain download --hsm-name "$MHSM" --sd-wrapping-keys \
      "$dir/sd0.cer" "$dir/sd1.cer" "$dir/sd2.cer" --sd-quorum 2 --security-domain-file "$dir/sd.json"
  fi
  az keyvault role assignment create --hsm-name "$MHSM" --role "Managed HSM Crypto Officer" \
    --assignee "$admin" --scope /keys -o none || true
  az keyvault role assignment create --hsm-name "$MHSM" --role "Managed HSM Crypto User" \
    --assignee "$admin" --scope /keys -o none || true
  cat <<EOF
export ANYKMS_AZURE_LIVE=1
export ANYKMS_AZURE_MHSM_URL=https://$MHSM.managedhsm.azure.net
# Then: cargo test -p anykms-azure --all-features --test conformance_mhsm
#       scripts/probe-azure.sh record https://$MHSM.managedhsm.azure.net --mhsm
# And:  scripts/azure-test-setup.sh mhsm-down   (it bills until purged)
EOF
}

mhsm_down() {
  az keyvault delete --hsm-name "$MHSM" -o none || true
  az keyvault purge --hsm-name "$MHSM" -l "$LOCATION" -o none || true
}

down() {
  az group delete -n "$RG" --yes
  az keyvault purge -n "$VAULT" -l "$LOCATION" -o none || true
}

case $cmd in
  vault-up) vault_up ;;
  oidc) oidc "$@" ;;
  janitor) janitor ;;
  mhsm-up) mhsm_up ;;
  mhsm-down) mhsm_down ;;
  down) down ;;
  *) usage ;;
esac
