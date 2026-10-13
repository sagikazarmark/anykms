#!/usr/bin/env bash
# Provisions (idempotently) the Google Cloud resources anykms-gcp's live tests, live conformance
# run and probe use, and sweeps what the conformance fixture leaves behind.
#
# Usage:
#   scripts/gcp-test-setup.sh setup    create the key ring, pooled keys, service accounts, IAM
#                                      bindings and the GitHub workload identity pool
#   scripts/gcp-test-setup.sh env      print the environment for local live runs
#   scripts/gcp-test-setup.sh sweep    schedule destruction of every version of the fixture's
#                                      keys (t-*) and the probe's keys (probe-*) older than a day
#
# Variables: PROJECT (required), LOCATION (default global), KEY_RING (default anykms-test),
# GITHUB_REPO (default sagikazarmark/anykms), POOL (default anykms-github), HSM=1 to also
# create an HSM key (billed per month while not destroyed). Needs gcloud (authenticated as a
# project owner for setup) and jq.
#
# Cloud KMS key rings and keys cannot be deleted; versions are destroyed after their
# destroyScheduledDuration (24 h for the fixture's keys) and are not billed afterwards. Expect
# roughly 60 key versions per live conformance run.
set -euo pipefail

usage() {
  sed -n '5,18p' "$0" >&2
  exit 2
}

[ $# -eq 1 ] || usage
mode=$1
PROJECT=${PROJECT:?set PROJECT}
LOCATION=${LOCATION:-global}
KEY_RING=${KEY_RING:-anykms-test}
GITHUB_REPO=${GITHUB_REPO:-sagikazarmark/anykms}
POOL=${POOL:-anykms-github}
RING="projects/$PROJECT/locations/$LOCATION/keyRings/$KEY_RING"

for tool in gcloud jq; do
  command -v "$tool" >/dev/null || { echo "gcp-test-setup: $tool is required" >&2; exit 2; }
done

g() { gcloud --project "$PROJECT" --quiet "$@"; }

# Pooled keys: name, purpose, algorithm (gcloud spelling), protection level.
POOLED=(
  "aead encryption google-symmetric-encryption software"
  "ec-p256 asymmetric-signing ec-sign-p256-sha256 software"
  "ec-p384 asymmetric-signing ec-sign-p384-sha384 software"
  "rsa-pss-2048 asymmetric-signing rsa-sign-pss-2048-sha256 software"
  "rsa-pss-4096-sha512 asymmetric-signing rsa-sign-pss-4096-sha512 software"
  "rsa-pkcs1-2048 asymmetric-signing rsa-sign-pkcs1-2048-sha256 software"
  "rsa-pkcs1-4096-sha512 asymmetric-signing rsa-sign-pkcs1-4096-sha512 software"
  "ed25519 asymmetric-signing ec-sign-ed25519 software"
  "hmac-sha256 mac hmac-sha256 software"
  "hmac-sha384 mac hmac-sha384 software"
  "hmac-sha512 mac hmac-sha512 software"
  "rsa-oaep-2048 asymmetric-encryption rsa-decrypt-oaep-2048-sha256 software"
)
if [ "${HSM:-}" = 1 ]; then
  POOLED+=("hsm-aead encryption google-symmetric-encryption hsm")
fi

SA_DATA="anykms-data@$PROJECT.iam.gserviceaccount.com"
SA_ADMIN="anykms-admin@$PROJECT.iam.gserviceaccount.com"
SA_NOROLES="anykms-noroles@$PROJECT.iam.gserviceaccount.com"

setup() {
  g services enable cloudkms.googleapis.com iamcredentials.googleapis.com sts.googleapis.com \
    iam.googleapis.com
  if ! g kms keyrings describe "$KEY_RING" --location "$LOCATION" >/dev/null 2>&1; then
    g kms keyrings create "$KEY_RING" --location "$LOCATION"
  fi
  for spec in "${POOLED[@]}"; do
    read -r name purpose alg level <<<"$spec"
    if ! g kms keys describe "$name" --keyring "$KEY_RING" --location "$LOCATION" >/dev/null 2>&1
    then
      g kms keys create "$name" --keyring "$KEY_RING" --location "$LOCATION" \
        --purpose "$purpose" --default-algorithm "$alg" --protection-level "$level"
    fi
  done

  for sa in anykms-data anykms-admin anykms-noroles; do
    if ! g iam service-accounts describe "$sa@$PROJECT.iam.gserviceaccount.com" >/dev/null 2>&1
    then
      g iam service-accounts create "$sa" --display-name "anykms tests ($sa)"
    fi
  done
  # The data-plane identity: the operational roles plus metadata reads (describe, the key-type
  # check) on the key ring, so a missing key is NotFound rather than PermissionDenied. Never
  # admin.
  for role in roles/cloudkms.cryptoKeyEncrypterDecrypter roles/cloudkms.signerVerifier \
    roles/cloudkms.publicKeyViewer roles/cloudkms.viewer; do
    g kms keyrings add-iam-policy-binding "$KEY_RING" --location "$LOCATION" \
      --member "serviceAccount:$SA_DATA" --role "$role" >/dev/null
  done
  # The fixture's admin identity: creates, rotates, disables and destroys test keys.
  g kms keyrings add-iam-policy-binding "$KEY_RING" --location "$LOCATION" \
    --member "serviceAccount:$SA_ADMIN" --role roles/cloudkms.admin >/dev/null
  g kms keyrings add-iam-policy-binding "$KEY_RING" --location "$LOCATION" \
    --member "serviceAccount:$SA_ADMIN" --role roles/cloudkms.cryptoKeyEncrypterDecrypter \
    >/dev/null

  # GitHub Actions OIDC → workload identity federation, limited to the repository's main branch
  # (the nightly schedule runs there).
  local number
  number=$(g projects describe "$PROJECT" --format 'value(projectNumber)')
  if ! g iam workload-identity-pools describe "$POOL" --location global >/dev/null 2>&1; then
    g iam workload-identity-pools create "$POOL" --location global \
      --display-name "anykms GitHub Actions"
  fi
  if ! g iam workload-identity-pools providers describe github --location global \
    --workload-identity-pool "$POOL" >/dev/null 2>&1; then
    g iam workload-identity-pools providers create-oidc github --location global \
      --workload-identity-pool "$POOL" \
      --issuer-uri https://token.actions.githubusercontent.com \
      --attribute-mapping 'google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref' \
      --attribute-condition "assertion.repository == '$GITHUB_REPO' && assertion.ref == 'refs/heads/main'"
  fi
  local principal="principalSet://iam.googleapis.com/projects/$number/locations/global/workloadIdentityPools/$POOL/attribute.repository/$GITHUB_REPO"
  for sa in "$SA_DATA" "$SA_ADMIN" "$SA_NOROLES"; do
    g iam service-accounts add-iam-policy-binding "$sa" \
      --role roles/iam.workloadIdentityUser --member "$principal" >/dev/null
  done

  cat <<EOF
Done. GitHub variables of the environment cloud-gcp:
  ANYKMS_GCP_KEY_RING=$RING
  GCP_WORKLOAD_IDENTITY_PROVIDER=projects/$number/locations/global/workloadIdentityPools/$POOL/providers/github
  GCP_DATA_SERVICE_ACCOUNT=$SA_DATA
  GCP_ADMIN_SERVICE_ACCOUNT=$SA_ADMIN
  GCP_UNAUTHORIZED_SERVICE_ACCOUNT=$SA_NOROLES
Then enable the nightly gcp-live job with a repository-level variable (not an environment
variable: the job's condition cannot read those):
  ANYKMS_GCP_LIVE=true
EOF
}

env_vars() {
  cat <<EOF
export ANYKMS_GCP_LIVE=1
export ANYKMS_GCP_KEY_RING=$RING
export ANYKMS_GCP_ADMIN_TOKEN=\$(gcloud auth print-access-token)
# Data plane: Application Default Credentials (gcloud auth application-default login), or
# impersonate the data-plane identity:
#   gcloud auth application-default login --impersonate-service-account $SA_DATA
# The request-counting provider needs a static data-plane token when the admin token cannot
# sign (the admin identity has no signerVerifier role):
export ANYKMS_GCP_DATA_TOKEN=\$(gcloud auth print-access-token --impersonate-service-account $SA_DATA)
EOF
  if [ "${HSM:-}" = 1 ]; then echo "export ANYKMS_GCP_HSM=1"; fi
  if [ "$LOCATION" != global ]; then echo "export ANYKMS_GCP_REGIONAL=1"; fi
}

sweep() {
  local cutoff
  cutoff=$(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null ||
    date -u -v-1d +%Y-%m-%dT%H:%M:%SZ)
  g kms keys list --keyring "$KEY_RING" --location "$LOCATION" --format json |
    jq -r --arg c "$cutoff" '.[] | select((.name | split("/") | last | test("^(t|probe)-"))
      and .createTime < $c) | .name' |
    while read -r key; do
      g kms keys versions list --key "$key" --format json |
        jq -r '.[] | select(.state == "ENABLED" or .state == "DISABLED") | .name' |
        while read -r version; do
          echo "destroying $version"
          g kms keys versions destroy "${version##*/}" --key "$key" >/dev/null
        done
    done
}

case "$mode" in
  setup) setup ;;
  env) env_vars ;;
  sweep) sweep ;;
  *) usage ;;
esac
