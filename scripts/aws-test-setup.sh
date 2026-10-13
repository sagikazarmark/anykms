#!/usr/bin/env bash
# Provisions the AWS test account for the live conformance run (crates/anykms-aws/tests/e2e):
#
#   scripts/aws-test-setup.sh pool      create the pooled long-lived keys (one per kind, and one
#                                       HMAC key per algorithm) and print
#                                       the ANYKMS_AWS_KEY_* values for CI repository variables
#   scripts/aws-test-setup.sh policy    print the IAM policy and the GitHub OIDC trust policy of
#                                       the CI role
#   scripts/aws-test-setup.sh cleanup   schedule deletion (7 days) of every key tagged
#                                       anykms-conformance=fresh/shared or anykms-probe that is
#                                       still enabled (left behind by an interrupted run)
#
# Needs the AWS CLI v2 (or scripts/aws-cli.sh) and AWS_REGION. `pool` and `policy` run with admin
# credentials of a dedicated test account; `cleanup` runs as the test identity (the anykms-test
# user or the CI role), which the permissions policy below allows (kms:ListResourceTags).
# Pooled keys cost the KMS monthly per-key price; GitHub's nightly run creates a few fresh keys
# per run (rotation and disable cases) and schedules them for deletion when it ends.
set -euo pipefail

region="${AWS_REGION:?set AWS_REGION}"
repo="${ANYKMS_GITHUB_REPOSITORY:-sagikazarmark/anykms}"

create() { # spec usage name
  aws kms create-key --region "$region" --key-spec "$1" --key-usage "$2" \
    --description "anykms conformance pool: $3" \
    --tags TagKey=anykms-conformance,TagValue=pool \
    --query KeyMetadata.Arn --output text
}

case "${1:-}" in
  pool)
    echo "ANYKMS_AWS_KEY_AEAD=$(create SYMMETRIC_DEFAULT ENCRYPT_DECRYPT aead)"
    echo "ANYKMS_AWS_KEY_HMAC=$(create HMAC_256 GENERATE_VERIFY_MAC hmac)"
    echo "ANYKMS_AWS_KEY_HMAC_384=$(create HMAC_384 GENERATE_VERIFY_MAC hmac-384)"
    echo "ANYKMS_AWS_KEY_HMAC_512=$(create HMAC_512 GENERATE_VERIFY_MAC hmac-512)"
    echo "ANYKMS_AWS_KEY_P256=$(create ECC_NIST_P256 SIGN_VERIFY p256)"
    echo "ANYKMS_AWS_KEY_P384=$(create ECC_NIST_P384 SIGN_VERIFY p384)"
    echo "ANYKMS_AWS_KEY_P521=$(create ECC_NIST_P521 SIGN_VERIFY p521)"
    echo "ANYKMS_AWS_KEY_RSA_SIGN=$(create RSA_2048 SIGN_VERIFY rsa-sign)"
    echo "ANYKMS_AWS_KEY_ED25519=$(create ECC_NIST_EDWARDS25519 SIGN_VERIFY ed25519)"
    echo "ANYKMS_AWS_KEY_RSA_WRAP=$(create RSA_2048 ENCRYPT_DECRYPT rsa-wrap)"
    echo "AWS_LIVE_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)"
    echo "AWS_LIVE_REGION=$region"
    ;;
  policy)
    account="$(aws sts get-caller-identity --query Account --output text)"
    cat <<JSON
# Trust policy of the CI role (GitHub OIDC; the provider token.actions.githubusercontent.com
# must exist in the account). Scheduled and manual runs of the default branch only.
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::$account:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:$repo:ref:refs/heads/main"
      }
    }
  }]
}

# Permissions policy of the CI role: data plane on every key of the account in $region, and the
# management actions the fixture needs for its fresh keys (tagged on creation), and the tag read
# that the cleanup command needs.
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt", "kms:Decrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo",
        "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:DescribeKey",
        "kms:Sign", "kms:Verify", "kms:GetPublicKey", "kms:GenerateMac", "kms:VerifyMac",
        "kms:RotateKeyOnDemand", "kms:DisableKey", "kms:ScheduleKeyDeletion",
        "kms:ListResourceTags"
      ],
      "Resource": "arn:aws:kms:$region:$account:key/*"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:CreateKey", "kms:TagResource", "kms:ListKeys"],
      "Resource": "*",
      "Condition": {"StringEquals": {"aws:RequestTag/anykms-conformance": ["fresh", "shared"]}}
    },
    {"Effect": "Allow", "Action": ["kms:ListKeys"], "Resource": "*"}
  ]
}
JSON
    ;;
  cleanup)
    for key in $(aws kms list-keys --region "$region" --query 'Keys[].KeyArn' --output text); do
      tags="$(aws kms list-resource-tags --region "$region" --key-id "$key" \
        --query "Tags[?TagKey=='anykms-conformance' || TagKey=='anykms-probe'].TagValue" \
        --output text 2>/dev/null || true)"
      case "$tags" in
        *fresh*|*shared*|1)
          state="$(aws kms describe-key --region "$region" --key-id "$key" --query KeyMetadata.KeyState --output text)"
          if [ "$state" != "PendingDeletion" ]; then
            echo "scheduling deletion of $key ($state)"
            aws kms schedule-key-deletion --region "$region" --key-id "$key" --pending-window-in-days 7 >/dev/null
          fi
          ;;
      esac
    done
    ;;
  *)
    sed -n '2,17p' "$0"
    exit 2
    ;;
esac
