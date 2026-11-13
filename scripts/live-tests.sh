#!/usr/bin/env bash
# Builds and runs the live-cloud test binaries in two separate steps, so that CI can build them in
# a job that holds no cloud credential and no OIDC permission, and run them in a job that compiles
# nothing (see the *-live jobs in .github/workflows/ci.yaml). A build script or proc-macro of any
# dependency then never runs where a cloud token can be minted or read.
#
#   scripts/live-tests.sh build <aws|gcp|azure> <dir>   build the binaries into <dir>
#   scripts/live-tests.sh run <dir> [test args...]       run every binary in <dir>
#
# `just live <package>` builds and runs in one go, for local use.
set -euo pipefail

tests_for() {
  case "$1" in
    aws) echo "--test conformance_live" ;;
    gcp) echo "--test live --test conformance_live" ;;
    azure) echo "--test live --test conformance_azure" ;;
    *) echo "unknown package: $1" >&2; exit 2 ;;
  esac
}

case "${1:-}" in
  build)
    package="$2"
    dir="$3"
    mkdir -p "$dir"
    # shellcheck disable=SC2046 # word splitting of the --test flags is intended
    cargo test -p "anykms-$package" --all-features --locked $(tests_for "$package") \
      --no-run --message-format=json \
      | jq -r 'select(.reason == "compiler-artifact" and .profile.test == true) | .executable // empty' \
      | while read -r exe; do cp "$exe" "$dir/"; done
    if [ -z "$(ls -A "$dir")" ]; then
      echo "no test binaries built for $package" >&2
      exit 1
    fi
    ls -l "$dir"
    ;;
  run)
    dir="$2"
    shift 2
    status=0
    for exe in "$dir"/*; do
      chmod +x "$exe"
      echo "== $(basename "$exe")"
      "$exe" "$@" || status=$?
    done
    exit "$status"
    ;;
  *)
    echo "usage: $0 build <aws|gcp|azure> <dir> | run <dir> [args...]" >&2
    exit 2
    ;;
esac
