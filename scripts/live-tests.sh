#!/usr/bin/env bash
# Builds and runs the live-cloud test binaries in two separate steps, so that CI can build them in
# a job that holds no cloud credential and no OIDC permission, and run them in a job that compiles
# nothing (see the *-live jobs in .github/workflows/ci.yaml). A build script or proc-macro of any
# dependency then never runs where a cloud token can be minted or read.
#
#   scripts/live-tests.sh build <aws|gcp|azure> <dir>   build the binaries into <dir>
#   scripts/live-tests.sh run <aws|gcp|azure> <dir> [test args...]
#                                                        run the expected binaries in <dir>
#
# What crosses from the build job to the run job is limited to the test binaries Cargo reported:
# <dir> must not exist while Cargo runs (a build script could otherwise drop an extra executable
# into it), it is created only after Cargo exits, and `run` executes only the files named after
# the package's live test targets, never anything else it finds. The binaries themselves still
# need the build to be trusted: a build script can influence what they contain.
#
# `just live <package>` builds and runs in one go, for local use.
set -euo pipefail

targets_for() {
  case "$1" in
    aws) echo "conformance_live" ;;
    gcp) echo "live conformance_live" ;;
    azure) echo "live conformance_azure" ;;
    *) echo "unknown package: $1" >&2; exit 2 ;;
  esac
}

# A test binary is named `<target>-<16 hex digit hash>`.
expected_name() {
  local package="$1" name="$2" t
  for t in $(targets_for "$package"); do
    [[ "$name" =~ ^${t}-[0-9a-f]{16}$ ]] && return 0
  done
  return 1
}

case "${1:-}" in
  build)
    package="$2"
    dir="$3"
    flags=()
    for t in $(targets_for "$package"); do flags+=(--test "$t"); done
    if [ -e "$dir" ]; then
      echo "$dir already exists; refusing to reuse it" >&2
      exit 1
    fi
    list="$(mktemp)"
    trap 'rm -f "$list"' EXIT
    # json-render-diagnostics: Cargo renders compiler errors on stderr (so a failed build shows them
    # in the log) and keeps only the JSON artifact records on stdout.
    cargo test -p "anykms-$package" --all-features --locked "${flags[@]}" \
      --no-run --message-format=json-render-diagnostics \
      | jq -r 'select(.reason == "compiler-artifact" and .profile.test == true) | .executable // empty' \
      > "$list"
    mkdir "$dir"
    while read -r exe; do
      expected_name "$package" "$(basename "$exe")" || {
        echo "unexpected test binary: $exe" >&2
        exit 1
      }
      cp "$exe" "$dir/"
    done < "$list"
    if [ -z "$(ls -A "$dir")" ]; then
      echo "no test binaries built for $package" >&2
      exit 1
    fi
    ls -l "$dir"
    ;;
  run)
    package="$2"
    dir="$3"
    shift 3
    targets_for "$package" >/dev/null
    status=0
    ran=0
    for exe in "$dir"/*; do
      name="$(basename "$exe")"
      if ! [ -f "$exe" ] || [ -L "$exe" ] || ! expected_name "$package" "$name"; then
        echo "refusing to run unexpected file: $name" >&2
        status=1
        continue
      fi
      chmod +x "$exe"
      echo "== $name"
      "$exe" "$@" || status=$?
      ran=$((ran + 1))
    done
    if [ "$ran" -eq 0 ]; then
      echo "no test binaries for $package in $dir" >&2
      exit 1
    fi
    exit "$status"
    ;;
  *)
    echo "usage: $0 build <aws|gcp|azure> <dir> | run <aws|gcp|azure> <dir> [args...]" >&2
    exit 2
    ;;
esac
