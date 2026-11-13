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
# the package's live test targets, exactly one per target (a missing one fails the step instead
# of passing without running), and runs nothing if it finds any other file. The binaries
# themselves still need the build to be trusted: a build script can influence what they contain.
#
# `just live <package>` builds and runs in one go, for local use.
set -euo pipefail

# Called as `$(targets_for ...)`, its `exit` leaves only the subshell, and `set -e` does not see a
# failed substitution in a `for` list: the package is checked first, by `check_package`.
targets_for() {
  case "$1" in
    aws) echo "conformance_live" ;;
    gcp) echo "live conformance_live" ;;
    azure) echo "live conformance_azure" ;;
    *) echo "unknown package: $1" >&2; exit 2 ;;
  esac
}

# Exits the script for an unknown package (see `targets_for`).
check_package() {
  targets_for "$1" > /dev/null
}

# A test binary is named `<target>-<16 hex digit hash>`.
expected_name() {
  local package="$1" name="$2" t
  for t in $(targets_for "$package"); do
    [[ "$name" =~ ^${t}-[0-9a-f]{16}$ ]] && return 0
  done
  return 1
}

# Checks <dir> as a whole and sets `bins` to its binaries, one per live test target of <package>:
# every file must be a regular file (not a symlink) named after one of those targets, and every
# target must have exactly one binary. A missing target would otherwise pass a job without running.
check_dir() {
  local package="$1" dir="$2" exe t found
  shopt -s nullglob
  for exe in "$dir"/*; do
    if ! [ -f "$exe" ] || [ -L "$exe" ] || ! expected_name "$package" "$(basename "$exe")"; then
      echo "unexpected file in $dir: $(basename "$exe")" >&2
      exit 1
    fi
  done
  bins=()
  for t in $(targets_for "$package"); do
    found=()
    for exe in "$dir"/*; do
      [[ "$(basename "$exe")" =~ ^${t}-[0-9a-f]{16}$ ]] && found+=("$exe")
    done
    if [ "${#found[@]}" -ne 1 ]; then
      echo "expected exactly one $t binary in $dir, found ${#found[@]}" >&2
      exit 1
    fi
    bins+=("${found[0]}")
  done
}

case "${1:-}" in
  build)
    package="$2"
    dir="$3"
    check_package "$package"
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
    check_dir "$package" "$dir"
    ls -l "$dir"
    ;;
  run)
    package="$2"
    dir="$3"
    check_package "$package"
    shift 3
    check_dir "$package" "$dir"
    status=0
    for exe in "${bins[@]}"; do
      chmod +x "$exe"
      echo "== $(basename "$exe")"
      "$exe" "$@" || status=$?
    done
    exit "$status"
    ;;
  *)
    echo "usage: $0 build <aws|gcp|azure> <dir> | run <aws|gcp|azure> <dir> [args...]" >&2
    exit 2
    ;;
esac
