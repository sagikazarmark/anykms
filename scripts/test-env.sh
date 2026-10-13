#!/usr/bin/env bash
# Runs a command with every credential-shaped variable and the live-test toggles removed from the
# environment (devenv loads .env into every shell, and every `cargo` build script would see it).
# Removed by name: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, any name
# containing ROOT, SECRET or PASSWORD, or ending in _TOKEN or _KEY_ID, and ANYKMS_*_LIVE. The
# rest of the environment (the devenv toolchain: the C compiler aws-lc-sys needs) is kept; a few
# build variables that merely contain ROOT are kept too.
#
# Emulator and mock runs need nothing else:
#   scripts/test-env.sh env RUSTFLAGS=-Dwarnings cargo test -p anykms-aws --test mock
#
# A live run opts in explicitly: --dotenv loads ./.env inside the wrapper (after the strip), then
# removes the root/admin keys (names containing ROOT) and the live toggles again, so the toggle
# must be on the command line:
#   scripts/test-env.sh --dotenv env ANYKMS_AWS_LIVE=1 cargo test -p anykms-aws --test conformance_live
set -euo pipefail

# Build variables that contain ROOT but are no credentials.
keep() {
  case "$1" in
    SDKROOT | DEVENV_ROOT | CARGO_INSTALL_ROOT) return 0 ;;
    *) return 1 ;;
  esac
}

# `unset` for each variable `$1` selects: `all` (credentials and toggles) or `root` (names
# containing ROOT, and toggles).
strip() {
  local name
  for name in $(compgen -e); do
    keep "$name" && continue
    case "$1:$name" in
      all:AWS_ACCESS_KEY_ID | all:AWS_SECRET_ACCESS_KEY | all:AWS_SESSION_TOKEN | \
        all:*SECRET* | all:*PASSWORD* | all:*_TOKEN | all:*_KEY_ID | \
        *:*ROOT* | *:ANYKMS_*_LIVE)
        unset "$name"
        ;;
    esac
  done
}

dotenv=0
if [ "${1:-}" = "--dotenv" ]; then
  dotenv=1
  shift
fi

strip all
if [ "$dotenv" = 1 ]; then
  if [ ! -f .env ]; then
    echo "test-env.sh: --dotenv: no .env in $PWD" >&2
    exit 1
  fi
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
  strip root
fi
exec "$@"
