#!/usr/bin/env bash
# Builds each published crate's documentation the way docs.rs does: on nightly, with the features
# and rustdoc arguments of its `[package.metadata.docs.rs]` (so `--cfg docsrs`, which enables
# `doc_cfg`), one crate at a time (no feature unification across the workspace), and with rustdoc
# warnings denied (a broken intra-doc link under the docs.rs features fails).
#
# Usage: scripts/docs-rs.sh [crate...]   (default: every crate that is not `publish = false`)
# The toolchain is the one on PATH when it is a nightly (`devenv --profile nightly shell`), or
# else rustup's `nightly`, or rustup's $DOCS_RS_TOOLCHAIN when set.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -z "${DOCS_RS_TOOLCHAIN:-}" ] && rustc -V | grep -q -- '-nightly'; then
  cargo="$(command -v cargo)"
  rustc="$(command -v rustc)"
  rustdoc="$(command -v rustdoc)"
else
  toolchain="${DOCS_RS_TOOLCHAIN:-nightly}"
  # By path: a toolchain manager (devenv, nix) may put another rustdoc first on PATH.
  cargo="$(rustup which --toolchain "$toolchain" cargo)"
  rustc="$(rustup which --toolchain "$toolchain" rustc)"
  rustdoc="$(rustup which --toolchain "$toolchain" rustdoc)"
fi
metadata="$(cargo metadata --no-deps --format-version 1 --locked)"

if [ "$#" -gt 0 ]; then
  crates=("$@")
else
  # `publish = false` shows as an empty list; publishable crates have null.
  crates=()
  while IFS= read -r c; do crates+=("$c"); done < <(jq -r '.packages[] | select(.publish != []) | .name' <<<"$metadata" | sort)
fi

for crate in "${crates[@]}"; do
  meta="$(jq -c --arg n "$crate" '.packages[] | select(.name == $n) | .metadata.docs.rs // {}' <<<"$metadata")"
  args=()
  if [ "$(jq -r '."all-features" // false' <<<"$meta")" = true ]; then
    args+=(--all-features)
  fi
  if [ "$(jq -r '."no-default-features" // false' <<<"$meta")" = true ]; then
    args+=(--no-default-features)
  fi
  features="$(jq -r '(.features // []) | join(",")' <<<"$meta")"
  # A hand-written list must name every public feature: all but `default` and `__*`.
  missing="$(jq -r --arg n "$crate" --argjson m "$meta" '.packages[] | select(.name == $n)
    | if $m."all-features" == true then [] else
        (.features | keys) - ($m.features // []) - ["default"] | map(select(startswith("__") | not))
      end | join(", ")' <<<"$metadata")"
  if [ -n "$missing" ]; then
    echo "$crate: [package.metadata.docs.rs] leaves out the features $missing" >&2
    exit 1
  fi
  if [ -n "$features" ]; then
    args+=(--features "$features")
  fi
  rustdoc_args="$(jq -r '(."rustdoc-args" // []) | join(" ")' <<<"$meta")"

  echo "::group::$crate (${args[*]:-default features}; $rustdoc_args)"
  RUSTDOCFLAGS="$rustdoc_args -D warnings" RUSTC="$rustc" RUSTDOC="$rustdoc" \
    "$cargo" doc -p "$crate" --no-deps --locked "${args[@]}"
  echo "::endgroup::"
done
