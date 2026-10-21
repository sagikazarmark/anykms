# List the recipes.
[private]
default:
    @just --list --unsorted

# Run the CI jobs that need no servers, credentials or other toolchains.
ci: fmt clippy check tls recipes doc test package (conformance "local") (conformance "gcp") (conformance "conformance") examples features deny fuzz-check

# Check formatting.
fmt:
    cargo fmt --all --check

# Run clippy with all features and with none.
clippy:
    cargo clippy --workspace --all-targets --all-features --locked
    cargo clippy --workspace --all-targets --no-default-features --locked

# Workspace builds unify features across crates, which can hide code that only compiles with a
# feature some other crate happens to enable.
[doc("Check each crate on its own without default features.")]
check:
    cargo hack check --workspace --no-default-features --all-targets --locked
    # Without the `reqwest` feature there is no built-in transport: the tests that pin the error
    # naming both remedies, and the facade skipping the HTTP backends.
    cargo test -p anykms-http --no-default-features --locked --lib
    cargo test -p anykms-transit --no-default-features --locked --test scripted
    cargo test -p anykms --no-default-features --features transit,aws,gcp,azure,recipes --locked --lib

# Each backend forwards them to anykms-http, which selects one for the built-in transport.
# aws-lc-rs is the default: the default build must not link ring, and the opt-in ring path
# (`--no-default-features --features reqwest,rustls-ring`) must not link aws-lc-sys. `check`
# covers "no provider" (process default at runtime). The ring path keeps its TLS tests; `test`
# runs the aws-lc-rs ones.
[doc("Check the rustls provider features.")]
tls:
    #!/usr/bin/env bash
    set -euo pipefail
    for c in anykms-http anykms-transit anykms-aws anykms-gcp anykms-azure anykms; do
      if cargo tree -p "$c" -e normal --prefix none --locked | grep -q '^ring '; then
        echo "ring is linked into $c with default features" >&2
        exit 1
      fi
    done
    if cargo tree -p anykms --features transit,aws,gcp,azure -e normal --prefix none --locked \
        | grep -q '^ring '; then
      echo "ring is linked into the facade with default features and every backend" >&2
      exit 1
    fi
    cargo hack check -p anykms-transit -p anykms-aws -p anykms-gcp -p anykms-azure \
      --no-default-features --features reqwest,rustls-ring --all-targets --locked
    for c in anykms-transit anykms-aws anykms-gcp anykms-azure; do
      if cargo tree -p "$c" --no-default-features --features reqwest,rustls-ring \
          -e normal --prefix none --locked | grep -q '^aws-lc-sys '; then
        echo "aws-lc-sys is linked into $c with only rustls-ring enabled" >&2
        exit 1
      fi
    done
    cargo check -p anykms --no-default-features --features transit,aws,gcp,azure,reqwest,rustls-ring --locked
    cargo test -p anykms-transit --no-default-features --features reqwest,rustls-ring --locked --lib --test tls --test scripted
    cargo test -p anykms-http --no-default-features --features reqwest,rustls-ring --locked --lib

# Each recipe feature alone, on top of the verification-only build (no default features, also
# linted on its own): what a backend that only verifies locally depends on. Then the RSA
# verification backends: `test` uses `rsa-rustcrypto` and `rsa-aws-lc-rs` together (aws-lc-rs
# wins), as do the defaults, so each backend alone, and none (RSA keys fail with `Unsupported`,
# ECDSA and Ed25519 keep working), are tested here, with the JOSE and envelope recipes on; the
# last run is the verification-only build.
[doc("Check and test anykms-recipes' features.")]
recipes:
    cargo hack clippy -p anykms-recipes --each-feature --all-targets --locked
    cargo test -p anykms-recipes --locked
    cargo test -p anykms-recipes --locked --no-default-features --features jose,envelope,rsa-rustcrypto
    cargo test -p anykms-recipes --locked --no-default-features --features jose,envelope
    cargo test -p anykms-recipes --locked --no-default-features
    cargo check -p anykms --locked --no-default-features --features recipes,rsa-rustcrypto

# The facade's default and no-default builds are what `cargo doc` shows a user: links to
# feature-gated modules must not break.
[doc("Run rustdoc with all features, and the facade as a user sees it.")]
[env("RUSTDOCFLAGS", "--deny warnings")]
doc:
    cargo doc --workspace --all-features --no-deps --locked
    cargo doc -p anykms --no-deps --locked
    cargo doc -p anykms --no-default-features --no-deps --locked

# Build each published crate's documentation as docs.rs does (nightly: devenv --profile nightly).
docs-rs *crates:
    scripts/docs-rs.sh {{ crates }}

# Server-free tests: core, recipes (incl. envelope test vectors), local (incl. its conformance
# run), transit unit and mock-server tests. Conformance and integration targets that need servers
# skip themselves without them. The facade's doc_snippets test compiles every `rust` snippet of the
# READMEs and docs/*.md (and runs the server-free ones).
[doc("Run the tests.")]
test:
    cargo test --workspace --all-features --locked

# `cargo publish` without uploading, against the other packaged workspace crates: catches files
# missing from a package and dev-dependencies that `cargo publish` strips.
[doc("Build every crate from its packaged sources.")]
package:
    cargo package --workspace --exclude anykms-testkit --exclude anykms-wasm-tests --locked

# local, gcp (its in-process fake Cloud KMS server, without and with the public-key cache) and
# conformance (the minimal_backend example) need nothing else, so every case they can run must
# run: a `skip` (fixture lacks a feature) fails, while `n/a` (absent by design: RSA, credentials,
# native ciphertexts, request counting) stays ignored. transit, aws and azure run against the
# servers in compose.yaml: Vault and OpenBao (scripts/dev-up.sh), Floci or LocalStack, and Lowkey
# Vault; with ANYKMS_FAIL_ON_SKIP=1 (as CI sets for all but LocalStack), a skipped case fails.
[arg("package", pattern="local|gcp|conformance|transit|aws|azure")]
[doc("Run a package's conformance suite (the package name without the `anykms-` prefix).")]
conformance package:
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ package }}" in
      local)
        # The GCP- and Azure-shaped proof fixtures (local keys exposed with only those backends'
        # parts and conventions) show that such backends pass the suite without `Unsupported` stubs.
        ANYKMS_FAIL_ON_SKIP=1 cargo test -p anykms-local --all-features --locked \
          --test conformance --test conformance_gcp_shaped --test conformance_azure_shaped
        ;;
      gcp)
        ANYKMS_FAIL_ON_SKIP=1 cargo test -p anykms-gcp --all-features --locked \
          --test conformance --test conformance_cached
        ;;
      conformance)
        ANYKMS_FAIL_ON_SKIP=1 cargo test -p anykms-conformance --locked --example minimal_backend
        ;;
      transit)
        cargo test -p anykms-transit --all-features --locked \
          --test conformance_vault --test conformance_openbao
        ;;
      aws)
        cargo test -p anykms-aws --all-features --locked --test conformance_emulator
        ;;
      azure)
        cargo test -p anykms-azure --all-features --locked --test conformance_lowkey
        ;;
    esac

# Run a backend's tests against the servers in compose.yaml, its conformance suite included.
[arg("package", pattern="transit|aws|azure")]
integration package:
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ package }}" in
      transit)
        cargo test -p anykms-transit --all-features --locked
        ;;
      aws)
        cargo test -p anykms-aws --all-features --locked --test emulator --test conformance_emulator
        ;;
      azure)
        # Mocks (every operation and error row), credentials, the TRACE hygiene test, and Lowkey
        # Vault end to end. The live targets run with `live`; conformance_mhsm runs by hand (a
        # Managed HSM is billed by the hour; see tests/conformance_mhsm.rs).
        cargo test -p anykms-azure --all-features --locked --lib \
          --test mock --test credentials --test hygiene --test lowkey --test conformance_lowkey
        # Default features only: without tracing, the CLI credential and experimental HMAC.
        cargo test -p anykms-azure --locked --lib --test mock --test credentials
        ;;
    esac

# Run a backend's tests against the real cloud service (credentials and keys from the environment).
[arg("package", pattern="aws|gcp|azure")]
live package *args:
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ package }}" in
      aws)
        cargo test -p anykms-aws --all-features --locked --test conformance_live {{ args }}
        ;;
      gcp)
        cargo test -p anykms-gcp --all-features --locked --test live --test conformance_live {{ args }}
        ;;
      azure)
        cargo test -p anykms-azure --all-features --locked --test live --test conformance_azure {{ args }}
        ;;
    esac

# Without VAULT_ADDR/BAO_ADDR or key URIs, the examples use in-memory local keys; they need only
# the `local` feature (on top of the defaults). tower_transport is about the transport, so it runs
# only against a server, and only when its key is named (ANYKMS_KEK_URI): it does not create one.
[doc("Run the facade's examples.")]
examples *flags="--features local":
    for e in field_encryption jwt_signing jwt_signing_jwt_simple hmac_tokens; do cargo run -p anykms --locked {{ flags }} --example "$e"; done
    if [ -n "${VAULT_ADDR:-}${BAO_ADDR:-}" ] && [ -n "${ANYKMS_KEK_URI:-}" ]; then cargo run -p anykms --locked --features transit,tower --example tower_transport; fi

# The transport-free crates on wasm32-unknown-unknown with their `js` feature (a JS host:
# browsers, Node.js, Cloudflare Workers): a check of each, then anykms-wasm-tests under Node via
# wasm-bindgen-test-runner (.cargo/config.toml), which needs a wasm-bindgen-cli matching the
# `wasm-bindgen` crate in Cargo.lock (`just wasm-bindgen-cli` installs it). The HTTP backends with
# `js` and anykms-http's `tower` feature are checked for the target too; anykms-wasm-tests runs
# anykms-aws over a `TowerTransport` under Node: the Cloudflare Workers shape, minus the `fetch`
# service, which needs workerd to drive.
wasm:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo check -p anykms-core -p anykms-recipes -p anykms-local -p anykms-conformance \
      --target wasm32-unknown-unknown --locked --no-default-features \
      --features anykms-core/js,anykms-recipes/js,anykms-recipes/jose,anykms-recipes/envelope,anykms-recipes/rsa-rustcrypto,anykms-local/js,anykms-conformance/js
    cargo check -p anykms-http -p anykms-transit -p anykms-aws -p anykms-gcp -p anykms-azure \
      --target wasm32-unknown-unknown --locked --no-default-features \
      --features anykms-http/tower,anykms-http/js,anykms-transit/js,anykms-aws/js,anykms-gcp/js,anykms-azure/js,anykms-aws/rsa-rustcrypto,anykms-gcp/rsa-rustcrypto,anykms-azure/rsa-rustcrypto
    cargo test -p anykms-wasm-tests --target wasm32-unknown-unknown --locked
    # The HTTP backends without the built-in transport (`reqwest` off): a wasm32 build that brings
    # its own `HttpTransport` must not pull reqwest, hyper or rustls into the tree, neither the
    # facade's with every backend nor anykms-wasm-tests' (anykms-aws + anykms-http/tower).
    for dep in reqwest hyper rustls; do
      if cargo tree -p anykms --no-default-features --features transit,aws,gcp,azure \
          --target wasm32-unknown-unknown -e normal --prefix none --locked | grep -q "^$dep "; then
        echo "$dep is in the facade's dependency tree with the reqwest feature off" >&2
        exit 1
      fi
      if cargo tree -p anykms-wasm-tests --target wasm32-unknown-unknown -e normal,dev --prefix none --locked \
          | grep -q "^$dep "; then
        echo "$dep is in anykms-wasm-tests' dependency tree" >&2
        exit 1
      fi
    done

# Install the wasm-bindgen-cli release that matches Cargo.lock (the test runner refuses a mismatch).
wasm-bindgen-cli:
    cargo install wasm-bindgen-cli --locked --version "$(cargo metadata --format-version 1 --locked | jq -r '.packages[] | select(.name == "wasm-bindgen") | .version')"

# Check feature combinations that workspace builds hide (Cargo unifies features across the workspace).
features:
    #!/usr/bin/env bash
    set -euo pipefail

    # Each feature alone (with no default features), the defaults, and none. anykms-testkit and
    # anykms-wasm-tests are unpublished test helpers.
    cargo hack check --each-feature --lib --locked --workspace --exclude anykms-testkit --exclude anykms-wasm-tests

    # The facade with its cloud backends (default features).
    cargo check -p anykms --features aws,gcp,azure --locked

    # Both TLS providers: features unify, so both may be on together (aws-lc-rs then wins).
    cargo hack check -p anykms-http -p anykms-transit -p anykms-aws -p anykms-gcp -p anykms-azure \
      --no-default-features --features rustls-ring,rustls-aws-lc-rs --lib --locked

    # The RustCrypto RSA path without aws-lc. It is tested in anykms-recipes (`recipes`). A backend
    # test under rsa-rustcrypto would not test it: the dev-dependencies (conformance, Azure's) bring
    # aws-lc-rs into the test build. So the cloud backends get a library check and a guard that
    # their normal dependencies hold no aws-lc-sys.
    cargo hack check -p anykms-aws -p anykms-gcp -p anykms-azure \
      --no-default-features --features rustls-ring,rsa-rustcrypto --lib --locked
    for c in anykms-aws anykms-gcp anykms-azure; do
      if cargo tree -p "$c" --no-default-features --features rustls-ring,rsa-rustcrypto \
          -e normal --prefix none --locked | grep -q '^aws-lc-sys '; then
        echo "aws-lc-sys is linked into $c with rustls-ring and rsa-rustcrypto" >&2
        exit 1
      fi
    done

    # anykms-recipes without default features is what a backend that only verifies locally
    # depends on: its direct dependencies stay this list.
    actual=$(cargo tree -p anykms-recipes --no-default-features -e normal --depth 1 \
      --prefix none --locked | tail -n +2 | awk '{print $1}' | sort -u | tr '\n' ' ')
    expected="anykms-core base64 ecdsa ed25519-dalek getrandom p256 p384 p521 signature spki zeroize "
    if [ "$actual" != "$expected" ]; then
      echo "anykms-recipes (no default features) depends on: $actual" >&2
      echo "expected: $expected" >&2
      exit 1
    fi

    # anykms-aws's `__test-fixtures` (key administration for its own tests) must never be
    # reachable through the facade, not even with every feature on.
    if cargo tree -e features -p anykms --all-features --locked \
        | grep -q 'anykms-aws feature "__test-fixtures"'; then
      echo "the facade enables anykms-aws's __test-fixtures" >&2
      exit 1
    fi

# Check advisories, bans, licenses and sources.
deny:
    cargo deny check

# The fuzz crate is outside the workspace, so nothing else compiles it. A plain check (no
# sanitizers) needs no nightly; it also covers the seed generator example.
[doc("Check the fuzz crate's formatting and targets.")]
[working-directory("fuzz")]
fuzz-check:
    cargo fmt --all --check
    cargo check --locked --all-targets

# New inputs go to the (uncommitted) corpus/<target>; the committed seeds/<target> (real
# encodings, see examples/gen_seeds.rs) and dicts/<target>.dict get the fuzzer past the format
# magic.
[doc("Fuzz a target for a number of seconds (nightly: devenv --profile nightly).")]
[working-directory("fuzz")]
fuzz target seconds="600":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p "corpus/{{ target }}"
    corpora=("$PWD/corpus/{{ target }}")
    if [ -d "seeds/{{ target }}" ]; then corpora+=("$PWD/seeds/{{ target }}"); fi
    flags=(-max_total_time={{ seconds }} -rss_limit_mb=2048)
    if [ -f "dicts/{{ target }}.dict" ]; then flags+=("-dict=$PWD/dicts/{{ target }}.dict"); fi
    cargo fuzz run -O "{{ target }}" "${corpora[@]}" -- "${flags[@]}"
