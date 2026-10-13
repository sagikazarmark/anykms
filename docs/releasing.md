# Releasing

## Versioning policy

All published workspace crates share one version (`[workspace.package] version` in `Cargo.toml`)
and are released together. This lockstep holds while `anykms-core` is 0.x: a breaking change to
core is a breaking change for every backend, so separate versions would only add bookkeeping.
Per-crate backend versions are reconsidered when a backend first needs a release that core does
not.

`anykms-testkit` (`publish = false`) is never published. The backends use it as a path-only
dev-dependency, which `cargo publish` strips.

## Build requirements

The default TLS provider is aws-lc-rs (`rustls-aws-lc-rs`), and the default RSA backend of the
cloud backends and the facade (`rsa-aws-lc-rs`) uses it too. Every default build, transit-only
included, therefore compiles `aws-lc-sys`, which builds C and assembly: it needs a C compiler (on
Windows it uses prebuilt NASM objects). CMake is needed only for the FIPS build. The opt-in ring
path (`--no-default-features --features rustls-ring`, plus `rsa-rustcrypto` where RSA is needed)
avoids aws-lc, but ring also compiles a small C and assembly part.

The release machine and the CI runners need a C compiler for the packaging dry run below.

## Steps

1. **Record the release gate decision.** Before the first publish, the maintainer's decision on
   the live-probe gate is recorded in `docs/PLAN.md` §24.4. For 0.1.0 the decision is to hold the
   publish until the GCP probe T1 (`scripts/probe-gcp.sh`) and the Azure probe T3
   (`scripts/probe-azure.sh`) have run (both ran on 2026-10-12) and their results are folded into the error mappings and
   `docs/guarantees.md`. Check that every gate listed in §24.4 is closed.
2. **Confirm the public repository.** The `repository` field in `Cargo.toml`, the README links
   (the facade's crates.io page) and the CI live-job guards all name
   `github.com/sagikazarmark/anykms`. That repository must exist and be public before tagging:
   the metadata of a published version cannot change.

   When it goes public, enable private vulnerability reporting (Settings → Code security →
   Private vulnerability reporting, or `gh api -X PUT
   repos/sagikazarmark/anykms/private-vulnerability-reporting`). The account-level `SECURITY.md`
   (in `sagikazarmark/.github`) covers every repository without its own and sends reporters to
   the repository's "Report a vulnerability" button, which exists only while this is on. Check it
   with `gh api repos/sagikazarmark/anykms/private-vulnerability-reporting` (`"enabled": true`).
3. Bump `version` in `[workspace.package]` and every `version` in the workspace's
   `[workspace.dependencies]` entries for `anykms-*` crates (they must match exactly).
4. Run the CI checks locally, in the devenv shell: `just ci` runs every job that needs no servers
   or credentials, `cargo deny check` and a full packaging dry run included (it builds each crate
   from its packaged sources against the other packaged crates), and the `msrv` profile runs the
   MSRV job on Rust 1.91:

   ```sh
   just ci
   devenv --profile msrv shell -- just test
   ```

   Build every crate's documentation as docs.rs will (CI's `docs-rs` job runs the same recipe).
   A docs.rs page is frozen with its version, so a feature missing from a crate's
   `[package.metadata.docs.rs]` hides its items until the next release:

   ```sh
   devenv --profile nightly shell -- just docs-rs   # one crate at a time, with --cfg docsrs
   ```

   Every user-facing feature must be in the metadata: `all-features = true`, except
   `anykms-aws`, which lists its features by hand because `__test-fixtures` is a
   `compile_error!` in release builds. The script fails when such a list leaves out a feature
   other than `default` and the hidden `__*` ones.

5. **Get one green GitHub CI run.** Push the release commit to the public repository and open a
   pull request. Its `pull_request` run must be green on the release commit, including the MSRV
   job, the semver job (its non-blocking path before the first publish), the docs.rs job, the
   service jobs (Floci and Lowkey, both of which fail on a skipped conformance case), and the
   Vault/OpenBao integration matrix. Local gates are not enough: they have missed a red CI job
   before. The LocalStack job is not a gate: without `LOCALSTACK_AUTH_TOKEN` it skips every step
   and still reports success (with a warning), and Floci covers the same suite.
6. **Merge to `main` before publishing.** The README links point at `blob/main/docs/...`, so the
   documents they name must be on `main` when the crates.io page goes live. Tag `vX.Y.Z` on the
   merge commit and push the tag.
7. **Publish in dependency order, in batches.** crates.io limits how fast one account creates
   *new* crates: a burst of 5, then one every 10 minutes (a request over the limit fails with
   HTTP 429 and the time to retry). All ten crates are new on the first publish, so a single
   `cargo publish --workspace` stops at the sixth. Later releases publish new versions of
   existing crates, which crates.io limits separately; the batches below work for them too.
   (Alternatively, ask help@crates.io for a temporary limit increase before release day.)

   The order follows each crate's published dependencies, dev-dependencies with a version
   included (crates.io requires them to exist; path-only dev-dependencies, such as
   `anykms-testkit` and `anykms-recipes`'s `anykms-local`, are stripped on publish):

   | Crate | Needs on crates.io |
   |---|---|
   | `anykms-core` | — |
   | `anykms-recipes` | core |
   | `anykms-conformance` | core, recipes |
   | `anykms-http` | core |
   | `anykms-local` | core; dev: conformance, recipes |
   | `anykms-transit` | core, http; dev: conformance, recipes |
   | `anykms-aws`, `anykms-gcp`, `anykms-azure` | core, http, recipes; dev: conformance |
   | `anykms` (the facade, last) | every other published crate |

   ```sh
   # Batch 1: five new crates, the burst. Cargo 1.90+ publishes them in dependency order and
   # waits for each to reach the index before the next.
   cargo publish --locked -p anykms-core -p anykms-recipes -p anykms-conformance \
     -p anykms-http -p anykms-local

   # Then one crate every 10 minutes, the facade last.
   for crate in anykms-transit anykms-aws anykms-gcp anykms-azure anykms; do
     sleep 600
     cargo publish --locked -p "$crate"
   done
   ```

   **After an interruption** (a 429, a network error, a closed terminal), do not rerun a
   finished batch: `cargo publish` refuses a version that already exists, so a crate that made
   it fails the whole command. Find what is still pending, then publish only those, in the
   order above (with `-p` for each, or `--workspace --exclude anykms-testkit --exclude <crate>`
   for each published one), waiting out the time a 429 names:

   ```sh
   VERSION=X.Y.Z
   for crate in anykms-core anykms-recipes anykms-conformance anykms-http anykms-local \
       anykms-transit anykms-aws anykms-gcp anykms-azure anykms; do
     if cargo info --registry crates-io "$crate@$VERSION" >/dev/null 2>&1; then
       echo "published  $crate"
     else
       echo "pending    $crate"
     fi
   done
   ```

   A crate whose upload succeeded but whose index entry is not visible yet counts as published:
   wait a minute and check again before retrying it.

8. Create a GitHub release from the tag and write its release notes.
9. **After publishing:** add the crates.io co-owners to every published crate (`cargo owner
    --add`), and check that docs.rs built all ten crates (`anykms`, `anykms-core`,
    `anykms-recipes`, `anykms-conformance`, `anykms-local`, `anykms-http`, `anykms-transit`,
    `anykms-aws`, `anykms-gcp`, `anykms-azure`).
10. **After the first publish only:** check that the CI `semver` job now compares against
    crates.io. Its "Find baseline" step asks crates.io for each crate (`cargo info --registry
    crates-io`); a published crate is checked against its registry version, and that check
    blocks. Before the first publish every crate falls back to the PR's base branch,
    non-blocking. Open a trivial PR and confirm each matrix entry logs "comparing with crates.io
    (blocking)".
