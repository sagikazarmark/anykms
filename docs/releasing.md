# Releasing

## Versioning policy

All published workspace crates share one version (`[workspace.package] version` in `Cargo.toml`)
and are released together. This lockstep holds while `anykms-core` is 0.x: a breaking change to
core is a breaking change for every backend, so separate versions would only add bookkeeping.
Per-crate backend versions are reconsidered when a backend first needs a release that core does
not.

`anykms-testkit` and `anykms-wasm-tests` (`publish = false`) are never published. The backends use
`anykms-testkit` as a path-only dev-dependency, which `cargo publish` strips.

## Build requirements

The default TLS provider is aws-lc-rs (`rustls-aws-lc-rs`), and the default RSA backend of the
cloud backends and the facade (`rsa-aws-lc-rs`) uses it too. Every default build, transit-only
included, therefore compiles `aws-lc-sys`, which builds C and assembly: it needs a C compiler (on
Windows it uses prebuilt NASM objects). CMake is needed only for the FIPS build. The opt-in ring
path (`--no-default-features --features rustls-ring`, plus `rsa-rustcrypto` where RSA is needed)
avoids aws-lc, but ring also compiles a small C and assembly part.

The CI runners, and any machine that runs `just package`, need a C compiler for the packaging dry
run.

## How a release works

Releases run in GitHub Actions, from `main`, with the
[Release workflow](../.github/workflows/release.yaml). Nothing is published from a workstation,
and no crates.io token is stored anywhere: crates.io trusts the workflow through
[Trusted Publishing](https://crates.io/docs/trusted-publishing).

| Job | What it does | Changes |
|---|---|---|
| Version | Picks the version from the latest `vX.Y.Z` tag and the `bump` input, or takes the `version` input. Fails if the tag exists. | nothing |
| Package | Bumps the version in the working tree (`cargo release version`) and builds every crate from its packaged sources (`cargo publish --dry-run --workspace`). | nothing |
| Commit | Makes the same bump, commits it as `chore: release vX.Y.Z` and pushes it to `main`. The push fails if `main` moved since the run started. | `main` |
| Publish to crates.io | In the `release` environment: publishes the crates not yet on crates.io at the version (`cargo info` tells), in dependency order. | crates.io |
| GitHub Release | Creates the `vX.Y.Z` tag on the release commit and the GitHub Release, with generated notes. | tag, release |

Package is the release's only build. It runs every dependency's build script, so it holds no
write permission and cannot request the OIDC token crates.io accepts. Commit and Publish build
nothing: the bump edits manifests only, and Publish runs `cargo publish --no-verify` on the
sources Package built.

The workflow does not check CI: check that the commit's CI run passed before starting it. The
commit the workflow pushes starts no CI run (pushes with the workflow token start no workflows);
Package covers the bump.

Releases carry no signature from the maintainer: neither the release commit nor the tag is
signed. The GitHub Release is immutable (its tag cannot move, and GitHub signs an attestation of
the tag and the commit, checked with `gh release verify vX.Y.Z`), and crates.io records the
repository, workflow run and commit of every version published through Trusted Publishing.

## One-time setup

1. **The `release` environment** (Settings → Environments): deployment branches limited to
   `main`. Add a required reviewer to approve each publish; leave "Prevent self-review" off while
   the maintainer who starts the run is the only reviewer.
2. **Trusted Publishing on crates.io**, for each published crate (`anykms`, `anykms-core`,
   `anykms-recipes`, `anykms-conformance`, `anykms-local`, `anykms-http`, `anykms-transit`,
   `anykms-aws`, `anykms-gcp`, `anykms-azure`), under the crate's Settings → Trusted Publishing:
   owner `sagikazarmark`, repository `anykms`, workflow `release.yaml`, environment `release`.
3. **Immutable releases** (Settings → General → Releases → Enable release immutability).
4. **After the first release from the workflow:** turn on "Trusted Publishing only" for every
   crate, so an API token can no longer publish it, and revoke the personal crates.io token used
   for 0.1.0 and 0.2.0.

### Still open after 0.3.0

0.3.0 was published through Trusted Publishing, but the setup above is not complete. Until these
are done, a crates.io token on a maintainer's machine can still publish, and nobody has to approve
a publish:

- [ ] "Trusted Publishing only" is still off on `anykms`, `anykms-core`, `anykms-aws` and
      `anykms-http` (check every crate: `curl -s https://crates.io/api/v1/crates/<crate>` shows
      `"trustpub_only":true` once it is on).
- [ ] Revoke the personal crates.io token used for 0.1.0 and 0.2.0 (crates.io → Account Settings
      → API Tokens), and remove it from `~/.cargo/credentials.toml` and any `.env`.
- [ ] Add a required reviewer to the `release` environment (step 1): it has a branch policy but
      no reviewer, so a dispatched run publishes without an approval.

## Releasing

1. **Merge everything into `main` and wait for its CI run to pass.** The README links point at
   `blob/main/docs/...`, so the documents they name must be on `main` when the crates.io page goes
   live. The Release workflow does not check CI. The `push` run of `CI` on `main` covers the MSRV
   job, the docs.rs job, the service jobs (Floci, AWS Emulator and Lowkey, each of which fails on
   a skipped conformance case) and the Vault/OpenBao integration matrix. The LocalStack job is not
   a gate: without `LOCALSTACK_AUTH_TOKEN` it skips every step and still reports success (with a
   warning), and Floci and AWS Emulator cover the same suite.
2. **Start the Release workflow** from `main` (Actions → Release → Run workflow), with a `bump`
   (`patch`, `minor`, `major`) or an exact `version` (`vX.Y.Z`):

   ```sh
   gh workflow run release.yaml --ref main -f bump=minor
   ```

   `bump` defaults to `none`, which fails: each release names its bump. A workspace already at the
   version (bumped in a pull request, say) is released as it is, with no new commit.
3. **Approve the publish** in the `release` environment, when it has a required reviewer.
4. **Write the release notes.** The GitHub Release starts with the generated notes; edit them
   (an immutable release keeps its notes editable).
5. **Check that docs.rs built every crate.**

## When a run fails

Every job before the GitHub Release skips what an earlier run did, so a release resumes where it
stopped. The GitHub Release comes last: once it exists, the release is done.

- **Re-run failed jobs** on the same run (within 30 days). It keeps the version and the release
  commit of the jobs that passed. A re-run of Publish asks for approval again.
- **Or start a new run** with the same `bump` or `version`. The tag is created last, so until it
  exists a new run picks the same version. When the version commit is on `main` already, the new
  run releases it as it is, and Commit pushes nothing. Start it before anything else lands on
  `main`: a new run releases the head of `main`, and crates published by the stopped run came from
  the version commit.

Publish skips every crate that is on crates.io at the version already: `cargo publish` refuses a
version that exists, so a crate that made it would fail the whole command. `cargo info --registry
crates-io <crate>@X.Y.Z` tells whether a crate is published.

crates.io rate limits are per account. New versions of existing crates are allowed in a burst of
30, then one a minute, which a release of ten crates stays within. A request over a limit fails
with HTTP 429 and the time to retry: re-run Publish after it.

## A new crate

Trusted Publishing cannot create a crate: the first version of a new crate is published by hand,
with an API token, before its Trusted Publishing configuration can be added. New crates have their
own rate limit: a burst of 5, then one every 10 minutes.

When a release adds a crate, start the Release workflow as usual. Publish fails at the new crate:
publish it from the release commit with a token
(`cargo publish --locked -p <crate>`, after `git checkout <release commit>`), add its Trusted
Publishing configuration and turn on "Trusted Publishing only", then re-run the failed jobs.
Publish picks up the crates that are still pending. Add the crate to the list in "One-time setup".
