# Credentials: built-in workload sources, SDK bridges, MSRV (plan, 2026-10-12)

Status: **implemented** (2026-10-12; see §9 for the decisions taken and the deviations).
Revisits PLAN §23 Q5 ("in-house REST clients, MSRV 1.85 for every crate") for credentials only.
The KMS data plane stays in-house.

## 1. Summary

- **Keep the in-house KMS clients.** Every reason in `docs/cloud/README.md` §1 other than MSRV still
  holds: one retry layer (`Retry`), zeroized request bodies, TLS provider precedence, no redirects,
  consistent error classification. This is the line `object_store` drew for the same reasons
  ([apache/arrow-rs-object-store#250](https://github.com/apache/arrow-rs-object-store/issues/250)).
- **Built-in credentials cover workloads**, the sources services run with. Developer and
  enterprise sources (profiles, SSO, CLIs, role chaining) come from the vendor SDKs through
  optional **bridges** onto the credential traits each backend already has. `object_store` does
  the same: it removed AWS profile support and points users to an SDK credential provider
  ([apache/arrow-rs-object-store#152](https://github.com/apache/arrow-rs-object-store/issues/152)).
- **Raise the workspace MSRV** (the maintainer accepts a higher one). The bridges carry their SDK's
  MSRV, which may be higher still (§4).

Why not hand-roll everything: the long tail (SSO, role chaining, `credential_process`,
certificates, new federation types) is the most security-sensitive code with the fewest users,
and the vendors keep extending it. Why not SDKs everywhere: the SDK data planes retry internally,
bring their own HTTP and TLS stacks, keep plaintext in buffers we cannot zeroize, and need
1.88–1.94.1 today (§4).

## 2. Current state

Shared: `anykms-http::credentials` (`CredentialCache`, `Expiring`, `Credential`): lazy,
single-flight, refresh ahead of expiry, forced refresh after a 401 at most every 30 s. AWS, GCP
and Azure use it; transit has its own cache.

| Backend | Plug-in point (public) | Built-in sources |
|---|---|---|
| AWS | `CredentialSource { kind, credentials(cx) }` (`credentials/mod.rs:144`); `AwsProviderBuilder::credentials[_arc]` | `DefaultChain` (`chain.rs`): env → profile (`profile.rs` 423 LOC: static keys, `credential_process` via `process.rs` 116 LOC, `web_identity_token_file`; refuses SSO, `source_profile`) → STS web identity (`sts.rs` 461) → container (ECS, EKS Pod Identity; `container.rs` 248) → IMDSv2 (`imds.rs` 241); `StaticCredentials` |
| GCP | `CredentialSource { token, invalidate, quota_project }` (`auth/mod.rs:89`); `Credentials::custom` | ADC (`adc.rs`): `GOOGLE_APPLICATION_CREDENTIALS` → gcloud ADC file → metadata server; file types `authorized_user`, `service_account` (feature `service-account-key`), `external_account` file/url subject, `impersonated_service_account`; `Credentials::impersonated`; static token |
| Azure | `TokenCredential { token(scope), invalidate, kind, tenant_id }` (`credential.rs:62`); `AzureProviderBuilder::credential[_arc]` | `ANYKMS_AZURE_CREDENTIAL` / env selection (`cred/mod.rs`, no probing): `WorkloadIdentity`, `ClientSecret`, `ManagedIdentity` (IMDS, App Service), `AzureCli` (feature `cli-credential`); `StaticToken` |
| Transit | `TokenSource` (`token.rs:69`) | token, env, file, `~/.vault-token`; Kubernetes and JWT login with renewal (`auth.rs`) |

Live CI depends on: AWS STS web identity (GitHub OIDC), GCP `external_account` +
impersonation (`google-github-actions/auth`), Azure workload identity. Fuzzing covers the AWS
profile INI parser (`aws_profile`), the AWS credential JSON/STS parsers (`aws_credentials`) and
Azure's token response (`azure_response`).

## 3. Target scope of the built-in sources

| Source | Today | Target | Reason |
|---|---|---|---|
| AWS env, static | ✅ | keep | trivial |
| AWS STS web identity | ✅ | keep | EKS IRSA, GitHub OIDC, live CI |
| AWS container (ECS, EKS Pod Identity) | ✅ | keep | workloads |
| AWS IMDSv2 | ✅ | keep | EC2 |
| AWS profile: static keys | ✅ | **decision D2** | developer machines; the only remaining user of the INI parser |
| AWS profile: `credential_process`, `web_identity_token_file` | ✅ | **remove** → bridge | spawns a shell (`sh -c`); rare outside developer setups |
| AWS SSO, role chaining, MFA | ❌ | bridge | already unsupported |
| GCP metadata server | ✅ | keep | GCE, GKE, Cloud Run |
| GCP `service_account` key | ✅ (feature) | keep | common, small, already gated |
| GCP `authorized_user` | ✅ | keep | `gcloud auth application-default login`; small |
| GCP `external_account` file/url, impersonation | ✅ | keep | GitHub Actions and other clouds; live CI uses it |
| GCP `external_account` aws/executable, `external_account_authorized_user`, GDCH | ❌ | bridge | already unsupported |
| Azure workload identity, client secret, managed identity | ✅ | keep | AKS, CI, VMs, App Service |
| Azure CLI | ✅ (feature) | **remove** → bridge | developer-only; `azure_identity` has it |
| Azure certificate, Arc, Pipelines | ❌ | bridge | certificates need openssl in `azure_identity` |
| Transit | ✅ | unchanged | no SDK to bridge to |

Removed sources fail with `Configuration` naming the bridge feature. Their fuzz targets, seeds,
tests and docs go with them.

## 4. MSRV

Today: workspace 1.85 (`Cargo.toml:9`), the MSRV CI job checks every library on 1.85 and drops the
JWT dev-dependencies with `--cfg anykms_msrv`.

| Crate needing a newer compiler | MSRV | Policy |
|---|---|---|
| jsonwebtoken 11.1 (dev) | 1.88 | |
| jwt-simple 0.15 (dev) | 1.89 | |
| `azure_core` 1.x (`azure_identity`) | 1.88 | raising it is breaking for them |
| `google-cloud-auth` 1.17 | 1.91 | compiles with rustc releases of the previous year; bumps are not breaking |
| `aws-credential-types` 1.3, `aws-config` 1.12 | 1.94.1 | stable minus two, moves continuously |

Proposal (decision D1): **workspace MSRV 1.91**, the oldest that covers every dev-dependency and
the GCP and Azure bridges; `--cfg anykms_msrv` goes away for the JWT dev-dependencies. The AWS
bridge feature is the one exception: it carries the AWS SDK's MSRV, documented on the feature,
and the MSRV job does not enable it. Policy going forward: raise deliberately when a dependency
needs it, and note each raise in the CHANGELOG.

## 5. Bridges

One optional feature per backend, in the backend crate, forwarded by the facade. Each is an
adapter onto the existing trait, so the KMS request path, its retries and its zeroization are
unchanged; only token acquisition goes through the SDK.

| Feature | Adapter | Dependency | Notes |
|---|---|---|---|
| `anykms-aws/sdk-credentials` | `SdkCredentials(SharedCredentialsProvider)` → `CredentialSource` | `aws-credential-types` only; users build the provider with `aws-config` | expiry mapped to `Credentials::with_expiry`; secret copied into `Zeroizing` |
| `anykms-gcp/google-cloud-auth` | `Credentials::google_cloud_auth(c)` → `CredentialSource` | `google-cloud-auth` | access token + expiry; `quota_project` forwarded; `invalidate` clears the SDK cache if it exposes one |
| `anykms-azure/azure-identity` | `AzureIdentity(Arc<dyn azure_core::credentials::TokenCredential>)` → `TokenCredential` | `azure_core` (users pick `azure_identity` credentials) | scope passed through; tenant from the SDK credential when available |

Shared rules for every bridge:

- **Retries:** the SDK credential clients retry on their own. Document that they run under
  `Retry` (credential fetches happen inside an operation) and show how to turn SDK retries off
  (`RetryConfig::disabled()` for `aws-config`; the equivalents for Google and Azure).
- **TLS and HTTP:** the SDK fetches tokens with its own stack and TLS provider. Documented as a
  known difference; the KMS calls keep ours.
- **Laziness:** constructing the bridge does no I/O; the first operation fetches (core §3.3).
- **Errors:** SDK errors map to `ErrorKind::Unauthenticated` (or `Unavailable` when the SDK says
  transient), with the source chain kept and secrets never formatted (TRACE hygiene test per
  bridge).
- **Public API:** SDK types appear in the constructors, so an SDK major version is an anykms
  breaking change. All three are on 1.x; pin the major in `Cargo.toml`.
- **Tests:** unit tests over in-process SDK providers (static AWS credentials, a fake Google
  token, an Azure `TokenCredential` impl): token mapped, expiry honoured, `invalidate` forces one
  refresh, errors classified. No network. Each live job keeps its built-in source; optionally
  one live case per cloud through the bridge.
- **Supply chain:** check `cargo deny` per bridge before merging (`multiple-versions = "deny"`:
  smithy's hyper stack and `azure_core` may duplicate crates; skips need named reasons). Licences
  are Apache-2.0/MIT.

## 6. Decisions for the maintainer

- **D1 MSRV:** 1.91 for the workspace with the AWS bridge exempt (recommended), or 1.94.1 for
  everything (one number, follows AWS), or a rolling "stable minus N" policy.
- **D2 AWS profiles:** keep static-key profiles only (recommended: `~/.aws/credentials` keys are
  common on developer machines and the parser is small and fuzzed), or remove profiles entirely
  like `object_store`.
- **D3 Azure CLI:** remove the in-house `cli-credential` (recommended) or keep it as a no-SDK
  developer option.
- **D4 Timing:** the removals before 0.1.0 is published (recommended: they are breaking later);
  the bridges are additive and can follow in 0.1.x.
- **D5 Feature names:** `sdk-credentials` / `google-cloud-auth` / `azure-identity` (named after
  what they pull in), or one uniform name per crate (`sdk-credentials`).

## 7. Work packages

| WP | Content | Size | Depends on |
|---|---|---|---|
| C1 | MSRV raise (D1): `Cargo.toml`, MSRV job, drop `--cfg anykms_msrv` for the JWT dev-dependencies, README/PLAN §2/`docs/cloud/*`/crate READMEs/`releasing.md`; remove the 1.85 workarounds (`conformance/src/cases/layers.rs:49`, `recipes/tests/semantics.rs:12`) | S | D1 |
| C2 | Narrow AWS (D2): remove `credential_process` and profile web identity (and profiles entirely if D2 says so), `process.rs`, the tokio `process` feature, the matching mock tests, `aws_profile`/`aws_credentials` coverage; `Configuration` errors naming the bridge | S | D2 |
| C3 | Narrow Azure (D3): remove `AzureCli`, `cli-credential`, its tests and the `ANYKMS_AZURE_CREDENTIAL=cli` value (error naming the bridge) | S | D3 |
| C4 | AWS bridge (the template: feature wiring, facade forwarding, CI, docs pattern) | M | C1 |
| C5 | GCP bridge | S | C4 |
| C6 | Azure bridge | S | C4 |
| C7 | Docs: `operations-{aws,gcp,azure}.md` coverage tables ("built-in" vs "via bridge"), README crate and feature tables, CHANGELOG, PLAN §28 (Q5 revisited), `docs/cloud/aws.md` Q8 and §2, `gcp.md` Q3/§4.3, `azure.md` §2/§4.5 marked superseded where they disagree | S | C2–C6 |

Order: decisions → C1 → C2, C3 (before 0.1.0, D4) → C4 → C5, C6 → C7 alongside each.

Acceptance: CI green including `features` (`cargo hack --each-feature`), `deny`, MSRV and the
three live jobs unchanged; each bridge has its mock tests and a TRACE hygiene test; every removed
source fails with `Configuration` naming its bridge; docs list exactly what is built in.

## 8. Risks

- **Bridge dependency weight and duplicate versions** may need `deny.toml` skips (§5).
- **Double retries** through an SDK credential client under `Retry`: documented, with the knob to
  disable them.
- **AWS MSRV drift:** the AWS bridge's MSRV moves with every SDK release; users on the workspace
  MSRV who enable it get resolver-held old SDK releases. Documented on the feature.
- **Regressions for users of the removed sources** (pre-0.1, so none published): the
  `Configuration` errors point to the replacement.

## 9. Implementation (2026-10-12)

Decisions taken, each the recommended option: **D1** workspace MSRV 1.91; **D2** AWS profiles keep
static keys only; **D3** the in-house Azure CLI credential is removed; **D4** everything lands
before 0.1.0; **D5** features named after what they pull in: `anykms-aws/sdk-credentials`
(facade `aws-sdk-credentials`), `anykms-gcp/google-cloud-auth` (facade `gcp-google-cloud-auth`),
`anykms-azure/azure-identity` (facade `azure-identity`).

Deviations from §4–§5:

- **No MSRV exemption for the AWS bridge.** With `rust-version = "1.91"`, Cargo's MSRV-aware
  resolver locks `aws-credential-types` 1.2.13 and the smithy crates it needs, all declaring
  1.91, so the MSRV job runs `cargo test --workspace --all-features --locked` with no exclusions.
  Newer SDK releases (1.94.1) are picked by users on newer toolchains. The HTTP backends' tests and
  the JWT examples also build on 1.91, so the MSRV job now tests everything, and `--cfg
  anykms_msrv` is gone.
- **The GCP bridge is not cached by anykms.** `google-cloud-auth`'s `AccessToken` carries no
  expiry; the library caches and refreshes tokens itself, so `Credentials::google_cloud_auth` asks
  it on every request. Building its credentials spawns a refresh task (a tokio runtime is needed),
  and with its default features off it needs a process-wide rustls provider (documented).
- **SDK types in the API:** the AWS bridge takes any `ProvideCredentials`, GCP an
  `AccessTokenCredentials`, Azure an `Arc<dyn azure_core::credentials::TokenCredential>`. All are
  1.x crates (`version = "1"`).
- **Error kinds:** AWS `CredentialsNotLoaded`/`InvalidConfiguration` → `Configuration`,
  `ProviderTimedOut` → `Timeout`, else `Unavailable`; GCP transient → `Unavailable`, else
  `Unauthenticated`; Azure connection/IO, 429 and 5xx → `Unavailable`, else `Unauthenticated`.
  Each keeps the SDK error as its `source()`.
- **Supply chain:** `deny.toml` skips `http@0.2` and `http-body@0.4` (AWS smithy types) and
  `base64@0.22` (Azure's typespec), each with its reason. Dropping `credential_process` and the
  Azure CLI removed tokio's `process` feature (and `errno`, `signal-hook-registry`) from the tree.
- **Clippy at 1.91:** raising `rust-version` let clippy suggest let-chains (stable since 1.88);
  `cargo clippy --fix` collapsed the nested `if let`s across the workspace (mechanical).
- **Tests:** each bridge has mock tests over an in-process SDK provider (credentials sign the
  request, caching/expiry, error kinds with no KMS request) and a `Debug` redaction check in its
  hygiene test. The live jobs keep their built-in sources.

Acceptance, as verified on 2026-10-12 (branch `credentials-sdk-bridges`, CI run 38308533656):
every job that ran passed (33), including `features`, `deny`, MSRV 1.91, the Vault/OpenBao,
Floci and Lowkey Vault emulator jobs and every fuzz target. (This first recorded LocalStack as
passed too: its job reported success, but without `LOCALSTACK_AUTH_TOKEN` every step was
skipped, so LocalStack did not run. Corrected per `docs/release-plan.md` 4.3, R-40.) The three
live jobs were skipped: they only run in `sagikazarmark/anykms` with its OIDC roles and
variables, which this checkout (`anykms.orig`) does not have. Their definitions are identical to
those before this work, and the credential paths they use (AWS STS web identity, GCP
`external_account` with impersonation, Azure workload identity) are kept and covered by mock
tests. The maintainer accepted this ("unchanged", not yet run) as meeting the live-job criterion;
the live jobs run once the code is in the repository they name.
