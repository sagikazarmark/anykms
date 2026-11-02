# Architecture plan after the cloud backends

Status: **implemented** (2026-10-07, branch `cloud-backends`). Signed off by the API, security
and implementation reviewers (revision 2, plus the round-2 fix in revision 3); the **Review log**
(§8) maps each item to its resolution. Every task (X0–X23) is done; each design section ends with
the task's "Implementation notes", and PLAN §25 summarizes the result.

Inputs were three read-only analyses:

- core API stress (A1–A7);
- duplication across the backends (B1–B5, plus inconsistencies);
- packaging and operations (C1–C7).

Every claim was checked against the code before any design was based on it. Where the code
disagreed with an analysis, this plan follows the code (§1.4). Once the maintainer accepts the
plan, its decisions move into `PLAN.md` as §25 (tasks X6, X22). The tasks in §5 need no further
design.

**Task IDs.** This plan's tasks are `X0`–`X23`. `T1`, `T3` and `T13` always mean the live
probes of PLAN §24.4, written as "§24.4 probe T1" and so on. They never mean tasks of this plan.

## 1. Summary and scope

### 1.1 Release state

- **0.1.0 has not been published.**
  - `git tag` is empty.
  - crates.io answers 404 for `anykms-core` and `anykms`.
  - The workspace version is `0.1.0`.
  - `CHANGELOG.md` has two unpublished sections: `[Unreleased]`, which holds the cloud work, and
    `[0.1.0] - Unreleased`.
- **Consequence:** breaking changes to core cost nothing outside the repository.

**R1. All three phases land before the first publish.** That publish is **0.1.0** and contains
core, recipes, conformance, local, http, transit, aws, gcp, azure and the facade. The two
changelog sections merge into one `[0.1.0]` section (X23).

**§23 Q1 is superseded.** Q1 said "0.2.0 ships AWS; GCP and Azure follow as 0.2.x". That
assumed 0.1 had been published with transit only. Instead, every backend ships in 0.1.0, and the
first breaking release after the publish is 0.2.0. §24.4 probes T1 (GCP) and T3 (Azure) become
0.1.0 release gates; see open question 1 (answered: hold the publish until they run). §24.4 probe T13 (Managed HSM) is not a gate: MHSM
ships documented as "not live-tested", as `CHANGELOG.md` already says.

**R2. The semver job is non-blocking until the publish.** X0 adds `continue-on-error: true` to
the CI `semver` job. That job compares against the PR's base branch, and Phase 2 breaks the API
on purpose. After the publish the job compares against crates.io and blocks (X19).

### 1.2 What changes

1. **Phase 1: consistency fixes.** One rule per behavior across the four HTTP backends. The
   shared code moves into `anykms-http`, and a new unpublished `anykms-testkit` crate holds the
   test helpers. No new portable API.
2. **Phase 2: core API**, in dependency order:
   - A3: the error model;
   - A1: `KeySemantics`;
   - A2: versioning;
   - A4: one type-erased `Call` through layers;
   - A5: a `Preflight` part and backend `KeyInfo`;
   - A6: `PublicKeys` on `KeyWrapKey`.

   A7 (a separate crypto crate) is **not** done; §3.7 gives the reason.
3. **Phase 3: packaging and operations.** The CI feature matrix, the default TLS provider,
   `from_env_with` on every backend, the transit variable prefix, `deny.toml`, the fixture
   helpers, `releasing.md` and the versioning policy.

### 1.3 What does not change

- **Provider openers.** The `Provider` open methods are unchanged. `forward_provider!` and
  `impl Provider for Arc<P>` gain only the non-opener methods `name` and `pin` (A2).
- **`OpenOptions`** and its typed extensions.
- **`KeyUri`**: an opaque `rest`, which each backend parses itself (the allowlists differ per
  cloud).
- **Errors:** `Error`, `BackendDetail` and `ErrorClass` keep their shape. Two rules stay: no
  retries inside backends, and retries never nest.
- **The capability trait split**, and `PinnedVerifier`.
- **Layers:** `Layer::part` stays the one required method.
- **Ciphertexts and framing:** `Ciphertext` stays opaque. The Azure frame and the 405 fallback
  stay internal. `Decrypted::used_primary` stays.
- **`call_extension`** stays as the escape hatch (only its types are renamed, A4).
- **Wire formats:** envelope v1, the AWS AAD context (`associatedData`, Tink's, since the release
  plan D1) and the Azure frame.
- **`full` bounds stay frozen at today's set.** New parts go in `later {}`.
- **Transit's `VAULT_*` / `BAO_*` variables.**
- **The `anykms-recipes` crate layout** (§3.7).

### 1.4 Where the code contradicted the analysis

| # | Analysis | Code | Effect |
|---|---|---|---|
| 1 | A5: add `preflight()` | Opaque handles already have a generic, describe-based `preflight()` (`dynamic.rs:1800-1870`). What is missing is each backend's own key-type check. | A5 adds a `Preflight` part. |
| 2 | A3(a): only AWS and Azure disagree | GCP verify with an unknown version is `NotFound` (a `getPublicKey` 404). AWS `public_key_of` gives `NotFound` for a non-ARN version. | Both are migrated (§3.1). |
| 3 | C4: prefix the transit variables | Transit reads the standard `VAULT_*`/`BAO_*` names plus six unprefixed `ANYKMS_*` names. | Only the six are renamed. |
| 4 | B2: three header filters | GCP's request id comes from the `google.rpc.RequestInfo` body detail. | The filter takes a `&str`. |
| 5 | Azure `Proxy` leaks | `anykms_http::client::ClientOptions` also derives `Debug` over the proxy URL, and AWS `sigv4::Signed` derives `Debug` over the `Authorization` header (`sigv4.rs:43-49`). | P1-1 covers all three. |
| 6 | — | Azure's local-verifier cache (`handles.rs:563`) has no TTL, so a disabled version keeps verifying locally. | P1-13. |
| 7 | — | Transit maps the 400 "does not support … key type" to `InvalidArgument` (`errors.rs:181-191`). | It becomes `KeyMismatch` (P1-4). |
| 8 | — | The Azure-shaped proof fixture declares `UsesCurrent` and no primary for signing. The real Azure fixture is `Rejected`, with a primary. | Aligned in X12a. |
| 9 | C7 | Several stale texts: the semver comment cites `publish = false` (no crate has it); the MSRV step name ("except transit and aws") excludes all four; the `KeyVersion` rustdoc says AWS is "planned"; `ci/cloud/` IaC does not exist (the `scripts/*-test-setup.sh` scripts provision instead). | Fixed in X19, X10 and X21. |
| 10 | I2 | Transit token files are already `Unavailable`. The GCP ADC file is `Configuration` (correct). Other non-missing token-file errors are inconsistent: transit not-UTF-8 is `Unavailable`, GCP too-large is `Unavailable`, Azure `EACCES` is `Unavailable`. | One classifier for all four (P1-2). |
| 11 | — | The GCP fake fixture's `EmptyPlaintext` is `lacks`. With `ANYKMS_FAIL_ON_SKIP=1` (CI) the two `roundtrip_empty` cases fail at HEAD: 298 passed, 2 failed, 148 ignored. | Fixed in X0. |
| 12 | — | AWS `GetPublicKey` serves a disabled key, and `CachedVerifier` promises revocation within its TTL (`cached.rs:171-176`). On AWS that promise is false. | AWS (and GCP) refuse public keys of disabled keys client-side (§3.1(f)). |

## 2. Phase 1: consistency fixes (no API design)

Each row gives one rule for every backend, the reason, and what to change. Paths are under
`crates/`.

### 2.1 Inconsistencies

| # | Rule | Why | Change |
|---|---|---|---|
| P1-1 | `Debug` of any type holding a URL prints `scheme://host:port` only, through one helper, `anykms_http::redact::url_origin(&str) -> String`. Signed requests print the access key id and the credential scope, never the signature. | Proxy URLs carry credentials. A SigV4 signature can be replayed for about 5 minutes. | Azure `config.rs:250`; `anykms-http/src/client.rs:19`; AWS `sigv4.rs:43-49`. Transit, AWS and GCP `Proxy` adopt the helper. The testkit hygiene test (§2.2) formats every public config, builder and credential type that holds a proxy with userinfo, a fake secret and a fake token, and asserts none of them appears in the output. |
| P1-2 | Token **files** (projected or rotated: web identity, container token, Azure federated, GCP subject, transit token and JWT) are classified by one function, `anykms_http::zbuf::token_file_error_kind(&io::Error) -> ErrorKind`: `NotFound` → `Unavailable`; everything else → `Configuration` (`EACCES`, `ENOTDIR`, `EISDIR`, too large, not UTF-8, empty, control characters). Files that *select* a credential source (ADC JSON, AWS profiles) stay `Configuration`. | A missing file is a rotation race. Every other failure is a deployment error that retrying cannot fix. | AWS `credentials/sts.rs:158`, `credentials/container.rs:95`; transit `auth.rs:293-305`, `token.rs:259`; GCP `auth/external_account.rs:174-185`; Azure `cred/entra.rs:153-158`. The P1-8 `warn!` names the path. |
| P1-3 | `Retry-After` is attached whenever present, whatever the kind. | `Retry` reads it only for retryable kinds. GCP 503s carry it. | GCP `errors.rs:355-359`. |
| P1-4 | **Cached key metadata** (type check, describe, Azure key bundle) is dropped only when a request that addressed the **handle's own key or configured version** (the URI pin, or the current or primary version) fails with `NotFound`, `KeyMismatch`, `Unsupported` or `KeyStateInvalid`. Azure also drops it on `PermissionDenied` until §24.4 probe T3 reclassifies disabled keys. **A request whose version came from input never drops it**: verify, `public_key_version`, a decrypt of a version from a frame or ciphertext, Azure `ReqClass::InputVersion` and `get_bundle(Some(input))`, GCP `version_key` with a signature or `kid` version. `InvalidArgument` never drops it. | Kind alone cannot tell "the key changed" from "a caller named a version that does not exist". Filtering by origin stops a forged `kid` from forcing a describe on every caller. | Move the forget decision out of the generic `send` in transit (`handles.rs:219-231`), AWS (`:409`), GCP (`:180-192`) and Azure (`:204-214`). Each request passes `Origin::{Handle, Input}`, and only `Handle` requests can drop the cache. The input-version 404 is classified **before** this check (in Phase 1 as today's kind; X8c/X8d then change the kind only). Transit 400 "does not support … key type" → `KeyMismatch` (`errors.rs:181-191`). **Test per backend:** 100 distinct forged versions through verify and `public_key_version` cause 0 extra describe or type-check requests (the `RequestCount` counter or mock hit count). |
| P1-5 | Withdrawn after review. The Azure `verify_with_describe` additions would be deleted by A5; X16 implements the Azure `Preflight` directly. | Avoids churn. | — |
| P1-6 | Every error raised after the URI is parsed carries `resource` (`uri.without_query()`), including `require_shape` and other open-time checks. | Operators need the key (§20). | Transit `provider.rs:307/322/337/352`; AWS `provider.rs:336/348/360/374`; Azure `provider.rs:424`. Conformance `local_checks_name_the_key_signing` and `_mac` (`cases/errors.rs`) also assert open-time shape errors (owned by X2). |
| P1-7 | Every credential source, custom ones included, goes through `CredentialCache` and the token span. The refresh lead is the cache default (5 min). GCP keeps 4 min, with this comment: the metadata server hands out a cached token until it has about 5 min left. §24.4 probe T1 confirms the value. | One cache and one span for every source. | GCP `auth/mod.rs:533` (wrap `Spec::Custom` in `Cached`) and `:37`; the GCP docs that tell custom sources to cache. |
| P1-8 | Token-span events are `debug!` on success and `warn!` on failure. The failure event carries `error_kind`, the sanitized `Display`, and the file path where a token file failed. | A refresh is routine; a failure needs an operator. | AWS `client.rs:212`; Azure `credential.rs:186-221`; transit (new span, §2.2). |
| P1-9 | One request-id filter, `anykms_http::redact::request_id(&str) -> Option<&str>`: 1–128 characters, all `is_ascii_graphic`. An empty id is `None`. | An empty id carries nothing. | AWS `errors.rs:102`; GCP `errors.rs:174`; Azure `client.rs:64`. |
| P1-10 | An empty allowlist, or an empty environment value, is `Configuration` at `build()`: "allowed_X is empty: omit it to allow every X". | Nobody means "refuse every key". D2: a broken configuration fails at construction. | AWS `config.rs:329-340`; GCP `provider.rs:241-245`. |
| P1-11 | `max_response_bytes >= anykms_http::client::MIN_RESPONSE_BYTES` (64 KiB). | Smaller limits break describe and token responses with confusing `Backend` errors. | Transit `config.rs:401`; AWS `config.rs:355`; Azure `provider.rs:270`; GCP `provider.rs:238`. |
| P1-12 | The data-plane HTTP client is built in `build()`: TLS roots and the rustls provider are resolved there, with no network I/O. Credential-endpoint clients (IMDS, STS, the Entra authority) stay lazy. | A broken TLS configuration fails at construction everywhere. | AWS `client.rs:115-130`, `provider.rs:82`. |
| P1-13 | A local verifier caches a version's public key for at most the provider's metadata TTL (GCP `public_key_ttl`, Azure `key_cache_ttl`), jittered by `jittered_ttl`. The expiry counts from fetch time, not from last use. A re-read that fails does **not** extend a stale entry: verification fails closed with the re-read's error. A small negative cache (64 entries, the same TTL) remembers input versions that came back unknown, so forged versions cost at most one request each per TTL. | Revocation reaches local verification within a bounded lag (`KeySemantics`, A1), and forged-version amplification is bounded. | Azure `handles.rs:563,751-783`; GCP `handles.rs:292-375` (negative cache only; its TTL already exists); `docs/operations-azure.md:159`. |

### 2.2 Shared code (B1–B5)

**B1, span schema in `anykms-http`** (feature `tracing`):

- `pub const REQUEST_FIELDS: &[&str]` holds the D3 fields: `backend, op, resource, key_version,
  attempt, http_status, code, request_id, latency_ms, error_kind, outcome`.
- `pub const TOKEN_FIELDS: &[&str]` holds `backend, credential, outcome, error_kind, latency_ms,
  expires_in_s`.
- **Macros:**
  - `request_span!("anykms.aws", op = .., resource = .., key_version = ..)` takes the span name
    as a literal and lists every D3 field literally, with each unset field `Empty`. `attempt` is
    recorded later, so it is not an argument.
  - `token_span!("anykms.aws.token", credential = ..)` works the same way.
  - Both expand through `$crate::__private::tracing` (a `#[doc(hidden)]` re-export).
  - Without the `tracing` feature, both expand to a unit no-op type.
  - A testkit test asserts that each macro's `metadata().fields()` equals its constant.
- **Finish helpers:**
  - `pub fn finish_request<T>(span, started: Instant, request_id: Option<&str>, r: &Result<T>)`
    records `latency_ms`, `outcome` and `error_kind`, plus `code` and `request_id` from the
    error detail on failure, or from the `request_id` argument on success.
  - `finish_token(span, started, expires_in: Option<Duration>, r)` does the same for token
    spans.

**Transit adopts the schema** (X2):

- The request span becomes `anykms.transit` with exactly `REQUEST_FIELDS`. `server_alias`,
  `mount` and `key` fold into `resource`.
- A new token span, `anykms.transit.token`, covers login and renewal (`auth.rs:330,347`). Its
  `credential` field is one of `token | token_file | kubernetes | jwt | agent`.
- Transit's hygiene test gets the schema assertion.
- `docs/operations.md` names `resource` instead of `server_alias` (owned by X2).

**B4, `send()`:**

```rust
pub async fn send(req: reqwest::RequestBuilder, limit: usize) -> Result<Response, SendError>;
pub struct Response { pub status: StatusCode, pub headers: HeaderMap, pub body: Zeroizing<Vec<u8>> }
pub enum SendError { Transport(reqwest::Error), TooLarge { status: StatusCode } }
```

- `send()` records `http_status` into the current span.
- It replaces transit `client.rs:107-126,211-230`, AWS `145-163,401-411`, GCP `117-137` and Azure
  `183-210`.

**B2, B5 and P1 helpers** in `anykms-http`:

- `redact::{request_id, url_origin, contains_ci}`; `contains_ci` becomes `pub`, and the transit
  and GCP copies are removed.
- `zbuf::token_file_error_kind`.
- `cache::jittered_ttl(ttl: Duration) -> Duration` (±10 %).
- `client::MIN_RESPONSE_BYTES`.

**B3, `anykms-testkit`:**

- Unpublished: `publish = false`, path-only, and not in `[workspace.dependencies]` with a version.
- Each backend declares `anykms-testkit = { path = "../anykms-testkit" }` under
  `[dev-dependencies]`.
- Each backend's `exclude` adds `tests/hygiene.rs`. Transit and Azure get an `exclude` list for
  the first time.
- Contents:
  - `Buf`;
  - `capture_trace(f) -> String` (every target at TRACE);
  - `SpanRecorder`;
  - `assert_request_schema(&SpanRecorder, backend)` and `assert_token_schema(..)`;
  - `assert_debug_redacts(&dyn Debug, secrets: &[&str])` for P1-1.
- It replaces AWS `hygiene.rs:37-85`, GCP `32-181`, Azure `28,345-432`, and transit's `Buf`.

**Left duplicated on purpose:** HTTP builder settings, token-source traits, IMDS and metadata
clients, provider skeletons, the `errors.rs` tables, and the refresh-once trigger. Token-file
*readers* converge on `zbuf::read_file` plus `token_file_error_kind`.

**Implementation notes (X1):**

- The span macros take `backend` too: `request_span!("anykms.aws", backend = BACKEND, op = ..,
  resource = .., key_version = ..)` and `token_span!("anykms.aws.token", backend = BACKEND,
  credential = ..)`. Field values are plain expressions (`&str` or `Option<&str>`), no `%`/`?`
  sigils, so the no-op expansion compiles too. Each macro is defined twice (per `tracing`, N4).
- They live in a new module `anykms_http::span`, with `REQUEST_FIELDS`, `TOKEN_FIELDS`,
  `finish_request`, `finish_token` and three small helpers so backends need no `cfg`: `Span`
  (`tracing::Span`, or a unit no-op type), `instrument(fut, &span)` and `record_attempt(n)`.
  `finish_request` filters its success `request_id` through `redact::request_id`.
  `finish_token` records fields only; the P1-8 `debug!`/`warn!` events stay with the backends
  (they name the source and the file path).
- `cache` is a new module (`cache::jittered_ttl`); if the OS RNG fails it returns `ttl`.
- `send` strips the URL from `SendError::Transport` (`without_url`); `Response`'s `Debug` prints
  the status and body length only.
- X1 also did P1-1 for `anykms-http/src/client.rs` (`ClientOptions`' `Debug` prints the proxy
  through `url_origin`), since no other task owns that file.
- Testkit: besides `capture_trace(f) -> String`, a guard `capture() -> Capture` (`text()`,
  `spans()`) for async tests on a current-thread runtime; `SpanRecorder` records
  `RecordedSpan { name, fields, values }`. The `log` bridge (reqwest) is a process-wide
  `LogTracer`, installed on the first capture: a test binary that captures must not also call
  `try_init()` on a global subscriber (X2–X5 migrate the hygiene tests wholesale).
  `assert_*_schema` also reject any other `anykms.<backend>.*` span. The crate is a workspace
  member through `crates/*` (the root `Cargo.toml` is unchanged) and so runs in the MSRV test
  step; it has no wiremock. `fuzz/Cargo.lock` did not change.

**Implementation notes (X2):**

- Token spans are emitted where a token is fetched: every `Login` login and renewal
  (`credential` = `kubernetes` or `jwt`) and every read of a `FileToken` file that is not served
  from its cache (`token_file`; the span is created after the read, so a cached token costs no
  span). `StaticToken`, `EnvToken` and `NoToken` fetch nothing and emit none, so `token` and
  `agent` are not used; a custom `TokenSource` emits its own. A failed renewal is now a `warn`
  (P1-8) in its span; the "using the current token" event after a failed login became `debug`,
  since the login's span already warned.
- `key_version` is the version a request names from input (decrypt and rewrap: the
  ciphertext's; verify and MAC verification: the signature's or tag's; `public_key_version`);
  empty otherwise. `code` and `request_id` stay empty: transit errors carry neither.
- P1-4 origins: `Input` for decrypt, rewrap, verify, MAC verification and the metadata read of
  `public_key_version`; everything else is `Handle`. The whole 400 arm "does not support" / "not
  supported for key type" / "provided for non-AEAD cipher suite" became `KeyMismatch`.
- P1-2: `FileToken` and the `Login` JWT file now report an empty file, a file over the limit,
  non-UTF-8 and whitespace or control characters as `Configuration` (they were `Unavailable`,
  "the agent may be mid-write"); agents replace token files by rename, so only a missing file is
  a rotation race.
- P1-1: `ServerConfig` and the internal `Server` also print the server address through
  `url_origin`.
- Conformance: the open-time shape check (Ed25519 as a digest signer, ECDSA as a message signer)
  calls the fixture's `Provider` directly, bypassing the `Registry` (which already names every
  open error), in both `local_checks_name_the_key_*` cases. It runs only for providers named
  `transit`, `aws`, `gcp` or `azure`: P1-6 does not cover `anykms-local` or the shaped test
  fixtures, whose open-time errors are unnamed. AWS and Azure pass it once X3 and X5 land.
- Transit's `jittered_ttl` and `contains_ci` copies are replaced by the `anykms-http` ones.

**Implementation notes (X4):**

- P1-4 origins: `Input` for verify (the signature's version), MAC verification (the tag's) and
  `public_key_version`; everything else is `Handle`, decrypt included (a Cloud KMS ciphertext's
  version is opaque: the request addresses the key).
- P1-13: the negative cache holds the error of an input version's `NotFound` (returned again,
  with the caller's operation) per version name, 64 entries, evicting the entry nearest expiry;
  a later successful fetch of that version clears it. `public_key_ttl(ZERO)` disables it with
  the positive cache. Positive entries now store their jittered expiry (fetch time + TTL ±10 %).
- P1-7: `Credentials::custom` sources are wrapped in `Cached` (`credential = "custom"`). A token
  without `expires_at` is kept until a 401; a source returning no token is cached as "no
  token". On a 401 the cache also forwards `invalidate` to the source. The conformance fixture's
  counting source now hands out already-expired tokens, so it still counts one call per
  request.
- P1-3: `RetryInfo.retryDelay` is attached like `Retry-After`, whatever the kind.
- P1-2: a subject token **file** that is unreadable, too large, not UTF-8, not JSON, lacks the
  field or is empty is `Configuration`; the same faults from a subject token **URL** stay
  `Unavailable`.
- P1-10: an allowlist variable that is set but lists nothing (`""`, `" , "`) is kept as an
  empty list, which `build()` refuses (it was taken as unset).
- P1-1: `Endpoint` gets a manual `Debug` (a custom URL through `url_origin`), and the handle
  `Debug` prints the endpoint's origin. `AuthEndpoints` keeps its derived `Debug`: its URLs are
  fixed Google URLs or a custom origin that is refused with userinfo, path or query.
- The token-endpoint requests (`auth/oauth.rs`, `auth/metadata.rs`) keep their own
  `read_body`; only the data-plane client moved to `send()` (B4 lists `client.rs` only).

**Implementation notes (X3, AWS):**

- P1-4: every AWS request names the handle's key (a version from input that is not the
  handle's resolved ARN fails before any I/O), so `Origin::Input` marks the requests whose
  version came from input (`Verify`/`VerifyMac` with a version, `GetPublicKey` for
  `public_key_version`); only `Origin::Handle` requests drop the describe cache, now on
  `NotFound`, `KeyMismatch`, `Unsupported`, `KeyStateInvalid` (no longer `InvalidArgument`).
- P1-6: `digest_key`/`mac_key_with` parse the URI before the algorithm checks, so those
  errors name the key on the typed openers too.
- P1-8: the failure `warn!` carries `credential`, `error_kind` and the error's `Display`; a
  failed token file is named in that message (no separate `path` field).
- P1-10: the environment snapshot keeps empty `ANYKMS_AWS_ALLOWED_*` values (other AWS
  variables still treat empty as unset), so an empty variable fails at `build()`.
- P1-1 also covers `sigv4::Request` (header names and payload length only) and the endpoint
  URLs of `ImdsCredentials`, `WebIdentityCredentials` and `AwsProvider`.

**Implementation notes (X5, Azure):**

- P1-4: `Origin` is passed to the handle's `send`; `post` derives it from `ReqClass`
  (`InputVersion` → `Input`) and `get_bundle` takes it (`public_key_version` → `Input`).
- P1-13: the per-handle `LocalVerifiers` hold `(expiry, verifier)` per version and a separate
  unknown-version map, both bounded at 64 (expired entries evicted first, then cleared), TTL =
  `key_cache_ttl` jittered from fetch time; `key_cache_ttl(0)` caches nothing. An expired entry
  is removed before the re-read, so a failed re-read fails closed with its own error.
- P1-2: an empty or non-token federated file was `Unavailable`; it is now `Configuration`.
- P1-6: `digest_signing_key_with` parses the URI first, so `require_shape` and the RSA-backend
  error name the key.
- P1-8: as in X3, the token file is named in the error's message.

## 3. Phase 2: core API

Breaking before the publish is cheap (R1). Every item is marked **breaking** or **additive**.

### 3.1 A3: error model (breaking: classification and behavior)

```rust
#[non_exhaustive]
pub enum ErrorKind {
    // ... existing ...
    /// The input names a key version this key does not have, or another key's version (an
    /// untrusted `kid`, a stale reference; with a retry hint when the version may not have
    /// replicated yet). Caller class. Never drops cached key metadata.
    UnknownKeyVersion,
}
#[non_exhaustive]
pub enum Operation { /* ... existing ... */ WrapKey, UnwrapKey }

impl Error {
    pub fn is_config_error(&self) -> bool;  // == self.kind().is_config_error()
    pub fn is_caller_error(&self) -> bool;  // == self.kind().is_caller_error()
    /// Hinted(h) only when the kind is not caller class; a caller-class error keeps its hint in
    /// retry_hint() (Retry still honors it) but classifies as Caller.
    pub fn class(&self) -> ErrorClass;
}
```

**(a) A version taken from input.**

- Verify, or `verify_mac`, with an unknown version or another key's version is
  `VerificationFailed` on every backend, through server and local verification alike.
- `public_key_version` with such a version is `UnknownKeyVersion`.
- A malformed version string is `InvalidArgument`.
- None of these is config class.
- A hint on any of them no longer makes the class `Hinted`. A forged `vault:v999999:` token
  therefore maps to the caller class (401/400 in the `operations.md` table), not to 503.

**(b) The version a handle chose.** When the version a handle *chose* is unusable (its URI pin,
or its current or primary version), the error is `KeyStateInvalid` for **every** operation,
`public_key()` included.

- `KeyVersionUnusable` is only for versions taken from input, and is always caller class.
- Remove `Error::unusable_write_version` (`error.rs:500-508`).
- Rewrite the docs that state the operation rule: the `KeyStateInvalid` and `KeyVersionUnusable`
  rustdoc (`error.rs:66-70,101-112`), the class-table footnote (`error.rs:41-47`), and the
  `is_config_error`/`is_caller_error` docs (`error.rs:485-499`).

**(c) Parse errors are config class.** `Operation::ParseUri` errors become `Configuration` in
core `uri.rs:27` and in each backend's `uri.rs` (AWS `:193`, GCP `:30`, Azure `:36`, transit
`:47`), because URIs come from configuration. Exceptions that take input:

- `AzureKeyRef::from_key_id` and `with_version` (`uri.rs:85,156-158`) return `InvalidArgument`
  with `Operation::Construct`;
- every input-version parser (AWS `is_key_arn`, GCP and Azure `parse_version`) keeps returning a
  bool or an `Option`.

A unit test per backend asserts that no input-version path produces `ParseUri`. Applications
that accept URIs from users map `Error::operation() == ParseUri` themselves. No
`Registry::check_uri` is added (Review log).

**(d) Key-wrap operations are named.** `WrapKey`/`UnwrapKey` replace `Encrypt`/`Decrypt` in:

- AWS `handles.rs:1079-1110`, GCP `:1486-1534`, Azure `:988,1050,1117`;
- `AeadKeyWrap` (`traits.rs:418-431`), through `.with_operation(..)`;
- `Observed` (`observe.rs:393-406`);
- `KeyWrapKey`'s missing-part errors.

Metric labels change; CHANGELOG notes it.

**(e) Azure disabled key.** It stays `PermissionDenied` until §24.4 probe T3. Not part of this
plan.

**(f) Public keys of disabled keys.** Every built-in backend refuses the public key of a disabled
key (`KeyStateInvalid`) or of a disabled version (`KeyStateInvalid` if the handle chose it,
`KeyVersionUnusable` if it came from input). Where the server serves it anyway, the backend
checks first:

- **AWS:** `public_key` and `public_key_version` send `DescribeKey` uncached before
  `GetPublicKey` (two requests). `KeyState != Enabled` → `KeyStateInvalid`.
- **GCP:** on a public-key cache miss, `cryptoKeyVersions.get` checks that the state is
  `ENABLED` before `getPublicKey`. §24.4 probe T1 decides whether the extra call can be dropped.
- **Azure:** already enforced (`handles.rs:812-826`).

The `PublicKeys` rustdoc (`traits.rs:307-317`) states this contract, together with the A3(a)
kinds. `CachedVerifier`'s revocation promise is then true on every built-in backend; its rustdoc
says third-party sources must honor the same contract.

**Recipes:**

- `CachedVerifier::verify_*` maps `UnknownKeyVersion` from its source to `VerificationFailed`,
  keeping the original as `source`.
- It keeps `InvalidArgument` with its hint for the version-ceiling and non-numeric rejections.
- `negative_ttl_for` (`cached.rs:500`) adds `UnknownKeyVersion`.
- Its rustdoc documents both rules.

**Migration per backend:**

| Backend | verify: unknown or foreign version | `public_key_version`: unknown | malformed version | chosen version unusable |
|---|---|---|---|---|
| transit | already `VerificationFailed` | `NotFound` → `UnknownKeyVersion`; the hint above latest stays (`handles.rs:920-932`) | `InvalidArgument` | n/a (no pins) |
| local | already `VerificationFailed` | `NotFound` → `UnknownKeyVersion` (`keyset.rs:193`) | `InvalidArgument` | n/a |
| AWS | `NotFound` → `VerificationFailed`, before I/O (`handles.rs:559-573`); MAC too | `NotFound` → `UnknownKeyVersion` (`:1248-1254`) | add an `is_key_arn` check in `public_key_of` → `InvalidArgument` | disabled key: `KeyStateInvalid` (unchanged), and now on public keys (f) |
| GCP | a `getPublicKey` 404 for an input version → `VerificationFailed` (`handles.rs:294,894-964`) | 404 → `UnknownKeyVersion` | `InvalidArgument` | `FAILED_PRECONDITION` on encrypt, sign, MAC, RSA-KEK wrap (`version_key(pinned, ..)`) and `public_key()` with no argument (`handles.rs:952-960`) → `KeyStateInvalid`; the `PENDING_GENERATION` hint is kept (`errors.rs:264-276`) |
| Azure | server path unchanged; `verify_local` matches `UnknownKeyVersion` (was `NotFound`, `handles.rs:769-777`) | `NotFound` → `UnknownKeyVersion` (`:789-806`, including "the URI pins another version") | `InvalidArgument` | disabled pinned or current version → `KeyStateInvalid`; disabled input version stays `KeyVersionUnusable` (`:814-826`) |
| local shaped GCP (`tests/shaped/gcp.rs`) | `:206-207` `NotFound` → `VerificationFailed` on verify | → `UnknownKeyVersion` | — | `:209-210,300-307` `KeyVersionUnusable` → `KeyStateInvalid` for pinned or primary versions |
| local shaped Azure (`tests/shaped/azure.rs`) | same as Azure | same as Azure | — | same as Azure |

**Conformance (X8e):**

- `sign::foreign_versions` (`cases/sign.rs:697-745`) and `mac.rs:84` expect exactly
  `VerificationFailed` (verify) and `UnknownKeyVersion` (`public_key_version`).
- `sign.rs:498` ("public key below min version") expects `UnknownKeyVersion`.
- `aead::disabled_primary_version` (`cases/aead.rs:317-337`), `sign::disabled_version`
  (`sign.rs:571-593`) and `mac::disabled_version` (`mac.rs:209-234`) expect `KeyStateInvalid`
  **and keep `is_config_error()`** on the write. Reads of the disabled version expect
  `KeyVersionUnusable` with `is_caller_error()`.
- `sign::disabled_key`: the public key of a disabled key fails with `KeyStateInvalid` on every
  backend.
- New: `errors::parse_uri_is_configuration`.
- New: `errors::forged_versions_do_not_flush`. 32 forged versions are sent; where the fixture
  declares `RequestCount`, the count must equal 32 plus a constant (no describes).
- **Deleted:** `FixtureCaps::{foreign_version_error, with_foreign_version_error,
  foreign_version_errors}`, and `public_key_when_disabled` with its builder.
- `docs/operations.md`: the kind table gains `UnknownKeyVersion`, and the `class()` row changes.

**Tests:**

- the `ErrorKind` class table;
- `Error::class` for each kind, with and without a hint;
- the AWS, GCP and Azure mock rows, including one "write with a disabled pinned version →
  `KeyStateInvalid`" row each;
- the fuzz targets that assert kinds.

Revision 1 proposed a core test that "no `errors.rs` maps a write to `KeyVersionUnusable`". It
was rejected: core cannot see backend tables. The conformance and mock rows above enforce the
rule instead.

**Implementation notes (X8c, GCP):**

- The request origin of P1-4 gains a third value, `Origin::Ciphertext` (symmetric decrypt): it
  addresses the handle's key, so it may drop the cached checks like `Handle`, but its version
  comes from the ciphertext, so a disabled one is `KeyVersionUnusable`. `classify` receives the
  origin; `Handle` maps a non-enabled version to `KeyStateInvalid` (with the pending hint),
  `Ciphertext` and `Input` to `KeyVersionUnusable`.
- An input-version `NOT_FOUND` is `UnknownKeyVersion` unless the message names the key itself
  ("CryptoKey … not found", not "CryptoKeyVersion … not found"): verify on a missing key stays
  `NotFound`, as conformance `errors::missing_key::*` requires on every backend. §24.4 probe T1
  confirms the live texts.
- (f): the version-state lookup (`cryptoKeyVersions.get`) runs with the version's origin, so for
  an input version it is input-origin (never drops the checks). Its refusals of input versions
  (`UnknownKeyVersion`, and `KeyVersionUnusable` without a retry hint) share the P1-13 negative
  cache; pending versions are not remembered. A refused handle version is not negative-cached.

**Implementation notes (X8a, transit and local):**

- (c) also covers local's `parse_local_uri` and the shaped fixtures' URI parsers
  (`Configuration`, `Operation::ParseUri`; local used `InvalidArgument` with `Open`).
- (d) also covers transit's KEK (`TransitKek`, the `AeadKeyWrap` look-alike): `WrapKey`/`UnwrapKey`.
- Transit `public_key()` keeps `NotFound` when the latest version is missing from the key read
  (the handle's version); only an input version becomes `UnknownKeyVersion`.

**Implementation notes (X8b, X8d, X8e; AWS, Azure, conformance):**

- AWS (f): `public_key()` sends a fresh `DescribeKey` of the URI's key or alias (it refreshes
  the metadata cache and resolves the alias) and then `GetPublicKey` of the key ARN it described;
  `public_key_version` describes the resolved key ARN (input origin, so no cache drop) and fetches
  that ARN. Both run the key-type check on the fresh metadata (not under `TrustCaller`) and need
  `kms:DescribeKey` even under `TrustCaller`. States: `Enabled` passes; `Creating`, `Updating`,
  `Unavailable` are `Unavailable`; every other state is `KeyStateInvalid`.
- AWS: a server `NotFound` for the handle's own ARN given as input (the key was deleted) stays
  `NotFound`: on AWS the version is the key, so this is not an unknown version.
- Azure has no "write with a disabled pinned version → `KeyStateInvalid`" mock row: the vault
  answers that write with 403, which stays `PermissionDenied` until §24.4 probe T3 ((e)). The row
  is the pinned disabled version's `public_key()` → `KeyStateInvalid` instead.
- Azure: a 404 for an input version in `public_key_version` is `UnknownKeyVersion` (detail kept);
  `docs/operations-azure.md` (not in X8d's file list) got the matching runbook rows.
- Conformance: `errors::parse_uri_is_configuration` is split per family (`::aead`,
  `::key_wrap`), as the registry rule "a case that would branch on a feature is split" requires;
  `errors::forged_versions_do_not_flush` runs on both paths. With `RequestCount`, "32 plus a
  constant" is checked as: each forged verify or `public_key_version` costs at most what the same
  honest call costs (AWS rejects forged ARNs before any I/O, so equality cannot hold; Lowkey's
  fixture counts two requests per call), and an honest sign and verify afterwards costs exactly
  what it cost before (no cache drop). Totals grow by 6 cases per target (454).
- `sign::foreign_versions` also requires the other key's real version to be exactly
  `UnknownKeyVersion`; the synthetic strings may be `UnknownKeyVersion` or `InvalidArgument`
  (which strings are malformed is backend-specific).
- `CachedVerifier` keeps the source error's retry hint on the mapped `VerificationFailed` (its
  class stays `Caller`), so a hinted retry still covers replica lag with the version checks off.

### 3.2 A1: `KeySemantics` (additive in core; breaking in conformance)

New file `anykms-core/src/semantics.rs`:

```rust
/// Where backends legitimately differ, what this handle does. Known at open (no I/O) and
/// constant for the handle's life: every field states a contract that holds before any request.
/// `None` from `semantics()` means undeclared (third-party backends); the conformance suite
/// fails undeclared handles once migration is done (X13).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySemantics { /* private */ }

impl KeySemantics {
    pub fn new(version_model: VersionModel, version_shape: VersionShape) -> Self;
    pub fn with_primary_reported(self, v: bool) -> Self;                // default true
    pub fn with_state_scope(self, s: StateScope) -> Self;               // default Key
    pub fn with_versions_listed(self, v: bool) -> Self;                 // default true
    pub fn with_ciphertext_reveals_version(self, v: bool) -> Self;      // default false
    pub fn with_reports_used_primary(self, v: bool) -> Self;            // default false
    pub fn with_unversioned_verify(self, u: UnversionedVerify) -> Self; // default Rejected
    pub fn with_pinned_verify(self, p: PinnedVerify) -> Self;           // default PinnedOnly; read only for Pinned
    pub fn with_verification(self, v: Verification) -> Self;            // default Backend
    pub fn with_data_keys(self, d: Option<DataKeySource>) -> Self;      // default None (no DataKeys part)
    /// Byte limits below the request size. `None` = no such limit, or the handle has no such
    /// operation. Large plaintexts go through `EnvelopeAead`.
    pub fn with_max_plaintext(self, n: Option<usize>) -> Self;
    pub fn with_max_mac_input(self, n: Option<usize>) -> Self;
    pub fn with_max_signed_message(self, n: Option<usize>) -> Self;
    // one getter per field: version_model(), version_shape(), reports_used_primary(), ...
}

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionModel {
    /// Writes use the current version, which rotation moves (transit, local, GCP AEAD, unversioned
    /// Azure URIs).
    Floating,
    /// The URI names one version; every write uses it (GCP signing/MAC/RSA KEK, versioned Azure).
    Pinned,
    /// One key identity, no addressable versions; rotation (if any) is inside it (AWS). An alias
    /// URI resolves to a key per request: repointing the alias moves writes to another key.
    Single,
}
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinnedVerify {
    /// A pinned handle verifies only its pinned version (Azure).
    PinnedOnly,
    /// A pinned handle verifies signatures of any version of the same key (GCP: signing keys must
    /// be pinned, so verification across rotation needs this).
    AnyVersion,
}
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum VersionShape { Numeric, Opaque }
/// VersionOnly: KeyInfo::state() is None. Key: a key-level state, which on Azure is the current
/// (or pinned) version's enabled flag (Azure has no key-level flag).
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum StateScope { Key, VersionOnly }
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum UnversionedVerify { Rejected, UsesCurrent }

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verification {
    Backend,
    #[non_exhaustive]
    /// Verified in this process with the version's public key. A version the backend stops
    /// serving keeps verifying for at most `revocation_lag` (cache TTL × 1.1, counted from when
    /// the backend starts refusing).
    Local { revocation_lag: Duration },
}
impl Verification { pub fn local(revocation_lag: Duration) -> Self; }

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataKeySource { #[non_exhaustive] Native { aad: DataKeyAad }, #[non_exhaustive] Emulated { aad: DataKeyAad } }
impl DataKeySource { pub fn native(aad: DataKeyAad) -> Self; pub fn emulated(aad: DataKeyAad) -> Self; }
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataKeyAad {
    /// The wrapped key is bound to the AAD.
    Bound,
    /// Non-empty AAD is `Unsupported` (never ignored).
    Refused,
    /// Bound where the server or key supports it, otherwise `Unsupported`; never ignored. For
    /// handles that cannot know which at open (OpenBao before the first request; Managed HSM
    /// `DataKeysKey`, whose key type is read lazily).
    BoundOrRefused,
}

/// Handles that report semantics.
pub trait Semantics { fn semantics(&self) -> Option<&KeySemantics>; }
```

**Forwarding rule** (rustdoc of `Semantics` and `Layer`):

- A wrapper forwards `Semantics` only if it changes no behavior that `KeySemantics` describes.
- These forward: `Retry`, `Observed`, `Arc`, `Box` and `&T`.
- These do **not** implement `Semantics`: `EnvelopeAead`, `CachedVerifier` (it turns `Backend`
  verification into local), `AeadKeyWrap`, `KeyWrapDataKeys`, `EmulatedDataKeys` and
  `CachingKeyWrap`.
- A layer must not change a behavior that `KeySemantics` describes. Layers cannot replace the
  value.

**Carrying the value:**

- Opaque handles store `Option<Arc<KeySemantics>>` and expose `.with_semantics(..)`.
- `OpaqueHandle` (sealed) gains `fn semantics(&self) -> Option<&KeySemantics>`.
- `KeyWrapKey::from_aead` and `From<AeadKey>` keep the value.
- Typed backend handles have an inherent `fn semantics(&self) -> &KeySemantics`, and their
  `Semantics` impl returns `Some(..)`.
- Providers write `AeadKey::full(..).with_semantics(k.semantics().clone())`.

**Values per backend** (one test per backend pins its row):

| Field | transit/Vault | transit/OpenBao | local | AWS | GCP | Azure vault | Azure MHSM |
|---|---|---|---|---|---|---|---|
| versions | Floating | Floating | Floating | Single | AEAD Floating; signing, MAC and RSA KEK Pinned | Floating, or Pinned for a versioned URI | same as the vault |
| shape | Numeric | Numeric | Numeric | Opaque (ARN) | Numeric | Opaque (32 hex) | Opaque |
| primary_reported | yes | yes | yes | symmetric no; asymmetric and HMAC yes | AEAD yes; others no | yes | yes |
| state_scope | Key | Key | Key | Key | VersionOnly | Key (current or pinned version's flag) | Key |
| versions_listed | HMAC no; others yes | HMAC no; others yes | yes | yes (one) | yes | yes (≤ 10 pages) | yes |
| ciphertext_reveals_version | yes | yes | yes | no | no | KeyWrap yes (frame) | yes (frame) |
| used_primary | no | no | no | no | AEAD yes | no | no |
| unversioned_verify | Rejected | Rejected | Rejected | UsesCurrent | Rejected | Rejected | Rejected |
| pinned_verify | n/a | n/a | n/a | n/a | AnyVersion | PinnedOnly | PinnedOnly |
| verification | Backend | Backend | Backend | Backend | signing `local(public_key_ttl × 1.1)`; MAC Backend (`macVerify`) | Backend; `local_verify()` gives `local(key_cache_ttl × 1.1)` | same as the vault |
| data_keys | native(Refused) | native(BoundOrRefused) | native(Bound) | native(Bound) | None | emulated(Refused) (`KeyWrapDataKeys`) | `AeadKey`: emulated(Bound); `DataKeysKey`: emulated(BoundOrRefused) |
| max_plaintext | None | None | 4 MiB | 4096 | 65536 | None (no `Aead`) | None (unknown until §24.4 probe T13) |
| max_mac_input | None | None | None | 4096 | 65536 | None | None |
| max_signed_message | None | None | None | 4096 | 65536 | None | None |

**Decisions on specific cells:**

- **OpenBao and MHSM `BoundOrRefused`.** OpenBao is known from configuration
  (`from_env_openbao`), its version is not. Vault is `Refused`, because Vault ignores
  `associated_data` on `datakey` and the backend refuses non-empty AAD.
- **`public_key_when_disabled`** is not a semantic: §3.1(f) makes every backend refuse.
- **`settle_time`** stays on the fixture, because it depends on the environment.
- **No pre-open query.** Revision 1 said `VersionModel` makes GCP's pinned requirement "visible
  before any open". That was wrong, because semantics come only from an opened handle, and the
  claim is dropped. The open error names `Registry::pin` instead.

**Conformance:**

- **X11, transition.** Each case reads `semantics()` from the handle it opened. When the result
  is `None`, the case falls back to today's `FixtureCaps` fields, so backends migrate
  independently and nothing goes red.
- **X13, hard failure.** X13 makes `None` a failure ("the handle declares no KeySemantics") and
  deletes the replaced fields.
- **Gating stays declared.** The harness gates before any handle exists (`lib.rs:105-196`), and
  a case cannot report n/a at run time (`ctx.rs:17`). So `Feature::UsedPrimary`,
  `MacInputLimit` and `MessageInputLimit` stay as `FixtureCaps` declarations.
  `with_max_mac_input(len)` and `with_max_signed_message(len)` become
  `supports(MacInputLimit)` and `supports(MessageInputLimit)`. The limit values come from the
  handle. A declared feature whose handle reports `None` fails the case.
- **New case `capabilities::semantics_match_caps`.** For every declared `TestKeyKind`, it opens
  the handle and checks:
  - `UsedPrimary` declared ⇔ `reports_used_primary()`;
  - `MacInputLimit` declared ⇔ `max_mac_input().is_some()`;
  - `MessageInputLimit` declared ⇔ `max_signed_message().is_some()`;
  - `semantics().is_some()` (X13 onward).
- **Deleted in X13** (the old `pub` fields and builders):
  - `ciphertext_versions`, `hmac_versions_listed`, `max_plaintext`, `max_mac_input`,
    `max_signed_message`, `versions`, `unversioned`;
  - `no_primary_version` and `without_primary_version`;
  - `key_state_per_version`, `datakey_aad` and `with_used_primary(bool)`.

  In X11 they are **not** `#[deprecated]` (the gates use `-D warnings`). They are documented as
  "fallback only; removed in X13". The `pub` fields stay readable until X13 removes them, in the
  same commit that removes the fixture calls.
- **Kept on the fixture:** `features`, `Support`, `oversize_plaintext`, `throttle_retry_after`,
  `settle_time`, `with_emulated_errors`, `lacks` and `not_applicable`.
- **`DataKeyAad::BoundOrRefused`:** a case accepts either outcome, provided non-empty AAD is
  never ignored.

**Tests:**

- core: defaults, constructors, forwarding through `Retry`, `Observed`, `Arc`, `Box`, `&T`,
  layers and `KeyWrapKey::from_aead`;
- each backend's row, opened through `Registry`;
- a compile test that `CachedVerifier` does not implement `Semantics`.

**Implementation notes (X9):**

- The value lives on the handle beside its parts (`Option<Arc<KeySemantics>>`), not in a part, so
  `layer`, `replace_retry`, `with_resource`, parts added later and the registry's layers all keep
  it; no layer can reach it. The handles' `Debug` output is unchanged (no `semantics` field), so
  existing `Debug` assertions hold.
- Added `DataKeySource::aad()`, a getter over both variants, because the variants are
  `#[non_exhaustive]` and matching them outside core needs `{ aad, .. }`.
- The compile test that `CachedVerifier` does not implement `Semantics` lives in recipes, which
  X9 does not own; it is left to the first task that edits `anykms-recipes` tests (X11 or later).

**Implementation notes (X11):**

- The fallback is one function, `FixtureCaps::fallback_semantics(kind)`, which builds a
  `KeySemantics` from the fallback fields; cases call `Ctx::semantics_or_caps(handle.semantics(),
  kind)` (or `Ctx::semantics(&key)`, which opens the key's handle without I/O) and read only
  `KeySemantics` getters. Only the fields `FixtureCaps` described are meaningful in a fallback
  value (version model `Floating`, verification `Backend`, data keys `Native`).
- The typed path assembles handles from bridged parts, so the bridges carry the typed handle's
  value: `AeadBridge::semantics()`, `KeyWrapBridge::semantics()` and
  `{Digest,Message,Mac}KeyHandles::with_semantics(..)` (a new `pub semantics` field). Without
  them the typed path falls back (and fails from X13), so every fixture's `TypedHandles` adopts
  them with its backend's X12 task.
- `describe::version_algorithms` adds no `Feature` (an undeclared feature would fail every
  fixture until it declares it, against "nothing goes red"). It is two cases,
  `::signing` (`[Signing(P-256), Describe]`) and `::mac` (`[Mac, Describe]`), run everywhere:
  each version's algorithm is the key's or `None`, all versions alike, and never the other
  family's. GCP's own tests assert that GCP fills them (X12c).
- `semantics_match_caps` also checks the §3.3 URI rule (`Pinned` exactly when `TestKey::version`
  is set) and that `reports_used_primary()` is `false` on non-AEAD handles. Until X13 it skips handles
  that declare nothing.
- `DataKeyAad::BoundOrRefused`: an `Unsupported` refusal passes; any success must be bound.
- The `CachedVerifier` check is a static negative-impl assertion in
  `crates/anykms-recipes/tests/semantics.rs` over `CachedVerifier<PublicKeysKey>` (its source
  implements `Semantics`).

**Implementation notes (X12a):**

- Fields that name an operation a handle lacks take the "no such operation" value: only AEAD
  handles (and data-key sources, KEKs from AEAD keys) declare `data_keys`,
  `ciphertext_reveals_version` and `max_plaintext`; signing and HMAC handles declare `None` /
  `false` there. Transit HMAC handles declare `versions_listed(false)`.
- `Provider::describe` handles of transit and local declare **no** semantics: the URI does not
  say the key's family, which decides them. Cases read semantics from the family's own handle,
  so X13 should not require them on describe handles.
- The Azure-shaped fixture is aligned with Azure (§1.4 row 8): unversioned verify is `Rejected`
  (`InvalidArgument` before any request) and signing keys report a primary version. Versioned
  URIs, and so `pin`, are not modelled by it.

**Implementation notes (X12b–X12d, X13):**

- X12b–X12d (AWS, GCP, Azure) were finished on the integration branch after the W6 lane agents
  stopped (usage limit); AWS's lane had committed its `semantics.rs` and provider wiring.
- **GCP** keeps one `GcpSemantics` per provider in its shared state (verification depends on
  `public_key_ttl`); typed handles return references to it. RSA KEKs are `Pinned` with
  `Backend` verification; an unversioned KEK is `KeyWrapKey::from_aead` and keeps the AEAD value.
- **Azure** computes each handle's value at open from the URI (`Pinned` exactly for a versioned
  URI), the vault kind and `local_verify`, and stores it on the typed handle (`sem`). The typed
  conformance path's vault data-key source carries `emulated(Refused)`, matching the provider.
- Describe handles (GCP, Azure, transit, local) declare no semantics: the URI does not say the
  key's family. X13 does not require them there.
- **X13:** `Ctx::semantics_or_caps` now fails a case when the handle declares none, and
  `semantics_match_caps` fails such handles. Deleted from `FixtureCaps`: the `datakey_aad`,
  `ciphertext_versions`, `hmac_versions_listed`, `max_plaintext`, `max_mac_input`,
  `max_signed_message`, `versions`, `unversioned`, `no_primary_version` and
  `key_state_per_version` fields; their builders; `with_used_primary`; and the conformance
  `DataKeyAad`, `VersionShape` and `Unversioned` types. Fixtures declare `UsedPrimary`,
  `MacInputLimit` and `MessageInputLimit` with `supports`/`not_applicable`; the values come from
  the handles. The GCP-shaped proof fixture declares the GCP row (with `Backend` verification,
  since it verifies through the local keyset).

### 3.3 A2: versioning (additive)

```rust
pub trait Provider {
    // ... openers unchanged ...
    /// For configuration: the URI naming exactly `version` of the key at `uri`. Built
    /// structurally (parse → set the version → serialize), keeping the query. No I/O: the
    /// version is not checked to exist, and the purpose is unknown (a GCP AEAD URI pinned here is
    /// refused by `aead()` with KeyMismatch). The same version as the URI's → the URI unchanged;
    /// another version already in the URI → Configuration. A malformed version →
    /// Configuration with Operation::Open (never ParseUri). Unsupported where versions are not
    /// addressable (transit, local, AWS).
    /// Never pin a token's `kid`: verify through the handle and let the signature carry the
    /// version; pinning input would turn a disabled version into a config-class KeyStateInvalid.
    fn pin(&self, uri: &KeyUri, version: &KeyVersion) -> Result<KeyUri> { Err(unsupported_pin()) }
}
impl Registry { pub fn pin(&self, uri: impl IntoKeyUri, version: &KeyVersion) -> Result<KeyUri>; }
```

> **Release review (Q6, maintainer decision):** a malformed version and a URI naming another
> version are `Configuration` (config class), not `InvalidArgument` as first written: `pin`
> exists for configuration, and the class decides who gets paged. Applies to core's `pin` docs
> and the GCP and Azure implementations.

```rust
impl KeyVersionInfo {
    pub fn with_signature_algorithm(self, a: Option<SignatureAlgorithm>) -> Self;
    pub fn signature_algorithm(&self) -> Option<SignatureAlgorithm>;
    pub fn with_mac_algorithm(self, a: Option<MacAlgorithm>) -> Self;
    pub fn mac_algorithm(&self) -> Option<MacAlgorithm>;
}
```

- **Forwarding.** `impl Provider for Arc<P>` forwards `pin` and `name` (`provider.rs:321-329`).
  `forward_provider!` gains a non-opener section that forwards both, in both of its forms; the
  body form evaluates `$body` with `uri` bound. `forwarders_cover_every_open_method`
  (`provider.rs:608`) is extended to `pin` and `name`. The `Counting` conformance providers and
  the facade wrappers forward through these.
- **URI rule.** An unversioned URI is `Floating` and a versioned URI is `Pinned`. GCP keeps
  refusing unversioned signing and MAC URIs at open (`KeyMismatch`); the message names
  `Registry::pin`.
- **Implementations.** `pin` is implemented by GCP (`/cryptoKeyVersions/<decimal>`) and Azure
  (`/<32 hex>`).
- **Version algorithms.** GCP fills `KeyVersionInfo::{signature,mac}_algorithm` per version. The
  other backends leave them `None`.
- **Rustdoc fix.** The `KeyVersion` rustdoc (`types.rs:16-24`) stops calling AWS "planned".
- **Deferred:** the GCP newest-enabled-version mode (§24.2).

Tests:

- `pin` units per backend: query kept, same version, conflicting version, malformed version;
- `Registry::pin` through an `Arc<P>`-registered provider;
- a conformance case `describe::version_algorithms` on the GCP and GCP-shaped fixtures.

**Implementation notes (X10):**

- The default `pin` is `Unsupported` with `Operation::Open` and the message "provider does not
  address key versions in URIs". `Registry::pin` routes by scheme like the openers, applies no
  layer and labels errors with the URI (without its query).
- Per review N1, `forward_provider!`'s target form forwards `name` and `pin`; the body form
  forwards `pin` only (evaluating the body with `uri` bound). `impl Provider for Arc<P>` lost its
  hand-written `name`, which the target form now generates.
- Review N2 (`KeyInfo::backend_type_id()`) is not done here: X10 introduces no backend-info hook.
  It belongs with `KeyInfo::with_backend` in A5 (§3.5, X16).

### 3.4 A4: one type-erased `Call` through layers (breaking for `Layer` implementors and extension-call users)

```rust
#[derive(Clone, Copy)]
pub struct Call<'a> { part: PartKind, op: Operation, name: &'static str, run: &'a dyn RunCall }
impl<'a> Call<'a> {
    pub fn part(&self) -> PartKind;
    pub fn operation(&self) -> Operation;
    pub fn name(&self) -> &'static str;   // "encrypt", ... or the extension's name
    /// One attempt. Only a retrying interceptor may call it again, and never concurrently.
    pub fn run(&self) -> BoxFuture<'a, Result<CallOutput>>;
}
pub struct CallOutput(Box<dyn Any + Send>);
impl CallOutput { pub fn new<T: Any + Send>(v: T) -> Self; }

pub trait Around: Send + Sync + 'static {
    fn around<'a>(&'a self, cx: &'a CallCx, call: Call<'a>) -> BoxFuture<'a, Result<CallOutput>>;
}
#[non_exhaustive]
pub struct CallCx { /* backend: Option<&'static str>, resource: Option<Arc<str>> */ }

impl Part<'_> { pub fn wrap_around(self, cx: &LayerCx<'_>, a: Arc<dyn Around>); }
pub trait Layer: Send + Sync {
    fn retries(&self) -> bool { false }
    fn part(&self, cx: &LayerCx<'_>, part: Part<'_>);
}
pub trait ExtensionCalls { async fn run_extension(&self, call: Call<'_>) -> Result<CallOutput>; }
```

**Semantics:**

- `wrap_around` decorates any part kind. Every async method builds a `Call` and goes through
  `around`.
- Sync methods (`ciphertext_version`, `signature_algorithm`, `wrapped_key_version`) are
  forwarded by core and never reach the layer.
- **Downcast failure.** If the output of `around` does not downcast to the method's type (a
  layer returned its own `CallOutput`), the result is `Backend` "an interceptor returned a value
  of an unexpected type" with the call's operation, as `call_extension` does today.
- **`ObserveLayer`:**
  - `OpEvent::extension_name` is `Some(call.name())` only when `call.part() ==
    PartKind::Extension`.
  - `ObserveLayer::wrap(inner, part)` (`observe.rs:140`) drops its `part` parameter, because
    calls carry it.
- The part is in `Call` only; `CallCx` does not repeat it.

**Removed:**

- the 13 per-part `Layer` methods;
- `ExtensionCall` and `ExtensionOutput`, renamed to `Call` and `CallOutput`;
- the exhaustive `match` in `RetryLayer::part` and `ObserveLayer::part`
  (`retry.rs:397-421`, `observe.rs:157-187`). Each becomes `part.wrap_around(cx,
  self.around.clone())`.

**Typed decorators stay on the generic path.** `Retry<T>` and `Observed<T>` keep their per-trait
generic impls, with no boxing, and share only the policy code with `Around`
(`RetryState::attempt` and `ObserveState::record`). `Retry::call(FnMut)` and
`Observed::call(op, name, fut)` keep their signatures and their path outside `Around`.

> **Superseded (2026-11-02).** `Retry<T>` and `Observed<T>` were removed. The zero-allocation
> property that justified them was never measured (see the spike record below) and is noise
> against an HTTPS round trip; no backend implemented an extension trait on `Retry<TheirKey>`;
> `Observed<T>` could not carry `backend`/`resource` labels; and the typed path bypassed
> `Layer::retries`, so it needed its own "do not nest" documentation. The retry engine is public
> as `RetryLayer::call(|| fut)`, which covers a backend's extension method on its typed key, and
> `CachedVerifier::with_retry(&RetryLayer)` covers the one in-tree dependent (the hinted
> post-rotation retry, keeping `PinnedVerifier` and `invalidate()` on one type). A new part now
> costs the four places below, without item 5.

A new part therefore costs:

1. the trait;
2. the `dyn_layer!` entry;
3. `Part`/`PartKind`;
4. the `handle!` entry;
5. ~~the typed `Retry`/`Observed` impl~~ (removed, see above).

That is 5 places instead of 9, and nothing silently falls back. A test enumerates `PartKind`
against `wrap_around`.

**Cost:** per call and per wrapping layer, one boxed attempt future, one boxed `around` future
and one boxed output. This applies to opaque handles only. ~~Typed handles keep zero
allocations.~~

**`full` is not re-frozen.** The `later {}` rule stays: every part added after the bounds froze
goes in `later {}`.

**Spike first (X14).** Implement `Call`, `Around` and `wrap_around` for `Aead` (`encrypt`,
`decrypt_with_info`) and `Extension`. Exit criteria:

1. Builds on 1.85 with no `unsafe`.
2. `Send` futures through `Registry` → `EnvelopeAead<KeyWrapKey>` (an `assert_send` test).
3. No `'static` bound on inputs.
4. The existing retry and observe tests pass.
5. Allocations per opaque `encrypt` through Retry and Observe layers are measured with a counting
   allocator, and the typed `Retry<Observed<T>>` path still allocates zero.

**Fallback** (if 1–3 fail):

- A core-private `parts!` table generates the per-part dyn decorators and the bodies of
  `RetryLayer` and `ObserveLayer`.
- The per-part `Layer` methods are removed anyway.
- `Around` is not public.
- The `Call`/`CallOutput` rename of extension calls proceeds.

**Migration.** Two places change:

- `anykms-conformance/src/cases/layers.rs`, whose test layers implement `Around`;
- the facade `lib.rs`, where it names the removed types.

**Tests:**

- the existing layer, retry and observe suites;
- a `part`-only layer intercepts every `PartKind`;
- sync forwarding through two layers;
- the downcast-mismatch error.

**Spike record and implementation notes (X14, X15):**

- **Spike outcome: the full design, no fallback.** The spike went straight to all parts because
  `call_extension` already proved the borrowed, re-runnable erased closure. Criteria:
  1. builds with no `unsafe` (on the 1.99 toolchain here; nothing newer than 1.85 is used, and the
     CI MSRV job checks it);
  2. `Send` futures through two layers and `tokio::spawn` (`around::tests::futures_are_send`);
  3. no `'static` bound on inputs (the closures borrow plaintext, AAD, digests and versions);
  4. every existing retry, observe and layer test passes unchanged in behavior;
  5. the allocation count was **not** measured: a counting `#[global_allocator]` needs `unsafe
     impl GlobalAlloc`, which the workspace forbids. The typed `Retry<T>`/`Observed<T>` path is
     unchanged (generic, no `Call`), so its zero-allocation property holds by construction; the
     opaque path costs the boxes listed above.
- `Call`, `CallOutput`, `CallCx` and `Around` live in `anykms-core/src/around.rs`;
  `Part::wrap_around` installs a core decorator (`Arounded<dyn DynX>`) per part kind, so a new
  part adds one `impl` there and one arm in `wrap_around`.
- `Layer` keeps `retries` and `part` only. The handle macros apply a layer through a private
  `wrap` module (one function per part that calls `part`).
- `RetryLayer` and `ObserveLayer` implement `Around`; their `part` is `part.wrap_around(cx, ..)`.
  `RetryLayer`'s `around` runs the typed retry loop (`Retry::<()>::run`), so the policy code is
  shared. `ObserveLayer::wrap(inner)` lost its `part` argument: each typed `Observed<T>` impl
  passes its own `PartKind`.
- `ExtensionCall`/`ExtensionOutput` are now `Call`/`CallOutput`; an extension call carries
  `PartKind::Extension`. An `Around` returning another type is `Backend` "an interceptor returned a
  value of an unexpected type", with the call's operation
  (`around::tests::an_output_of_another_type_is_a_backend_error`).
- New tests: every one of the 13 `PartKind`s goes through `Around` with its operation and method
  name, through two layers, and sync methods are forwarded without reaching the layer
  (`around::tests::every_part_kind_goes_through_around`).
- Migrated: `anykms-conformance/src/cases/layers.rs` (`FailFirst` is an `Around` on the extension
  part); the facade needed no change.

### 3.5 A5: `Preflight` part and backend `KeyInfo` (breaking for typed handles)

```rust
#[trait_variant::make(Send)]
pub trait Preflight { async fn preflight(&self) -> Result<KeyInfo>; }   // dyn_layer! entry; Call op = Describe

impl KeyInfo {
    /// Backend metadata (TransitKeyInfo, AwsKeyInfo, ...). Must carry no policy documents,
    /// credentials or secrets: KeyInfo's Debug prints it.
    pub fn with_backend<T: Any + Send + Sync + fmt::Debug>(self, info: T) -> Self;
    pub fn backend<T: Any>(&self) -> Option<&T>;
}
```

- **Storage.** `KeyInfo` stores the extension as `Option<Arc<dyn AnyDebug>>`, the pattern of the
  `OpenOptions` extensions (`provider.rs:55-105`). `PartialEq`, `Eq` and `Debug` are manual, and
  equality ignores the extension.
- **The part.** Every opaque handle gets `preflight` as an optional part in its `later {}` group
  (`with_preflight`, `supports_preflight`).
- **`preflight()`.** The inherent `preflight()` (`dynamic.rs:1854`) calls the part if present,
  else does today's generic check.
- **`KeyWrapKey::from_aead`** keeps the AEAD's preflight part. Its check is the AEAD key check,
  which is correct, because the KEK *is* that AEAD key.
- **Typed handles.** `verify_with_describe()` becomes `impl Preflight`.
- **Removed:** `verify_with_describe` and `transit_info`, `aws_info`, `gcp_info`, `azure_info`.
  `describe()` attaches the backend struct instead. `with_key_type_check` stays.
- **Azure** gets `Preflight` on all four handle kinds directly (P1-5 withdrawn).

**Migration**, in exactly these files (X16):

- core `dynamic.rs`, `types.rs`;
- `src/handles.rs`, `provider.rs` and `keyinfo.rs` of transit, aws, gcp and azure;
- tests: transit `tests/mock.rs`, `integration.rs`; AWS `tests/mock.rs`; GCP `tests/mock.rs`,
  `e2e.rs`, `live.rs`; Azure `tests/mock.rs`, `lowkey.rs`;
- docs: `operations.md`, `operations-gcp.md`, `README.md` (the `*_info` mentions);
- conformance `cases/aead.rs` (`preflight`), `cases/describe.rs` and `fixture.rs` (new hook
  `Fixture::backend_info_type() -> Option<TypeId>`, default `None` = n/a).

New case: `describe::backend_info`.

**Implementation notes (X16):**

- Core: `Preflight` (trait, `DynPreflight`, `Part`/`PartKind::Preflight`, a `later` part on every
  opaque handle with `with_preflight`/`supports_preflight`, typed `Retry`/`Observed` impls and an
  `Around` decorator; its `Call` reports `Operation::Describe`). The inherent `preflight()` runs
  the part when present, else the generic describe check. `KeyWrapKey::from_aead` keeps it.
- `KeyInfo::{with_backend, backend, backend_type_id}` (review N2 lands here; renamed
  `with_backend_info`, `backend_info`, `backend_info_type_id` in the release review, PLAN §26).
  Equality ignores the backend value; `Debug` prints it.
- Backends: each typed handle's `verify_with_describe` became `impl Preflight` (the same key-type
  check, then `describe()`), and the providers attach it to every opaque handle except describe
  handles (whose key family is unknown). Azure gets it on all four handle kinds. The
  `transit_info`/`aws_info`/`gcp_info`/`azure_info` methods are gone: `to_key_info()` attaches
  `TransitKeyInfo`/`AwsKeyInfo`/`GcpKeyInfo`/`AzureKeyInfo` to every `describe()` result.
- `preflight()` on a typed handle now costs the check plus one fresh describe; the Azure P1-4
  request-count test counts from a measured baseline.
- Conformance: `Feature::BackendInfo` (declared supported by transit, AWS, GCP and Azure, n/a by
  the local fixtures) gates `describe::backend_info`, which checks the type named by
  `Fixture::backend_info_type` on `describe()` and on `preflight()`. A declared feature rather
  than a `None` default, because a case cannot report n/a while running.

### 3.6 A6: `PublicKeys` on `KeyWrapKey` (additive in core; breaking for typed AWS and GCP KEKs)

- **The part.** `KeyWrapKey` gets `later { public_keys }`, with `with_public_keys` and
  `supports_public_keys`.
- **Who sets it.** RSA KEKs on AWS (the private `rsa_public_key`, `handles.rs:1044`, becomes the
  impl), GCP (the inherent `GcpKeyWrapKey::public_key`, `handles.rs:1459`, moves into the trait)
  and Azure (the bundle's key). Symmetric KEKs do not set it.
- **Errors** follow A3, including (f).
- **Layers.** After A4 nothing changes; under the fallback it is one table row.

Conformance: `keywrap::public_key_wraps` encrypts locally with `rsa_oaep_sha256_encrypt` and
unwraps with the backend. It is gated on `Feature::KeyWrap` plus `supports_public_keys()`.

**Implementation notes (X17):**

- `KeyWrapKey` has `later { public_keys }` (`with_public_keys`, `supports_public_keys`,
  `impl PublicKeys`); `from_aead` leaves it unset. `KeyWrapBridge::public_keys()` carries it on
  the typed conformance path.
- AWS sets it on every KEK (one opener serves symmetric and RSA keys): RSA keys serve their
  public key through the same uncached-`DescribeKey`-then-`GetPublicKey` path as signing keys
  (`public_key_for`), a symmetric KEK is `KeyMismatch`. GCP sets it on versioned
  `RSA_DECRYPT_OAEP_*_SHA256` KEKs (the inherent `public_key` moved into the trait, plus
  `public_key_version`). Azure sets it on every KEK; `oct-HSM` keys are `KeyMismatch`.
- Conformance `keywrap::public_key_wraps` is gated on a declared `Feature::KeyWrapPublicKeys`
  (supported by AWS and GCP; n/a elsewhere) rather than on `supports_public_keys()` at run time,
  because a case cannot report n/a while running. **Azure declares it n/a**: an offline wrap must
  be framed with the key version (`docs/azure-ciphertext.md`), which the portable case cannot do;
  `anykms-azure/tests/lowkey.rs::kek_public_keys_wrap_offline` covers the framed path.

### 3.7 A7: lower crypto crate — not done (decision)

Neither a new crate nor a core feature. **The backends keep depending on `anykms-recipes` with
`default-features = false`.**

- That configuration already depends only on core, and contains exactly what the backends use:
  `LocalVerifier`, `ecdsa_der`, `spki_key_type`, `pem_to_der`, `MIN_RSA_BITS`,
  `rsa_oaep_sha256_encrypt`, `EmulatedDataKeys` and `KeyWrapDataKeys` (`recipes/Cargo.toml:17-24`).
- A split would move the same `rsa`/`aws-lc-rs` features to a new crate, keep the same feature
  forwarding, and add a published crate.
- Lockstep versioning removes the semver ripple.
- `EmulatedDataKeys` and `KeyWrapDataKeys` are emulations, so they would not belong in a
  "crypto" crate anyway.

**Revisit** if recipes' no-default build gains a dependency the backends must not have. The
check is part of the `features` CI job (§4, C1).

This closes revision 1's open question 2.

## 4. Phase 3: packaging and operations (C1–C7)

### C1: Cargo features

- **AWS `test-fixtures` becomes `__test-fixtures`.**
  - `#[doc(hidden)]`.
  - A `compile_error!` under `cfg(all(feature = "__test-fixtures", not(debug_assertions)))`.
    This is defense in depth only, because `debug_assertions` is a profile knob.
  - Touch points: `src/lib.rs:86,120-124`, `src/admin.rs`, `src/client.rs`,
    `src/provider.rs:276`, and `Cargo.toml:11-13,66-68`.
  - CI guard: `cargo tree -e features -p anykms --all-features --locked | grep -q
    'anykms-aws feature "__test-fixtures"'` fails the job.
  - `cargo test --release -p anykms-aws` is documented as unsupported.
- **Facade `gcp` stops forcing `anykms-gcp/service-account-key`.**
  - New facade feature `gcp-service-account-key = ["anykms-gcp?/service-account-key"]`.
  - The facade `default` lists it explicitly: `default = ["recipes", "rsa-aws-lc-rs", "tokio",
    "rustls-aws-lc-rs", "gcp-service-account-key"]`. It is not tied to an RSA feature.
  - Without it, a service-account key is `Configuration` naming the feature.

### C1: CI (`.github/workflows/ci.yaml`), new job `features`

- `cargo hack check --each-feature --lib --locked --workspace --exclude anykms-testkit`.
  - `cargo-hack` is installed with `taiki-e/install-action`, pinned by SHA.
  - Locally: `cargo install cargo-hack --locked` (X18 verifies the command once and records
    its runtime).
- The facade on defaults: `cargo check -p anykms --features aws,gcp,azure --locked`.
- Both TLS providers together: `cargo check -p <c> --no-default-features --features
  rustls-ring,rustls-aws-lc-rs --lib`, for http, transit, aws, gcp and azure.
- **RustCrypto RSA path.**
  - The test runs in recipes, where it is meaningful: `cargo test -p anykms-recipes
    --no-default-features --features rsa` (already in `ci.yaml:121-125`).
  - For each cloud backend, `cargo check -p <b> --no-default-features --features
    rustls-ring,rsa-rustcrypto --lib`, plus a guard that `cargo tree -p <b>
    --no-default-features --features rustls-ring,rsa-rustcrypto -e normal --prefix none` lists
    no `aws-lc-sys`.
  - A backend *test* under rsa-rustcrypto is not a gate. The dev-dependencies (conformance,
    Azure) unify `aws-lc-rs` into the test build, so such a test would exercise aws-lc anyway.
- The recipes no-default dependency guard (§3.7): `cargo tree -p anykms-recipes
  --no-default-features -e normal --depth 1` lists only anykms-core, base64, zeroize, getrandom,
  ecdsa, ed25519-dalek, signature, spki and the curve crates (p256, p384, p521).
- The `__test-fixtures` guard (above).

### C2: TLS default

- **Switch.** Every crate's `default` moves from `rustls-ring` to `rustls-aws-lc-rs`: http,
  transit, aws, gcp, azure and the facade. `rustls-ring` stays opt-in.
- **Effect on the graph.** ring leaves the default build. aws-lc-sys was already linked through
  `rsa-aws-lc-rs` (`Cargo.lock:355-365`), so the default build has one crypto library instead of
  two.
- **Build requirements.** A transit-only default build now compiles aws-lc-sys, which builds C
  and assembly (prebuilt NASM objects on Windows; cmake only for FIPS). README, the transit docs
  and `releasing.md` say so.
- **Provider precedence** is unchanged, and FIPS process defaults still win.
- **Docs to update:**
  - the crate rustdoc of `anykms-http/src/lib.rs:30`, `transit/src/lib.rs:82-92`,
    `aws/src/lib.rs:72`, `gcp/src/lib.rs:91-101` and `azure/src/lib.rs:93-102`;
  - the facade `Cargo.toml` comments;
  - `README.md:362-384`.
- **CI guards invert.**
  - The default must not link `ring`.
  - `--no-default-features --features rustls-ring` must not link `aws-lc-sys`, for transit, aws,
    gcp and azure.
  - The non-default ring path stays tested: `cargo test -p anykms-transit --no-default-features
    --features rustls-ring --locked --lib --test tls`, and the same for `anykms-http`. This
    replaces `ci.yaml:70-71`.
  - The Azure job's TLS step (`ci.yaml:460-473`) changes the same way.
- `fuzz/Cargo.lock` loses `ring`, so X18 is a **lock** task.
- §22 ("TLS stays ring") and §23 Q13 are superseded.

**Implementation notes (X18, C1 and C2):**

- `fuzz/Cargo.lock` does not lose `ring`: only rustls's `ring` edge goes. The `ring` entry stays
  because the lockfile keeps `rustls-webpki`'s optional `ring` dependency, although
  `cargo tree --target all -i ring` shows that nothing builds it. `Cargo.lock` is unchanged:
  the transit and Azure tests take `rustls/ring` as a dev-dependency, because their own TLS
  servers and admin clients use ring whatever the library uses. The `-e normal` guards are
  unaffected.
- The facade rustdoc (`crates/anykms/src/lib.rs`, the paragraph on the TLS provider) said
  "ring through the default `rustls-ring` feature". It is not one of the five listed headers,
  but it would have been wrong, so X18 updated that paragraph only.
- Without `gcp-service-account-key`, the GCP error names the anykms-gcp feature
  `service-account-key`, not the facade name. X18 does not own GCP `src/`. A later GCP task
  can add the facade name to the message.
- CI: the inverted TLS guards stay in the `check` job's "TLS provider features" step and the
  Azure job's step. The default must not link `ring`, for http, transit, aws, gcp, azure, the
  facade, and the facade with every backend. `rustls-ring` alone must not link `aws-lc-sys`,
  for transit, aws, gcp and azure. The ring path runs `cargo test … --lib --test tls`
  (transit) and `--lib` (http). The new `features` job holds §4 C1's commands. It installs
  `cargo-hack` with `taiki-e/install-action` at the SHA the fuzz job already pins (v2.87.23).
  The recipes guard compares the exact sorted list of direct dependencies.
- Locally, `cargo install cargo-hack --locked` (0.6.45) took 22 s.
  `cargo hack check --each-feature --lib --locked --workspace --exclude anykms-testkit` makes
  78 runs. It passed in 171 s from an empty `target/` (4 CPUs, `CARGO_BUILD_JOBS=4`).

### C3: dependencies

- **`deny.toml`.** `[bans] multiple-versions = "deny"`, with three `skip` entries, each with its
  reason:
  - `getrandom@0.2`, via ring under `rustls-ring` and other dependents;
  - `syn@2`, kept by proc-macro dependents next to `syn@3`;
  - `windows-sys` (the older version), used by Windows-only dependents.

  X19 runs `cargo deny check bans` and replaces each reason with the dependent crate
  `cargo tree -d` names. A skip whose duplicate no longer occurs is removed. The `--exclude-dev`
  split from revision 1 is dropped, because it reports the same three.
- **MSRV.** The policy is "MSRV 1.85 covers the published libraries; the HTTP backends' tests
  need a newer compiler (wiremock)". It is written in the README and the job comment, and the
  MSRV step is renamed "Test (except the HTTP backends)".

**Implementation notes (X19, C3):**

- `cargo deny check bans` (cargo-deny 0.20.2) reports exactly the three duplicates. The skip
  reasons name the dependents: `getrandom@0.2` is kept by ring only; `syn@2` by
  curve25519-dalek-derive, jni-macros, jni-sys-macros, tracing-attributes, trait-variant and
  zeroize_derive; `windows-sys@0.52` by ring and errno. The many older RustCrypto crates that
  jsonwebtoken brings are dev-only and not reported (`multiple-versions-include-dev` defaults to
  false). `cargo deny check` passes.
- The MSRV policy sentence replaces the stale README bullet ("transit's tests"). The README is not
  in X19's file list, but C3 names it; the edit is that one bullet.

### C4: configuration

- **`from_env_with` on every backend:** `from_env_with(lookup: impl Fn(&str) -> Option<String>
  + Send + Sync + 'static) -> Result<Self>`.
  - Applies to `TransitProvider` (plus `from_env_openbao_with`), `GcpProvider`, `AzureProvider`
    and **AWS**. AWS's existing signature (`config.rs:151`) gains the bounds, which is breaking
    there.
  - Variables read lazily use the same lookup, stored as `Arc<dyn Fn ..>`:
    - GCP `GOOGLE_APPLICATION_CREDENTIALS`, `CLOUDSDK_CONFIG`, `HOME`/`APPDATA` and
      `GCE_METADATA_HOST`;
    - Azure `AZURE_*` and `IDENTITY_*`;
    - transit's `*_TOKEN` re-read;
    - the AWS chain.
  - Transit's private `load_with` (`config.rs:576`) becomes the public path.
  - Facade: `with_default_providers_from(lookup)`.
- **Transit renames.**
  - `ANYKMS_AUTH`, `ANYKMS_AUTH_ROLE`, `ANYKMS_AUTH_JWT_FILE` and `ANYKMS_AUTH_MOUNT` become
    `ANYKMS_TRANSIT_AUTH`, `ANYKMS_TRANSIT_AUTH_ROLE`, `ANYKMS_TRANSIT_AUTH_JWT_FILE` and
    `ANYKMS_TRANSIT_AUTH_MOUNT`.
  - `ANYKMS_NO_TOKEN` → `ANYKMS_TRANSIT_NO_TOKEN`.
  - `ANYKMS_ALLOW_INSECURE_TOKEN_FILE` → `ANYKMS_TRANSIT_ALLOW_INSECURE_TOKEN_FILE`.
  - There are no aliases. An old name that is set is `Configuration` "renamed to <new>", even
    when the new name is set too. The check is removed in 0.2.0.
  - Touch points: `README.md:97,140`; transit `lib.rs:40,49,64`, `auth.rs:40`, `token.rs:169`;
    `docs/operations.md` (11 lines); `docs/PLAN.md:1446` (by X22).
  - `scripts/`, `compose.yaml` and `ci.yaml` reference none of the old names.

**Implementation notes (X20, C4):**

- Signatures. `from_env_with(lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static)`
  on `TransitProvider` (plus `from_env_openbao_with`), `EnvConfig::load_with` (now public),
  `AwsProvider`, `AwsProviderBuilder`, `GcpProvider`, `GcpProviderBuilder`, `AzureProvider` and
  `AzureProviderBuilder`. The AWS credential sources' existing `from_env_with` gained the same
  bounds. `AwsProvider::from_env_with` is new (AWS `provider.rs`, outside the file list): the
  provider-level form exists on the other three, and the facade uses it.
- Only transit and GCP read variables after construction, so only they keep the lookup
  (`Arc<dyn Fn>`): transit's `EnvToken` re-reads `*_TOKEN` through it (`EnvToken`'s fields stay private;
  its `Debug` output is unchanged), and GCP's `AuthCtx` carries it for
  `GOOGLE_APPLICATION_CREDENTIALS`, `CLOUDSDK_CONFIG`, `HOME`/`APPDATA` and `GCE_METADATA_HOST`.
  AWS already snapshots every variable into `Vars` (the chain included); Azure reads its
  `AZURE_*`/`IDENTITY_*` settings when the credential is built. Without a lookup, everything
  still reads the process environment exactly as before (`var_os` for transit's token and GCP's
  paths). A non-UTF-8 `GCE_METADATA_HOST` is now `Configuration` instead of being ignored.
- Azure also gains `credential_from_env_with` and `env_credential_kind_with` (the facade needs
  the latter to honor `ANYKMS_AZURE_CREDENTIAL=none` from the lookup); exporting them is a
  one-line change to Azure `lib.rs`, outside the file list.
- Transit renames: no aliases. Any of the six old names that is *present* (even empty) makes
  `EnvConfig::load`/`load_with` fail with `Configuration` "`<old>` was renamed to `<new>`: set
  `<new>` instead and unset `<old>`", checked before anything else, whether or not the new name is
  set. The table (`RENAMED` in transit `config.rs`) is marked for removal in 0.2.0.
  `docs/operations.md` documents the rename. Transit's own README names none of the variables.
- Facade: `with_default_providers_from(lookup)`. A test per backend set checks that the lookup is
  the only source (no child process needed). GCP gained an in-process ADC test through the lookup
  (`tests/auth.rs`).

### C5: observability

No attempt count on `OpEvent`. Placing `ObserveLayer` inside `RetryLayer` observes every attempt,
as documented.

### C6: fixture helpers

- `anykms-conformance` gains a published, off-by-default feature, `fixture-helpers`:
  - `RunId`;
  - `KeySpecTable<S>`;
  - `FreshKeys`;
  - `typed_handles!`.
- The AWS, GCP and Azure fixtures and the local shaped fixtures adopt it. Their `Cargo.toml`
  dev-dependencies enable the feature. Admin clients stay per backend.
- `docs/cloud/shared.md` §6.5 is marked "implemented as `scripts/*-test-setup.sh`".

**Implementation notes (X21):**

- `anykms_conformance::{RunId, KeySpecTable, FreshKeys}` and `typed_handles!` (feature
  `fixture-helpers`, in `src/helpers.rs`, unit-tested). `typed_handles!` generates the
  `digest_key`/`message_key`/`mac_key` methods (open, bridge, carry the handle's semantics) and
  takes the backend's other methods verbatim; it reaches `anykms_core` through a hidden
  `__private` re-export.
- Adopted: AWS (`KeySpecTable` for its `(KeySpec, KeyUsage)` table, `FreshKeys` for live keys,
  `typed_handles!`), GCP (`typed_handles!` for message and MAC keys; `digest_key` keeps its shape
  check), Azure (`RunId` behind `run_prefix`, `typed_handles!` for digest keys), and the local
  shaped fixtures (`RunId` key names). The shaped fixtures' typed handles have no inherent
  `semantics()`, so they keep their own bridges.

### C7: release

- **`docs/releasing.md`:**
  - Publish order: core → recipes → conformance → local → http → transit → aws → gcp → azure →
    anykms.
  - `anykms-testkit` is never published.
  - Remove "once they exist".
  - A note on aws-lc-sys build requirements.
  - A step: after the first publish, the semver job uses crates.io and becomes blocking.
- **Semver job.** "Find baseline" queries crates.io (`cargo info <pkg>`). For a published crate
  it uses the registry baseline. Otherwise it uses the base SHA with `continue-on-error` (set in
  X0). The comment about `publish = false` now refers to `anykms-testkit`, which is not in the
  matrix.
- **Versioning policy:** lockstep while core is 0.x. Per-crate backend versions are reconsidered
  when a backend first needs a release that core does not.

**Implementation notes (X19, C7):**

- The semver job no longer has a job-level `continue-on-error`. "Find baseline" runs `cargo info
  <pkg> --registry crates-io` (the `--registry` flag stops it answering from the workspace) and
  sets `source` to `registry`, `base` or `none`. The crates.io check is a blocking step; the
  base-branch check is a separate step with `continue-on-error: true`. So the job blocks for each
  crate as soon as it is published, with no CI edit; `releasing.md` step 7 is a check that this
  happened. A `cargo info` failure other than "could not find" fails the step, so a registry outage
  cannot silently downgrade a published crate to the non-blocking check.
- The versioning policy and the build requirements live in `docs/releasing.md`.

## 5. Task list

Sizes: S ≤ 0.5 day, M 1–2 days, L 3–5 days.

### 5.1 Rules for every agent

1. **Environment.** devenv loads `.env` into every shell. That includes root keys
   (`AWS_ROOT_*`), live toggles and `ANYKMS_REQUIRE_FIXTURE=1`. `scripts/test-env.sh` strips
   every credential-shaped variable (by name pattern) and the live toggles, but keeps
   `ANYKMS_REQUIRE_FIXTURE`. So:
   - **every** `cargo` command runs through `scripts/test-env.sh`, as `scripts/test-env.sh env
     -u ANYKMS_REQUIRE_FIXTURE cargo …`, unless a gate below says otherwise;
   - root keys are never used for tests, by any agent;
   - live targets need explicit opt-in (§6.5).
2. **Disk and memory.** The machine has 4 CPUs, 7 GB of RAM and about 23 GB of free disk (re-check with `df -h .` before each wave); one
   all-features build is about 8 GB.
   - **At most 2 worktrees run at once**, each with its own `target/` and
     `CARGO_BUILD_JOBS=2`.
   - In a worktree an agent runs gates 1–2 scoped to the crates it owns (`-p`). Full gates run
     once per wave on the main checkout after the merge.
   - After a task merges, its worktree is removed together with its `target/`.
   - Do not start a worktree with less than 12 GB free (`df -h /`).
3. **Shared files.** `CHANGELOG.md`, `docs/PLAN.md` and `docs/cloud/README.md` are edited only
   by the docs tasks (X6, X22, X23).
4. **Lockfiles.** `Cargo.lock` and `fuzz/Cargo.lock` change only in tasks marked **lock**.
5. **IDs.** Name the §24.4 probes as "§24.4 probe T1/T3/T13" in code, comments and tests. Never
   write a bare `T1`.

### 5.2 Tasks

| # | Task | Size | Depends on | Files |
|---|---|---|---|---|
| X0 | Baselines and environment: GCP fake declares `EmptyPlaintext` `not_applicable` ("Cloud KMS documents empty plaintext as refused; §24.4 probe T1 confirms"; live keeps `lacks`); `continue-on-error: true` on the semver job; IAM policy in `scripts/aws-test-setup.sh` gains `kms:ListResourceTags` on `key/*`, and its header says cleanup runs as the test identity (the maintainer applies the policy once with root); record the transit baselines (both CI image pairs) in §6 | S | — | `crates/anykms-gcp/tests/common/fixture.rs`, `.github/workflows/ci.yaml` (semver job only), `scripts/aws-test-setup.sh`, this file |
| X1 | **lock** `anykms-http` shared code (§2.2); `anykms-testkit`; dev-dependency and `exclude` entries in the four backends | M | — | `crates/anykms-http/**`, `crates/anykms-testkit/**`, root `Cargo.toml` (members), the four backends' `Cargo.toml` (dev-deps and `exclude` only), `Cargo.lock`, `fuzz/Cargo.lock` |
| X2 | Transit Phase 1: schema and token span, `send`, P1-1, P1-2, P1-4, P1-6 (including the conformance `local_checks_name_the_key_*`), P1-8, P1-11; hygiene via testkit; `docs/operations.md` span field | M | X1 | `crates/anykms-transit/**` (not `Cargo.toml`), `crates/anykms-conformance/src/cases/errors.rs`, `docs/operations.md` |
| X3 | AWS Phase 1: P1-1 (including `sigv4::Signed`), P1-2, P1-4, P1-6, P1-8–P1-12, B adoption | M | X1 | `crates/anykms-aws/src/**`, `tests/**`, `docs/operations-aws.md` |
| X4 | GCP Phase 1: P1-1–P1-4, P1-7, P1-9–P1-11, P1-13 (negative cache), B adoption | M | X1 | `crates/anykms-gcp/src/**`, `tests/**`, `docs/operations-gcp.md` |
| X5 | Azure Phase 1: P1-1, P1-2, P1-4, P1-6, P1-8, P1-9, P1-11, P1-13, B adoption | M | X1 | `crates/anykms-azure/src/**`, `tests/**`, `docs/operations-azure.md` |
| X6 | Phase 1 docs: PLAN §25 (Phase 1), `shared.md` §5 checklist, `docs/cloud/README.md` status, CHANGELOG | S | X2–X5 | `docs/PLAN.md`, `docs/cloud/{shared,README}.md`, `CHANGELOG.md` |
| X7 | A3 core: `UnknownKeyVersion`, `WrapKey`/`UnwrapKey`, class by kind, `class()` hint rule, `ParseUri` → `Configuration` in core; rewritten error docs; `PublicKeys` rustdoc contract (f) | M | X1 (sequencing only) | `crates/anykms-core/src/{error,uri,observe,traits}.rs`, `dynamic.rs` (missing-part ops only) |
| X8a | A3 in transit and local, plus the shaped fixtures | M | X7 | `crates/anykms-transit/{src,tests}/**`, `crates/anykms-local/{src,tests}/**` |
| X8b | A3 in AWS, including (f) `DescribeKey` before `GetPublicKey`; drop the two deleted flags from its fixture | M | X7 | `crates/anykms-aws/**` (not `Cargo.toml`), `docs/operations-aws.md` |
| X8c | A3 in GCP, including (f) and the write, `public_key()` and KEK rows | M | X7 | `crates/anykms-gcp/**` (not `Cargo.toml`), `docs/operations-gcp.md` |
| X8d | A3 in Azure (`verify_local` arm, `from_key_id` → `Construct`); fixture flag | S | X7 | `crates/anykms-azure/**` (not `Cargo.toml`) |
| X8e | A3 in conformance (§3.1 list, deleted flags, two new cases); recipes `CachedVerifier` mapping and rustdoc; fuzz; `docs/operations.md` kind table | M | X7 | `crates/anykms-conformance/**`, `crates/anykms-recipes/src/cached.rs`, `fuzz/fuzz_targets/**`, `docs/operations.md` |
| X9 | A1 core: `semantics.rs`, handle field, `Semantics`, `OpaqueHandle::semantics`, forwarding | M | X8* (sequencing) | `crates/anykms-core/src/{semantics,dynamic,retry,observe,lib}.rs` |
| X10 | A2 core: `pin`, `Registry::pin`, forwarding in `forward_provider!` and `Arc<P>`, `KeyVersionInfo` algorithms, `KeyVersion` doc | S | X9 | `crates/anykms-core/src/{provider,types}.rs` |
| X11 | A1 conformance transition: read semantics with fallback; `semantics_match_caps`; limit features without values | L | X10 | `crates/anykms-conformance/**` |
| X12a | A1 and A2 in transit and local (shaped Azure correction) | M | X10 | `crates/anykms-transit/**`, `crates/anykms-local/**` (not `Cargo.toml`) |
| X12b | A1 and A2 in AWS | S | X10 | `crates/anykms-aws/**` (not `Cargo.toml`) |
| X12c | A1 and A2 in GCP (`pin`, version algorithms) | M | X10 | `crates/anykms-gcp/**` (not `Cargo.toml`) |
| X12d | A1 and A2 in Azure (`pin`) | S | X10 | `crates/anykms-azure/**` (not `Cargo.toml`) |
| X13 | Hard failure on `None`; delete the replaced fields and the fixture calls | S | X11, X12a–d | `crates/anykms-conformance/src/**`, the fixture files of the five backend test suites |
| X14 | A4 spike (§3.4 criteria); record the result in this file | S | X13 | `crates/anykms-core/src/{dynamic,retry,observe}.rs`, this file |
| X15 | A4 full or fallback | L | X14 | `crates/anykms-core/src/{dynamic,retry,observe,provider,traits}.rs`, `crates/anykms-conformance/src/cases/layers.rs`, `crates/anykms/src/lib.rs` |
| X16 | A5 (exact files in §3.5) | L | X15, X21 | §3.5 list |
| X17 | A6 and its case | S | X16 | `crates/anykms-core/src/dynamic.rs`, AWS/GCP/Azure `src/{handles,provider}.rs`, `crates/anykms-conformance/src/cases/keywrap*` |
| X18 | **lock** C1 and C2: TLS default, facade features, `__test-fixtures`, `features` job, inverted guards; install and time `cargo-hack` | M | X6 | every crate's `Cargo.toml` `[features]`, the five crate `lib.rs` rustdoc headers, AWS `src/{lib,admin,client,provider}.rs` (cfg lines only), `.github/workflows/ci.yaml`, `README.md` (features and TLS sections), `Cargo.lock`, `fuzz/Cargo.lock` |
| X19 | C3 and C7: `deny.toml`, MSRV doc and step, semver baseline logic, `releasing.md`, versioning policy | S | X18 | `deny.toml`, `.github/workflows/ci.yaml`, `docs/releasing.md` |
| X20 | C4: `from_env_with` (four backends, facade), transit renames | M | X19 (lane) | transit `src/{config,provider,auth,token,lib}.rs`, AWS `src/config.rs` and `src/credentials/**`, GCP `src/provider.rs` and `src/auth/**`, Azure `src/provider.rs` and `src/cred/**`, `crates/anykms/src/lib.rs`, `README.md:97,140`, `docs/operations*.md` |
| X21 | C6: `fixture-helpers` and adoption | M | X13 | `crates/anykms-conformance/{Cargo.toml,src/helpers.rs,src/lib.rs}`, backends' `Cargo.toml` (dev-dependency feature only), `crates/anykms-{aws,gcp,azure}/tests/{common,e2e}/**`, `crates/anykms-local/tests/shaped/**`, `docs/cloud/shared.md`, `Cargo.lock` |
| X22 | Phase 2 and 3 docs: PLAN §25, Appendix A, §3 refresh; mark superseded §3.6, §20 (operation class), §22 (TLS ring, conformance unpublished), §23 Q1/Q13; README; `docs/cloud/*` notes; CHANGELOG (including the metric label change, `UnknownKeyVersion`, TLS default, env renames, `__test-fixtures`, the facade `gcp` features, `from_env_with`, deny) | M | X17, X20 | `docs/**`, `README.md`, `CHANGELOG.md` |
| X23 | Release prep: merge the CHANGELOG sections; run every gate; `cargo package --workspace --locked`; **stop before `cargo publish`** until open question 1 is answered | S | all | `CHANGELOG.md`, `docs/PLAN.md` §24.4 |

### 5.3 Waves

At most 2 lanes run at once. A lane is a sequence of tasks for one agent. × marks a conflict
that the ordering avoids.

| Wave | Lane A | Lane B | Merge and notes |
|---|---|---|---|
| W1 | X0 | X1 | X0 edits only the semver job in `ci.yaml`. |
| W2 | X2 → X4 | X3 → X5 | |
| W3 | X6 → X18 | — | X18 × X3/X5 (AWS and Azure files) is avoided because W2 is merged. X18 × X6 (README) is avoided by ordering in the lane. |
| W4 | X7 → X8b → X8d → X8e | X8c → X8a | **Merge as one batch.** X7 changes the write-side class that GCP only adopts in X8c, and X8e's cases fail until every backend lands, so X7 is not merged alone. The gate runs on the batch. |
| W5 | X9 → X10 | X19 → X20 | X20 × X8* and X12* (backend `config.rs` and `provider.rs`): X8 is merged and X12 has not started. X20 and X9/X10 share no files (X9 makes no facade edit; the facade has `pub use anykms_core::*`). |
| W6 | X11 → X12a → X12c | X12b → X12d | Then X13. No batch is needed: the X11 fallback keeps every target green. |
| W7 | X14 → X15 | X21 | X15 owns conformance `cases/layers.rs` and the facade `lib.rs`; X21 owns `helpers.rs`, `Cargo.toml` and backend `tests/{common,e2e}`. Disjoint. |
| W8 | X16 → X17 | — | X16 × X21 (backend tests) is avoided because X21 is merged in W7. |
| W9 | X22 → X23 | — | |

Always serial:

- every task that touches `crates/anykms-core/src/dynamic.rs` (X7, X9, X14, X15, X16, X17);
- every task that touches `ci.yaml` (X0 (semver only), X18, X19).

Sizes were raised after review: X11 is L, X16 is L, and X8c is M.

## 6. Verification gates

Every wave merges only when all gates pass on the merged main checkout. Each command runs through
the wrapper. `W` below stands for `scripts/test-env.sh env -u ANYKMS_REQUIRE_FIXTURE RUSTFLAGS=-Dwarnings`
(warnings are errors in every gate build, as in CI). Its
validity was checked on 2026-10-07: `W cargo test --workspace --all-features --locked` passes
at `da9f69c` (60 test binaries, 0 failed).

### 6.1 Format and lint

- `cargo fmt --all --check`.
- `W cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`.
- `W cargo clippy --workspace --all-targets --no-default-features --locked -- -D warnings`.
- The per-crate `--no-default-features` loop (`ci.yaml:50-55`).
- `W cargo check --manifest-path fuzz/Cargo.toml --locked --all-targets` (from the repo root, so the wrapper path resolves).
- From W3 onward, the `features` job commands (§4 C1).

### 6.2 Tests

- `W cargo test --workspace --all-features --locked`.
- The recipes RSA matrix (`ci.yaml:121-125`).

### 6.3 Conformance counts

Passed must not drop, and the total may only grow (448 per target today). A case moving from
passed to n/a needs a sentence in the PR and a row here. Baselines at `d9d88a4`/`da9f69c`:

| Target | Command (each prefixed with `scripts/test-env.sh env`) | Passed | Ignored |
|---|---|---|---|
| local | `-u ANYKMS_REQUIRE_FIXTURE cargo test -p anykms-local --all-features --locked --test conformance` | 211 | 237 |
| GCP-shaped | `… --test conformance_gcp_shaped` | 189 | 259 |
| Azure-shaped | `… --test conformance_azure_shaped` | 91 | 357 |
| GCP fake | `ANYKMS_FAIL_ON_SKIP=1 cargo test -p anykms-gcp --all-features --locked --test conformance` | 298 | 150 (after X0; at HEAD 2 fail, 148 ignored) |
| AWS Floci | 6.4 | 315 | 133 |
| Azure Lowkey | 6.4 | 243 | 205 |
| AWS live | 6.5 | 340 | 108 |
| Vault (`conformance_vault`), both CI pairs | 6.4 | 369 | 79 (X0, at `31143e8`: identical on 1.20.4 and 2.1.1) |
| OpenBao (`conformance_openbao`), both CI pairs | 6.4 | 391 | 57 (X0, at `31143e8`: identical on 2.4.4 and 2.7.1) |

### 6.4 Emulators and servers

Stop the containers afterwards with `docker compose --profile aws --profile azure --profile
sealed --profile tls down`.

- **Floci:** `docker compose --profile aws up -d --wait floci`, then `scripts/test-env.sh env
  ANYKMS_REQUIRE_FIXTURE=1 cargo test -p anykms-aws --all-features --locked --test emulator
  --test conformance_emulator`.
- **Lowkey:** `docker compose --profile azure up -d lowkey-vault`, wait for
  `http://127.0.0.1:8480/ping`, then `scripts/test-env.sh env ANYKMS_REQUIRE_FIXTURE=1
  ANYKMS_FAIL_ON_SKIP=1 cargo test -p anykms-azure --all-features --locked --lib --test mock
  --test credentials --test hygiene --test lowkey --test conformance_lowkey`.
- **Transit:** run once per CI image pair, setting `VAULT_IMAGE` and `OPENBAO_IMAGE` to the two
  pairs in `ci.yaml:248-261` (1.20.4/2.4.4, which exercises the OpenBao `Refused` path, and
  2.1.1/2.7.1). For each pair: `scripts/dev-up.sh --sealed --tls`, then
  `scripts/test-env.sh env ANYKMS_REQUIRE_FIXTURE=1 ANYKMS_FAIL_ON_SKIP=1 cargo test -p
  anykms-transit --all-features --locked`.

### 6.5 AWS live

Required after W2, W4, W6 and W8, and before X23. Root keys are never used.

1. **Identity check.** The wrapper strips every credential from the shell, so `--dotenv` loads
   `.env` *inside* the wrapper, and `test-env.sh` then strips the root keys and the live toggles
   again. The `aws` CLI is either installed or `scripts/aws-cli.sh` (the AWS CLI v2 in Docker,
   pinned by digest; use it in place of `aws`):

   ```sh
   scripts/test-env.sh --dotenv aws sts get-caller-identity --query Arn --output text
   ```

   The ARN must end in `:user/anykms-test`. It does today. If it ends in `:root`, or is anything
   else, **stop**.
2. **Run.**

   The live toggle goes on the command line (`--dotenv` strips toggles that `.env` sets):

   ```sh
   scripts/test-env.sh --dotenv env ANYKMS_AWS_LIVE=1 ANYKMS_REQUIRE_FIXTURE=1 cargo test -p anykms-aws --all-features --locked --test conformance_live
   ```

3. **Cleanup.** The fixture schedules deletion of its fresh keys. Then run
   `scripts/aws-test-setup.sh cleanup` in the same wrapper, with the CLI or the shim on `PATH`.
   Until the maintainer applies X0's `kms:ListResourceTags` grant, cleanup as `anykms-test` is a
   no-op: the script swallows the error. Record "cleanup pending policy" in the PR instead.

### 6.6 GCP fake and mocks

`scripts/test-env.sh env -u ANYKMS_REQUIRE_FIXTURE ANYKMS_FAIL_ON_SKIP=1 cargo test -p anykms-gcp
--all-features --locked --test mock --test e2e --test auth --test hygiene --test conformance
--test conformance_cached`.

`conformance_cached` (release review COR-3) runs the suite with the provider's default
public-key cache; it declares `DisableVersion` not applicable (a disabled version's public key
stays cached for up to `public_key_ttl`). Its `errors::forged_versions_do_not_flush` passes only
with the conformance bound `N * each.max(1)` (WP-7).

GCP and Azure live runs are not gates; they wait for accounts (§24.4).

### 6.7 Docs

- `W env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked`.
- The facade docs with default and with no default features.
- Every new public item has rustdoc.
- PLAN §25, `docs/cloud/README.md` and the CHANGELOG are updated by X6, X22 and X23.

### 6.8 Phase-specific

- **Phase 1:**
  - each backend's hygiene test uses testkit and asserts D3 (transit included);
  - the P1-1 redaction test;
  - the P1-4 forged-version request-count tests.
- **Phase 2:**
  - `cargo package --workspace --exclude anykms-testkit --locked` (the testkit is `publish =
    false` and depends on `anykms-http` by path only);
  - `full_bounds_are_frozen` (`dynamic.rs:1933`);
  - the A4 spike record;
  - `forged_versions_do_not_flush` on every fixture that declares `RequestCount`.
- **Phase 3:**
  - the `features` job;
  - the inverted guards;
  - `W cargo deny check`, with duplicates set to `deny`.

## 7. Risks and open questions

Risks, each with a decision:

- **A4 spike fails.** The fallback is designed (§3.4), and X16/X17 work with either outcome.
- **Semantics drift.** Every field is checked by a conformance case or by
  `semantics_match_caps`, and each backend's row is pinned by a test.
- **AWS public keys cost two requests (§3.1(f)).** Accepted: correctness of revocation over one
  extra `DescribeKey`. `CachedVerifier` amortizes the cost over its TTL.
- **The TLS default needs a C compiler** for transit-only builds. Accepted: the facade default
  already needs one, and `rustls-ring` remains.
- **`ParseUri` → `Configuration`.** Accepted. Applications that take URIs from users inspect
  `Error::operation()`.
- **`__test-fixtures` `compile_error!`** breaks `cargo test --release -p anykms-aws`. Accepted
  and documented.
- **Disk.** At most 2 worktrees, and targets are deleted after merge (§5.1).

Open questions for the maintainer:

1. **Publish without live-verified GCP and Azure?** R1 makes §24.4 probes T1 and T3 gates for
   0.1.0. There are two options:
   - (a) hold the whole publish until they run (recommended: the facade's optional dependencies
     must be published together);
   - (b) publish GCP and Azure marked "not live-verified" in their crate docs and the README.

   X23 stops before `cargo publish` until this is answered. *Answered (2026-10-08, release
   review, PLAN §26): (a) hold. The publish waits for T1 and T3, plus one green GitHub CI run;
   no "not live-verified" markers.*
2. **IAM grant.** Apply X0's `kms:ListResourceTags` grant to `anykms-test` once, with root. *Done (2026-10-07): applied to `anykms-test` with the root key; cleanup now runs as the test
   identity.*
   Until then, AWS cleanup is manual.

## 8. Review log

Round 1, revision 1 (`a405472`). The reviews are API (5 blocking), security (3) and
implementation (10).

### 8.1 Blocking items

| Reviewer | # | Item | Resolution |
|---|---|---|---|
| API | B1 | A3(b) migration incomplete: conformance `disabled_*` cases, GCP-shaped fixture, `KeyStateInvalid` docs, PLAN §20/§3.6 | §3.1(b) rewrites the docs (X7). The conformance list includes the three `disabled_*` cases, which expect `KeyStateInvalid` and keep `is_config_error()` (X8e). The shaped fixtures are in the migration table and in X8a. X22 marks §3.6 and §20 superseded. |
| API | B2 | `KeySemantics` not constant for OpenBao data-key AAD and the MHSM `DataKeysKey` | Option (a): `DataKeyAad::BoundOrRefused`, known at open. OpenBao and the MHSM `DataKeysKey` use it, and conformance accepts either outcome (§3.2). |
| API | B3 | Derived features cannot be gated from per-handle semantics | Option (b): `UsedPrimary`, `MacInputLimit` and `MessageInputLimit` stay declared. `capabilities::semantics_match_caps` checks them against the handle. Limit values come from the handle (§3.2, X11). |
| API | B4 | `pin` not forwarded by `forward_provider!` or `Arc<P>` | Both forward `pin` and `name`. `forwarders_cover_every_open_method` is extended, and §1.3 is amended (§3.3, X10). |
| API | B5 | Verify rule not carried through local paths; Azure row wrong; `CachedVerifier`; `PublicKeys` rustdoc | The Azure `verify_local` arm matches `UnknownKeyVersion`. `CachedVerifier` maps `UnknownKeyVersion` to `VerificationFailed`, keeping the source. The `PublicKeys` rustdoc is in X7, the recipes change in X8e (§3.1). |
| Security | B1 | P1-4 lets a forged `kid` flush the cache | P1-4 is rewritten by request origin (`Origin::{Handle, Input}`): only handle-addressed requests drop the cache, and input-version 404s are classified first. A 100-forged-versions request-count test runs per backend, and the conformance case `forged_versions_do_not_flush` is added. |
| Security | B2 | Chosen-version writes would become caller errors | The rule is stated once: a version the handle chose is `KeyStateInvalid` for every operation, `public_key()` included. The GCP `public_key()` and KEK wrap rows are added, along with the three conformance cases, the shaped fixtures and the mock rows. The core-table test is rejected (§3.1, reason given there). |
| Security | B3 | AWS public key of a disabled key vs `CachedVerifier`'s revocation promise | §3.1(f): every built-in backend refuses public keys of disabled keys. AWS sends an uncached `DescribeKey`, GCP checks the version state, and Azure already refuses. The `PublicKeys` contract and the `CachedVerifier` rustdoc are updated. `public_key_when_disabled` is deleted from `FixtureCaps` and never added to `KeySemantics`. |
| Implementation | B1 | Task IDs collide with §24.4 probe IDs | Tasks are renamed `X0`–`X23`. Probes are always written "§24.4 probe Tn" (§5.1 rule 5). |
| Implementation | B2 | P1-4 vs A3 on version-level `NotFound` | Same fix as Security B1. The ordering (classify input 404s before the drop check) is implemented in Phase 1, so X8c/X8d only change the kind. |
| Implementation | B3 | Gates fail and silently run live AWS in an agent shell | Every command runs through `scripts/test-env.sh` (commit `da9f69c`) plus `-u ANYKMS_REQUIRE_FIXTURE`, which `.env` sets and the script keeps. Live runs opt in explicitly, with `.env` loaded inside the wrapper (`--dotenv`, since the release review). Gate 2 was validated through the wrapper (§5.1, §6). |
| Implementation | B4 | GCP fake fails with `FAIL_ON_SKIP` at baseline | X0 declares `EmptyPlaintext` `not_applicable` on the fake. The baseline is restated as 298/150 after X0, and 298/2 failed/148 at HEAD (§6.3). |
| Implementation | B5 | No `aws` CLI; cleanup lacks `ListResourceTags`; no `cargo-hack` | The identity check uses the CLI or the dockerized `amazon/aws-cli:2.31.0` shim (checked: `user/anykms-test`). X0 adds `kms:ListResourceTags` to the policy, and the maintainer applies it once with root (open question 2). X18 installs `cargo-hack` (`cargo install cargo-hack --locked`; CI via `taiki-e/install-action`). |
| Implementation | B6 | 3 worktrees do not fit the disk | At most 2 lanes, `CARGO_BUILD_JOBS=2`, `-p`-scoped gates in worktrees, full gates once per wave on main, `target/` deleted after merge, and no new worktree under 12 GB free. One all-features build measured 8.1 GB (§5.1). |
| Implementation | B7 | `fuzz/Cargo.lock` has no owner | X1 and X18 are **lock** tasks and own `fuzz/Cargo.lock`. The fuzz check is in gate 6.1. (A7, which would also have changed it, is dropped.) |
| Implementation | B8 | Parallel groups not file-disjoint | The waves are rebuilt (§5.3): X18 is laned after X6; X9 makes no facade edit; X16 runs after X21 and lists its exact test files. |
| Implementation | B9 | W6 goes red; deprecated shims break `-D warnings`; `pub` fields | The X11 fallback keeps every target green. The shims are documented but not `#[deprecated]`. The `pub` fields stay until X13 removes them, together with the fixture calls (§3.2). |
| Implementation | B10 | The RustCrypto test does not test RustCrypto | The RustCrypto path is tested in recipes. The backends get `cargo check --lib` plus a `cargo tree` guard against `aws-lc-sys`, and the doc states why a backend test is no gate (§4 C1). |

### 8.2 Non-blocking items

**Taken:**

- **API:**
  - 1: `max_*` `None` documented; `PinnedVerify`.
  - 2: claim dropped.
  - 3: forwarding rule, including `Box`.
  - 4: `#[non_exhaustive]` variants with constructors.
  - 5: inherent `semantics()` and `OpaqueHandle`.
  - 6: X11 fallback.
  - 7: `pin` contract.
  - 8: `from_key_id` stays `InvalidArgument` (`Construct`).
  - 9: `UnknownKeyVersion` never invalidates.
  - 11: CHANGELOG and `operations.md`.
  - 12: typed `call` helpers keep their path.
  - 13: `extension_name` rule; `CallCx::backend` is an `Option`; `wrap` drops `part`; the part is
    only in `Call`.
  - 14: downcast error.
  - 15: typed decorators stay generic (superseded 2026-11-02: removed, see the note in §X14).
  - 16: no re-freeze; `later {}` rule.
  - 17: `Preflight` details.
  - 18: A6 labeled breaking for typed KEKs.
  - 20–23: macro, `finish_request`, `SendError`, testkit packaging.
  - 24: labels.
  - 25: X16 lists `fixture.rs`.
- **Security:**
  - N1: `class()` hint rule.
  - N3: `token_file_error_kind`.
  - N4: every cell corrected; GCP disabled public key enforced by (f).
  - N5: `PinnedVerify`.
  - N6: `pin` built structurally; error kind; rustdoc.
  - N7 (test part): no input-version `ParseUri`.
  - N8: `sigv4::Signed`, redaction test, P1-13 expiry and fail-closed.
  - N9: CI `cargo tree` guard.
  - N10: `gcp-service-account-key` is in the facade default.
  - N11: `releasing.md` note.
  - N12: P1-13 negative cache.
  - N13: `KeyInfo::with_backend` rule; `Call::run` concurrency.
- **Implementation:**
  - 1: sequencing deps labeled.
  - 2: `continue-on-error` in X0.
  - 3: X2 owns the conformance errors case and `operations.md`; X8a owns `tests/**`.
  - 4: X18 file list.
  - 5: `cargo hack … --lib --locked`.
  - 6: three explicit `skip` entries.
  - 7: AWS `from_env_with` bounds; touch points; old+new → error.
  - 8: hygiene tests excluded from packages.
  - 10: X21 files.
  - 11: X22 covers Phases 2 and 3; X6 owns `docs/cloud/README.md`.
  - 12: transit gate with `--sealed --tls` and both pairs.
  - 13: X23 stops before publish.
  - 14: sizes.
  - 15: P1-5 withdrawn.
  - 16: line corrections.

**Rejected:**

- **API 10** (rewrap AAD kind mismatch). Kept as is: transit cannot rewrap with AAD at all
  (`Unsupported`), while a KEK's `Rewrap` has no AAD slot (`InvalidArgument`). Recorded in §25
  by X22.
- **API 19** (A7 alternative). Taken in substance: A7 is dropped (§3.7), so the naming question
  is moot.
- **Security N2** (interim 403 → `KeyVersionUnusable` on Azure input versions). It would hide
  real `keys/verify` permission failures as caller errors. It waits for §24.4 probe T3, as
  (e) says.
- **Security N7** (`Registry::check_uri`). It would need a new `Provider` parse method;
  `Error::operation() == ParseUri` already lets applications map the error.
- **Implementation 9** (`anykms-crypto` CI matrix and gaps). Moot: A7 is dropped.

### Round 2

- API: SIGN-OFF. Non-blocking N1–N5 (forward `pin` in both `forward_provider!` forms and `name`
  only in the target form; `KeyInfo::backend_type_id()`; stale `error.rs` docs and a caller-class
  hint test; `request_span!` defined twice inside `anykms-http` per `tracing`; A4 labeled breaking
  for typed `ObserveLayer::wrap` callers) are taken: implementing agents apply them in the task
  that owns the code (X10/X11 for N1, N2, N5; X7 for N3; X1 for N4).
- Security: SIGN-OFF. Non-blocking notes on refusing public keys of disabled keys are taken in
  X8a/X8c: AWS describes the same key it then fetches (alias URIs resolve first); transient AWS
  states (`Creating`, `Updating`, `Unavailable`) map to a retryable `Unavailable`, not
  `KeyStateInvalid`; a missing `kms:DescribeKey` / `cloudkms.cryptoKeyVersions.get` permission
  fails closed (operator docs list the permission); the GCP version-state lookup is input-origin
  and negative-cached. Probe T1 checks whether `publicKeyViewer` grants the GCP permission.
- Implementability: 1 blocking. **X7 merged alone in W3 breaks the GCP gates until X8c (W4).**
  Resolved: X7 moved into W4's batch (§5 wave table). Non-blocking taken: the fuzz gate runs from
  the repo root with `--manifest-path`; the recipes dependency guard lists the real crates; the
  AWS CLI shim is `scripts/aws-cli.sh` in the repo, pinned by digest; disk is about 23 GB;
  X2 includes P1-1; transit gates set `ANYKMS_FAIL_ON_SKIP=1`; local gates run with
  `RUSTFLAGS=-D warnings`; X21 may update `Cargo.lock`.
