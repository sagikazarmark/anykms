# Operating anykms with Vault and OpenBao transit

This guide is for whoever runs the Vault/OpenBao servers and the services that call them. The
behavior below was verified against Vault 1.20/2.1 and OpenBao 2.4/2.7 (see
`research/vault-openbao-transit.md`).

For the cloud backends, see [operations-aws.md](operations-aws.md) (AWS KMS),
[operations-gcp.md](operations-gcp.md) (Google Cloud KMS) and
[operations-azure.md](operations-azure.md) (Azure Key Vault and Managed HSM).

Terms such as *KEK*, *typed handle* and *opaque handle* are defined in the
[glossary](glossary.md).

## Server-side setup

### Disable upsert

By default, encrypting to a key that does not exist **creates** that key. Turn this off on every
transit mount anykms uses:

```sh
vault write transit/config/keys disable_upsert=true      # or: bao write ...
```

Whoever runs this needs `update` on `transit/config/keys`. With upsert disabled and no `create`
capability, data-plane calls are side-effect free and safe to retry.

### Least-privilege policy

```hcl
# Data plane for keys under transit/ (one block per key works too).
path "transit/encrypt/*"            { capabilities = ["update"] }
path "transit/decrypt/*"            { capabilities = ["update"] }
path "transit/rewrap/*"             { capabilities = ["update"] }
path "transit/datakey/plaintext/*"  { capabilities = ["update"] }
path "transit/datakey/wrapped/*"    { capabilities = ["update"] }
path "transit/sign/*"               { capabilities = ["update"] }
path "transit/verify/*"             { capabilities = ["update"] }
path "transit/hmac/*"               { capabilities = ["update"] }
# Key-type check, describe and public keys.
path "transit/keys/*"               { capabilities = ["read"] }
```

Never grant `create` on these paths: it re-enables key creation through `encrypt`.

The `read` on `transit/keys/<name>` lets each handle check the key's type once before first use.
Transit itself does not reject a mismatched type: a P-384 key signs a "P-256" request, and an RSA
key "encrypts" with RSA-OAEP; anykms reports such a mismatch as `KeyMismatch`. If you cannot
grant `read`, the application must opt out with
`KeyTypeCheck::TrustCaller` and accept that risk.

### Envelope KEKs need their own mount

`EnvelopeAead` wraps data keys with empty AAD, so a KEK used for envelopes must not be used for
anything else. Use a dedicated mount so policy enforces this:

```sh
vault secrets enable -path=transit-envelope transit
vault write transit-envelope/config/keys disable_upsert=true
vault write -f transit-envelope/keys/app-kek type=aes256-gcm96
```

```hcl
path "transit-envelope/encrypt/app-kek" { capabilities = ["update"] }
path "transit-envelope/decrypt/app-kek" { capabilities = ["update"] }
path "transit-envelope/rewrap/app-kek"  { capabilities = ["update"] }
path "transit-envelope/keys/app-kek"    { capabilities = ["read"] }
```

### Rate-limit quotas

anykms maps 429 to `Throttled` (retryable). Turn on response headers so clients get `Retry-After`:

```sh
vault write sys/quotas/config enable_rate_limit_response_headers=true
```

This setting is server-wide, so application teams have to ask the server operators for it. anykms
treats `Retry-After` as a *floor* over its normal backoff: a retry waits for the longer of the
jittered exponential delay and `Retry-After` plus a random extra of up to the backoff base, so
clients throttled together do not retry in lockstep. `Retry-After: 0` (which OpenBao can send)
therefore never shortens the schedule. A value above the backoff cap, or one that would pass the
deadline, fails fast with `Throttled` instead of sleeping.

### Health checks

Do not gate application readiness on `/sys/health`. Standby nodes answer it with 429 by default,
and a dependency on it couples your deployment to Vault failover. Let anykms errors
(`Unavailable`, retryable) drive retries instead.

### Failover

Measured with `scripts/probe-failover.sh` (three-node raft cluster, every data-plane request sent
to every node):

| Event | Vault 1.20.4 / 2.1.1 | OpenBao 2.4.4 | OpenBao 2.7.1 |
|---|---|---|---|
| Step-down (`sys/step-down`, rolling upgrades) | about 5 s, up to 6 s, after a third to a half of step-downs; under 1 s otherwise | under 1 s, once about 5 s | under 1 s |
| Active node dies | 8–22 s | 11–19 s | no errors on the surviving nodes |

During the long windows **no node serves requests**: standbys answer 307 and the old active node
500 "local node not active but active cluster node not found", so a load balancer cannot route
around them; only retries ride them out. No failover response carries `Retry-After`.

- The default `RetryPolicy` (5 retries, 4.65–9.3 s in total) spans step-downs. The price: a real
  outage takes that long to surface as `Unavailable`. Lower `max_attempts` where failing fast
  matters more.
- A dying active node takes longer than the defaults wait. Raft timing sets this: lowering
  `performance_multiplier` in the server's raft storage stanza shortens elections. Jobs that must
  survive it can raise `max_attempts` and the deadline.
- The retry budget (at most about 10% of requests are retries, see "Retry budgets" below) still
  applies: a busy service sees errors during a several-second outage, because retrying every
  request would hit the recovering cluster with a multiple of its normal load.

### Retry budgets

Backends never retry on their own (the single exception is one retry with a refreshed token after
a 403), so the attempts configured on `Retry` are the only ones; they do not multiply.

The budget is a token bucket per `RetryBudget`: every call adds 0.1 token (up to a capacity of
10, which it starts with) and every retry spends one. Each `RetryLayer` (each
`anykms::retry_layer()` call) creates its own budget, shared by every handle and part it wraps. The
"about 10% of requests" bound therefore holds **per budget**: a service with 50 handles, each
wrapped separately, may send up to 50 independent bursts of retries at a struggling cluster. To
bound them, wrap the handles with one layer, most simply on the registry. A registry layer has
**one budget shared by every backend** behind it: a failing backend that drains it leaves no
retries for the others, whose transient errors then come back unretried. Where that matters
(several backends, or keys of very different health), give each backend's handles their own
layer instead:

```rust
let registry = anykms::with_default_providers()?
    .layer(anykms::retry_layer())                          // one budget for every handle and backend
    .build()?;
// Or per handle of a registry without a retry layer, with one shared layer:
let retry = anykms::retry_layer();
let kek = registry.aead(&kek_uri)?.layer(&retry);
let mac = registry.mac(&mac_uri, MacAlgorithm::HmacSha256)?.layer(&retry);
// Typed handles take the same layer as a decorator:
let typed = retry.wrap(transit.aead_key(&kek_uri)?);
```

A handle takes at most one retry layer: `.layer(&retry)` on a handle that already retries (one
from a registry with a retry layer) returns it unchanged (logged at debug level with the
`tracing` feature), so a registry layer and a per-handle layer never nest into multiplied
attempts. To give one handle another policy (a request path with a tighter deadline, say), use
`.replace_retry(&retry)`: it puts the new retry layer where the old one was and rebuilds the
handle's parts with its other layers. Parts added to a handle after layering (`with_describe`,
...) get every layer the handle already has. To share a budget between separate layers, pass one
`RetryBudget` to `RetryLayer::with_budget`; a shared budget overrides the policy's
`budget_ratio` and `budget_cap`.

### Restrict mounts

Set `ServerConfig::allowed_mounts(["transit", "transit-envelope"])`. Key URIs are trusted
configuration, but an allowlist keeps a mistyped URI from pointing at a non-transit mount (for
example a KV mount), which matters most with `KeyTypeCheck::TrustCaller`.

### Namespaces

The namespace is configured on the client (`ServerConfig::namespace`). A key URI may only select
a namespace listed in `allowed_namespaces`. **Vault CE silently ignores the namespace header**
and serves the root namespace. OpenBao returns 404 "namespace not found", which anykms maps to
`Configuration`.

**Deployments that use namespaces should also set `allowed_mounts`.** Vault Enterprise and
OpenBao resolve leading path segments as namespaces, so even a single-segment mount can name a
child namespace: `hashivault:///ns1/keys/k` is the mount `ns1`, which the server may resolve as
namespace `ns1`, mount `keys`. Multi-segment mounts already require `allowed_mounts`; this case
is contrived (it needs a child namespace whose name is a plausible mount and a mount named
`keys` in it), but an allowlist of the real transit mounts closes it.

**The token's policy is the real boundary.** anykms's checks keep configuration mistakes from
reaching other namespaces, but path resolution happens on the server: a URI such as
`hashivault:///team-b/keys/k` (a single-segment mount `team-b`) can resolve as child namespace
`team-b` on Vault Enterprise. A token that is only granted the namespaces and mounts the service
needs cannot be steered elsewhere by any key URI; a broadly privileged token can.

## Client-side configuration

### Addresses and TLS

- Use `https://`. Plain `http://` is accepted only for literal loopback IPs (`127.0.0.0/8`,
  `::1`), for example a Vault/Bao Agent API proxy. `from_env` enables this automatically for such
  addresses. The hostname `localhost` is rejected.
- TLS trust, client certificates (mTLS), the crypto provider, proxying, timeouts and the HTTP
  version are settings of the HTTP transport, not of `ServerConfig`: build a
  `ReqwestTransport` (`anykms_transit::anykms_http::ReqwestTransport::builder()`) and pass it to
  `ServerConfig::http_transport`, or bring any `HttpTransport`. One transport may serve several
  servers and providers. Without one, a default `ReqwestTransport` (system roots) is built.
- `ReqwestTransportBuilder::ca_pem`, and `VAULT_CACERT` / `VAULT_CAPATH` through `EnvConfig`
  (which builds the transport from them), **replace** the system roots. `VAULT_CAPATH` is a
  directory of PEM files (symlinks followed, subdirectories skipped); every file must hold a
  certificate, and `VAULT_CACERT` wins when both are set, as in the Vault CLI.
  `VAULT_CLIENT_CERT` and `VAULT_CLIENT_KEY` configure the client certificate the same way. There
  is no way to skip verification, and `*_SKIP_VERIFY=true` makes `from_env` fail. A transport
  passed to a `ServerConfig` loaded by `EnvConfig` replaces the one built from the variables.
- TLS failures are classified: a rejected server certificate (`TLS certificate rejected: unknown
  issuer`, `name mismatch`, `expired`, ...) or a client certificate the server refuses is
  `Configuration` and is not retried. `DNS lookup failed` stays `Unavailable` (resolver outages
  are transient), so a mistyped host shows up as repeated `Unavailable` with that message.
- The rustls crypto provider is aws-lc-rs by default (`rustls-aws-lc-rs`; building it needs a C
  compiler). ring is opt-in: `default-features = false, features = ["reqwest", "rustls-ring"]`. A
  provider passed with `ReqwestTransportBuilder::crypto_provider` wins, then the process default
  (`CryptoProvider::install_default`), then the feature's provider. See the anykms-http crate
  docs.
- Certificate files are read when the transport is built. To pick up rotated CAs or client
  certificates, build a new transport and provider.
- Redirects are never followed. A 307 becomes `Unavailable` (retryable); it usually means the
  address points at a standby node without request forwarding (check the load balancer or
  `api_addr`). Any other 3xx (301/308 permanent redirects, and 302/303 from proxies or login
  pages in front of the server) is `Configuration` and is not retried.
- Environment proxies (`HTTPS_PROXY`) are ignored unless configured explicitly.

### Tokens

| Setup | Configuration |
|---|---|
| Vault/Bao Agent sink file | `VAULT_TOKEN_FILE=/vault/secrets/token` (anykms-specific) or `ServerConfig::token_file` |
| Agent API proxy (`use_auto_auth_token`) | `VAULT_ADDR=http://127.0.0.1:8100` and `ANYKMS_TRANSIT_NO_TOKEN=1` (`EnvConfig::no_token`, `ServerConfig::no_token`) |
| Static token | `VAULT_TOKEN` (read on every request) |
| OpenBao (`from_env_openbao`) | with `BAO_ADDR`: `BAO_TOKEN`, then `BAO_TOKEN_FILE` (anykms-specific), then `~/.bao-token`, `~/.vault-token`; with only `VAULT_ADDR`: the `VAULT_*` equivalents |
| Developer machine | `~/.vault-token` (disable with `EnvConfig::vault().no_home_token()`) |
| Kubernetes auth (renewed) | `ANYKMS_TRANSIT_AUTH=kubernetes`, `ANYKMS_TRANSIT_AUTH_ROLE=<role>` or `ServerConfig::login(Login::kubernetes(role))` |
| JWT auth (renewed) | `ANYKMS_TRANSIT_AUTH=jwt`, `ANYKMS_TRANSIT_AUTH_ROLE=<role>`, `ANYKMS_TRANSIT_AUTH_JWT_FILE=<path>` or `ServerConfig::login(Login::jwt(role, path))` |
| Other login (AppRole, cloud IAM, ...) | implement `TokenSource` |

`from_env` reads `<P>_ADDR`, `<P>_TOKEN`, `<P>_TOKEN_FILE`, `<P>_NAMESPACE`, `<P>_CACERT`,
`<P>_CAPATH`, `<P>_CLIENT_CERT`, `<P>_CLIENT_KEY` and `<P>_SKIP_VERIFY` (only to refuse it), where
`<P>` is `VAULT` or `BAO`, plus `ANYKMS_TRANSIT_NO_TOKEN`,
`ANYKMS_TRANSIT_ALLOW_INSECURE_TOKEN_FILE`, the login variables (`ANYKMS_TRANSIT_AUTH`,
`ANYKMS_TRANSIT_AUTH_ROLE`, `ANYKMS_TRANSIT_AUTH_JWT_FILE`, `ANYKMS_TRANSIT_AUTH_MOUNT`) and
`HOME`. `from_env_with` (and `from_env_openbao_with`, `EnvConfig::load_with`) reads the same
variables from a lookup function instead of the process environment; a `<P>_TOKEN` is then re-read
through that lookup on every request.
`VAULT_TOKEN_FILE` and `BAO_TOKEN_FILE` are anykms conventions: the Vault and OpenBao CLIs do not
read them. The other `VAULT_*`/`BAO_*` variables mean what they mean to the CLIs.

The anykms variables were unprefixed in development builds before 0.1.0 (`ANYKMS_AUTH`,
`ANYKMS_AUTH_ROLE`, `ANYKMS_AUTH_JWT_FILE`, `ANYKMS_AUTH_MOUNT`, `ANYKMS_NO_TOKEN`,
`ANYKMS_ALLOW_INSECURE_TOKEN_FILE`). They have no aliases: if any old name is set, loading fails
with `Configuration` ("`ANYKMS_AUTH` was renamed to `ANYKMS_TRANSIT_AUTH`"), even when the new
name is set too, so a stale deployment cannot silently lose its login or token-file setting. The check may be
removed in a future release.

Configuration loaded from the environment (`from_env`, `with_default_providers`) **fails when no
token source is found**, listing the variables and files it checked; without a token every request
would fail with `PermissionDenied`. Behind an Agent API proxy, opt out explicitly with
`ANYKMS_TRANSIT_NO_TOKEN=1` or `EnvConfig::no_token()`.

OpenBao reads every setting (token, namespace, CA, client certificate) from the prefix that
supplied the address, so a token is never sent to an address configured under the other prefix:
with `BAO_ADDR` all `VAULT_*` variables are ignored; with only `VAULT_ADDR`, a `BAO_*` setting
(for example a stray `BAO_TOKEN`) makes loading fail.

`with_default_providers()` skips transit when neither `VAULT_ADDR` nor `BAO_ADDR` is set. The
skip is reported by `DefaultProviders::skipped()` (`SkipCause::NotConfigured`) and logged with the
`tracing` feature, and opening a `hashivault://`/`openbao://` key then fails with `no provider
registered for scheme "hashivault" (transit: VAULT_ADDR/BAO_ADDR not set)`. Cloud providers are
different: with their feature on they are always registered, and their credentials are resolved on
first use. The exception is a system trust store without a usable root certificate: a cloud
provider cannot build its TLS client then, and is skipped with `SkipCause::TlsRoots` (logged as a
warning with the `tracing` feature), so a deployment that uses other backends (transit with its own
`VAULT_CACERT`, say) still starts. A cloud provider built explicitly fails with `Configuration`
instead.

#### Login and renewal

With `ANYKMS_TRANSIT_AUTH` (or `ServerConfig::login`), anykms logs in to `auth/<mount>/login`
(mount `kubernetes` or `jwt` by default; `ANYKMS_TRANSIT_AUTH_MOUNT` changes it) with the role
and the JWT read from the file (the pod's service-account token for `kubernetes`), then keeps the token fresh: once
two thirds of its lease have passed it calls `auth/token/renew-self` if the token is renewable,
and logs in again when it is not, when renewal fails, or when the renewed lease is under half
of the previous one (the max TTL is near). A failed refresh keeps using the current token until it
expires and waits 5 s before the next attempt; a 403 retries the request once with a fresh login,
at most once per 30 s (policy denials are 403s too, and must not mint a token each); if the caller
cancels that login, the next request retries it. Concurrent requests share one login, and when a
login fails with no usable token, requests get that error for the next 5 s instead of each logging
in again. The token variables are ignored when `ANYKMS_TRANSIT_AUTH` is set, and combining it
with `ANYKMS_TRANSIT_NO_TOKEN` is an error. A refused login (wrong role, audience or mount; 400/401/403) is
`PermissionDenied`; a missing JWT file is `Unavailable` (a rotation race), any other unusable JWT
file (unreadable, empty, malformed) is `Configuration`. The JWT file's permissions are not
checked: Kubernetes mounts service-account tokens world-readable by default.

#### Token files

The file source re-reads the token when the file's modification time, size or inode changes, and
after a 403 (which also catches an in-place rewrite that keeps size and mtime).
The Agent should write the file atomically (rename). A missing file makes requests fail with
`Unavailable` (retryable: a rotation race). Every other failure is `Configuration`, which
retrying cannot fix: an unreadable file (`EACCES`), an empty file, a file over 8 KiB, one that is
not UTF-8 or holds whitespace or control characters, and anything but a regular file (a FIFO,
device or directory, refused without being read). After a 403
the request is retried **once**, and only if the token source returns a different token.

On Unix, a token file that is group- or world-accessible (any of `mode & 0o077`) is refused with
`Configuration`. Common sources default to readable modes, so set them explicitly:

- **Vault/Bao Agent file sink** (default `0640`): set `mode = 0600` (or `0400`) in the sink:

  ```hcl
  sink "file" {
    config = {
      path = "/vault/secrets/token"
      mode = 0600
    }
  }
  ```

- **Kubernetes secret or projected volume** (default `0644`): set `defaultMode: 0400` (or
  `0600`) on the volume (or `mode` per item). The files are owned by root, so this works for a
  container running as root. **`fsGroup` does not help a non-root container:** with it set, the
  kubelet chowns every file of a secret or projected volume to the group and adds group read
  (`0400` becomes `0440`, `0600` becomes `0640`), which the check refuses. For a non-root
  container, let a Vault/Bao Agent sidecar running as the container's user write the token
  (sink `mode = 0600`) into a shared `emptyDir`, or copy the secret into an `emptyDir` in an init
  container (`chmod 600`, owned by the container's user); the kubelet does not change the mode of
  files written into an `emptyDir` after it is mounted. Or accept the group-readable file: set
  `fsGroup` and opt out below.

The permission check applies to the opened file (`fstat` on the handle), so swapping the path
between the check and the read does not bypass it.

Token copies anykms cannot wipe: the process environment keeps `VAULT_TOKEN` for the process
lifetime, and reqwest copies the token into an `X-Vault-Token` header value (marked sensitive, so
it is not printed, but not zeroized). Prefer a token file over `VAULT_TOKEN` where that matters.

Where the mode cannot be changed, opt out explicitly: `FileToken::allow_insecure_permissions()`,
`EnvConfig::allow_insecure_token_file()`, or `ANYKMS_TRANSIT_ALLOW_INSECURE_TOKEN_FILE=1` for
configuration loaded from the environment (`VAULT_TOKEN_FILE`, `~/.vault-token`). Group access is
refused by default as well: a group-readable token is shared with every process in that group.

### Timeouts and connections

Connection settings live on the built-in transport (`ReqwestTransportBuilder`); the retry
settings on `RetryPolicy`.

| Setting | Default | Notes |
|---|---|---|
| `connect_timeout` | 2 s | fails fast on partitions |
| `request_timeout` | 10 s | per attempt; a backend's metadata probes override it per request (`RequestTimeout`) |
| `pool_idle_timeout` | 50 s | below common load-balancer idle timeouts |
| `tcp_keepalive` | 30 s | |
| `http2` | off | HTTP/2 multiplexes onto one node behind a load balancer; it is negotiated over TLS only (needs the `http2` feature), so plain-HTTP loopback servers always use HTTP/1.1 |
| `proxy` | none | environment proxy variables are ignored; link-local and loopback hosts are never proxied |
| `Retry` attempts / backoff | 6 / 300 ms base, 5 s cap, equal jitter | the 5 retries wait 4.65–9.3 s in total, which spans a leader step-down (see "Failover" below) |
| `Retry` deadline | 15 s | across attempts (see `RetryPolicy`) |

### Startup checks

Opening a key does no I/O, so a wrong URI, a missing policy path or a key of the wrong type shows
up on the first operation. Call `preflight()` on each opaque or typed handle at startup
to fail fast. It describes the key and fails with `KeyMismatch` when the key
cannot do the handle's operation or algorithm, and with `KeyStateInvalid` when it is disabled or
scheduled for deletion; its errors are labelled `Operation::Describe`. The backend runs its own
key-type and state check, and an opaque handle then repeats the generic capability and state
checks on the result. The returned `KeyInfo` carries the backend's metadata
(`info.backend_info::<TransitKeyInfo>()`). Preflight also pays the one-time key-type read up
front. Handles from a `Registry` (`AeadKey`, `DigestSignerKey`, `MacKey`, ...)
report which optional parts they carry (`supports_rewrap()`, `supports_describe()`, ...); a
missing part fails with `Unsupported` before any I/O.

### Retiring envelope KEKs

`EnvelopeKeyring` trusts **every** KEK in its ring for decryption, and anyone allowed to encrypt
under a KEK can forge envelopes for any AAD. Once data has been moved off an old KEK, remove that
KEK from the ring promptly and revoke `encrypt` on it (or the whole key), instead of keeping it
"just in case": a retired KEK that is still in the ring lets whoever holds encrypt rights on it
inject envelopes your service accepts as genuine.

With a public-key (RSA-OAEP) KEK (AWS, GCP and Azure RSA keys), wrapping needs only the public
key, so **every holder of the public key** can write envelopes, and revoking a permission does
not take that away: a published or cached public key keeps working. Such envelopes give
confidentiality only; the AAD does not authenticate the writer. A symmetric primary does not
protect a keyring that keeps an RSA secondary: the ring still accepts envelopes wrapped under the
secondary's public key. Retiring an RSA KEK therefore means removing it from the ring (and
disabling the key once nothing reads it), not revoking a permission.

To retire a KEK, or to move every envelope to a rotated KEK's new version:

1. Make the new KEK the keyring's primary (`with_kek(..)?.with_primary(..)`), or rotate the KEK.
   New envelopes use the primary's current version from then on.
2. Rewrite every stored envelope with `ring.rewrap_current(&ct)` (one `EnvelopeAead`:
   `envelope.rewrap_current(&ct)`). It moves envelopes off the other KEKs of the ring and off
   older versions of the primary, server-side where the primary KEK can rewrap (transit, AWS,
   local) and otherwise locally (`rewrap_local`, which works on any backend). The payload is
   never touched. Each call writes a new wrapped key, so skip envelopes that are already current
   (step 3) and the job can be re-run after an interruption.
   To also report rows that no longer decrypt (an envelope copied from another row, a corrupted
   payload), use `rewrap_verified(&ct, aad)` with each row's AAD instead: it decrypts the
   payload first (the plaintext is zeroized, never returned) and costs like `decrypt`.
   `rewrap_local` checks only that the data key unwraps and matches the key commitment;
   `rewrap_current` does the same when it falls back to it, but its server-side rewrap only needs
   the KMS to unwrap the data key (the data key never reaches the process, so there is no
   commitment check).
3. Scan for completion before removing anything. An envelope is current when
   `Envelope::parse(ct.as_bytes())?.kek_id()` equals `ring.primary_id()` and, where both are
   known, `ring.ciphertext_version(&ct)?` equals the primary KEK's
   `describe().await?.primary_version()`. Some wrapped keys do not reveal their version (it is
   `None`) and AWS rotates transparently (a key's version is its ARN), so compare versions only
   when both sides report one. The envelope module's rustdoc has the scan as code.
   `ring.kek_ids()` lists the KEKs still configured.
4. Remove the old KEK from the ring and revoke `encrypt` on it (decrypt too, once nothing
   should read it). An envelope the scan missed then fails with `DecryptFailed` ("unknown
   kek_id"), which is caller-class and does not page anyone, so the scan in step 3 is what
   catches leftovers.

### Large envelope payloads block a thread

`EnvelopeAead` (and `EnvelopeKeyring`) `encrypt`/`decrypt` run AES-GCM over the payload
synchronously inside the async call, so it blocks its thread for time proportional to the size
(up to `MAX_PLAINTEXT`, 64 GiB). On x86-64 with AES-NI that is roughly 3 GB/s, about 0.3 ms per
MB (100 MB: on the order of 100 ms); without hardware AES it is much slower. Field-sized payloads
need nothing. With large payloads on tokio, keep the work off the async workers:
`tokio::task::block_in_place(|| Handle::current().block_on(envelope.encrypt(pt, aad)))` on a
multi-thread runtime (borrowed data works), or `tokio::task::spawn_blocking` with the same
`block_on` (owned data and a clone of the envelope). Rewrapping never touches the payload.

### Caching unwrapped data keys

Every envelope decrypt unwraps its data key with one KMS call. Where the same envelopes are
decrypted repeatedly, or KMS request quotas and cost matter, wrap the KEK in `CachingKeyWrap`:
`EnvelopeAead::new(kek_id, CachingKeyWrap::new(kek).with_ttl(ttl))`. It caches only unwrapped data keys
(keyed by the wrapped key's bytes, zeroized on eviction) and never reuses data keys for new
envelopes. The costs: a revocation (disabling the KEK, removing decrypt permission) takes effect
in the process only after the TTL, unless you call `invalidate()`; the KMS audit log records one
unwrap per data key per TTL instead of one per decrypt; and plaintext data keys stay in memory
for up to the TTL. Keep the TTL short (the default is 60 seconds).

### HMAC keys and `describe`

Transit reports `keys: null` for `hmac` keys, so their `KeyInfo::versions()` (and
`TransitKeyInfo::versions`) is empty. The primary version (`latest_version`) and the
`TransitKeyInfo` minimum versions are still reported.

## Runbook: `ErrorKind` → cause → action

Every error belongs to exactly one class, so alerting can be written against the class instead of
individual kinds: `Error::is_config_error()` (an operator must fix configuration, policy or the
key, or look at the backend; page or alert), `Error::is_caller_error()` (the input of one request
is at fault; report it to whoever sent it, do not page) and `Error::is_retryable()` (transient;
the retry layer handles it). The class follows the kind alone, whatever the operation: a key
version the handle chose itself (its URI pin, or the current or primary version) that cannot be
used is `KeyStateInvalid` (config) for every operation, while a version taken from the input is
`KeyVersionUnusable` or `UnknownKeyVersion` (caller), or `VerificationFailed` when verifying.

Every transit error names the key it is about (`Error::resource()`), so with several keys the
failing one is obvious:

```text
transit decrypt [hashivault://default/transit/keys/app-kek]: not_found: key not found (http 400) (server: "encryption key not found")
transit open [hashivault://prod/transit/keys/app-kek]: configuration: unknown server alias
```

The resource is `<scheme>://<server alias>/<mount>/keys/<name>`, with ` (namespace <ns>)` when a
namespace applies; it never holds a query string or token. File-related configuration errors
name the path and the reason (`cannot read the CA certificate file /etc/vault/ca.pem
(VAULT_CACERT): No such file or directory`). Vault and OpenBao return no request id on error
responses (neither in the body nor in a header), so transit errors carry none.

| ErrorKind | Class | Likely cause | Action |
|---|---|---|---|
| `NotFound` | config | key name or mount wrong; key deleted; **replica lag** right after a key was created | check the URI and mount; on performance standbys or OpenBao raft standbys, enable `RetryPolicy::with_retry_on_hint` (see below) |
| `PermissionDenied` | config | token expired or revoked on OpenBao (a plain 403, indistinguishable from a policy denial; Vault names the token as invalid, which is `Unauthenticated`); policy missing a path; encrypt to a missing key without `create` | check the token TTL and Agent health; compare the policy with the snippet above |
| `Unauthenticated` | config | the credentials were not accepted at all: a 401, or a 403 naming the token as invalid | renew the token; check the token source (Agent, token file, `VAULT_TOKEN`) |
| `KeyStateInvalid` | config | key disabled or soft-deleted (OpenBao); a key version the handle chose (its URI pin, or the current or primary version it writes with) is disabled, for every operation including `public_key()` | restore or re-enable the key or version, or unpin it |
| `KeyMismatch` | config | the key's type or algorithm does not fit the handle: an AES key opened as a MAC key, a P-384 key opened for P-256 signatures, an RSA key opened as an AEAD key; the server says the key's type does not support the operation (400 "does not support", with the key-type check skipped or the key recreated with another type) | fix the key URI or the algorithm in the configuration, or recreate the key with the right type |
| `Unsupported` | config | capability missing on this flavor (for example data-key AAD on Vault); **the server warned about ignored parameters** (fails closed); with upsert enabled, an encrypt that raced the key's creation ("Attempted creation of the key during the encrypt operation, but it was created beforehand": every warning fails closed, although the encrypt succeeded); derived keys; a handle from a `Registry` without that optional part | use the recipe (`EmulatedDataKeys`); check the server version; after the upsert race, encrypt again (the key exists now) or disable upsert |
| `Configuration` | config | a key URI the provider's grammar refuses (`Error::operation()` is `ParseUri`: key URIs come from configuration; an application that accepts URIs from users maps that operation to 400 itself); unknown server alias; namespace not found (OpenBao); disallowed mount or namespace; insecure address; `TLS certificate rejected: ...` (wrong CA, hostname or expired certificate) or a refused client certificate; a redirect other than 307 (301/308, or 302/303 from a proxy or login page); a token or JWT file that is group- or world-accessible (token files only), not a regular file, unreadable, empty or malformed; no token source found at startup | fix the client configuration (`VAULT_CACERT`/`VAULT_CAPATH`, the address's hostname, the client certificate) |
| `DecryptFailed` | caller | wrong key or AAD; tampered or truncated data (including a stored value that is not valid base64, from `Ciphertext::from_base64`); ciphertext from another key; **replica lag** ("version is too new") right after a rotation | check the AAD scheme and the key URI |
| `VerificationFailed` | caller | the signature or MAC does not match, or is malformed | expected for forged input |
| `KeyVersionUnusable` | caller | the ciphertext, signature or tag was made with a key version below `min_decryption_version` (or a disabled or destroyed version), or `public_key_version` names such a version | rewrap or re-sign old data before raising the minimum; lower the minimum to recover |
| `UnknownKeyVersion` | caller | `public_key_version` names a version this key does not have, or another key's version (an untrusted `kid`, a stale reference); with a retry hint when the version may not have replicated yet. Verifying such a signature or tag is `VerificationFailed`, and `CachedVerifier` reports it that way too | expected for forged input; for real versions, check the `kid` routing |
| `InvalidArgument` | caller | payload too large; digest of the wrong length or algorithm; unversioned signature for transit | use `EnvelopeAead` for large data; fix the calling code |
| `Throttled` | retryable | rate-limit quota | back off; raise the quota; enable rate-limit headers |
| `Unavailable` | retryable | server sealed (503); standby, failover or raft trouble; connection refused or reset; `DNS lookup failed` (resolver outage, or a mistyped host if it persists); a temporary redirect (307, from a standby that cannot forward); token or JWT file missing | check the cluster state; check that the address points at the active node or a forwarding standby |
| `Timeout` | retryable | network partition; overloaded server | check latency; tune timeouts |
| `Backend` | config | an unclassified server response (the message is redacted to a fingerprint); an undecodable or oversized response | look up the fingerprint in the server logs; report it so the mapping can be pinned; check `max_response_bytes` |

### Replica lag and `retry_on_hint`

On performance standbys and secondaries (Vault Enterprise), and on OpenBao standbys in a raft
cluster, a key that was just created can answer "not found", and ciphertext from a just-rotated key
can fail with "version is too new": these nodes answer from their own copy of storage, which can
trail the active node. (`scripts/probe-failover.sh` saw OpenBao standbys answer 400 "encryption key
not found" for a key created milliseconds earlier; Vault Community standbys forward instead.)
Transit attaches a 500 ms *retry hint* (`Error::retry_hint`) to exactly these errors, and to a
public-key request for a version above the node's latest version; `CachedVerifier` attaches its
refresh interval (500 ms by default) when it rejects a signature naming a version above the latest
version it knows. The kinds stay `NotFound` / `DecryptFailed` / `VerificationFailed` /
`UnknownKeyVersion` / `InvalidArgument`, which are not retryable. A hint never changes the class
of a caller-class kind (`Error::class()` stays `Caller`; see below), but the retry layer honors it
all the same.

`RetryPolicy::with_retry_on_hint(true)` allows one retry of a hinted error, after at least the hint
(as with `Retry-After`, never less than the normal backoff, plus a small random spread). The retry
counts towards `max_attempts`, spends a retry-budget token and must fit in the deadline; a hint
above the backoff cap (5 s by default) is not waited for. Hinted errors are not negatively cached
for longer than the hint, so the retry asks again. The server cannot tell lag from a key that
really does not exist, so with the option enabled **every genuine `NotFound` costs one extra retry
delay** (also on single-node setups) before it is returned. Enable it for the handles of
the backends where the lag occurs. Other backends hint the same way where a condition is usually
transient but looks permanent (for example a key version that is still being
generated), so the option is not transit-specific.

**Enable it for any retry layer that wraps a `CachedVerifier`, whatever the replica topology.** The
verifier rejects a signature naming a version above the latest it knows, without a lookup, when it
read the latest version within its refresh interval (500 ms by default). That also happens on one
node: right after a rotation, if the first verification after startup, another signature naming a
version above the latest, or a recheck after a failed verification read the latest version less
than 500 ms earlier, the new version's first tokens fail with `InvalidArgument`. The hinted retry
waits out the interval, re-reads the latest version and verifies. Wrap the verifier itself
(`retry_layer().with_policy(RetryPolicy::default().with_retry_on_hint(true)).wrap(verifier)`): a
retry layer on the registry the source came from never sees this rejection. If the source already
retries, add `with_max_attempts(2)` so transient errors are not retried at both levels. The
verifier deliberately does not re-read the latest version inline: that would make every forged
`kid` a backend request again. Give the verifier its own layer (each `retry_layer()` call has its
own budget): a flood of forged above-latest kids spends that budget on hinted retries, and once
it is empty they stop (the rejection is returned at once) without affecting other handles.

### Errors as HTTP responses

A service that answers HTTP requests can map an error that came out of the retry layer by its
class. Caller errors come first, hint or not: the input may name a version that has not
replicated yet, but it may as well be forged, and a forged `kid` must not turn into a 503. Check
the hint next: other hinted errors have kinds that are not retryable, so their class says config
although the condition is usually transient. `Error::class()` returns an `ErrorClass` (`Caller`,
`Hinted`, `Retryable`, `Config`) in exactly this order, so a `match` on it is the whole table; its
documentation has a ready-made mapping function.

The default `RetryPolicy` (6 attempts, 15 s deadline) suits background work; a request handler
should not hold its client for 15 s. Give request-path handles `RetryPolicy::interactive()` (3
attempts, 50-500 ms backoff, 2 s deadline), on their own registry layer or per handle with
`key.replace_retry(&anykms::retry_layer().with_policy(RetryPolicy::interactive()))`. With
`with_retry_on_hint(true)` around a `CachedVerifier`, keep the deadline above the verifier's
refresh interval plus backoff (the preset fits the default 500 ms interval).

The deadline bounds the retry schedule, not an attempt in flight: the worst case is the deadline
plus one attempt, which lasts up to the transport's request timeout (10 s by default), plus any
wait for credentials. A server that accepts connections and never answers costs an interactive
request about 10 s. To bound it, lower `ReqwestTransportBuilder::request_timeout` on the
transport you pass to the providers, or wrap the call in `tokio::time::timeout`.

| Condition (in this order) | Status | Notes |
|---|---|---|
| `e.is_caller_error()` | 400; 401 when verifying the caller's token; 500 when the input is the service's own stored data | also with a retry hint. 400 and 401 apply when the input came from the request. A caller-class error on a ciphertext the service stored itself (a tampered, swapped or corrupt row, a row below `min_decryption_version`) is a data-integrity failure: 500, and alert. For token verification, `VerificationFailed` (including a `kid` naming a version the key does not have), `InvalidArgument` (malformed token, other algorithm, non-numeric version, `CachedVerifier`'s version above the latest), `UnknownKeyVersion` and `KeyVersionUnusable` (revoked version) all mean the token is not accepted |
| `e.retry_hint()` is `Some` | 503 with `Retry-After` (the hint, rounded up to whole seconds) | the retry layer returns hinted errors unchanged, hint included, when the hinted retry failed again or was not made (option off, budget empty, past the deadline): transit replica lag on a key just created (`NotFound`), a key version still being generated |
| `e.is_retryable()` | 503 with `Retry-After` (`e.retry_after()` if set, rounded up) | the retry layer gave up (attempts, deadline, budget); a server `Retry-After` above the cap comes back as `Throttled` carrying it |
| `e.is_config_error()` | 500 | an operator must act. `NotFound` here is a configured key or mount that does not exist, not a missing resource of the request: never 404. `Unauthenticated` is the service's own KMS credential, never the client's: 500, not 401 |

A hinted error that keeps coming back is the permanent condition (a key that does not exist):
alert on its rate as for its class. A forged `kid`, above the latest version or naming a version
or key that does not exist, is a caller error (401 when verifying a token), not a 503, and costs
no backend request through `CachedVerifier` with its version checks on. A token naming a version
the backend no longer publishes (below `min_decryption_version`) fails through `CachedVerifier`
with `VerificationFailed` (the source's `UnknownKeyVersion`) or `KeyVersionUnusable`, both 401.
Do not send `Display` output to clients: it names the backend, key URI and mount.

### Tracing

With the `tracing` feature, every HTTP request emits a span (`anykms.transit`) with the fields
every anykms HTTP backend shares: `backend`, `op`, `resource` (the key, as errors name it:
`hashivault://<server alias>/<mount>/keys/<name>`, plus ` (namespace <ns>)` when one applies),
`key_version` (the version a decrypt, rewrap, verify or `public_key_version` names; empty
otherwise), `attempt` (1, or 2 for the 403 token-refresh retry), `http_status` (on success and on
error; after a 403 token refresh it is the retried request's status), `code` and `request_id`
(empty: transit sends neither), `latency_ms`, `error_kind` and `outcome` (`ok`, `error`, or
`cancelled` for a call dropped before it finished, e.g. by a timeout around it: its `latency_ms`
is the time until the drop), and never any data.
A handle's first use emits a separate span for its metadata read.

Every login and renewal of `Login`, and every read of a token file (not a cached token), emits a
token span (`anykms.transit.token`) with `backend`, `credential` (`kubernetes`, `jwt` or
`token_file`), `outcome`, `error_kind`, `latency_ms` and `expires_in_s` (the lease, for logins and
renewals), with a `debug` event on success and a `warn` event on failure that carries the error
kind, the error and, when a JWT or token file failed, its path. Sources that fetch nothing (a
static or environment token, no token) emit no token span. The `credential` values are stable
snake_case labels, as on every backend.

With a retry layer, each retry is an `info` event `anykms retry` with `attempt` (the number of
the call that failed: 1 for the first), `error_kind`, `backend`, `op`, `retry_after_ms`,
`retry_hint_ms` and `delay_ms`. Its `attempt` counts operation calls, and each retried call is a
new request span; the request span's `attempt` counts only the 403 token-refresh resend within
one call.

Warn events are logged for every fallback to `Backend` (an unclassified server error, with the
server message redacted to its length and a hash fingerprint; an undecodable or oversized
response, never with its body) and for fail-closed warnings; the 403 retry is logged too.

### Metrics

`ObserveLayer::new(|e: &OpEvent| ...)` is a layer that calls back after every operation with its
part, operation, outcome (`e.outcome()`: `ok`, the error kind, or `cancelled` for a call dropped
before it finished; the error itself), latency, backend and key (`e.resource()`, the
same non-secret string errors carry), and never any data: feed it to any metrics library (request
counts, error rates, latency histograms per operation or per key). Put it on
the registry **before** the retry layer to see every attempt (backend latency, throttling rate),
or after it to see what callers see, retries included; both together give the retry
amplification:

```rust
let registry = anykms::with_default_providers()?
    .layer(ObserveLayer::new(record_attempt))   // every backend request
    .layer(anykms::retry_layer())
    .layer(ObserveLayer::new(record_call))      // every call, retries included
    .build()?;
```

Calls through the typed handle behind an opaque handle (`downcast_ref`) bypass every layer, this
one and retries included; wrap such calls yourself (`observe.wrap(key)`, `retry.wrap(key)`) where
they matter.
