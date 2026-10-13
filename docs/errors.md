# Errors

One `Error` type with one taxonomy (`ErrorKind`) for every backend. `Display` names the backend,
the operation, the resource (for transit, the key) and the kind:

```text
transit encrypt [hashivault://default/transit/keys/app-kek]: not_found: key not found (http 404)
app: invalid_argument: tenant id is not a number
```

Every error is in exactly one class, so handling and alerting can work on classes:
`is_retryable()` (transient; the retry layer handles it), `is_config_error()` (an operator must fix
the key, policy, credentials or configuration, or look at the backend; this includes the
unclassified `Backend` kind and `Unauthenticated`, the service's own KMS credentials) and `is_caller_error()` (this request's input is at fault). A corrupt stored
ciphertext fails like a tampered one (`DecryptFailed`), also when it is not even valid base64.
The class follows the kind alone, whatever the operation. A key version the handle chose itself
(its URI pin, or the current or primary version) that cannot be used is `KeyStateInvalid`, a
config error, for every operation. A version taken from the input is `KeyVersionUnusable` or
`UnknownKeyVersion`, a caller error: the data was made with a key version below the key's minimum
(or a disabled or destroyed version), so that one row needs attention, not the key.

```rust
use anykms::ErrorKind;

for (id, ct) in rows {
    match kek.decrypt(&ct, id.as_bytes()).await {
        Ok(pt) => process(&pt),
        Err(e) if e.kind() == ErrorKind::KeyVersionUnusable => report_stale_row(id, &e),
        Err(e) if e.is_caller_error() => report_bad_row(id, &e), // tampered, wrong AAD, ...
        Err(e) => return Err(e), // config errors: alert; retryable ones were already retried
    }
}
```

Application code reports its own failures through the same type with `Error::app(kind, msg)` or
the shorthands `Error::invalid_argument(msg)`, `Error::unsupported(msg)` and
`Error::key_mismatch(msg)`; backends and recipes use `Error::new(kind, backend, operation, msg)`
and `with_resource`. Errors never contain plaintext, AAD, tokens, data keys, request bodies or
query strings; unknown server messages are reduced to a fingerprint. The
[runbook](operations.md#runbook-errorkind--cause--action) maps each kind to a cause and an
action.

As HTTP responses, after the retry layer, `Error::class()` checks four cases in this order and
returns the first as an `ErrorClass`: `Caller` (`is_caller_error()`, even with a retry hint, as
the input may be forged) is 400, or 401 when verifying the caller's token (a `CachedVerifier`
rejection right after a rotation included); `Hinted` (a `retry_hint()` on a kind that is not
retryable, e.g. replica lag on a key just created) is 503 with `Retry-After`; `Retryable`
(`is_retryable()`) is 503 with `Retry-After` from `retry_after()` when set; `Config` is 500
(`NotFound` means a configured key is missing, not 404). 400 is for input that came from the
request: a caller-class error on the application's own stored ciphertext (a tampered, swapped
or stale row) is a data-integrity failure, a 500 that should alert. One `match` maps them:

```rust
use anykms::ErrorClass;

let (status, retry_after) = match e.class() {
    ErrorClass::Caller if !input_from_request => (500, None), // stored data: integrity, alert
    ErrorClass::Caller if verifying_token => (401, None),
    ErrorClass::Caller => (400, None),
    ErrorClass::Hinted(d) => (503, Some(d)),
    ErrorClass::Retryable(d) => (503, d),
    _ => (500, None), // Config, and classes added later
};
```

Details in [operations](operations.md#errors-as-http-responses).
