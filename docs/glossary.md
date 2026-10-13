# Glossary

The terms the anykms READMEs, crate docs and operator guides use, one name per concept. Type
names link to their rustdoc on docs.rs.

## Key-management terms

### AAD (additional authenticated data)

Context bound to a ciphertext without being encrypted, such as `users/42/ssn`: decrypting with
other AAD fails with `DecryptFailed`. An empty AAD is the same as no AAD on every backend. AAD
must not be secret: some backends log it (AWS records it in CloudTrail as the encryption
context).

### Backend

One key-management service as anykms supports it (Vault and OpenBao transit, AWS KMS, Google
Cloud KMS, Azure Key Vault and Managed HSM, and the in-process `local` keys for tests), and the
crate that implements it (`anykms-transit`, `anykms-aws`, ...). Each backend has a
[provider](#provider), and its name (`transit`, `aws`, ...) appears in every error it
returns.

### Data key (DEK, data-encryption key)

A fresh symmetric key that encrypts data locally, in the application. It is stored only in
wrapped form, next to the data it encrypts. A KMS can generate it
([`DataKeys::generate_data_key`], which returns both forms as a [`DataKey`]), or the application
generates it and has the KMS wrap it (`EmulatedDataKeys`, `KeyWrapDataKeys`, `EnvelopeAead`).
The API says *data key*; *DEK* appears in prose about envelopes.

### Envelope encryption, envelope

Encrypting data under a data key and storing that data key wrapped under a KEK, so bulk data
never travels to the KMS. An *envelope* is the byte string `EnvelopeAead` produces: a header,
the wrapped data key and the encrypted payload (see
[envelope-format.md](envelope-format.md)).

### KEK (key-wrapping key)

A key whose only job is to wrap data keys. In anykms that is anything implementing
[`KeyWrap`]: open one with `registry.key_wrap(uri)` (a [`KeyWrapKey`]), or adapt an AEAD key
explicitly with `into_key_wrap()`, which wraps by encrypting with empty AAD. Other libraries
call it a *key-encryption key*; anykms always says *key-wrapping key*, after the trait.

### Key

A named key in the KMS (a transit key, an AWS KMS key, a Cloud KMS `CryptoKey`, a Key Vault key),
addressed by a [key URI](#key-uri). Its type decides which operations it supports, and it
may have several versions.

### Key version

One generation of a key's material. Rotating a key adds a version; older versions keep
decrypting and verifying until they are disabled. A [`KeyVersion`] is an opaque string whose
shape differs per backend (numbers on transit and GCP, version ids on Azure, the key ARN for
AWS signing and MAC keys; AWS symmetric keys expose none).

### Key wrap, wrapped key

Encrypting key material under a KEK ([`KeyWrap::wrap_key`]); the result is the *wrapped key*,
stored next to the data. Unwrapping it ([`KeyWrap::unwrap_key`]) needs the KEK, so it needs the
KMS and the permission to use the key.

### KMS (key-management service)

A service that holds keys and performs operations with them, so the key material never leaves
it. anykms covers the data plane (encrypt, decrypt, rewrap, data keys, sign and verify, MAC,
public keys, describe), not creating keys or managing their policies.

### Primary version

The version a key uses for new ciphertexts (and, on backends that have one, new signatures):
transit's latest version, Cloud KMS's primary version of a symmetric key, Azure's current
version. Cloud KMS asymmetric and MAC keys have no primary version, so their key URIs name a
version. [`KeyInfo::primary_version`] reports it.

### Rewrap

Re-encrypting a ciphertext or wrapped key under the key's primary version without the
plaintext reaching the caller ([`Rewrap`]), server-side where the backend can.

## anykms terms

### Capability trait

One of the async traits a handle implements, one per kind of operation: [`Aead`],
[`Rewrap`], [`DataKeys`], [`WrappedDataKeys`], [`KeyWrap`], [`DigestSigner`],
[`MessageSigner`], [`DigestVerifier`], [`MessageVerifier`], [`Mac`], [`PublicKeys`],
[`Describe`], [`Preflight`]. A handle implements exactly the traits its key supports. They are
not object-safe; the `Dyn*` mirrors and the opaque handles are the trait-object path.

### Handle (key handle)

The in-process value an application calls operations on, for one key opened for one purpose
(AEAD, key wrapping, signing with one algorithm, ...). Opening a handle does no I/O;
`preflight()` checks the key at startup. A handle is either a [typed handle](#typed-handle) or
an [opaque handle](#opaque-handle).

### Key semantics

What a handle declares about the points where backends legitimately differ (version model,
input limits, data-key AAD, where verification runs): [`KeySemantics`], read through
[`Semantics`] without I/O.

### Key URI

A string that names a key and, by its scheme, its backend: `hashivault:///transit/keys/app-kek`,
`aws-kms://arn:aws:kms:...`, `local://default/kek` ([`KeyUri`]). The scheme selects the
provider, which parses the rest with its own grammar. Key URIs come from configuration, so a
malformed one is a `Configuration` error with operation `ParseUri`.

### Layer

A decorator applied to every part of a handle without changing the handle's type: retries
([`RetryLayer`]), metrics ([`ObserveLayer`]), or your own ([`Layer`], or [`Around`] to only
see operations). Add one to a registry (`RegistryBuilder::layer`, for every handle it opens) or
to one handle (`handle.layer(&layer)`). Calls through the typed handle behind an opaque handle
(`downcast_ref`) bypass every layer.

### Opaque handle

A backend-independent handle type from `anykms-core`: [`AeadKey`], [`KeyWrapKey`],
[`DataKeysKey`], [`DigestSignerKey`], [`MessageSignerKey`], [`DigestVerifierKey`],
[`MessageVerifierKey`], [`MacKey`], [`PublicKeysKey`], [`DescribeKey`]. Providers and the
registry return them, so they are also what config-driven code holds (sometimes called a
*registry handle*). An opaque handle is made of parts and implements the capability trait of
each part it can hold (a missing optional part fails with `Unsupported` before any I/O); it
reaches its typed handle, when the provider recorded one, with `downcast_ref`.

### Part

One capability slot of an opaque handle ([`Part`]): its main capability (the AEAD of an
[`AeadKey`]) plus optional ones (rewrap, data keys, describe, public keys, preflight, and the
extension slot for backend-specific operations). Calling a missing optional part fails with
`Unsupported` before any I/O. Layers decorate parts.

### Provider

A backend's entry point ([`Provider`]; `TransitProvider`, `AwsProvider`, `GcpProvider`,
`AzureProvider`, `LocalProvider`): it holds the configuration, credentials and HTTP client, and
opens the key URIs of its schemes as handles. Its inherent methods (`aead_key(uri)`, ...)
return typed handles; the [`Provider`] trait methods return opaque handles.

### Recipe

A portable construction in `anykms-recipes`, written against the capability traits, that adds
what backends do not do natively: envelope encryption (`EnvelopeAead`, `EnvelopeKeyring`),
emulated data keys, local signature verification, JOSE. Each recipe documents what the KMS
enforces and what runs in the application.

### Registry

Routes key URIs to providers by scheme and applies its layers to every handle it opens
([`Registry`]). `anykms::with_default_providers()` builds one with every provider configurable
from the environment.

### Typed handle

A backend's own handle type (`TransitAeadKey`, `AwsMacKey`, `LocalAeadKey`, ...), returned by
the provider's inherent methods (`transit.aead_key(uri)`). It implements exactly the capability
traits its key supports, so with a backend known at compile time a missing capability is a
compile error, and it has the backend-specific operations as inherent methods. Some API docs
call it the *concrete key* behind an opaque handle.

[`Aead`]: https://docs.rs/anykms-core/latest/anykms_core/trait.Aead.html
[`AeadKey`]: https://docs.rs/anykms-core/latest/anykms_core/struct.AeadKey.html
[`Around`]: https://docs.rs/anykms-core/latest/anykms_core/trait.Around.html
[`DataKey`]: https://docs.rs/anykms-core/latest/anykms_core/struct.DataKey.html
[`DataKeys`]: https://docs.rs/anykms-core/latest/anykms_core/trait.DataKeys.html
[`DataKeys::generate_data_key`]: https://docs.rs/anykms-core/latest/anykms_core/trait.DataKeys.html#tymethod.generate_data_key
[`DataKeysKey`]: https://docs.rs/anykms-core/latest/anykms_core/struct.DataKeysKey.html
[`Describe`]: https://docs.rs/anykms-core/latest/anykms_core/trait.Describe.html
[`DescribeKey`]: https://docs.rs/anykms-core/latest/anykms_core/struct.DescribeKey.html
[`DigestSigner`]: https://docs.rs/anykms-core/latest/anykms_core/trait.DigestSigner.html
[`DigestSignerKey`]: https://docs.rs/anykms-core/latest/anykms_core/struct.DigestSignerKey.html
[`DigestVerifier`]: https://docs.rs/anykms-core/latest/anykms_core/trait.DigestVerifier.html
[`DigestVerifierKey`]: https://docs.rs/anykms-core/latest/anykms_core/struct.DigestVerifierKey.html
[`KeyInfo::primary_version`]: https://docs.rs/anykms-core/latest/anykms_core/struct.KeyInfo.html#method.primary_version
[`KeySemantics`]: https://docs.rs/anykms-core/latest/anykms_core/struct.KeySemantics.html
[`KeyUri`]: https://docs.rs/anykms-core/latest/anykms_core/struct.KeyUri.html
[`KeyVersion`]: https://docs.rs/anykms-core/latest/anykms_core/struct.KeyVersion.html
[`KeyWrap`]: https://docs.rs/anykms-core/latest/anykms_core/trait.KeyWrap.html
[`KeyWrap::wrap_key`]: https://docs.rs/anykms-core/latest/anykms_core/trait.KeyWrap.html#tymethod.wrap_key
[`KeyWrap::unwrap_key`]: https://docs.rs/anykms-core/latest/anykms_core/trait.KeyWrap.html#tymethod.unwrap_key
[`KeyWrapKey`]: https://docs.rs/anykms-core/latest/anykms_core/struct.KeyWrapKey.html
[`Layer`]: https://docs.rs/anykms-core/latest/anykms_core/trait.Layer.html
[`Mac`]: https://docs.rs/anykms-core/latest/anykms_core/trait.Mac.html
[`MacKey`]: https://docs.rs/anykms-core/latest/anykms_core/struct.MacKey.html
[`MessageSigner`]: https://docs.rs/anykms-core/latest/anykms_core/trait.MessageSigner.html
[`MessageSignerKey`]: https://docs.rs/anykms-core/latest/anykms_core/struct.MessageSignerKey.html
[`MessageVerifier`]: https://docs.rs/anykms-core/latest/anykms_core/trait.MessageVerifier.html
[`MessageVerifierKey`]: https://docs.rs/anykms-core/latest/anykms_core/struct.MessageVerifierKey.html
[`ObserveLayer`]: https://docs.rs/anykms-core/latest/anykms_core/struct.ObserveLayer.html
[`Part`]: https://docs.rs/anykms-core/latest/anykms_core/enum.Part.html
[`Preflight`]: https://docs.rs/anykms-core/latest/anykms_core/trait.Preflight.html
[`Provider`]: https://docs.rs/anykms-core/latest/anykms_core/trait.Provider.html
[`PublicKeys`]: https://docs.rs/anykms-core/latest/anykms_core/trait.PublicKeys.html
[`PublicKeysKey`]: https://docs.rs/anykms-core/latest/anykms_core/struct.PublicKeysKey.html
[`Registry`]: https://docs.rs/anykms-core/latest/anykms_core/struct.Registry.html
[`RetryLayer`]: https://docs.rs/anykms-core/latest/anykms_core/struct.RetryLayer.html
[`Rewrap`]: https://docs.rs/anykms-core/latest/anykms_core/trait.Rewrap.html
[`Semantics`]: https://docs.rs/anykms-core/latest/anykms_core/trait.Semantics.html
[`WrappedDataKeys`]: https://docs.rs/anykms-core/latest/anykms_core/trait.WrappedDataKeys.html
