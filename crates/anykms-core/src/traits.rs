//! Capability traits. A key handle implements exactly the traits its key supports.
//!
//! Every trait requires `Send + Sync` and produces `Send` futures, so a generic key (`K: Aead`,
//! `Arc<K>`) can be shared across tasks and threads without further bounds. The traits use
//! `async fn`, so they are not object-safe: `dyn Aead` does not compile (E0038). For trait
//! objects, every trait has an object-safe mirror (`Arc<dyn DynAead>`, ...), and providers return
//! opaque handles ([`AeadKey`](crate::AeadKey), ...) that implement the static traits again; see
//! the `Dyn*` traits at the crate root.

use std::future::Future;

use zeroize::Zeroizing;

use crate::around::{Call, CallOutput};
use crate::error::{Error, ErrorKind, Operation, Result};
use crate::types::{
    Ciphertext, DataKey, DataKeySpec, Decrypted, Digest, KeyInfo, KeyVersion, MacAlgorithm,
    PublicKey, Signature, SignatureAlgorithm, Tag,
};

/// Authenticated encryption with associated data.
///
/// An empty `aad` is equivalent to "no AAD" on every backend.
///
/// The KMS encrypts the whole plaintext, so backend request limits apply: Vault transit fails
/// at about 2 MB, OpenBao at its `max_request_size` (32 MiB by default), and cloud KMSs have far
/// smaller limits (AWS KMS 4 KiB, GCP Cloud KMS 64 KiB). Encrypt bulk data with `EnvelopeAead`
/// from `anykms-recipes`, which sends only a data key to the KMS. Backends may also log or
/// expose the AAD (AWS records its encryption context in CloudTrail), so AAD must not be secret.
///
/// # Errors
///
/// Besides the kinds every operation uses (see [`Provider`](crate::Provider#errors)):
///
/// - [`encrypt`](Self::encrypt): a plaintext over the handle's limit
///   ([`KeySemantics::max_plaintext`](crate::KeySemantics::max_plaintext)) is `InvalidArgument`,
///   before any request (`aead::oversize_plaintext`).
/// - [`decrypt`](Self::decrypt): every authentication failure (wrong or missing AAD, another
///   key's ciphertext, a tampered, truncated or unparsable ciphertext) is the same
///   `DecryptFailed`, never `InvalidArgument` or `Backend` (`aead::authentication_failures`). A
///   ciphertext on a version that is disabled, destroyed or below the minimum decryption version
///   is `KeyVersionUnusable` (`aead::disabled_version`, `aead::min_decryption_version`).
/// - [`ciphertext_version`](Self::ciphertext_version): a ciphertext that does not parse is
///   `InvalidArgument`, labelled `Decrypt`.
///
/// # Trait objects
///
/// `dyn Aead` is not object-safe (E0038: the methods are `async fn`). Use `Arc<dyn DynAead>`
/// (see [`DynAead`](crate::DynAead)) or the opaque [`AeadKey`](crate::AeadKey) a
/// [`Registry`](crate::Registry) returns; both implement `Aead` again. The same holds for every
/// capability trait (`DynMac`/[`MacKey`](crate::MacKey), ...).
#[trait_variant::make(Send)]
pub trait Aead: Send + Sync {
    /// Encrypts `plaintext`, binding it to `aad`.
    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext>;

    /// Decrypts `ct`. Any authentication failure is [`ErrorKind::DecryptFailed`](crate::ErrorKind::DecryptFailed).
    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>>;

    /// The key version a ciphertext was produced with, parsed locally without I/O.
    ///
    /// Usable with decrypt-only permissions to find data still on old key versions. Backends whose
    /// ciphertext does not reveal a version return `Ok(None)`.
    fn ciphertext_version(&self, ct: &Ciphertext) -> Result<Option<KeyVersion>> {
        let _ = ct;
        Ok(None)
    }

    /// Decrypts `ct` like [`decrypt`](Self::decrypt) and reports which key version decrypted it
    /// and, where the backend says so, whether that is the primary version (data on an older
    /// version is due for a rewrap).
    ///
    /// The default implementation takes the version from
    /// [`ciphertext_version`](Self::ciphertext_version) (ignoring a parse failure: the decrypt
    /// result decides) and leaves `used_primary` unknown; backends that learn more from the
    /// server override it.
    fn decrypt_with_info(
        &self,
        ct: &Ciphertext,
        aad: &[u8],
    ) -> impl Future<Output = Result<Decrypted>> + Send {
        let version = self.ciphertext_version(ct).ok().flatten();
        let decrypt = self.decrypt(ct, aad);
        async move { Ok(Decrypted::new(decrypt.await?).with_version(version)) }
    }

    /// Decrypts `ct` and checks that the plaintext is UTF-8, without an unzeroized copy: the
    /// decrypted buffer becomes the string, and is wiped if it is not UTF-8. A plaintext that is
    /// not UTF-8 is `InvalidArgument` (operation `Decrypt`).
    ///
    /// Built on [`decrypt`](Self::decrypt); there is no reason to override it.
    fn decrypt_utf8(
        &self,
        ct: &Ciphertext,
        aad: &[u8],
    ) -> impl Future<Output = Result<Zeroizing<String>>> + Send {
        let decrypt = self.decrypt(ct, aad);
        async move { plaintext_to_utf8(decrypt.await?) }
    }

    /// Uses this key as a [`KeyWrap`] (e.g. an envelope KEK) that wraps with empty AAD; see
    /// [`AeadKeyWrap`]. Lend a key with `(&key).into_key_wrap()`.
    fn into_key_wrap(self) -> AeadKeyWrap<Self>
    where
        Self: Sized,
    {
        AeadKeyWrap::new(self)
    }
}

/// Moves a zeroizing plaintext buffer into a zeroizing string; on invalid UTF-8 the bytes are
/// wiped before the error is returned.
fn plaintext_to_utf8(mut pt: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>> {
    match String::from_utf8(std::mem::take(&mut *pt)) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            drop(Zeroizing::new(e.into_bytes()));
            Err(Error::new(
                ErrorKind::InvalidArgument,
                "core",
                Operation::Decrypt,
                "plaintext is not valid UTF-8",
            ))
        }
    }
}

/// Re-encrypt a ciphertext under the key's current version without exposing the plaintext to the
/// caller.
///
/// Not object-safe; use `Arc<dyn DynRewrap>` (see [`DynRewrap`](crate::DynRewrap)) or
/// [`AeadKey`](crate::AeadKey) for trait objects.
#[trait_variant::make(Send)]
pub trait Rewrap: Send + Sync {
    /// Rewraps `ct` (which was encrypted with `aad`).
    ///
    /// A key can support rewrap without supporting it for every ciphertext: backends whose
    /// server would ignore the AAD on rewrap return `Unsupported` for non-empty `aad` before any
    /// I/O. Vault and OpenBao transit do (they ignore `associated_data` on rewrap), so on transit
    /// only ciphertexts encrypted with empty AAD (such as envelope-wrapped data keys) can be
    /// rewrapped; `supports_rewrap()` on an opaque handle is still `true`. Re-encrypt
    /// AAD-bound ciphertexts with `decrypt` then `encrypt` instead.
    async fn rewrap(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext>;
}

/// Backend-generated data keys.
///
/// # Errors
///
/// A data key the backend cannot bind to a non-empty `aad` is `Unsupported`, never generated
/// unbound: before any request where the backend is known not to bind AAD, otherwise after the
/// call, discarding the key. The handle's
/// [`KeySemantics::data_keys`](crate::KeySemantics::data_keys) declares which
/// (`datakeys::aad`).
///
/// Not object-safe; use `Arc<dyn DynDataKeys>` (see [`DynDataKeys`](crate::DynDataKeys)) or
/// [`AeadKey`](crate::AeadKey) for trait objects.
#[trait_variant::make(Send)]
pub trait DataKeys: Send + Sync {
    /// Generates a data key whose wrapped form is bound to `aad`. Backends known not to bind AAD
    /// return `Unsupported` for non-empty `aad` before any I/O; servers that only reveal it in
    /// their response (e.g. OpenBao < 2.5 warning about an ignored parameter) fail closed with
    /// `Unsupported` after the call, and the generated key is discarded.
    async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey>;
}

/// Backend-generated data keys returned **only wrapped**: the plaintext key never reaches the
/// caller (AWS KMS `GenerateDataKeyWithoutPlaintext`, transit `datakey/wrapped`).
///
/// For a writer that prepares keys for others to unwrap later: it can hold this permission
/// without the one to see plaintext keys (a separate IAM action on AWS, a separate policy path
/// on transit), which is why it is a trait of its own rather than an option of [`DataKeys`].
/// Unwrap the result with [`Aead::decrypt`] on the same key and the same `aad`.
///
/// On an [`AeadKey`](crate::AeadKey) it is an optional part, not set by `full` (whose bounds
/// are frozen at the original part set); set it with `with_wrapped_data_keys`
/// ([`supports_wrapped_data_keys`](crate::AeadKey::supports_wrapped_data_keys)).
///
/// Not object-safe; use `Arc<dyn DynWrappedDataKeys>` (see
/// [`DynWrappedDataKeys`](crate::DynWrappedDataKeys)) or [`AeadKey`](crate::AeadKey) for trait
/// objects.
#[trait_variant::make(Send)]
pub trait WrappedDataKeys: Send + Sync {
    /// Generates a data key and returns it only in wrapped form (the ciphertext
    /// [`DataKeys::generate_data_key`] would return), bound to `aad`. AAD is handled as by
    /// [`DataKeys`]: backends known not to bind it return `Unsupported` for non-empty `aad`
    /// before any I/O, and servers that only reveal it in their response fail closed.
    async fn generate_wrapped_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<Ciphertext>;
}

/// Checks now that the key behind a handle exists, can do what the handle was opened for and is
/// usable, and returns what it read (with the backend's own metadata attached, see
/// [`KeyInfo::backend_info`]).
///
/// Opening a handle does no I/O; call this at startup for config-driven keys to fail fast. A
/// backend implements it with its own key-type check (the one it otherwise runs before the first
/// operation); opaque handles without this part fall back to a generic check over
/// [`Describe`] (see [`AeadKey::preflight`](crate::AeadKey::preflight)). Every opaque handle
/// implements it by forwarding to its inherent `preflight`, which runs the backend's part (if
/// any) and then the same capability and state checks over the returned [`KeyInfo`].
///
/// # Contract for implementations
///
/// Typed handles are called directly, without the opaque handle's post-check, so an
/// implementation must itself:
///
/// - refuse a key, or the version it would write with, that is disabled, destroyed or scheduled
///   for deletion with `KeyStateInvalid`;
/// - refuse a key that cannot do the handle's operation with `KeyMismatch`, even under
///   [`KeyTypeCheck::TrustCaller`](crate::KeyTypeCheck::TrustCaller) (which only skips the check
///   before ordinary operations);
/// - label its own refusals [`Operation::Describe`](crate::Operation::Describe).
///
/// Not object-safe; use `Arc<dyn DynPreflight>` (see [`DynPreflight`](crate::DynPreflight)).
///
/// The prelude brings the trait into scope:
///
/// ```
/// use anykms_core::prelude::*;
///
/// // Checks every configured key at startup, whatever its handle type.
/// async fn startup<K: Preflight>(keys: &[K]) -> anykms_core::Result<()> {
///     for k in keys {
///         k.preflight().await?;
///     }
///     Ok(())
/// }
/// # let _ = startup::<anykms_core::AeadKey>;
/// ```
#[trait_variant::make(Send)]
pub trait Preflight: Send + Sync {
    /// Runs the check and returns the key's metadata.
    async fn preflight(&self) -> Result<KeyInfo>;
}

/// The layered slot for backend-specific operations (e.g. AWS encryption with a native
/// encryption-context map), present on every opaque handle.
///
/// Backends do not implement this trait: they reach their own operations through
/// [`AeadKey::call_extension`](crate::AeadKey::call_extension) (and the same method of every
/// opaque handle), which runs the call through this slot, so the handle's layers apply to it
/// like to any other part ([`Part::Extension`](crate::Part::Extension)). Layers implement it on
/// their decorators: forward the call (once, or again per retry attempt) with [`Call::run`] or to
/// the inner slot, and use [`Call::operation`] and [`Call::name`] for labels. A layer that only
/// needs to see operations implements [`Around`](crate::Around) instead.
///
/// Not object-safe; use `Arc<dyn DynExtensionCalls>` (see
/// [`DynExtensionCalls`](crate::DynExtensionCalls)).
#[trait_variant::make(Send)]
pub trait ExtensionCalls: Send + Sync {
    /// Runs `call`, decorated as the implementor sees fit.
    async fn run_extension(&self, call: Call<'_>) -> Result<CallOutput>;
}

/// Signs digests (ECDSA, RSA).
///
/// # Errors
///
/// A digest of another hash than the [`signature_algorithm`](Self::signature_algorithm)'s is
/// `InvalidArgument`, checked locally before any request (servers do not check it). A key of
/// another type than the algorithm's is `KeyMismatch`, also where the server would sign anyway
/// (`sign::*::input_validation`, `sign::*::key_type_mismatch`).
///
/// Not object-safe; use `Arc<dyn DynDigestSigner>` (see [`DynDigestSigner`](crate::DynDigestSigner)) or
/// [`DigestSignerKey`](crate::DigestSignerKey) for trait objects.
#[trait_variant::make(Send)]
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a digest signer (`DigestSigner`)",
    note = "ECDSA and RSA keys sign digests (`registry.digest_signer(uri, alg)`); Ed25519 keys are `MessageSigner`s: use the `*_message` variant of the function"
)]
pub trait DigestSigner: Send + Sync {
    /// The algorithm every signature from this signer uses.
    fn signature_algorithm(&self) -> SignatureAlgorithm;

    /// Signs a digest. The digest's hash must match [`SignatureAlgorithm::hash`].
    async fn sign_digest(&self, digest: &Digest) -> Result<Signature>;
}

/// Signs messages (pure Ed25519).
///
/// The KMS receives the whole message, so backend request limits apply and differ widely: AWS
/// KMS caps `Sign` with `MessageType=RAW` at 4096 bytes, while transit accepts megabytes. Code
/// meant to be portable must not assume transit's limits: keep messages small, or sign a digest
/// (`sign_message_hashed` in `anykms-recipes`, with an ECDSA or RSA [`DigestSigner`]).
///
/// # Errors
///
/// A message over the handle's limit
/// ([`KeySemantics::max_signed_message`](crate::KeySemantics::max_signed_message)) is
/// `InvalidArgument`, before any request (`sign::*::input_limit`).
///
/// Not object-safe; use `Arc<dyn DynMessageSigner>` (see [`DynMessageSigner`](crate::DynMessageSigner)) or
/// [`MessageSignerKey`](crate::MessageSignerKey) for trait objects.
#[trait_variant::make(Send)]
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a message signer (`MessageSigner`)",
    note = "Ed25519 keys sign messages (`registry.message_signer(uri, alg)`); ECDSA and RSA keys are `DigestSigner`s: use the variant of the function without `_message`"
)]
pub trait MessageSigner: Send + Sync {
    /// The algorithm every signature from this signer uses.
    fn signature_algorithm(&self) -> SignatureAlgorithm;

    /// Signs a message.
    async fn sign_message(&self, msg: &[u8]) -> Result<Signature>;
}

/// Verifies digest signatures.
///
/// # Errors
///
/// A signature that does not verify is `VerificationFailed`, and so is one an attacker could have
/// shaped: malformed signature bytes, or a signature naming a key version this key does not
/// have or another key's version (`sign::*::tampered`, `sign::*::malformed`,
/// `sign::*::foreign_versions`). The caller passing the wrong kind of input is
/// `InvalidArgument`: a digest of another hash than the algorithm's, a signature labelled with
/// another algorithm, a malformed key version, or a signature naming no version where the handle
/// needs one ([`UnversionedVerify::Rejected`](crate::UnversionedVerify::Rejected))
/// (`sign::*::input_validation`).
///
/// Not object-safe; use `Arc<dyn DynDigestVerifier>` (see [`DynDigestVerifier`](crate::DynDigestVerifier)) or
/// [`DigestVerifierKey`](crate::DigestVerifierKey) for trait objects.
#[trait_variant::make(Send)]
pub trait DigestVerifier: Send + Sync {
    /// Verifies `sig` over `digest`.
    async fn verify_digest(&self, digest: &Digest, sig: &Signature) -> Result<()>;
}

/// Verifies message signatures.
///
/// # Errors
///
/// As for [`DigestVerifier`]: a signature that does not verify (malformed bytes, a key version
/// this key does not have or another key's version included) is `VerificationFailed`; a
/// malformed key version, or a signature naming no version where the handle needs one, is
/// `InvalidArgument`.
///
/// Not object-safe; use `Arc<dyn DynMessageVerifier>` (see [`DynMessageVerifier`](crate::DynMessageVerifier)) or
/// [`MessageVerifierKey`](crate::MessageVerifierKey) for trait objects.
#[trait_variant::make(Send)]
pub trait MessageVerifier: Send + Sync {
    /// Verifies `sig` over `msg`.
    async fn verify_message(&self, msg: &[u8], sig: &Signature) -> Result<()>;
}

/// A verifier bound to one signature algorithm, which it alone decides: the algorithm
/// `verify_message_hashed` (in `anykms-recipes`) hashes with and requires of every
/// signature, so an (untrusted) signature never picks it.
///
/// Implemented explicitly, never by a blanket impl, so wrappers can forward it:
///
/// - `LocalVerifier` and `CachedVerifier` (the algorithm given at construction);
/// - [`DigestSignerKey`](crate::DigestSignerKey) and
///   [`MessageSignerKey`](crate::MessageSignerKey), and the backends' typed signer handles (the
///   algorithm the handle was opened for), so a handle with a verifier part verifies its own
///   signatures;
/// - `&T`, `Arc<T>` and `Box<T>` when `T` is pinned.
///
/// A verifier with no algorithm of its own (a [`DigestVerifierKey`](crate::DigestVerifierKey),
/// an `Arc<dyn DynDigestVerifier>`) names the algorithm with the `_as` variants of those
/// functions instead. Implement it for a custom signer or verifier by returning its algorithm.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not bound to one signature algorithm (`PinnedVerifier`)",
    note = "use the `_as` variant of the function and name the expected algorithm, or implement `PinnedVerifier` for the type"
)]
pub trait PinnedVerifier {
    /// The only signature algorithm this verifier accepts.
    fn pinned_algorithm(&self) -> SignatureAlgorithm;
}

impl<T: PinnedVerifier + ?Sized> PinnedVerifier for &T {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        (**self).pinned_algorithm()
    }
}

impl<T: PinnedVerifier + ?Sized> PinnedVerifier for std::sync::Arc<T> {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        (**self).pinned_algorithm()
    }
}

impl<T: PinnedVerifier + ?Sized> PinnedVerifier for Box<T> {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        (**self).pinned_algorithm()
    }
}

/// Message authentication codes.
///
/// The KMS receives the whole input, so backend request limits apply and differ widely: AWS
/// KMS caps `GenerateMac` and `VerifyMac` at 4096 bytes, while transit accepts megabytes. Code
/// meant to be portable must not assume transit's limits: MAC short values (tokens, IDs), or
/// hash a large input locally and MAC the hash.
///
/// # Errors
///
/// [`mac`](Self::mac) of an input over the handle's limit
/// ([`KeySemantics::max_mac_input`](crate::KeySemantics::max_mac_input)) is `InvalidArgument`,
/// before any request (`mac::*::input_limit`). See [`verify_mac`](Self::verify_mac) for
/// verification.
///
/// Not object-safe; use `Arc<dyn DynMac>` (see [`DynMac`](crate::DynMac)) or
/// [`MacKey`](crate::MacKey) for trait objects.
#[trait_variant::make(Send)]
pub trait Mac: Send + Sync {
    /// The algorithm every tag from this key uses.
    fn mac_algorithm(&self) -> MacAlgorithm;

    /// Computes a tag over `data`.
    async fn mac(&self, data: &[u8]) -> Result<Tag>;

    /// Verifies a tag, server-side or in constant time.
    ///
    /// # Errors
    ///
    /// A tag that does not match is `VerificationFailed`: tampered data or tag, a truncated tag,
    /// another key's tag, or a tag naming a key version this key does not have or another key's
    /// version. A tag of the wrong kind is `InvalidArgument`, before any request: a tag of
    /// another algorithm than [`mac_algorithm`](Self::mac_algorithm), a malformed key version,
    /// or a tag naming no version where the handle needs one
    /// ([`UnversionedVerify::Rejected`](crate::UnversionedVerify::Rejected)). The conformance
    /// suite checks both (`mac::*::failures`).
    async fn verify_mac(&self, data: &[u8], tag: &Tag) -> Result<()>;
}

/// Public keys of asymmetric keys.
///
/// # Contract
///
/// Verifiers cache public keys (e.g. `anykms-recipes`' `CachedVerifier`) and rely on these rules
/// to stop trusting a key once it is disabled; every built-in backend follows them, and other
/// implementations must too:
///
/// - **A disabled key, or a disabled version the handle chose** (its URI pin, or the current or
///   primary version), is refused with [`KeyStateInvalid`](crate::ErrorKind::KeyStateInvalid),
///   also where the server would serve the public key anyway: the backend checks the state first.
/// - **A version taken from input** (see [`public_key_version`](Self::public_key_version)):
///   disabled or destroyed is [`KeyVersionUnusable`](crate::ErrorKind::KeyVersionUnusable); one
///   this key does not have, or another key's version, is
///   [`UnknownKeyVersion`](crate::ErrorKind::UnknownKeyVersion); a malformed one is
///   [`InvalidArgument`](crate::ErrorKind::InvalidArgument). All three are caller errors.
///
/// Not object-safe; use `Arc<dyn DynPublicKeys>` (see [`DynPublicKeys`](crate::DynPublicKeys)) or
/// [`PublicKeysKey`](crate::PublicKeysKey) for trait objects.
#[trait_variant::make(Send)]
pub trait PublicKeys: Send + Sync {
    /// The public key of the version this handle signs with: the primary (current) version where
    /// the backend has one (e.g. transit), or the pinned version for backends that require
    /// versioned key URIs (e.g. GCP asymmetric keys, which have no primary version).
    ///
    /// A disabled key or version is [`KeyStateInvalid`](crate::ErrorKind::KeyStateInvalid) (see
    /// the [contract](Self#contract)).
    async fn public_key(&self) -> Result<PublicKey>;

    /// The public key of a specific version.
    ///
    /// The version often comes from untrusted input (a JWT `kid`), so it must never select
    /// another key. A version this key does not have, including one that identifies another key
    /// (e.g. another key's ARN where versions are key identifiers), is
    /// [`UnknownKeyVersion`](crate::ErrorKind::UnknownKeyVersion), possibly with a
    /// [retry hint](crate::Error::retry_hint) where the version may not have replicated yet; a
    /// malformed version is [`InvalidArgument`](crate::ErrorKind::InvalidArgument); a disabled
    /// or destroyed version is [`KeyVersionUnusable`](crate::ErrorKind::KeyVersionUnusable), and
    /// a disabled key [`KeyStateInvalid`](crate::ErrorKind::KeyStateInvalid). Backends decide
    /// this from the handle's own key: they never fetch a key or resource named by `version`.
    /// The conformance suite checks it (`sign::*::foreign_versions`).
    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey>;
}

/// Key metadata.
///
/// Not object-safe; use `Arc<dyn DynDescribe>` (see [`DynDescribe`](crate::DynDescribe)) or
/// [`DescribeKey`](crate::DescribeKey) for trait objects.
#[trait_variant::make(Send)]
pub trait Describe: Send + Sync {
    /// Describes the key.
    async fn describe(&self) -> Result<KeyInfo>;
}

/// Wraps and unwraps key material (data keys) under a KMS key: the capability envelope
/// encryption needs from its key-wrapping key.
///
/// Keys with a native wrap operation (RSA-OAEP, AES key wrap) implement `KeyWrap` directly, and
/// providers open them with [`Provider::key_wrap`](crate::Provider::key_wrap) as a
/// [`KeyWrapKey`](crate::KeyWrapKey). An [`Aead`] key is **not** a `KeyWrap` by itself: adapt it
/// explicitly with [`Aead::into_key_wrap`] (or [`AeadKeyWrap::new`]), which wraps by encrypting
/// with **empty AAD**, so `wrap_key(k)` is exactly `encrypt(k, b"")`. The built-in providers open
/// their AEAD keys as a `KeyWrapKey` through this adapter.
///
/// Being a separate trait, `KeyWrap` is decorated on its own: layers see it as a part, `Arc<T>`,
/// `Box<T>` and `&T` forward it, and a key can implement both `Aead` and a native `KeyWrap`.
///
/// # Errors
///
/// As for [`Aead`], labelled [`Operation::WrapKey`] and [`Operation::UnwrapKey`]: every
/// authentication failure of [`unwrap_key`](Self::unwrap_key) is the same `DecryptFailed`, and
/// wrapping to a disabled key is `KeyStateInvalid`, also where wrapping runs locally with the
/// public key once the handle has read the key's state (`keywrap::disabled_key`), so no data key
/// is wrapped that only a disabled key could unwrap.
///
/// Not object-safe; use `Arc<dyn DynKeyWrap>` (see [`DynKeyWrap`](crate::DynKeyWrap)) or
/// [`KeyWrapKey`](crate::KeyWrapKey) for trait objects.
#[trait_variant::make(Send)]
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a key-wrapping key (`KeyWrap`)",
    label = "not a `KeyWrap`",
    note = "open the KEK with `registry.key_wrap(uri)`, or adapt an AEAD key explicitly with `.into_key_wrap()` (wraps with empty AAD)"
)]
pub trait KeyWrap: Send + Sync {
    /// Wraps `key`.
    async fn wrap_key(&self, key: &[u8]) -> Result<Ciphertext>;

    /// Unwraps a key wrapped by [`wrap_key`](KeyWrap::wrap_key). Any authentication failure is
    /// [`ErrorKind::DecryptFailed`](crate::ErrorKind::DecryptFailed).
    async fn unwrap_key(&self, wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>>;

    /// The key version a wrapped key was produced with, parsed locally without I/O, or `Ok(None)`
    /// where the wrapped form does not reveal it (see [`Aead::ciphertext_version`]).
    fn wrapped_key_version(&self, wrapped: &Ciphertext) -> Result<Option<KeyVersion>> {
        let _ = wrapped;
        Ok(None)
    }
}

/// An [`Aead`] key used as a [`KeyWrap`]: wraps by encrypting with **empty AAD** and unwraps by
/// decrypting with empty AAD; [`wrapped_key_version`](KeyWrap::wrapped_key_version) is
/// [`ciphertext_version`](Aead::ciphertext_version). Create it with [`Aead::into_key_wrap`] or
/// [`new`](Self::new).
///
/// It also forwards [`Describe`] and [`Rewrap`] when the inner key has them. `Rewrap` is the
/// server-side rewrap of a wrapped key, always with empty AAD: a non-empty `aad` is
/// `InvalidArgument` before any I/O, so the KEK cannot rewrap the key's ordinary ciphertexts
/// (rewrap those through the AEAD key). A key used this way MUST be dedicated to wrapping:
/// any other code that decrypts with empty AAD under it could unwrap the wrapped keys.
///
/// ```
/// use anykms_core::{Aead, AeadKeyWrap, KeyWrap};
/// fn takes_kek<K: KeyWrap>(_: K) {}
/// fn adapt(k: anykms_core::AeadKey) {
///     takes_kek((&k).into_key_wrap()); // lend the key
///     takes_kek(AeadKeyWrap::new(k));
/// }
/// ```
#[derive(Clone, Debug)]
pub struct AeadKeyWrap<T>(T);

impl<T> AeadKeyWrap<T> {
    /// Adapts `aead`.
    pub fn new(aead: T) -> Self {
        Self(aead)
    }

    /// The AEAD key.
    pub fn inner(&self) -> &T {
        &self.0
    }

    /// Returns the AEAD key.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: Aead> KeyWrap for AeadKeyWrap<T> {
    /// Errors are labeled [`Operation::WrapKey`].
    async fn wrap_key(&self, key: &[u8]) -> Result<Ciphertext> {
        self.0
            .encrypt(key, b"")
            .await
            .map_err(|e| e.with_operation(Operation::WrapKey))
    }

    /// Errors are labeled [`Operation::UnwrapKey`].
    async fn unwrap_key(&self, wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
        self.0
            .decrypt(wrapped, b"")
            .await
            .map_err(|e| e.with_operation(Operation::UnwrapKey))
    }

    fn wrapped_key_version(&self, wrapped: &Ciphertext) -> Result<Option<KeyVersion>> {
        self.0.ciphertext_version(wrapped)
    }
}

impl<T: Rewrap> Rewrap for AeadKeyWrap<T> {
    /// Rewraps a wrapped key with empty AAD; a non-empty `aad` is `InvalidArgument` before any
    /// I/O.
    async fn rewrap(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext> {
        check_kek_rewrap_aad("core", aad)?;
        self.0.rewrap(ct, b"").await
    }
}

/// Refuses a non-empty `aad` for the rewrap of a wrapped key: keys are wrapped with empty AAD, so
/// any other AAD means the caller is rewrapping an ordinary ciphertext through the KEK.
pub(crate) fn check_kek_rewrap_aad(backend: &'static str, aad: &[u8]) -> Result<()> {
    if aad.is_empty() {
        return Ok(());
    }
    Err(Error::new(
        ErrorKind::InvalidArgument,
        backend,
        Operation::Rewrap,
        "a key-wrapping key rewraps wrapped keys, which have empty AAD; aad must be empty",
    ))
}

impl<T: Describe> Describe for AeadKeyWrap<T> {
    async fn describe(&self) -> Result<KeyInfo> {
        self.0.describe().await
    }
}
