//! `local://<keyset>/<name>` URIs and the [`LocalProvider`].

use std::sync::Arc;

use anykms_core::{
    AeadKey, DataKeysKey, DescribeKey, DigestSignerKey, DigestVerifierKey, Error, ErrorKind,
    IntoKeyUri, KeyUri, KeyWrapKey, MacAlgorithm, MacKey, MessageSignerKey, MessageVerifierKey,
    OpenOptions, Operation, Provider, PublicKeysKey, Result, SignatureAlgorithm, SigningShape,
};

use crate::handles::{
    LocalAeadKey, LocalDigestKey, LocalEd25519Key, LocalMacKey, mac_algorithm_supported,
    unsupported_mac,
};
use crate::keyset::{BACKEND, LocalKeyset};

/// The URI scheme of local keys.
pub const SCHEME: &str = "local";

fn segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Parses `local://<keyset>/<name>` into `(keyset, name)`.
///
/// A URI that does not parse is [`Configuration`](ErrorKind::Configuration) with
/// [`Operation::ParseUri`]: key URIs come from configuration.
pub fn parse_local_uri(uri: &KeyUri) -> Result<(&str, &str)> {
    let bad =
        |m: &'static str| Error::new(ErrorKind::Configuration, BACKEND, Operation::ParseUri, m);
    if uri.scheme() != SCHEME {
        return Err(bad("not a local:// URI"));
    }
    let rest = uri
        .rest()
        .strip_prefix("//")
        .ok_or_else(|| bad("expected local://<keyset>/<name>"))?;
    let (keyset, name) = rest
        .split_once('/')
        .ok_or_else(|| bad("expected local://<keyset>/<name>"))?;
    if !segment_ok(keyset) || !segment_ok(name) {
        return Err(bad("invalid keyset or key name segment"));
    }
    Ok((keyset, name))
}

/// Logs the warning every open of an ephemeral key emits (§7).
fn warn_ephemeral(keyset: &str, name: &str) {
    tracing::warn!(
        key = name,
        keyset = keyset,
        "opening an ephemeral local key: key material lives in process memory and is lost on exit"
    );
}

/// Typed accessors. They bypass [`LocalProvider::allow_ephemeral_local_keys`]: that opt-in guards
/// the *registry* path, where a config-supplied `local://` URI could select in-memory keys by
/// accident, while these accessors need the keyset in hand, so they cannot be reached from
/// configuration. Like every open through [`LocalProvider`], each one logs a warning that the key
/// is ephemeral.
///
/// Like a [`LocalProvider`] open, they do not check that the key exists: a missing key fails with
/// `NotFound` on its first operation, where a remote backend fails too. Use
/// [`contains`](LocalKeyset::contains) to check up front.
impl LocalKeyset {
    /// A typed AEAD handle (no URI, no opt-in: the caller holds the keyset explicitly). Logs a
    /// warning.
    pub fn aead_key(&self, name: &str) -> LocalAeadKey {
        warn_ephemeral(self.name(), name);
        LocalAeadKey {
            ks: self.clone(),
            name: name.to_owned(),
        }
    }

    /// A typed ECDSA handle for `alg`. Logs a warning.
    pub fn digest_signing_key(&self, name: &str, alg: SignatureAlgorithm) -> LocalDigestKey {
        warn_ephemeral(self.name(), name);
        LocalDigestKey {
            ks: self.clone(),
            name: name.to_owned(),
            alg,
        }
    }

    /// A typed Ed25519 handle. Logs a warning.
    pub fn ed25519_key(&self, name: &str) -> LocalEd25519Key {
        warn_ephemeral(self.name(), name);
        LocalEd25519Key {
            ks: self.clone(),
            name: name.to_owned(),
        }
    }

    /// A typed HMAC handle for `alg`. Logs a warning. An algorithm local keys do not implement
    /// makes every operation fail with `Unsupported` ([`LocalProvider::mac_key`] refuses it at
    /// open).
    pub fn mac_key(&self, name: &str, alg: MacAlgorithm) -> LocalMacKey {
        warn_ephemeral(self.name(), name);
        LocalMacKey {
            ks: self.clone(),
            name: name.to_owned(),
            alg,
        }
    }
}

/// Opens `local://<keyset>/<name>` keys from one [`LocalKeyset`].
///
/// **Not for production.** Every open fails with `Configuration` unless the provider was created
/// with [`LocalProvider::allow_ephemeral_local_keys`], so Cargo feature unification alone can never
/// route production keys to in-memory keys. Every open logs a warning.
///
/// Opening checks the URI and the keyset name but not whether the key exists: a missing key fails
/// with `NotFound` on its first operation, as on every other backend (opening does no I/O, so
/// transit cannot check at open). Code tested against local keys therefore sees errors where it
/// will see them in production, and a key may be inserted after its handle was opened.
#[derive(Clone, Debug)]
pub struct LocalProvider {
    keyset: LocalKeyset,
    allowed: bool,
}

impl LocalProvider {
    /// Creates a provider. Call [`allow_ephemeral_local_keys`](Self::allow_ephemeral_local_keys) to
    /// enable it.
    pub fn new(keyset: LocalKeyset) -> Self {
        Self {
            keyset,
            allowed: false,
        }
    }

    /// Explicit runtime opt-in: allows opening in-memory keys that vanish when the process exits.
    pub fn allow_ephemeral_local_keys(mut self) -> Self {
        self.allowed = true;
        self
    }

    /// The keyset.
    pub fn keyset(&self) -> &LocalKeyset {
        &self.keyset
    }

    /// The key name `uri` opens. Errors carry the URI without its query string as their resource.
    fn resolve<'u>(&self, uri: &'u KeyUri) -> Result<&'u str> {
        self.resolve_inner(uri)
            .map_err(|e| e.with_resource(uri.without_query()))
    }

    fn resolve_inner<'u>(&self, uri: &'u KeyUri) -> Result<&'u str> {
        if !self.allowed {
            return Err(Error::new(
                ErrorKind::Configuration,
                BACKEND,
                Operation::Open,
                "local:// keys are ephemeral; enable them with LocalProvider::allow_ephemeral_local_keys()",
            ));
        }
        let (keyset, name) = parse_local_uri(uri)?;
        if keyset != self.keyset.name() {
            return Err(Error::new(
                ErrorKind::Configuration,
                BACKEND,
                Operation::Open,
                "unknown local keyset",
            ));
        }
        // The typed keyset accessor every open goes through logs the warning.
        Ok(name)
    }

    /// Opens a typed AEAD handle.
    pub fn aead_key(&self, uri: impl IntoKeyUri) -> Result<LocalAeadKey> {
        let uri = uri.into_key_uri()?;
        Ok(self.keyset.aead_key(self.resolve(&uri)?))
    }

    /// Opens a typed ECDSA handle.
    pub fn digest_signing_key(
        &self,
        uri: impl IntoKeyUri,
        alg: SignatureAlgorithm,
    ) -> Result<LocalDigestKey> {
        let uri = uri.into_key_uri()?;
        if alg.is_message_signing() {
            return Err(Error::new(
                ErrorKind::KeyMismatch,
                BACKEND,
                Operation::Open,
                "message-signing algorithm; use ed25519_key",
            )
            .with_resource(uri.without_query()));
        }
        Ok(self.keyset.digest_signing_key(self.resolve(&uri)?, alg))
    }

    /// Opens a typed Ed25519 handle.
    pub fn ed25519_key(&self, uri: impl IntoKeyUri) -> Result<LocalEd25519Key> {
        let uri = uri.into_key_uri()?;
        Ok(self.keyset.ed25519_key(self.resolve(&uri)?))
    }

    /// Opens a typed HMAC handle. An algorithm local keys do not implement fails with
    /// `Unsupported`.
    pub fn mac_key(&self, uri: impl IntoKeyUri, alg: MacAlgorithm) -> Result<LocalMacKey> {
        let uri = uri.into_key_uri()?;
        let name = self.resolve(&uri)?;
        if !mac_algorithm_supported(alg) {
            return Err(unsupported_mac(Operation::Open).with_resource(uri.without_query()));
        }
        Ok(self.keyset.mac_key(name, alg))
    }
}

impl Provider for LocalProvider {
    fn schemes(&self) -> &[&'static str] {
        &[SCHEME]
    }

    fn name(&self) -> &'static str {
        BACKEND
    }

    fn aead(&self, uri: &KeyUri, _opts: &OpenOptions) -> Result<AeadKey> {
        let k = self.aead_key(uri)?;
        let sem = k.semantics().clone();
        Ok(AeadKey::full(BACKEND, k.clone())
            .with_wrapped_data_keys(Arc::new(k))
            .with_semantics(sem))
    }

    /// An AEAD key as a data-key source (data keys bound to AAD), with describe.
    fn data_keys(&self, uri: &KeyUri, _opts: &OpenOptions) -> Result<DataKeysKey> {
        let k = self.aead_key(uri)?;
        let sem = k.semantics().clone();
        Ok(DataKeysKey::full(BACKEND, k).with_semantics(sem))
    }

    /// An AEAD key as a KEK, wrapping with empty AAD; local rewrap stays available.
    fn key_wrap(&self, uri: &KeyUri, opts: &OpenOptions) -> Result<KeyWrapKey> {
        self.aead(uri, opts).map(KeyWrapKey::from_aead)
    }

    fn digest_signer(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        _opts: &OpenOptions,
    ) -> Result<DigestSignerKey> {
        alg.require_shape(SigningShape::Digest, BACKEND)?;
        let k = self.digest_signing_key(uri, alg)?;
        let sem = k.semantics().clone();
        Ok(DigestSignerKey::full(BACKEND, k).with_semantics(sem))
    }

    fn digest_verifier(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        _opts: &OpenOptions,
    ) -> Result<DigestVerifierKey> {
        alg.require_shape(SigningShape::Digest, BACKEND)?;
        let k = self.digest_signing_key(uri, alg)?;
        let sem = k.semantics().clone();
        Ok(DigestVerifierKey::full(BACKEND, k).with_semantics(sem))
    }

    fn message_signer(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        _opts: &OpenOptions,
    ) -> Result<MessageSignerKey> {
        alg.require_shape(SigningShape::Message, BACKEND)?;
        let k = self.ed25519_key(uri)?;
        let sem = k.semantics().clone();
        Ok(MessageSignerKey::full(BACKEND, k).with_semantics(sem))
    }

    fn message_verifier(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        _opts: &OpenOptions,
    ) -> Result<MessageVerifierKey> {
        alg.require_shape(SigningShape::Message, BACKEND)?;
        let k = self.ed25519_key(uri)?;
        let sem = k.semantics().clone();
        Ok(MessageVerifierKey::full(BACKEND, k).with_semantics(sem))
    }

    fn mac(&self, uri: &KeyUri, alg: MacAlgorithm, _opts: &OpenOptions) -> Result<MacKey> {
        let k = self.mac_key(uri, alg)?;
        let sem = k.semantics().clone();
        Ok(MacKey::full(BACKEND, k).with_semantics(sem))
    }

    fn public_keys(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        _opts: &OpenOptions,
    ) -> Result<PublicKeysKey> {
        if alg.is_message_signing() {
            let k = self.ed25519_key(uri)?;
            let sem = k.semantics().clone();
            Ok(PublicKeysKey::full(BACKEND, k).with_semantics(sem))
        } else {
            let k = self.digest_signing_key(uri, alg)?;
            let sem = k.semantics().clone();
            Ok(PublicKeysKey::full(BACKEND, k).with_semantics(sem))
        }
    }

    /// Describes any key type. `opts` has no effect: describing never runs the key-type check,
    /// and the local backend defines no open-option extensions. The handle declares no
    /// [`KeySemantics`](anykms_core::KeySemantics): the URI does not say the key's family.
    fn describe(&self, uri: &KeyUri, _opts: &OpenOptions) -> Result<DescribeKey> {
        Ok(DescribeKey::new(BACKEND, Arc::new(self.aead_key(uri)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_parsing() {
        let u: KeyUri = "local://default/kek".parse().unwrap();
        assert_eq!(parse_local_uri(&u).unwrap(), ("default", "kek"));
        for bad in [
            "local:default/kek",
            "local://default",
            "local://default/a/b",
            "local://../x",
            "local://d/",
        ] {
            let u: KeyUri = bad.parse().unwrap();
            let e = parse_local_uri(&u).unwrap_err();
            // A3(c): URIs come from configuration.
            assert_eq!(e.kind(), ErrorKind::Configuration, "{bad}");
            assert_eq!(e.operation(), Operation::ParseUri, "{bad}");
        }
    }

    /// Captures formatted log output.
    #[derive(Clone, Default)]
    struct Buf(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn warnings(f: impl FnOnce()) -> usize {
        let buf = Buf::default();
        let w = buf.clone();
        let sub = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .with_writer(move || w.clone())
            .finish();
        tracing::subscriber::with_default(sub, f);
        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        out.matches("opening an ephemeral local key").count()
    }

    #[test]
    fn every_open_warns_once() {
        let ks = LocalKeyset::builder()
            .aead("kek")
            .hmac("tok")
            .ecdsa_p256("sig")
            .ed25519("ed")
            .build();
        // Typed keyset accessors: no opt-in (the caller holds the keyset), but still a warning.
        assert_eq!(warnings(|| drop(ks.aead_key("kek"))), 1);
        assert_eq!(
            warnings(|| drop(ks.mac_key("tok", MacAlgorithm::HmacSha256))),
            1
        );
        assert_eq!(
            warnings(|| drop(ks.digest_signing_key("sig", SignatureAlgorithm::EcdsaP256Sha256))),
            1
        );
        assert_eq!(warnings(|| drop(ks.ed25519_key("ed"))), 1);
        // Provider opens warn exactly once too.
        let p = LocalProvider::new(ks).allow_ephemeral_local_keys();
        let u: KeyUri = "local://default/kek".parse().unwrap();
        assert_eq!(
            warnings(|| drop(p.aead(&u, &OpenOptions::new()).unwrap())),
            1
        );
        assert_eq!(warnings(|| drop(p.aead_key(&u).unwrap())), 1);
    }

    /// R-39: the typed openers name the key (the URI without its query) on every error, and a
    /// kind mismatch names the key's kind and the kind the operation needs.
    #[tokio::test]
    async fn typed_open_errors_name_the_key_and_kinds() {
        use anykms_core::{Aead, Digest, DigestSigner, HashAlgorithm};
        let ks = LocalKeyset::builder().aead("kek").ecdsa_p256("sig").build();
        let e = LocalProvider::new(ks.clone())
            .aead_key("local://default/kek?x=1")
            .unwrap_err();
        assert_eq!(e.resource(), Some("local://default/kek"), "{e}");

        let p = LocalProvider::new(ks).allow_ephemeral_local_keys();
        for (e, resource) in [
            (
                p.aead_key("local://default").unwrap_err(),
                "local://default",
            ),
            (
                p.aead_key("local://other/kek?x=1").unwrap_err(),
                "local://other/kek",
            ),
            (
                p.digest_signing_key("local://default/sig", SignatureAlgorithm::Ed25519)
                    .unwrap_err(),
                "local://default/sig",
            ),
            (
                p.mac_key("local://other/kek?x=1", MacAlgorithm::HmacSha256)
                    .unwrap_err(),
                "local://other/kek",
            ),
        ] {
            assert_eq!(e.resource(), Some(resource), "{e}");
        }

        let e = p
            .aead_key("local://default/sig")
            .unwrap()
            .encrypt(b"x", b"")
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{e}");
        assert_eq!(
            e.message(),
            "key type does not support this operation: the key is ecdsa-p256, the operation \
             needs aes256-gcm"
        );
        let digest = Digest::new(HashAlgorithm::Sha384, &[0; 48]).unwrap();
        let e = p
            .digest_signing_key("local://default/sig", SignatureAlgorithm::EcdsaP384Sha384)
            .unwrap()
            .sign_digest(&digest)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{e}");
        assert_eq!(
            e.message(),
            "key type does not match the asserted signature algorithm: the key is ecdsa-p256, \
             ecdsa-p384-sha384 needs ecdsa-p384"
        );
    }

    /// AEAD handles carry the wrapped-data-keys part: the wrapped key decrypts with its AAD only,
    /// the part is retried by a retry layer, and other key kinds refuse it.
    #[tokio::test]
    async fn aead_handles_generate_wrapped_data_keys() {
        use anykms_core::{
            Aead, DataKeySpec, RetryLayer, RetryPolicy, WrappedDataKeys, instant_sleep,
        };
        let ks = LocalKeyset::builder().aead("kek").hmac("tok").build();
        let p = LocalProvider::new(ks.clone()).allow_ephemeral_local_keys();
        let open = |name: &str| {
            let u: KeyUri = format!("local://default/{name}").parse().unwrap();
            p.aead(&u, &OpenOptions::new()).unwrap()
        };
        let k = open("kek")
            .layer(&RetryLayer::new(instant_sleep()).with_policy(RetryPolicy::immediate()));
        assert!(k.supports_wrapped_data_keys());
        ks.inject_for_key("kek", crate::Fault::unavailable(2));
        let wrapped = k
            .generate_wrapped_data_key(DataKeySpec::Aes256, b"ctx")
            .await
            .unwrap();
        assert_eq!(k.decrypt(&wrapped, b"ctx").await.unwrap().len(), 32);
        assert_eq!(
            k.decrypt(&wrapped, b"other").await.unwrap_err().kind(),
            ErrorKind::DecryptFailed
        );
        let e = open("tok")
            .generate_wrapped_data_key(DataKeySpec::Aes256, b"")
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{e}");
        assert_eq!(e.resource(), Some("local://default/tok"));
    }

    /// A data-key source over an AEAD key: its data keys decrypt with the AEAD key and their
    /// AAD; other key kinds refuse.
    #[tokio::test]
    async fn data_key_sources() {
        use anykms_core::{Aead, DataKeySpec, DataKeys, Describe, Registry};
        let ks = LocalKeyset::builder().aead("kek").hmac("tok").build();
        let reg = Registry::builder()
            .provider(LocalProvider::new(ks).allow_ephemeral_local_keys())
            .build()
            .unwrap();
        let dks = reg.data_keys("local://default/kek").unwrap();
        assert!(dks.supports_describe());
        assert!(dks.downcast_ref::<LocalAeadKey>().is_some());
        dks.describe().await.unwrap();
        let dk = dks
            .generate_data_key(DataKeySpec::Aes256, b"ctx")
            .await
            .unwrap();
        let aead = reg.aead("local://default/kek").unwrap();
        assert_eq!(
            &*aead.decrypt(dk.ciphertext(), b"ctx").await.unwrap(),
            dk.plaintext()
        );
        let e = reg
            .data_keys("local://default/tok")
            .unwrap()
            .generate_data_key(DataKeySpec::Aes256, b"")
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{e}");
    }

    /// Pins the local column of the semantics table (architecture plan §3.2), opened through a
    /// `Registry`; local versions are not addressable in URIs, so `pin` is `Unsupported`.
    #[test]
    fn semantics_through_the_registry() {
        use anykms_core::{
            DataKeyAad, DataKeySource, KeySemantics, KeyVersion, Registry, SignatureAlgorithm as S,
            VersionModel, VersionShape,
        };
        let ks = LocalKeyset::builder().build();
        let reg = Registry::builder()
            .provider(LocalProvider::new(ks).allow_ephemeral_local_keys())
            .build()
            .unwrap();
        let u = "local://default/k";
        let base = KeySemantics::new(VersionModel::Floating, VersionShape::Numeric);
        let aead = base
            .clone()
            .with_ciphertext_reveals_version(true)
            .with_data_keys(Some(DataKeySource::native(DataKeyAad::Bound)))
            .with_max_plaintext(Some(crate::MAX_PLAINTEXT));
        assert_eq!(reg.aead(u).unwrap().semantics(), Some(&aead));
        assert_eq!(reg.data_keys(u).unwrap().semantics(), Some(&aead));
        // A KEK has no data keys and no plaintext limit.
        let kek = base.clone().with_ciphertext_reveals_version(true);
        assert_eq!(reg.key_wrap(u).unwrap().semantics(), Some(&kek));
        let p256 = S::EcdsaP256Sha256;
        assert_eq!(reg.digest_signer(u, p256).unwrap().semantics(), Some(&base));
        assert_eq!(
            reg.digest_verifier(u, p256).unwrap().semantics(),
            Some(&base)
        );
        assert_eq!(
            reg.message_signer(u, S::Ed25519).unwrap().semantics(),
            Some(&base)
        );
        assert_eq!(
            reg.message_verifier(u, S::Ed25519).unwrap().semantics(),
            Some(&base)
        );
        assert_eq!(reg.public_keys(u, p256).unwrap().semantics(), Some(&base));
        assert_eq!(
            reg.public_keys(u, S::Ed25519).unwrap().semantics(),
            Some(&base)
        );
        assert_eq!(
            reg.mac(u, MacAlgorithm::HmacSha256).unwrap().semantics(),
            Some(&base)
        );
        assert_eq!(reg.describe(u).unwrap().semantics(), None);
        let e = reg.pin(u, &KeyVersion::from_u64(1)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
    }

    #[test]
    fn opt_in_required() {
        let ks = LocalKeyset::builder().aead("kek").build();
        let u: KeyUri = "local://default/kek".parse().unwrap();
        let e = LocalProvider::new(ks.clone())
            .aead(&u, &OpenOptions::new())
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
        assert!(
            LocalProvider::new(ks)
                .allow_ephemeral_local_keys()
                .aead(&u, &OpenOptions::new())
                .is_ok()
        );
    }
}
