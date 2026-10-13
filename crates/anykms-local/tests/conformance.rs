//! Runs the anykms conformance suite against the local software backend.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anykms_conformance::{
    AeadKeyHandles, DigestKeyHandles, Feature, Fixture, FixtureCaps, KeyUse, MacKeyHandles,
    MessageKeyHandles, TestKey, TestKeyKind, TypedHandles,
};
use anykms_core::{
    AeadKey, Error, ErrorKind, KeyUri, KeyVersion, MacAlgorithm, Operation, Provider, Result,
    SignatureAlgorithm,
};
use anykms_local::{Fault, LocalAeadKey, LocalKeyKind, LocalKeyset, LocalProvider, MAX_PLAINTEXT};

/// The typed API: `LocalProvider`'s typed constructors (`aead_key`, `digest_signing_key`, ...),
/// bridged into the dyn layer, rather than its `Provider` implementation.
struct LocalTyped(LocalProvider);

impl TypedHandles for LocalTyped {
    fn aead(&self, uri: &KeyUri) -> Result<AeadKeyHandles> {
        let k = Arc::new(self.0.aead_key(uri)?);
        let s = k.semantics().clone();
        Ok(AeadKeyHandles::bridge(k.clone())
            .with_rewrap(k.clone())
            .with_data_keys(k.clone())
            .with_wrapped_data_keys(k)
            .with_semantics(s))
    }

    fn digest_key(&self, uri: &KeyUri, alg: SignatureAlgorithm) -> Result<DigestKeyHandles> {
        let k = self.0.digest_signing_key(uri, alg)?;
        let s = k.semantics().clone();
        Ok(DigestKeyHandles::bridge(Arc::new(k)).with_semantics(s))
    }

    fn message_key(&self, uri: &KeyUri) -> Result<MessageKeyHandles> {
        let k = self.0.ed25519_key(uri)?;
        let s = k.semantics().clone();
        Ok(MessageKeyHandles::bridge(Arc::new(k)).with_semantics(s))
    }

    fn mac_key(&self, uri: &KeyUri, alg: MacAlgorithm) -> Result<MacKeyHandles> {
        let k = self.0.mac_key(uri, alg)?;
        let s = k.semantics().clone();
        Ok(MacKeyHandles::bridge(Arc::new(k)).with_semantics(s))
    }
}

struct LocalFixture {
    keyset: LocalKeyset,
    counter: AtomicU64,
}

impl Fixture for LocalFixture {
    fn name(&self) -> &str {
        "local"
    }

    async fn probe(&self) -> FixtureCaps {
        use Feature::*;
        let mut caps = FixtureCaps::new()
            .not_applicable(Feature::BackendInfo, "local keys carry no backend metadata")
            .not_applicable(Feature::KeyWrapPublicKeys, "no RSA key-wrapping keys")
            .supports_all(&[
                Aead,
                Rewrap,
                DataKeys,
                WrappedDataKeys,
                Extension,
                Mac,
                Describe,
                Rotate,
                RotateMac,
                RotateSigning,
                Disable,
                PreflightState,
                MinDecryptionVersion,
                Throttle,
                RewrapWithAad,
                EmptyPlaintext,
                EmptyMessage,
                ServerErrorMessages,
            ])
            .with_oversize_plaintext(MAX_PLAINTEXT + 1)
            .not_applicable(Feature::UsedPrimary, "decrypt does not report whether the primary version was used")
            .not_applicable(
                KeyWrap,
                "local AES keys wrap as AEAD keys (KeyWrapKey::from_aead); no native key-wrapping keys",
            )
            .not_applicable_all(&[KeyWrapRewrap, RotateKeyWrap], "no native key-wrapping keys")
            .not_applicable(DisableVersion, "local keys are disabled as a whole")
            .not_applicable(MacInputLimit, "local MAC input is not limited")
            .not_applicable(MessageInputLimit, "local Ed25519 messages are not limited")
            .not_applicable(
                Feature::NativeCiphertext,
                "local ciphertexts are only produced by anykms",
            )
            .not_applicable(
                Feature::UnauthorizedProvider,
                "local keys have no credentials",
            )
            .not_applicable(
                Feature::RequestCount,
                "the local backend is in-process and sends no requests",
            );
        for &alg in SignatureAlgorithm::ALL {
            caps = match kind(alg) {
                Some(_) => caps.supports(Feature::Signing(alg)),
                None => caps.not_applicable(Feature::Signing(alg), "local backend has no RSA keys"),
            };
        }
        caps
    }

    /// Every key is fresh: local keys cost nothing.
    async fn create_key(&self, kind_: TestKeyKind, _: KeyUse) -> Result<TestKey> {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let name = format!("k{n}");
        let k = match kind_ {
            TestKeyKind::Aead => LocalKeyKind::Aes256Gcm,
            TestKeyKind::Hmac(_) => LocalKeyKind::Hmac,
            TestKeyKind::Signing(alg) => kind(alg).expect("caps gate RSA"),
            _ => unreachable!(),
        };
        self.keyset.insert(name.clone(), k);
        Ok(TestKey::new(uri(&name), name, kind_))
    }

    async fn rotate(&self, key: &TestKey) -> Result<TestKey> {
        self.keyset.rotate(&key.name)?;
        Ok(key.clone())
    }

    async fn disable(&self, key: &TestKey) -> Result<()> {
        self.keyset.disable(&key.name)
    }

    async fn set_min_decryption_version(&self, key: &TestKey, version: &KeyVersion) -> Result<()> {
        let v = version.as_u64().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidArgument,
                "local",
                Operation::Configure,
                "non-numeric key version",
            )
        })?;
        self.keyset.set_min_decryption_version(&key.name, v)
    }

    async fn throttle(&self, key: &TestKey) -> Result<()> {
        // A one-shot fault: the default `unthrottle` (nothing to undo) suffices.
        self.keyset
            .inject_for_key(key.name.clone(), Fault::throttled(1));
        Ok(())
    }

    // `encrypt_natively`, `counting`, `secret_markers` and `unauthorized_provider` keep their
    // defaults: the features are declared not applicable in `probe`.

    /// A call through `AeadKey::call_extension`, as a backend extension trait makes it.
    async fn extension_call(&self, key: &AeadKey) -> Result<()> {
        let k = key.downcast_arc::<LocalAeadKey>().ok_or_else(|| {
            Error::new(
                ErrorKind::Unsupported,
                "fixture",
                Operation::Encrypt,
                "not a local AEAD key",
            )
        })?;
        key.call_extension(Operation::Encrypt, "local.conformance_encrypt", || {
            let k = k.clone();
            Box::pin(async move { anykms_core::Aead::encrypt(&*k, b"extension", b"").await })
        })
        .await
        .map(drop)
    }

    fn missing_key_uri(&self, _: TestKeyKind) -> KeyUri {
        uri("does-not-exist")
    }

    fn provider(&self) -> Arc<dyn Provider> {
        Arc::new(self.local_provider())
    }

    fn typed(&self) -> Arc<dyn TypedHandles> {
        Arc::new(LocalTyped(self.local_provider()))
    }
}

impl LocalFixture {
    fn local_provider(&self) -> LocalProvider {
        LocalProvider::new(self.keyset.clone()).allow_ephemeral_local_keys()
    }
}

fn kind(alg: SignatureAlgorithm) -> Option<LocalKeyKind> {
    match alg {
        SignatureAlgorithm::EcdsaP256Sha256 => Some(LocalKeyKind::EcdsaP256),
        SignatureAlgorithm::EcdsaP384Sha384 => Some(LocalKeyKind::EcdsaP384),
        SignatureAlgorithm::EcdsaP521Sha512 => Some(LocalKeyKind::EcdsaP521),
        SignatureAlgorithm::Ed25519 => Some(LocalKeyKind::Ed25519),
        _ => None,
    }
}

fn uri(name: &str) -> KeyUri {
    format!("local://default/{name}")
        .parse()
        .expect("valid URI")
}

fn main() -> ExitCode {
    anykms_conformance::run(async || LocalFixture {
        keyset: LocalKeyset::builder().build(),
        counter: AtomicU64::new(0),
    })
}
