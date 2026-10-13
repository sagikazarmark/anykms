//! The [`KeySemantics`] of each Azure handle.
//!
//! An unversioned URI writes with the key's current version, which rotation moves
//! ([`VersionModel::Floating`]); a versioned URI names one version ([`VersionModel::Pinned`]),
//! and a pinned handle verifies only that version ([`PinnedVerify::PinnedOnly`]). Versions are
//! 32 hex characters ([`VersionShape::Opaque`]). The state reported for a key is the enabled flag
//! of its current or pinned version ([`StateScope::Key`]; Azure has no key-level flag).
//! Wrapped keys and ciphertexts are framed with the version that made them.

use std::sync::Arc;
use std::time::Duration;

use anykms_core::{
    DataKeyAad, DataKeySource, KeySemantics, PinnedVerify, Semantics, StateScope,
    UnversionedVerify, Verification, VersionModel, VersionShape,
};

use crate::handles::{AzureAeadKey, AzureDigestKey, AzureKeyWrapKey, KeyCtx};

/// What every Azure handle on `k` shares.
pub(crate) fn base(k: &KeyCtx) -> KeySemantics {
    let versions = if k.uri.version().is_some() {
        VersionModel::Pinned
    } else {
        VersionModel::Floating
    };
    KeySemantics::new(versions, VersionShape::Opaque)
        .with_primary_reported(true)
        .with_state_scope(StateScope::Key)
        .with_versions_listed(true)
        .with_ciphertext_reveals_version(false)
        .with_reports_used_primary(false)
        .with_unversioned_verify(UnversionedVerify::Rejected)
        .with_pinned_verify(PinnedVerify::PinnedOnly)
        .with_verification(Verification::Backend)
}

/// A signing key: verified by the vault, or in this process when `local` is the provider's
/// key-cache TTL (a version the vault stops serving keeps verifying for at most the TTL,
/// jittered by up to 10 %).
pub(crate) fn digest(k: &KeyCtx, local: Option<Duration>) -> Arc<KeySemantics> {
    let s = base(k);
    Arc::new(match local {
        Some(ttl) => s.with_verification(Verification::local(ttl.mul_f64(1.1))),
        None => s,
    })
}

/// A key-wrapping key: the wrapped key's frame names the version.
pub(crate) fn key_wrap(k: &KeyCtx) -> Arc<KeySemantics> {
    Arc::new(base(k).with_ciphertext_reveals_version(true))
}

/// A Managed HSM AES-GCM key: framed ciphertexts, data keys from `EmulatedDataKeys` (AAD bound).
pub(crate) fn aead(k: &KeyCtx) -> Arc<KeySemantics> {
    Arc::new(
        base(k)
            .with_ciphertext_reveals_version(true)
            .with_data_keys(Some(DataKeySource::emulated(DataKeyAad::Bound))),
    )
}

/// A data-key source. On a vault, `KeyWrapDataKeys` over RSA-OAEP-256 (non-empty AAD refused);
/// on a Managed HSM the key type decides (AES: bound, RSA: refused), which is read lazily.
pub(crate) fn data_keys(k: &KeyCtx, mhsm: bool) -> KeySemantics {
    let aad = if mhsm {
        DataKeyAad::BoundOrRefused
    } else {
        DataKeyAad::Refused
    };
    base(k).with_data_keys(Some(DataKeySource::emulated(aad)))
}

/// A Managed HSM HMAC key: MAC inputs of at most 64 KiB (refused before any request).
#[cfg(feature = "mhsm-hmac")]
pub(crate) fn mac(k: &KeyCtx) -> Arc<KeySemantics> {
    Arc::new(base(k).with_max_mac_input(Some(crate::handles::mac::MAX_MAC_INPUT)))
}

macro_rules! typed {
    ($($ty:ty),* $(,)?) => {$(
        impl $ty {
            /// What this handle does where backends differ; constant for the handle.
            pub fn semantics(&self) -> &KeySemantics {
                &self.sem
            }
        }

        impl Semantics for $ty {
            fn semantics(&self) -> Option<&KeySemantics> {
                Some(&self.sem)
            }
        }
    )*};
}

typed!(AzureDigestKey, AzureKeyWrapKey, AzureAeadKey);
#[cfg(feature = "mhsm-hmac")]
typed!(crate::AzureMacKey);

#[cfg(test)]
mod tests {
    use anykms_core::{
        ErrorKind, IntoKeyUri, KeyUri, KeyVersion, OpenOptions, Operation, Provider, Registry,
        SignatureAlgorithm,
    };

    use super::*;
    use crate::{AzureOptions, AzureProvider, StaticToken};

    const V: &str = "0123456789abcdef0123456789abcdef";
    const KEY: &str = "azure-kv://contoso.vault.azure.net/keys/k";
    const MHSM: &str = "azure-kv://contoso.managedhsm.azure.net/keys/k";

    fn provider() -> AzureProvider {
        AzureProvider::builder()
            .credential(StaticToken::new("t"))
            .key_cache_ttl(Duration::from_secs(100))
            .build()
            .unwrap()
    }

    fn registry() -> Registry {
        Registry::builder().provider(provider()).build().unwrap()
    }

    fn uri(s: &str) -> KeyUri {
        s.into_key_uri().unwrap()
    }

    fn pinned(s: &str) -> String {
        format!("{s}/{V}")
    }

    /// The Azure columns of the per-backend semantics table (vault and Managed HSM).
    #[test]
    fn rows() {
        let r = registry();
        let p256 = SignatureAlgorithm::EcdsaP256Sha256;
        for (u, model) in [
            (KEY.to_string(), VersionModel::Floating),
            (pinned(KEY), VersionModel::Pinned),
        ] {
            let s = r
                .digest_signer(u.as_str(), p256)
                .unwrap()
                .semantics()
                .cloned()
                .unwrap();
            assert_eq!(s.version_model(), model);
            assert_eq!(s.version_shape(), VersionShape::Opaque);
            assert!(s.primary_reported());
            assert_eq!(s.state_scope(), StateScope::Key);
            assert!(s.versions_listed());
            assert!(!s.ciphertext_reveals_version());
            assert!(!s.reports_used_primary());
            assert_eq!(s.unversioned_verify(), UnversionedVerify::Rejected);
            assert_eq!(s.pinned_verify(), PinnedVerify::PinnedOnly);
            assert_eq!(s.verification(), Verification::Backend);
            assert_eq!(s.data_keys(), None);
            assert_eq!(
                (s.max_plaintext(), s.max_mac_input(), s.max_signed_message()),
                (None, None, None)
            );
            let kw = r
                .key_wrap(u.as_str())
                .unwrap()
                .semantics()
                .cloned()
                .unwrap();
            assert!(kw.ciphertext_reveals_version());
            assert_eq!(kw.version_model(), model);
        }
        let dk = r.data_keys(KEY).unwrap().semantics().cloned().unwrap();
        assert_eq!(
            dk.data_keys(),
            Some(DataKeySource::emulated(DataKeyAad::Refused))
        );
        let dk = r.data_keys(MHSM).unwrap().semantics().cloned().unwrap();
        assert_eq!(
            dk.data_keys(),
            Some(DataKeySource::emulated(DataKeyAad::BoundOrRefused))
        );
        #[cfg(feature = "mhsm-hmac")]
        {
            let mac = r
                .mac(MHSM, anykms_core::MacAlgorithm::HmacSha256)
                .unwrap()
                .semantics()
                .cloned()
                .unwrap();
            assert_eq!(mac.max_mac_input(), Some(64 * 1024));
        }
        let aead = r.aead(MHSM).unwrap().semantics().cloned().unwrap();
        assert!(aead.ciphertext_reveals_version());
        assert_eq!(
            aead.data_keys(),
            Some(DataKeySource::emulated(DataKeyAad::Bound))
        );
        // Describe opens any key family: it declares none.
        assert!(r.describe(KEY).unwrap().semantics().is_none());
    }

    /// `local_verify` makes verification local, with a revocation lag of the key-cache TTL × 1.1.
    #[test]
    fn local_verify() {
        let p = provider();
        let opts = OpenOptions::new().with_extension(AzureOptions::new().local_verify());
        let alg = SignatureAlgorithm::EcdsaP256Sha256;
        let k = p.digest_signing_key_with(KEY, alg, &opts).unwrap();
        assert_eq!(
            k.semantics().verification(),
            Verification::local(Duration::from_secs(110))
        );
        let opened = Provider::digest_verifier(&p, &uri(KEY), alg, &opts).unwrap();
        assert_eq!(opened.semantics(), Some(k.semantics()));
        assert_eq!(Semantics::semantics(&k), Some(k.semantics()));
    }

    /// `pin` sets the 32-hex version; the same version (any case) returns the URI unchanged;
    /// another version or a malformed one is `Configuration` with `Operation::Open`.
    #[test]
    fn pin() {
        let p = provider();
        let v = KeyVersion::new(V);
        assert_eq!(Provider::pin(&p, &uri(KEY), &v).unwrap(), uri(&pinned(KEY)));
        let upper = KeyVersion::new(V.to_ascii_uppercase());
        assert_eq!(
            Provider::pin(&p, &uri(&pinned(KEY)), &upper).unwrap(),
            uri(&pinned(KEY))
        );
        let other = "f".repeat(32);
        for (u, v) in [
            (pinned(KEY), other.as_str()),
            (KEY.to_string(), "abc"),
            (KEY.to_string(), ""),
            (KEY.to_string(), &"g".repeat(32)),
        ] {
            let e = Provider::pin(&p, &uri(&u), &KeyVersion::new(v)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration, "{u} {v}");
            assert_eq!(e.operation(), Operation::Open, "{u} {v}");
        }
        let r = Registry::builder()
            .provider(std::sync::Arc::new(provider()))
            .build()
            .unwrap();
        assert_eq!(r.pin(KEY, &v).unwrap(), uri(&pinned(KEY)));
    }
}
