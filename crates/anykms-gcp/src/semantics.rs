//! The [`KeySemantics`] of each GCP handle.
//!
//! AEAD keys write with their primary version, which rotation moves ([`VersionModel::Floating`]);
//! signing, MAC and RSA key-wrapping handles name one version in the URI
//! ([`VersionModel::Pinned`]). Versions are decimal ([`VersionShape::Numeric`]) and state is kept
//! per version only ([`StateScope::VersionOnly`]). Signatures are verified in this process with
//! the version's public key, cached for the provider's `public_key_ttl`.

use std::time::Duration;

use anykms_core::{
    KeySemantics, PinnedVerify, Semantics, StateScope, UnversionedVerify, Verification,
    VersionModel, VersionShape,
};

use crate::handles::{GcpAeadKey, GcpDigestKey, GcpEd25519Key, GcpKeyWrapKey, GcpMacKey};

/// The documented plaintext, MAC-input and signed-message limit (64 KiB).
const MAX_INPUT: usize = 65536;

/// The values of one provider (verification depends on its `public_key_ttl`).
#[derive(Debug)]
pub(crate) struct GcpSemantics {
    pub(crate) aead: KeySemantics,
    pub(crate) key_wrap: KeySemantics,
    pub(crate) digest: KeySemantics,
    pub(crate) ed25519: KeySemantics,
    pub(crate) mac: KeySemantics,
}

/// What every GCP handle shares.
fn base(versions: VersionModel) -> KeySemantics {
    KeySemantics::new(versions, VersionShape::Numeric)
        .with_state_scope(StateScope::VersionOnly)
        .with_versions_listed(true)
        .with_ciphertext_reveals_version(false)
        .with_reports_used_primary(false)
        .with_unversioned_verify(UnversionedVerify::Rejected)
        .with_pinned_verify(PinnedVerify::AnyVersion)
        .with_verification(Verification::Backend)
}

impl GcpSemantics {
    pub(crate) fn new(public_key_ttl: Duration) -> Self {
        // A version the backend stops serving keeps verifying for at most the cache TTL
        // (jittered by up to 10 %).
        let local = Verification::local(public_key_ttl.mul_f64(1.1));
        // Pinned handles have no primary version: they name theirs.
        let pinned = || base(VersionModel::Pinned).with_primary_reported(false);
        Self {
            aead: base(VersionModel::Floating)
                .with_primary_reported(true)
                .with_reports_used_primary(true)
                .with_max_plaintext(Some(MAX_INPUT)),
            key_wrap: pinned(),
            digest: pinned().with_verification(local),
            ed25519: pinned()
                .with_verification(local)
                .with_max_signed_message(Some(MAX_INPUT)),
            mac: pinned().with_max_mac_input(Some(MAX_INPUT)),
        }
    }
}

macro_rules! typed {
    ($($ty:ty => $field:ident),* $(,)?) => {$(
        impl $ty {
            /// What this handle does where backends differ; constant for the handle.
            pub fn semantics(&self) -> &KeySemantics {
                &self.k.shared.semantics.$field
            }
        }

        impl Semantics for $ty {
            fn semantics(&self) -> Option<&KeySemantics> {
                Some(&self.k.shared.semantics.$field)
            }
        }
    )*};
}

typed! {
    GcpAeadKey => aead,
    GcpKeyWrapKey => key_wrap,
    GcpDigestKey => digest,
    GcpEd25519Key => ed25519,
    GcpMacKey => mac,
}

#[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
mod tests {
    use anykms_core::{
        DescribeKey, ErrorKind, IntoKeyUri, KeyUri, KeyVersion, MacAlgorithm, Operation, Provider,
        Registry, SignatureAlgorithm,
    };

    use super::*;
    use crate::{Credentials, Endpoint, GcpProvider};

    const KEY: &str = "gcp-kms://projects/my-project/locations/global/keyRings/r/cryptoKeys/k";
    const V3: &str = "gcp-kms://projects/my-project/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/3";

    fn provider() -> GcpProvider {
        GcpProvider::builder()
            .credentials(Credentials::none())
            .endpoint(Endpoint::custom("http://127.0.0.1:9"))
            .allow_loopback_http()
            .public_key_ttl(Duration::from_secs(100))
            .build()
            .unwrap()
    }

    fn registry() -> Registry {
        Registry::builder().provider(provider()).build().unwrap()
    }

    /// The GCP column of the per-backend semantics table, cell by cell.
    #[test]
    fn row() {
        let s = GcpSemantics::new(Duration::from_secs(100));
        let local = Verification::local(Duration::from_secs(110));
        for v in [&s.aead, &s.key_wrap, &s.digest, &s.ed25519, &s.mac] {
            assert_eq!(v.version_shape(), VersionShape::Numeric);
            assert_eq!(v.state_scope(), StateScope::VersionOnly);
            assert!(v.versions_listed());
            assert!(!v.ciphertext_reveals_version());
            assert_eq!(v.unversioned_verify(), UnversionedVerify::Rejected);
            assert_eq!(v.data_keys(), None);
        }
        assert_eq!(s.aead.version_model(), VersionModel::Floating);
        assert!(s.aead.primary_reported());
        assert!(s.aead.reports_used_primary());
        assert_eq!(s.aead.max_plaintext(), Some(65536));
        for v in [&s.key_wrap, &s.digest, &s.ed25519, &s.mac] {
            assert_eq!(v.version_model(), VersionModel::Pinned);
            assert_eq!(v.pinned_verify(), PinnedVerify::AnyVersion);
            assert!(!v.primary_reported());
            assert!(!v.reports_used_primary());
            assert_eq!(v.max_plaintext(), None);
        }
        assert_eq!(s.digest.verification(), local);
        assert_eq!(s.ed25519.verification(), local);
        assert_eq!(s.mac.verification(), Verification::Backend);
        assert_eq!(s.key_wrap.verification(), Verification::Backend);
        assert_eq!(s.ed25519.max_signed_message(), Some(65536));
        assert_eq!(s.digest.max_signed_message(), None);
        assert_eq!(s.mac.max_mac_input(), Some(65536));
        assert_eq!(s.digest.max_mac_input(), None);
    }

    /// Every handle the registry opens carries its value; an AEAD key used as a KEK keeps the
    /// AEAD value without the plaintext limit (a KEK has no `max_plaintext` or data keys).
    #[test]
    fn registry_handles_declare_semantics() {
        let r = registry();
        let s = GcpSemantics::new(Duration::from_secs(100));
        let sem = |h: Option<&KeySemantics>| h.cloned();
        assert_eq!(sem(r.aead(KEY).unwrap().semantics()), Some(s.aead.clone()));
        assert_eq!(
            sem(r.key_wrap(KEY).unwrap().semantics()),
            Some(s.aead.clone().with_max_plaintext(None).with_data_keys(None))
        );
        assert_eq!(
            sem(r.key_wrap(V3).unwrap().semantics()),
            Some(s.key_wrap.clone())
        );
        let ecdsa = SignatureAlgorithm::EcdsaP256Sha256;
        let ed = SignatureAlgorithm::Ed25519;
        assert_eq!(
            sem(r.digest_signer(V3, ecdsa).unwrap().semantics()),
            Some(s.digest.clone())
        );
        assert_eq!(
            sem(r.digest_verifier(V3, ecdsa).unwrap().semantics()),
            Some(s.digest.clone())
        );
        assert_eq!(
            sem(r.public_keys(V3, ecdsa).unwrap().semantics()),
            Some(s.digest.clone())
        );
        assert_eq!(
            sem(r.message_signer(V3, ed).unwrap().semantics()),
            Some(s.ed25519.clone())
        );
        assert_eq!(
            sem(r.message_verifier(V3, ed).unwrap().semantics()),
            Some(s.ed25519.clone())
        );
        assert_eq!(
            sem(r.public_keys(V3, ed).unwrap().semantics()),
            Some(s.ed25519.clone())
        );
        let mac = r.mac(V3, MacAlgorithm::HmacSha256).unwrap();
        assert_eq!(sem(mac.semantics()), Some(s.mac.clone()));
        // Describe opens any key family, which decides the values: it declares none.
        let d: DescribeKey = r.describe(KEY).unwrap();
        assert_eq!(d.semantics(), None);
    }

    /// The typed handles report the same values, inherently and through `Semantics`.
    #[test]
    fn typed_handles_declare_semantics() {
        fn declared(h: &impl Semantics) -> Option<&KeySemantics> {
            h.semantics()
        }
        let p = provider();
        let s = GcpSemantics::new(Duration::from_secs(100));
        let aead = p.aead_key(KEY).unwrap();
        assert_eq!(aead.semantics(), &s.aead);
        assert_eq!(declared(&aead), Some(&s.aead));
        let d = p
            .digest_signing_key(V3, SignatureAlgorithm::EcdsaP256Sha256)
            .unwrap();
        assert_eq!(d.semantics(), &s.digest);
        assert_eq!(declared(&d), Some(&s.digest));
        let ed = p.ed25519_key(V3).unwrap();
        assert_eq!(ed.semantics(), &s.ed25519);
        let mac = p.mac_key(V3, MacAlgorithm::HmacSha256).unwrap();
        assert_eq!(declared(&mac), Some(&s.mac));
        let kw = p.key_wrap_key(V3).unwrap();
        assert_eq!(kw.semantics(), &s.key_wrap);
    }

    fn uri(s: &str) -> KeyUri {
        s.into_key_uri().unwrap()
    }

    /// `pin` sets `/cryptoKeyVersions/<n>`; the same version returns the URI unchanged; another
    /// version or a malformed one is `Configuration` (config class) with `Operation::Open`.
    #[test]
    fn pin() {
        let p = provider();
        let pinned = Provider::pin(&p, &uri(KEY), &KeyVersion::new("3")).unwrap();
        assert_eq!(pinned, uri(V3));
        assert_eq!(
            Provider::pin(&p, &uri(V3), &KeyVersion::new("3")).unwrap(),
            uri(V3)
        );
        for (u, v) in [
            (V3, "4"),
            (KEY, "0"),
            (KEY, "03"),
            (KEY, "x"),
            (KEY, ""),
            (KEY, "-1"),
        ] {
            let e = Provider::pin(&p, &uri(u), &KeyVersion::new(v)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration, "{u} {v}");
            assert!(e.is_config_error(), "{u} {v}");
            assert_eq!(e.operation(), Operation::Open, "{u} {v}");
        }
        // Through the registry, and through an `Arc`-registered provider.
        assert_eq!(registry().pin(KEY, &KeyVersion::new("3")).unwrap(), uri(V3));
        let r = Registry::builder()
            .provider(std::sync::Arc::new(provider()))
            .build()
            .unwrap();
        assert_eq!(r.pin(KEY, &KeyVersion::new("3")).unwrap(), uri(V3));
    }
}
