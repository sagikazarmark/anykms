//! The [`KeySemantics`] of each AWS handle.
//!
//! AWS keys are one identity with no addressable versions ([`VersionModel::Single`]); the
//! version anykms reports is the key ARN ([`VersionShape::Opaque`]). Every value is known at
//! open: where it depends on the key type (which only `DescribeKey` reveals), the handle states
//! what holds for every key type it opens.

use std::sync::LazyLock;

use anykms_core::{
    DataKeyAad, DataKeySource, KeySemantics, Semantics, StateScope, UnversionedVerify,
    Verification, VersionModel, VersionShape,
};

use crate::handles::{AwsAeadKey, AwsDigestKey, AwsEd25519Key, AwsKeyWrapKey, AwsMacKey};

/// The request limit of `Encrypt`, `GenerateMac` and `Sign` (`MessageType=RAW`).
const MAX_INPUT: usize = 4096;

/// What every AWS handle shares.
fn base() -> KeySemantics {
    KeySemantics::new(VersionModel::Single, VersionShape::Opaque)
        .with_primary_reported(true)
        .with_state_scope(StateScope::Key)
        .with_versions_listed(true)
        .with_ciphertext_reveals_version(false)
        .with_reports_used_primary(false)
        .with_unversioned_verify(UnversionedVerify::UsesCurrent)
        .with_verification(Verification::Backend)
}

/// A symmetric key: no primary version (rotation is inside the ARN), `GenerateDataKey` bound to
/// the AAD, plaintexts of at most 4096 bytes.
pub(crate) static AEAD: LazyLock<KeySemantics> = LazyLock::new(|| {
    base()
        .with_primary_reported(false)
        .with_data_keys(Some(DataKeySource::native(DataKeyAad::Bound)))
        .with_max_plaintext(Some(MAX_INPUT))
});

/// A symmetric key as a data-key source: as [`AEAD`], without an `Aead` part (no plaintext limit).
pub(crate) static DATA_KEYS: LazyLock<KeySemantics> =
    LazyLock::new(|| AEAD.clone().with_max_plaintext(None));

/// A describe handle opens any key type, and symmetric keys report no primary version.
pub(crate) static DESCRIBE: LazyLock<KeySemantics> =
    LazyLock::new(|| base().with_primary_reported(false));

/// A KEK is symmetric or RSA, known only after `DescribeKey`; symmetric keys report no primary
/// version, so the handle promises none. An RSA KEK wraps locally; its key state is checked
/// against `DescribeKey` metadata cached for up to about 11 minutes, so a disable takes effect
/// on wraps within that window (see `AwsKeyWrapKey`).
pub(crate) static KEY_WRAP: LazyLock<KeySemantics> =
    LazyLock::new(|| base().with_primary_reported(false));

/// ECDSA and RSA keys sign digests (no message limit).
pub(crate) static DIGEST: LazyLock<KeySemantics> = LazyLock::new(base);

/// A public-key source signs nothing (no message limit), for any asymmetric signing key.
pub(crate) static PUBLIC_KEYS: LazyLock<KeySemantics> = LazyLock::new(base);

/// Ed25519 keys sign messages of at most 4096 bytes.
pub(crate) static ED25519: LazyLock<KeySemantics> =
    LazyLock::new(|| base().with_max_signed_message(Some(MAX_INPUT)));

/// HMAC keys take MAC inputs of at most 4096 bytes.
pub(crate) static MAC: LazyLock<KeySemantics> =
    LazyLock::new(|| base().with_max_mac_input(Some(MAX_INPUT)));

macro_rules! typed {
    ($($ty:ty => $value:ident),* $(,)?) => {$(
        impl $ty {
            /// What this handle does where backends differ; constant for the handle.
            pub fn semantics(&self) -> &KeySemantics {
                &$value
            }
        }

        impl Semantics for $ty {
            fn semantics(&self) -> Option<&KeySemantics> {
                Some(&$value)
            }
        }
    )*};
}

typed! {
    AwsAeadKey => AEAD,
    AwsKeyWrapKey => KEY_WRAP,
    AwsDigestKey => DIGEST,
    AwsEd25519Key => ED25519,
    AwsMacKey => MAC,
}

#[cfg(test)]
mod tests {
    use anykms_core::{
        ErrorKind, IntoKeyUri, KeyVersion, MacAlgorithm, Operation, Provider, Registry,
        SignatureAlgorithm,
    };

    use super::*;
    use crate::AwsProvider;
    use crate::credentials::{Credentials, StaticCredentials};

    const KEY: &str =
        "aws-kms://arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    const ALIAS: &str = "aws-kms://arn:aws:kms:us-east-1:111122223333:alias/app";

    fn provider() -> AwsProvider {
        AwsProvider::builder()
            .credentials(StaticCredentials::new(Credentials::new("A", "S", None)))
            .build()
            .unwrap()
    }

    fn registry() -> Registry {
        Registry::builder().provider(provider()).build().unwrap()
    }

    /// The AWS column of the per-backend semantics table, cell by cell.
    #[test]
    fn row() {
        let all = [
            &*AEAD,
            &*DATA_KEYS,
            &*DESCRIBE,
            &*KEY_WRAP,
            &*DIGEST,
            &*PUBLIC_KEYS,
            &*ED25519,
            &*MAC,
        ];
        for s in all {
            assert_eq!(s.version_model(), VersionModel::Single);
            assert_eq!(s.version_shape(), VersionShape::Opaque);
            assert_eq!(s.state_scope(), StateScope::Key);
            assert!(s.versions_listed());
            assert!(!s.ciphertext_reveals_version());
            assert!(!s.reports_used_primary());
            assert_eq!(s.unversioned_verify(), UnversionedVerify::UsesCurrent);
            assert_eq!(s.verification(), Verification::Backend);
        }
        // Symmetric keys report no primary version; asymmetric and HMAC keys do. Handles that
        // may open either (describe, KEK) promise none.
        for s in [&*AEAD, &*DATA_KEYS, &*DESCRIBE, &*KEY_WRAP] {
            assert!(!s.primary_reported());
        }
        for s in [&*DIGEST, &*PUBLIC_KEYS, &*ED25519, &*MAC] {
            assert!(s.primary_reported());
        }
        let bound = Some(DataKeySource::native(DataKeyAad::Bound));
        for (s, data_keys, pt, mac, msg) in [
            (&*AEAD, bound, Some(4096), None, None),
            (&*DATA_KEYS, bound, None, None, None),
            (&*DESCRIBE, None, None, None, None),
            (&*KEY_WRAP, None, None, None, None),
            (&*DIGEST, None, None, None, None),
            (&*PUBLIC_KEYS, None, None, None, None),
            (&*ED25519, None, None, None, Some(4096)),
            (&*MAC, None, None, Some(4096), None),
        ] {
            assert_eq!(s.data_keys(), data_keys);
            assert_eq!(s.max_plaintext(), pt);
            assert_eq!(s.max_mac_input(), mac);
            assert_eq!(s.max_signed_message(), msg);
        }
    }

    /// Every handle the registry opens carries its value, for key and alias URIs alike.
    #[test]
    fn registry_handles_declare_semantics() {
        let r = registry();
        let ecdsa = SignatureAlgorithm::EcdsaP256Sha256;
        let ed = SignatureAlgorithm::Ed25519;
        let hmac = MacAlgorithm::HmacSha256;
        for uri in [KEY, ALIAS] {
            let s = |h: Option<&KeySemantics>| h.cloned();
            assert_eq!(s(r.aead(uri).unwrap().semantics()), Some(AEAD.clone()));
            let dk = r.data_keys(uri).unwrap();
            assert_eq!(s(dk.semantics()), Some(DATA_KEYS.clone()));
            let d = r.describe(uri).unwrap();
            assert_eq!(s(d.semantics()), Some(DESCRIBE.clone()));
            let kw = r.key_wrap(uri).unwrap();
            assert_eq!(s(kw.semantics()), Some(KEY_WRAP.clone()));
            let ds = r.digest_signer(uri, ecdsa).unwrap();
            assert_eq!(s(ds.semantics()), Some(DIGEST.clone()));
            let dv = r.digest_verifier(uri, ecdsa).unwrap();
            assert_eq!(s(dv.semantics()), Some(DIGEST.clone()));
            for alg in [ecdsa, ed] {
                let pk = r.public_keys(uri, alg).unwrap();
                assert_eq!(s(pk.semantics()), Some(PUBLIC_KEYS.clone()));
            }
            let ms = r.message_signer(uri, ed).unwrap();
            assert_eq!(s(ms.semantics()), Some(ED25519.clone()));
            let mv = r.message_verifier(uri, ed).unwrap();
            assert_eq!(s(mv.semantics()), Some(ED25519.clone()));
            let mac = r.mac(uri, hmac).unwrap();
            assert_eq!(s(mac.semantics()), Some(MAC.clone()));
        }
    }

    /// The typed handles report the same values, inherently and through `Semantics`.
    #[test]
    fn typed_handles_declare_semantics() {
        fn declared(h: &impl Semantics) -> Option<&KeySemantics> {
            h.semantics()
        }
        let p = provider();
        let aead = p.aead_key(KEY).unwrap();
        assert_eq!(aead.semantics(), &*AEAD);
        assert_eq!(declared(&aead), Some(&*AEAD));
        let kw = p.key_wrap_key(KEY).unwrap();
        assert_eq!(kw.semantics(), &*KEY_WRAP);
        assert_eq!(declared(&kw), Some(&*KEY_WRAP));
        let d = p
            .digest_signing_key(KEY, SignatureAlgorithm::RsaPssSha256)
            .unwrap();
        assert_eq!(d.semantics(), &*DIGEST);
        assert_eq!(declared(&d), Some(&*DIGEST));
        let ed = p.ed25519_key(KEY).unwrap();
        assert_eq!(ed.semantics(), &*ED25519);
        assert_eq!(declared(&ed), Some(&*ED25519));
        let mac = p.mac_key(KEY, MacAlgorithm::HmacSha512).unwrap();
        assert_eq!(mac.semantics(), &*MAC);
        assert_eq!(declared(&mac), Some(&*MAC));
    }

    /// AWS key versions are not addressable in URIs: `pin` is `Unsupported` (the default), with
    /// `Operation::Open`, on the provider and through the registry.
    #[test]
    fn pin_is_unsupported() {
        let v = KeyVersion::new(KEY.trim_start_matches("aws-kms://"));
        let uri = KEY.into_key_uri().unwrap();
        let e = Provider::pin(&provider(), &uri, &v).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported);
        assert_eq!(e.operation(), Operation::Open);
        let e = registry().pin(KEY, &v).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported);
        assert_eq!(e.operation(), Operation::Open);
    }
}
