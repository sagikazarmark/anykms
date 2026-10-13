//! The [`KeySemantics`] of transit handles (architecture plan §3.2, transit columns).

use anykms_core::{
    DataKeyAad, DataKeySource, KeySemantics, UnversionedVerify, Verification, VersionModel,
    VersionShape,
};

use crate::config::Flavor;

/// The semantics of one server's handles, by key family. Known from configuration alone: the
/// flavor decides the data-key AAD behavior.
#[derive(Debug)]
pub(crate) struct ServerSemantics {
    /// AEAD keys (also as data-key sources).
    pub(crate) aead: KeySemantics,
    /// AEAD keys as KEKs: no data keys, no plaintext limit.
    pub(crate) key_wrap: KeySemantics,
    /// Signing keys (digest and Ed25519).
    pub(crate) signing: KeySemantics,
    /// HMAC keys: transit lists no versions for them.
    pub(crate) hmac: KeySemantics,
}

impl ServerSemantics {
    pub(crate) fn new(flavor: Flavor) -> Self {
        // Every transit key floats on its latest version, numbered from 1, with a key-level
        // state and backend verification; signatures and tags must name their version.
        let base = KeySemantics::new(VersionModel::Floating, VersionShape::Numeric)
            .with_unversioned_verify(UnversionedVerify::Rejected)
            .with_verification(Verification::Backend);
        // Vault ignores `associated_data` on `datakey`, so the backend refuses non-empty AAD;
        // OpenBao binds it from 2.5 on, which is unknown before the first request.
        let aad = match flavor {
            Flavor::Vault => DataKeyAad::Refused,
            Flavor::OpenBao => DataKeyAad::BoundOrRefused,
        };
        let aead = base.clone().with_ciphertext_reveals_version(true);
        Self {
            key_wrap: aead.clone().with_data_keys(None).with_max_plaintext(None),
            aead: aead.with_data_keys(Some(DataKeySource::native(aad))),
            signing: base.clone(),
            hmac: base.with_versions_listed(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anykms_core::{PinnedVerify, StateScope};

    /// Pins the transit columns of the §3.2 table.
    #[test]
    fn rows() {
        for flavor in [Flavor::Vault, Flavor::OpenBao] {
            let s = ServerSemantics::new(flavor);
            for k in [&s.aead, &s.key_wrap, &s.signing, &s.hmac] {
                assert_eq!(k.version_model(), VersionModel::Floating);
                assert_eq!(k.version_shape(), VersionShape::Numeric);
                assert!(k.primary_reported());
                assert_eq!(k.state_scope(), StateScope::Key);
                assert!(!k.reports_used_primary());
                assert_eq!(k.unversioned_verify(), UnversionedVerify::Rejected);
                assert_eq!(k.pinned_verify(), PinnedVerify::PinnedOnly);
                assert_eq!(k.verification(), Verification::Backend);
                assert_eq!(k.max_plaintext(), None);
                assert_eq!(k.max_mac_input(), None);
                assert_eq!(k.max_signed_message(), None);
            }
            assert!(s.aead.versions_listed() && s.signing.versions_listed());
            assert!(!s.hmac.versions_listed());
            assert!(s.aead.ciphertext_reveals_version());
            assert_eq!(s.signing.data_keys(), None);
            assert_eq!(s.hmac.data_keys(), None);
            let aad = match flavor {
                Flavor::Vault => DataKeyAad::Refused,
                Flavor::OpenBao => DataKeyAad::BoundOrRefused,
            };
            assert_eq!(s.aead.data_keys(), Some(DataKeySource::native(aad)));
            // A KEK declares no data keys and no plaintext limit; otherwise it is the AEAD row.
            assert_eq!(s.key_wrap.data_keys(), None);
            assert_eq!(s.key_wrap.max_plaintext(), None);
            assert_eq!(s.key_wrap, s.aead.clone().with_data_keys(None));
        }
    }
}
