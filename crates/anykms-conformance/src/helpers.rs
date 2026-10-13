//! Helpers for backend fixtures (feature `fixture-helpers`): run-scoped key names, a table from
//! test key kinds to backend key specs, a list of keys created during a run, and
//! [`typed_handles!`](crate::typed_handles) for the [`TypedHandles`](crate::TypedHandles)
//! methods every backend writes the same way. Admin clients (creating, rotating and disabling
//! keys) stay per backend.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::TestKeyKind;

/// A run identifier for naming test keys: `anykms-<unix seconds>-<pid>-<n>`, unique per value
/// (also when several fixtures run in one process), so concurrent runs never share a key and a
/// janitor can sweep by prefix and age.
#[derive(Debug)]
pub struct RunId {
    prefix: String,
    next: AtomicU64,
}

impl RunId {
    /// A new run identifier.
    pub fn new() -> Self {
        static RUNS: AtomicU64 = AtomicU64::new(0);
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            prefix: format!(
                "anykms-{secs}-{}-{}",
                std::process::id(),
                RUNS.fetch_add(1, Ordering::Relaxed)
            ),
            next: AtomicU64::new(0),
        }
    }

    /// The prefix every name of this run starts with.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// A new name in this run: `<prefix>-<what>-<n>`.
    pub fn name(&self, what: &str) -> String {
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        format!("{}-{what}-{n}", self.prefix)
    }
}

impl Default for RunId {
    fn default() -> Self {
        Self::new()
    }
}

/// Backend key specs per [`TestKeyKind`]: exact entries, plus optional defaults for every
/// signing or HMAC algorithm without its own entry.
#[derive(Clone, Debug)]
pub struct KeySpecTable<S> {
    backend: &'static str,
    entries: Vec<(TestKeyKind, S)>,
    any_signing: Option<S>,
    any_hmac: Option<S>,
}

impl<S> KeySpecTable<S> {
    /// An empty table; `backend` names the backend in lookup errors.
    pub fn new(backend: &'static str) -> Self {
        Self {
            backend,
            entries: Vec::new(),
            any_signing: None,
            any_hmac: None,
        }
    }

    /// Adds the spec of `kind`.
    pub fn with(mut self, kind: TestKeyKind, spec: S) -> Self {
        self.entries.push((kind, spec));
        self
    }

    /// The spec of every signing algorithm without its own entry.
    pub fn with_any_signing(mut self, spec: S) -> Self {
        self.any_signing = Some(spec);
        self
    }

    /// The spec of every HMAC algorithm without its own entry.
    pub fn with_any_hmac(mut self, spec: S) -> Self {
        self.any_hmac = Some(spec);
        self
    }

    /// The spec of `kind`, or an error naming the backend and the kind.
    pub fn get(&self, kind: TestKeyKind) -> Result<&S, String> {
        if let Some((_, s)) = self.entries.iter().find(|(k, _)| *k == kind) {
            return Ok(s);
        }
        let fallback = match kind {
            TestKeyKind::Signing(_) => self.any_signing.as_ref(),
            TestKeyKind::Hmac(_) => self.any_hmac.as_ref(),
            _ => None,
        };
        fallback.ok_or_else(|| format!("no {} key spec for {kind:?}", self.backend))
    }
}

/// Keys created during a run, to clean up when it ends. Tolerates a poisoned lock (a panicking
/// case must not stop the cleanup of the others' keys).
#[derive(Debug)]
pub struct FreshKeys<K> {
    keys: Mutex<Vec<K>>,
}

impl<K> FreshKeys<K> {
    /// No keys yet.
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(Vec::new()),
        }
    }

    /// Records a created key.
    pub fn push(&self, key: K) {
        self.keys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(key);
    }

    /// Takes every recorded key, leaving none.
    pub fn take(&self) -> Vec<K> {
        std::mem::take(&mut *self.keys.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// How many keys are recorded.
    pub fn len(&self) -> usize {
        self.keys.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Whether no key is recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<K> Default for FreshKeys<K> {
    fn default() -> Self {
        Self::new()
    }
}

/// Implements [`TypedHandles`](crate::TypedHandles) for a fixture's typed-provider wrapper: the
/// `digest_key`, `message_key` and `mac_key` methods every backend writes the same way (open the
/// typed handle, bridge it, carry its semantics), plus any other methods given verbatim.
///
/// ```ignore
/// anykms_conformance::typed_handles! {
///     impl for Typed => |t| &t.0;
///     preflight;
///     digest_key => digest_signing_key;
///     message_key => ed25519_key;
///     mac_key => mac_key;
///     {
///         fn aead(&self, uri: &KeyUri) -> Result<AeadKey> { /* ... */ }
///     }
/// }
/// ```
///
/// Each named opener is called as `provider.<opener>(uri, alg)` (`message_key`:
/// `provider.<opener>(uri)`) and must return a typed handle with an inherent
/// `semantics(&self) -> &KeySemantics`. The optional `preflight;` line also carries each typed
/// handle's own [`Preflight`](anykms_core::Preflight) check onto the handles
/// (`*KeyHandles::with_preflight`); the typed handles must then implement `Preflight`.
#[macro_export]
macro_rules! typed_handles {
    (
        impl for $Ty:ty => |$this:ident| $p:expr;
        preflight;
        $( digest_key => $dig:ident; )?
        $( message_key => $msg:ident; )?
        $( mac_key => $mac:ident; )?
        { $($rest:tt)* }
    ) => {
        $crate::typed_handles! {
            @impl [preflight] $Ty, |$this| $p;
            $( digest_key => $dig; )?
            $( message_key => $msg; )?
            $( mac_key => $mac; )?
            { $($rest)* }
        }
    };
    (
        impl for $Ty:ty => |$this:ident| $p:expr;
        $( digest_key => $dig:ident; )?
        $( message_key => $msg:ident; )?
        $( mac_key => $mac:ident; )?
        { $($rest:tt)* }
    ) => {
        $crate::typed_handles! {
            @impl [] $Ty, |$this| $p;
            $( digest_key => $dig; )?
            $( message_key => $msg; )?
            $( mac_key => $mac; )?
            { $($rest)* }
        }
    };
    (
        @impl $pf:tt $Ty:ty, |$this:ident| $p:expr;
        $( digest_key => $dig:ident; )?
        $( message_key => $msg:ident; )?
        $( mac_key => $mac:ident; )?
        { $($rest:tt)* }
    ) => {
        impl $crate::TypedHandles for $Ty {
            $(
                fn digest_key(
                    &self,
                    uri: &$crate::__private::anykms_core::KeyUri,
                    alg: $crate::__private::anykms_core::SignatureAlgorithm,
                ) -> $crate::__private::anykms_core::Result<$crate::DigestKeyHandles> {
                    let $this = self;
                    let k = ($p).$dig(uri, alg)?;
                    let s = k.semantics().clone();
                    Ok($crate::typed_handles!(@bridge $pf DigestKeyHandles, k)
                        .with_semantics(s))
                }
            )?
            $(
                fn message_key(
                    &self,
                    uri: &$crate::__private::anykms_core::KeyUri,
                ) -> $crate::__private::anykms_core::Result<$crate::MessageKeyHandles> {
                    let $this = self;
                    let k = ($p).$msg(uri)?;
                    let s = k.semantics().clone();
                    Ok($crate::typed_handles!(@bridge $pf MessageKeyHandles, k)
                        .with_semantics(s))
                }
            )?
            $(
                fn mac_key(
                    &self,
                    uri: &$crate::__private::anykms_core::KeyUri,
                    alg: $crate::__private::anykms_core::MacAlgorithm,
                ) -> $crate::__private::anykms_core::Result<$crate::MacKeyHandles> {
                    let $this = self;
                    let k = ($p).$mac(uri, alg)?;
                    let s = k.semantics().clone();
                    Ok($crate::typed_handles!(@bridge $pf MacKeyHandles, k)
                        .with_semantics(s))
                }
            )?
            $($rest)*
        }
    };
    (@bridge [preflight] $H:ident, $k:ident) => {{
        let k = ::std::sync::Arc::new($k);
        $crate::$H::bridge(k.clone()).with_preflight(k)
    }};
    (@bridge [] $H:ident, $k:ident) => {
        $crate::$H::bridge(::std::sync::Arc::new($k))
    };
}

#[cfg(test)]
mod tests {
    use anykms_core::{MacAlgorithm, SignatureAlgorithm};

    use super::*;

    #[test]
    fn run_ids_are_unique() {
        let (a, b) = (RunId::new(), RunId::new());
        assert_ne!(a.prefix(), b.prefix());
        assert!(a.prefix().starts_with("anykms-"));
        let (x, y) = (a.name("k"), a.name("k"));
        assert_ne!(x, y);
        assert!(x.starts_with(&format!("{}-k-", a.prefix())));
    }

    #[test]
    fn spec_tables_fall_back_per_family() {
        let t = KeySpecTable::new("test")
            .with(TestKeyKind::Aead, "aes")
            .with(TestKeyKind::Signing(SignatureAlgorithm::Ed25519), "ed")
            .with_any_signing("rsa");
        assert_eq!(t.get(TestKeyKind::Aead), Ok(&"aes"));
        assert_eq!(
            t.get(TestKeyKind::Signing(SignatureAlgorithm::Ed25519)),
            Ok(&"ed")
        );
        assert_eq!(
            t.get(TestKeyKind::Signing(SignatureAlgorithm::RsaPssSha256)),
            Ok(&"rsa")
        );
        let e = t
            .get(TestKeyKind::Hmac(MacAlgorithm::HmacSha256))
            .unwrap_err();
        assert!(e.contains("no test key spec for Hmac"), "{e}");
    }

    /// The typed path's wiring: with the `preflight;` arm, a typed handle's own `Preflight`
    /// reaches the handles `Ctx` assembles on `Path::Typed`; without it, core's generic preflight
    /// (describe and check) runs.
    mod typed_preflight {
        use std::sync::Arc;

        use anykms_core::{
            Capabilities, Describe, Error, ErrorKind, KeyInfo, KeySemantics, KeyUri, Mac,
            MacAlgorithm, Operation, Preflight, Provider, Registry, Result, Tag, VersionModel,
            VersionShape,
        };

        use crate::ctx::{Ctx, Path};
        use crate::{Fixture, FixtureCaps, KeyUse, TestKey, TestKeyKind, TypedHandles};

        const SENTINEL: &str = "the typed handle's own preflight";

        struct FakeMac(KeySemantics);

        impl FakeMac {
            fn semantics(&self) -> &KeySemantics {
                &self.0
            }
        }

        impl Mac for FakeMac {
            fn mac_algorithm(&self) -> MacAlgorithm {
                MacAlgorithm::HmacSha256
            }

            async fn mac(&self, _: &[u8]) -> Result<Tag> {
                unimplemented!()
            }

            async fn verify_mac(&self, _: &[u8], _: &Tag) -> Result<()> {
                unimplemented!()
            }
        }

        impl Describe for FakeMac {
            async fn describe(&self) -> Result<KeyInfo> {
                Ok(KeyInfo::new("hmac", Capabilities::MAC))
            }
        }

        impl Preflight for FakeMac {
            async fn preflight(&self) -> Result<KeyInfo> {
                Err(Error::new(
                    ErrorKind::KeyMismatch,
                    "fake",
                    Operation::Describe,
                    SENTINEL,
                ))
            }
        }

        struct Opener;

        impl Opener {
            fn mac_key(&self, _: &KeyUri, _: MacAlgorithm) -> Result<FakeMac> {
                Ok(FakeMac(KeySemantics::new(
                    VersionModel::Single,
                    VersionShape::Opaque,
                )))
            }
        }

        struct Wired(Opener);
        struct Unwired(Opener);

        crate::typed_handles! {
            impl for Wired => |t| &t.0;
            preflight;
            mac_key => mac_key;
            {}
        }

        crate::typed_handles! {
            impl for Unwired => |t| &t.0;
            mac_key => mac_key;
            {}
        }

        struct NoFixture;

        impl Fixture for NoFixture {
            fn name(&self) -> &str {
                "none"
            }

            async fn probe(&self) -> FixtureCaps {
                FixtureCaps::new()
            }

            async fn create_key(&self, _: TestKeyKind, _: KeyUse) -> Result<TestKey> {
                unimplemented!()
            }

            fn missing_key_uri(&self, _: TestKeyKind) -> KeyUri {
                unimplemented!()
            }

            fn provider(&self) -> Arc<dyn Provider> {
                unimplemented!()
            }

            fn typed(&self) -> Arc<dyn TypedHandles> {
                unimplemented!()
            }
        }

        async fn preflight(typed: Arc<dyn TypedHandles>) -> Result<KeyInfo> {
            let ctx = Ctx::new(
                Arc::new(NoFixture),
                Arc::new(FixtureCaps::new()),
                Registry::builder().build().unwrap(),
                typed,
                Path::Typed,
            );
            let uri = KeyUri::parse("fake://k").unwrap();
            ctx.mac(&uri, MacAlgorithm::HmacSha256)
                .unwrap()
                .preflight()
                .await
        }

        #[tokio::test]
        async fn reaches_the_backend_impl() {
            let e = preflight(Arc::new(Wired(Opener))).await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::KeyMismatch);
            assert!(e.to_string().contains(SENTINEL), "{e}");
            // Without the arm, core's generic preflight describes the key and accepts it.
            preflight(Arc::new(Unwired(Opener))).await.unwrap();
        }
    }

    #[test]
    fn fresh_keys_are_taken_once() {
        let f = FreshKeys::new();
        assert!(f.is_empty());
        f.push("a");
        f.push("b");
        assert_eq!(f.len(), 2);
        assert_eq!(f.take(), ["a", "b"]);
        assert!(f.take().is_empty());
    }
}
