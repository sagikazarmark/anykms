//! Per-case context and assertion helpers.

use std::fmt;
use std::sync::Arc;

use anykms_core::{
    AeadKey, DataKeysKey, DescribeKey, DigestSignerKey, DigestVerifierKey, DynDescribe, Error,
    ErrorKind, KeySemantics, KeyUri, KeyWrapKey, MacAlgorithm, MacKey, MessageSignerKey,
    MessageVerifierKey, Operation, Provider, PublicKeysKey, Registry, SignatureAlgorithm,
};

use crate::fixture::{
    AeadKeyHandles, Feature, Fixture, FixtureCaps, KeyUse, KeyWrapKeyHandles, TYPED, TestKey,
    TestKeyKind, TypedHandles,
};

/// The outcome of a case: `Err` carries the failure message.
pub type CaseResult = std::result::Result<(), String>;

/// How a case obtains handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    /// Through the backend's typed constructors and the static→dyn bridges
    /// ([`Fixture::typed`]).
    Typed,
    /// Through a [`Registry`] holding the fixture's [`Provider`].
    Registry,
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Path::Typed => "typed",
            Path::Registry => "registry",
        })
    }
}

/// What a case gets: the fixture, its capabilities and handle accessors for the chosen path.
pub struct Ctx<F> {
    /// The fixture.
    pub fx: Arc<F>,
    /// Probed capabilities.
    pub caps: Arc<FixtureCaps>,
    registry: Registry,
    typed: Arc<dyn TypedHandles>,
    /// The path handles are opened through.
    pub path: Path,
    /// How [`settled`](Self::settled) waits between checks (the runner's clock).
    sleep: anykms_core::SleepFn,
}

impl<F> fmt::Debug for Ctx<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ctx")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl<F> Clone for Ctx<F> {
    fn clone(&self) -> Self {
        Self {
            fx: self.fx.clone(),
            caps: self.caps.clone(),
            registry: self.registry.clone(),
            typed: self.typed.clone(),
            path: self.path,
            sleep: self.sleep.clone(),
        }
    }
}

/// A request counter returned by [`Ctx::counting`].
pub type RequestCounter = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Carries the semantics of typed parts onto the handle assembled from them.
macro_rules! with_sem {
    ($handle:expr, $sem:expr) => {
        match $sem {
            Some(s) => $handle.with_semantics(s),
            None => $handle,
        }
    };
}

// Carries a typed handle's own preflight check (`*KeyHandles::with_preflight`) onto a handle the
// typed path assembles.
macro_rules! with_preflight {
    ($handle:expr, $preflight:expr) => {
        match $preflight {
            Some(p) => $handle.with_preflight(p),
            None => $handle,
        }
    };
}

fn typed_only(what: &'static str) -> Error {
    Error::new(
        ErrorKind::Configuration,
        "conformance",
        Operation::Open,
        what,
    )
}

impl<F: Fixture> Ctx<F> {
    pub(crate) fn new(
        fx: Arc<F>,
        caps: Arc<FixtureCaps>,
        registry: Registry,
        typed: Arc<dyn TypedHandles>,
        path: Path,
        sleep: anykms_core::SleepFn,
    ) -> Self {
        Self {
            fx,
            caps,
            registry,
            typed,
            path,
            sleep,
        }
    }

    /// The same case context over a fresh provider whose requests are counted, with the counter.
    /// `Err` when the fixture cannot count (cases using it require [`Feature::RequestCount`]).
    pub fn counting(&self) -> Result<(Self, RequestCounter), String> {
        if !self.caps.has(Feature::RequestCount) {
            return Err("fixture does not count requests".to_owned());
        }
        let c = self
            .fx
            .counting()
            .ok_or("fixture declared RequestCount but counting() returned None")?;
        let registry = Registry::builder()
            .provider_arc(c.provider)
            .build()
            .map_err(|e| format!("counting provider: {e}"))?;
        Ok((
            Self {
                fx: self.fx.clone(),
                caps: self.caps.clone(),
                registry,
                typed: c.typed,
                path: self.path,
                sleep: self.sleep.clone(),
            },
            c.requests,
        ))
    }

    /// A key the case only uses ([`KeyUse::Shared`]: possibly pooled).
    pub async fn key(&self, kind: TestKeyKind) -> Result<TestKey, String> {
        self.create(kind, KeyUse::Shared).await
    }

    /// A new key the case may change ([`KeyUse::Fresh`]).
    pub async fn fresh_key(&self, kind: TestKeyKind) -> Result<TestKey, String> {
        self.create(kind, KeyUse::Fresh).await
    }

    /// `n` distinct keys the case only uses: shared keys where the fixture has enough distinct
    /// ones, fresh keys for the rest.
    pub async fn keys(&self, kind: TestKeyKind, n: usize) -> Result<Vec<TestKey>, String> {
        let mut keys: Vec<TestKey> = Vec::with_capacity(n);
        while keys.len() < n {
            let mut k = self.key(kind).await?;
            if keys.iter().any(|x| x.uri == k.uri) {
                k = self.fresh_key(kind).await?;
                if keys.iter().any(|x| x.uri == k.uri) {
                    return Err(format!(
                        "fixture create_key({kind:?}, Fresh) returned a key already in use: {}",
                        k.uri
                    ));
                }
            }
            keys.push(k);
        }
        Ok(keys)
    }

    async fn create(&self, kind: TestKeyKind, key_use: KeyUse) -> Result<TestKey, String> {
        let k = self
            .fx
            .create_key(kind, key_use)
            .await
            .map_err(|e| format!("fixture create_key({kind:?}, {key_use:?}): {e}"))?;
        if k.kind != kind {
            return Err(format!(
                "fixture create_key({kind:?}) returned a {:?} key",
                k.kind
            ));
        }
        Ok(k)
    }

    /// Runs `check` until it passes or [`FixtureCaps::settle_time`] has elapsed since the first
    /// attempt (at least once), for expectations that follow a state change. Returns the last
    /// result.
    pub async fn settled<T, Fut>(&self, mut check: impl FnMut() -> Fut) -> Result<T, String>
    where
        Fut: std::future::Future<Output = Result<T, String>>,
    {
        use anykms_core::time::Instant;
        let deadline = Instant::now() + self.caps.settle_time;
        loop {
            let r = check().await;
            if r.is_ok() || Instant::now() >= deadline {
                return r;
            }
            (self.sleep)(std::time::Duration::from_millis(50)).await;
        }
    }

    /// Opens an AEAD key.
    pub fn aead(&self, uri: &KeyUri) -> anykms_core::Result<AeadKey> {
        match self.path {
            Path::Typed => self.typed.aead(uri).map(AeadKeyHandles::into_key),
            Path::Registry => self.registry.aead(uri),
        }
    }

    /// Opens a data-key source.
    pub fn data_keys(&self, uri: &KeyUri) -> anykms_core::Result<DataKeysKey> {
        match self.path {
            Path::Typed => self.typed.data_keys(uri),
            Path::Registry => self.registry.data_keys(uri),
        }
    }

    /// Opens a key-wrapping key (an envelope KEK).
    pub fn key_wrap(&self, uri: &KeyUri) -> anykms_core::Result<KeyWrapKey> {
        match self.path {
            Path::Typed => self.typed.key_wrap(uri).map(KeyWrapKeyHandles::into_key),
            Path::Registry => self.registry.key_wrap(uri),
        }
    }

    /// Opens a digest signer.
    pub fn digest_signer(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
    ) -> anykms_core::Result<DigestSignerKey> {
        match self.path {
            Path::Typed => {
                let h = self.typed.digest_key(uri, alg)?;
                let k = DigestSignerKey::new(TYPED, h.signer)
                    .with_verifier(h.verifier)
                    .with_public_keys(h.public_keys);
                let k = with_preflight!(with_sem!(k, h.semantics), h.preflight);
                Ok(match h.describe {
                    Some(d) => k.with_describe(d),
                    None => k,
                })
            }
            Path::Registry => self.registry.digest_signer(uri, alg),
        }
    }

    /// Opens a digest verifier.
    pub fn digest_verifier(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
    ) -> anykms_core::Result<DigestVerifierKey> {
        match self.path {
            Path::Typed => {
                let h = self.typed.digest_key(uri, alg)?;
                let k = DigestVerifierKey::new(TYPED, h.verifier).with_public_keys(h.public_keys);
                let k = with_preflight!(with_sem!(k, h.semantics), h.preflight);
                Ok(match h.describe {
                    Some(d) => k.with_describe(d),
                    None => k,
                })
            }
            Path::Registry => self.registry.digest_verifier(uri, alg),
        }
    }

    /// Opens a message signer. On the typed path, a digest algorithm cannot even be expressed
    /// (the typed constructor takes no algorithm); that yields a `Configuration` error from the
    /// suite itself, so cases assert the refusal on the registry path only.
    pub fn message_signer(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
    ) -> anykms_core::Result<MessageSignerKey> {
        match self.path {
            Path::Typed if !alg.is_message_signing() => Err(typed_only(
                "typed API: only message-signing algorithms have message signers",
            )),
            Path::Typed => {
                let h = self.typed.message_key(uri)?;
                let k = MessageSignerKey::new(TYPED, h.signer)
                    .with_verifier(h.verifier)
                    .with_public_keys(h.public_keys);
                let k = with_preflight!(with_sem!(k, h.semantics), h.preflight);
                Ok(match h.describe {
                    Some(d) => k.with_describe(d),
                    None => k,
                })
            }
            Path::Registry => self.registry.message_signer(uri, alg),
        }
    }

    /// Opens a message verifier (see [`message_signer`](Self::message_signer)).
    pub fn message_verifier(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
    ) -> anykms_core::Result<MessageVerifierKey> {
        match self.path {
            Path::Typed if !alg.is_message_signing() => Err(typed_only(
                "typed API: only message-signing algorithms have message verifiers",
            )),
            Path::Typed => {
                let h = self.typed.message_key(uri)?;
                let k = MessageVerifierKey::new(TYPED, h.verifier).with_public_keys(h.public_keys);
                let k = with_preflight!(with_sem!(k, h.semantics), h.preflight);
                Ok(match h.describe {
                    Some(d) => k.with_describe(d),
                    None => k,
                })
            }
            Path::Registry => self.registry.message_verifier(uri, alg),
        }
    }

    /// Opens a MAC key.
    pub fn mac(&self, uri: &KeyUri, alg: MacAlgorithm) -> anykms_core::Result<MacKey> {
        match self.path {
            Path::Typed => {
                let h = self.typed.mac_key(uri, alg)?;
                let k = with_sem!(MacKey::new(TYPED, h.mac), h.semantics);
                let k = with_preflight!(k, h.preflight);
                Ok(match h.describe {
                    Some(d) => k.with_describe(d),
                    None => k,
                })
            }
            Path::Registry => self.registry.mac(uri, alg),
        }
    }

    /// Opens a public-key source.
    pub fn public_keys(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
    ) -> anykms_core::Result<PublicKeysKey> {
        match self.path {
            Path::Typed => {
                let (pks, describe, sem, preflight) = if alg.is_message_signing() {
                    let h = self.typed.message_key(uri)?;
                    (h.public_keys, h.describe, h.semantics, h.preflight)
                } else {
                    let h = self.typed.digest_key(uri, alg)?;
                    (h.public_keys, h.describe, h.semantics, h.preflight)
                };
                let k = with_sem!(PublicKeysKey::new(TYPED, pks), sem);
                let k = with_preflight!(k, preflight);
                Ok(match describe {
                    Some(d) => k.with_describe(d),
                    None => k,
                })
            }
            Path::Registry => self.registry.public_keys(uri, alg),
        }
    }

    /// Opens a describe handle for `key`, through the typed handle of the key's kind on the
    /// typed path.
    pub fn describe_key(&self, key: &TestKey) -> anykms_core::Result<DescribeKey> {
        self.describe_for(key.kind, &key.uri)
    }

    /// Opens a describe handle for a key of `kind` at `uri` (which need not exist). The typed
    /// path describes through the typed handle of that kind; a handle without a describe part is
    /// `Unsupported`.
    pub fn describe_for(
        &self,
        kind: TestKeyKind,
        uri: &KeyUri,
    ) -> anykms_core::Result<DescribeKey> {
        if self.path == Path::Registry {
            return self.registry.describe(uri);
        }
        let (d, sem): (Option<Arc<dyn DynDescribe>>, Option<KeySemantics>) = match kind {
            TestKeyKind::Aead => {
                let k = self.typed.aead(uri)?.into_key();
                let s = k.semantics().cloned();
                (k.supports_describe().then(|| Arc::new(k) as _), s)
            }
            TestKeyKind::KeyWrap => {
                let k = self.typed.key_wrap(uri)?.into_key();
                let s = k.semantics().cloned();
                (k.supports_describe().then(|| Arc::new(k) as _), s)
            }
            TestKeyKind::Hmac(alg) => {
                let h = self.typed.mac_key(uri, alg)?;
                (h.describe, h.semantics)
            }
            TestKeyKind::Signing(alg) if alg.is_message_signing() => {
                let h = self.typed.message_key(uri)?;
                (h.describe, h.semantics)
            }
            TestKeyKind::Signing(alg) => {
                let h = self.typed.digest_key(uri, alg)?;
                (h.describe, h.semantics)
            }
        };
        d.map(|d| with_sem!(DescribeKey::new(TYPED, d), sem))
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Unsupported,
                    TYPED,
                    Operation::Describe,
                    "the typed handle has no describe part",
                )
            })
    }

    /// The provider with denied credentials, if any.
    pub fn unauthorized(&self) -> Option<Arc<dyn Provider>> {
        self.fx.unauthorized_provider()
    }

    /// The semantics a case relies on for a handle of `kind`: the handle's own `declared`
    /// [`KeySemantics`]. A handle that declares none fails the case: every handle a backend
    /// opens for a key family states its semantics.
    pub(crate) fn semantics_or_caps(
        &self,
        declared: Option<&KeySemantics>,
        kind: TestKeyKind,
    ) -> Result<KeySemantics, String> {
        declared.cloned().ok_or_else(|| {
            format!("the {kind:?} handle declares no KeySemantics (Semantics::semantics is None)")
        })
    }

    /// The semantics of `key`'s handle on this path (see
    /// [`semantics_or_caps`](Self::semantics_or_caps)): the AEAD, key-wrapping, MAC or signing
    /// handle of the key's kind, opened without I/O.
    pub(crate) fn semantics(&self, key: &TestKey) -> Result<KeySemantics, String> {
        let declared = self.declared_semantics(key).ctx("open for semantics")?;
        self.semantics_or_caps(declared.as_ref(), key.kind)
    }

    /// The [`KeySemantics`] the handle of `key`'s kind declares on this path, if any.
    pub(crate) fn declared_semantics(
        &self,
        key: &TestKey,
    ) -> anykms_core::Result<Option<KeySemantics>> {
        Ok(match key.kind {
            TestKeyKind::Aead => self.aead(&key.uri)?.semantics().cloned(),
            TestKeyKind::KeyWrap => self.key_wrap(&key.uri)?.semantics().cloned(),
            TestKeyKind::Hmac(alg) => self.mac(&key.uri, alg)?.semantics().cloned(),
            TestKeyKind::Signing(alg) if alg.is_message_signing() => {
                self.message_signer(&key.uri, alg)?.semantics().cloned()
            }
            TestKeyKind::Signing(alg) => self.digest_signer(&key.uri, alg)?.semantics().cloned(),
        })
    }
}

/// Converts an anykms result into a case result with context.
pub(crate) trait Check<T> {
    fn ctx(self, what: &str) -> Result<T, String>;
}

impl<T> Check<T> for anykms_core::Result<T> {
    fn ctx(self, what: &str) -> Result<T, String> {
        self.map_err(|e| format!("{what}: unexpected error: {e}"))
    }
}

/// Asserts that `r` failed with `kind`.
pub(crate) fn expect_kind<T>(
    r: anykms_core::Result<T>,
    kind: ErrorKind,
    what: &str,
) -> Result<Error, String> {
    match r {
        Ok(_) => Err(format!("{what}: expected {kind}, got success")),
        Err(e) if e.kind() == kind => Ok(e),
        Err(e) => Err(format!("{what}: expected {kind}, got {}: {e}", e.kind())),
    }
}

/// Like [`expect_kind`], and the error must name the key it is about ([`Error::resource`]): every
/// backend labels its operation errors with the key, including errors from checks it makes
/// before any request.
pub(crate) fn expect_kind_named<T>(
    r: anykms_core::Result<T>,
    kind: ErrorKind,
    what: &str,
) -> Result<Error, String> {
    let e = expect_kind(r, kind, what)?;
    if e.resource().is_none() {
        return Err(format!(
            "{what}: the {kind} error does not name the key: {e}"
        ));
    }
    Ok(e)
}

macro_rules! ensure {
    ($cond:expr, $($fmt:tt)+) => {
        if !$cond {
            return Err(format!($($fmt)+));
        }
    };
}
pub(crate) use ensure;
