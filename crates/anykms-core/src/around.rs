//! One type-erased [`Call`] per operation, through layers.
//!
//! A [`Layer`](crate::Layer) that only needs to see operations (count them, time them, retry
//! them) implements [`Around`] once and decorates every part of a handle with
//! [`Part::wrap_around`], instead of writing a decorator per capability trait: the decorators
//! core installs build a [`Call`] for each async method and pass it through
//! [`Around::around`]. Sync methods (`ciphertext_version`, `signature_algorithm`,
//! `wrapped_key_version`, `mac_algorithm`) are forwarded by core and never reach the layer.

use std::any::Any;
use std::fmt;
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::dynamic::{
    BoxFuture, DynAead, DynDataKeys, DynDescribe, DynDigestSigner, DynDigestVerifier,
    DynExtensionCalls, DynKeyWrap, DynMac, DynMessageSigner, DynMessageVerifier, DynPreflight,
    DynPublicKeys, DynRewrap, DynWrappedDataKeys, LayerCx, Part, PartKind,
};
use crate::{
    Aead, Ciphertext, DataKey, DataKeySpec, DataKeys, Decrypted, Describe, Digest, DigestSigner,
    DigestVerifier, Error, ErrorKind, ExtensionCalls, KeyInfo, KeyVersion, KeyWrap, Mac,
    MacAlgorithm, MessageSigner, MessageVerifier, Operation, Preflight, PublicKey, PublicKeys,
    Result, Rewrap, Signature, SignatureAlgorithm, Tag, WrappedDataKeys,
};

/// The result of a [`Call`], type-erased so that layers can pass it through without knowing the
/// part's types. Only core (or the handle's `call_extension`) takes the value out again.
pub struct CallOutput(Box<dyn Any + Send>);

impl CallOutput {
    /// Erases `value`.
    pub fn new<T: Any + Send>(value: T) -> Self {
        Self(Box::new(value))
    }

    /// The value, if it is a `T`.
    pub(crate) fn downcast<T: Any>(self) -> std::result::Result<T, Self> {
        match self.0.downcast::<T>() {
            Ok(v) => Ok(*v),
            Err(b) => Err(Self(b)),
        }
    }
}

impl fmt::Debug for CallOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallOutput").finish_non_exhaustive()
    }
}

/// Runs one attempt of a call: a closure, erased.
///
/// The future borrows the runner only, so a [`Call`] holding `&'a dyn RunCall` is covariant in
/// `'a` and can be lent to a layer for any shorter lifetime.
pub(crate) trait RunCall: Send + Sync {
    fn run(&self) -> BoxFuture<'_, Result<CallOutput>>;
}

/// A closure `f` returning futures of `R` that live for `'a`, erased into [`RunCall`].
pub(crate) struct Erased<'a, F, R>(
    pub(crate) F,
    pub(crate) std::marker::PhantomData<fn() -> &'a R>,
);

impl<'a, F, R> RunCall for Erased<'a, F, R>
where
    F: Fn() -> BoxFuture<'a, Result<R>> + Send + Sync,
    R: Send + 'static,
{
    fn run(&self) -> BoxFuture<'_, Result<CallOutput>> {
        let fut = (self.0)();
        Box::pin(async move { fut.await.map(CallOutput::new) })
    }
}

/// A closure that already returns [`CallOutput`] (an inner extension slot), erased without a
/// second box.
struct ErasedOutput<'a, F>(F, std::marker::PhantomData<fn() -> &'a ()>);

impl<'a, F> RunCall for ErasedOutput<'a, F>
where
    F: Fn() -> BoxFuture<'a, Result<CallOutput>> + Send + Sync,
{
    fn run(&self) -> BoxFuture<'_, Result<CallOutput>> {
        (self.0)()
    }
}

/// One operation of one part, as an [`Around`] layer sees it: what it is ([`part`](Self::part),
/// [`operation`](Self::operation), [`name`](Self::name)) and how to run it
/// ([`run`](Self::run), once per attempt).
///
/// Cheap to copy: a retrying layer runs the same call once per attempt.
#[derive(Clone, Copy)]
pub struct Call<'a> {
    pub(crate) part: PartKind,
    pub(crate) op: Operation,
    pub(crate) name: &'static str,
    pub(crate) run: &'a dyn RunCall,
}

impl<'a> Call<'a> {
    /// The part whose method this is ([`PartKind::Extension`] for backend-specific calls).
    pub fn part(&self) -> PartKind {
        self.part
    }

    /// The portable operation the call performs (`Encrypt`, `Decrypt`, ...), for retry
    /// decisions, metrics and labels.
    pub fn operation(&self) -> Operation {
        self.op
    }

    /// The method's name (`"encrypt"`, `"sign_digest"`, ...), or for a backend-specific call
    /// the backend's stable, non-secret name of it (e.g. `"aws.encrypt_with_context"`).
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Runs the call once (one attempt against the backend). Only a retrying layer may call it
    /// again, and never concurrently.
    pub fn run(&self) -> BoxFuture<'a, Result<CallOutput>> {
        self.run.run()
    }
}

impl fmt::Debug for Call<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Call")
            .field("part", &self.part)
            .field("op", &self.op)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// What an [`Around`] layer knows about the handle a call belongs to.
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct CallCx {
    backend: Option<&'static str>,
    resource: Option<Arc<str>>,
}

impl CallCx {
    /// A context with no backend and no resource (e.g. to test an [`Around`] directly).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the backend name.
    pub fn with_backend(mut self, backend: &'static str) -> Self {
        self.backend = Some(backend);
        self
    }

    /// Sets the resource.
    pub fn with_resource(mut self, resource: impl Into<Arc<str>>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// The backend name of the handle, as in errors and `Debug` output.
    pub fn backend(&self) -> Option<&'static str> {
        self.backend
    }

    /// The key the handle opens (see [`LayerCx::resource`]).
    pub fn resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }
}

impl From<&LayerCx<'_>> for CallCx {
    fn from(cx: &LayerCx<'_>) -> Self {
        Self {
            backend: Some(cx.backend),
            resource: cx.resource.map(Arc::from),
        }
    }
}

/// Intercepts every operation of the parts it decorates ([`Part::wrap_around`]).
///
/// `around` gets each call once and returns its result: run it with [`Call::run`] (once, or
/// again per retry attempt), or fail without running it. It must return the [`CallOutput`] that
/// `run` produced; a value of another type is a `Backend` error ("an interceptor returned a
/// value of an unexpected type").
pub trait Around: Send + Sync + 'static {
    /// Runs `call` for a handle described by `cx`.
    fn around<'a>(&'a self, cx: &'a CallCx, call: Call<'a>) -> BoxFuture<'a, Result<CallOutput>>;
}

impl fmt::Debug for dyn Around + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Around").finish_non_exhaustive()
    }
}

/// The error for an output of an unexpected type.
fn mismatch(backend: Option<&'static str>, op: Operation) -> Error {
    Error::new(
        ErrorKind::Backend,
        backend.unwrap_or("anykms"),
        op,
        "an interceptor returned a value of an unexpected type",
    )
}

/// A part decorated with an [`Around`]: every async method becomes a [`Call`].
struct Arounded<D: ?Sized> {
    inner: Arc<D>,
    around: Arc<dyn Around>,
    cx: Arc<CallCx>,
}

impl<D: ?Sized> Arounded<D> {
    /// Runs `f` (one attempt per call) through the interceptor and takes the `R` out again.
    async fn call<'a, R: Send + 'static>(
        &'a self,
        part: PartKind,
        op: Operation,
        name: &'static str,
        f: impl Fn() -> BoxFuture<'a, Result<R>> + Send + Sync + 'a,
    ) -> Result<R> {
        let erased = Erased(f, std::marker::PhantomData);
        let call = Call {
            part,
            op,
            name,
            run: &erased,
        };
        let out = self.around.around(&self.cx, call).await?;
        out.downcast::<R>()
            .map_err(|_| mismatch(self.cx.backend(), op))
    }
}

impl Aead for Arounded<dyn DynAead> {
    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
        let i = &self.inner;
        self.call(PartKind::Aead, Operation::Encrypt, "encrypt", move || {
            i.dyn_encrypt(plaintext, aad)
        })
        .await
    }

    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let i = &self.inner;
        self.call(PartKind::Aead, Operation::Decrypt, "decrypt", move || {
            i.dyn_decrypt(ct, aad)
        })
        .await
    }

    fn ciphertext_version(&self, ct: &Ciphertext) -> Result<Option<KeyVersion>> {
        self.inner.dyn_ciphertext_version(ct)
    }

    async fn decrypt_with_info(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Decrypted> {
        let i = &self.inner;
        self.call(
            PartKind::Aead,
            Operation::Decrypt,
            "decrypt_with_info",
            move || i.dyn_decrypt_with_info(ct, aad),
        )
        .await
    }
}

impl Rewrap for Arounded<dyn DynRewrap> {
    async fn rewrap(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext> {
        let i = &self.inner;
        self.call(PartKind::Rewrap, Operation::Rewrap, "rewrap", move || {
            i.dyn_rewrap(ct, aad)
        })
        .await
    }
}

impl DataKeys for Arounded<dyn DynDataKeys> {
    async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey> {
        let i = &self.inner;
        self.call(
            PartKind::DataKeys,
            Operation::GenerateDataKey,
            "generate_data_key",
            move || i.dyn_generate_data_key(spec, aad),
        )
        .await
    }
}

impl WrappedDataKeys for Arounded<dyn DynWrappedDataKeys> {
    async fn generate_wrapped_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<Ciphertext> {
        let i = &self.inner;
        self.call(
            PartKind::WrappedDataKeys,
            Operation::GenerateDataKey,
            "generate_wrapped_data_key",
            move || i.dyn_generate_wrapped_data_key(spec, aad),
        )
        .await
    }
}

impl DigestSigner for Arounded<dyn DynDigestSigner> {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.inner.dyn_signature_algorithm()
    }

    async fn sign_digest(&self, digest: &Digest) -> Result<Signature> {
        let i = &self.inner;
        self.call(
            PartKind::DigestSigner,
            Operation::Sign,
            "sign_digest",
            move || i.dyn_sign_digest(digest),
        )
        .await
    }
}

impl MessageSigner for Arounded<dyn DynMessageSigner> {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.inner.dyn_signature_algorithm()
    }

    async fn sign_message(&self, msg: &[u8]) -> Result<Signature> {
        let i = &self.inner;
        self.call(
            PartKind::MessageSigner,
            Operation::Sign,
            "sign_message",
            move || i.dyn_sign_message(msg),
        )
        .await
    }
}

impl DigestVerifier for Arounded<dyn DynDigestVerifier> {
    async fn verify_digest(&self, digest: &Digest, sig: &Signature) -> Result<()> {
        let i = &self.inner;
        self.call(
            PartKind::DigestVerifier,
            Operation::Verify,
            "verify_digest",
            move || i.dyn_verify_digest(digest, sig),
        )
        .await
    }
}

impl MessageVerifier for Arounded<dyn DynMessageVerifier> {
    async fn verify_message(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        let i = &self.inner;
        self.call(
            PartKind::MessageVerifier,
            Operation::Verify,
            "verify_message",
            move || i.dyn_verify_message(msg, sig),
        )
        .await
    }
}

impl Mac for Arounded<dyn DynMac> {
    fn mac_algorithm(&self) -> MacAlgorithm {
        self.inner.dyn_mac_algorithm()
    }

    async fn mac(&self, data: &[u8]) -> Result<Tag> {
        let i = &self.inner;
        self.call(PartKind::Mac, Operation::Mac, "mac", move || {
            i.dyn_mac(data)
        })
        .await
    }

    async fn verify_mac(&self, data: &[u8], tag: &Tag) -> Result<()> {
        let i = &self.inner;
        self.call(
            PartKind::Mac,
            Operation::VerifyMac,
            "verify_mac",
            move || i.dyn_verify_mac(data, tag),
        )
        .await
    }
}

impl PublicKeys for Arounded<dyn DynPublicKeys> {
    async fn public_key(&self) -> Result<PublicKey> {
        let i = &self.inner;
        self.call(
            PartKind::PublicKeys,
            Operation::PublicKey,
            "public_key",
            move || i.dyn_public_key(),
        )
        .await
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        let i = &self.inner;
        self.call(
            PartKind::PublicKeys,
            Operation::PublicKey,
            "public_key_version",
            move || i.dyn_public_key_version(version),
        )
        .await
    }
}

impl Describe for Arounded<dyn DynDescribe> {
    async fn describe(&self) -> Result<KeyInfo> {
        let i = &self.inner;
        self.call(
            PartKind::Describe,
            Operation::Describe,
            "describe",
            move || i.dyn_describe(),
        )
        .await
    }
}

impl Preflight for Arounded<dyn DynPreflight> {
    async fn preflight(&self) -> Result<KeyInfo> {
        let i = &self.inner;
        self.call(
            PartKind::Preflight,
            Operation::Describe,
            "preflight",
            move || i.dyn_preflight(),
        )
        .await
    }
}

impl KeyWrap for Arounded<dyn DynKeyWrap> {
    fn wrapped_key_version(&self, wrapped: &Ciphertext) -> Result<Option<KeyVersion>> {
        self.inner.dyn_wrapped_key_version(wrapped)
    }

    async fn wrap_key(&self, key: &[u8]) -> Result<Ciphertext> {
        let i = &self.inner;
        self.call(
            PartKind::KeyWrap,
            Operation::WrapKey,
            "wrap_key",
            move || i.dyn_wrap_key(key),
        )
        .await
    }

    async fn unwrap_key(&self, wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
        let i = &self.inner;
        self.call(
            PartKind::KeyWrap,
            Operation::UnwrapKey,
            "unwrap_key",
            move || i.dyn_unwrap_key(wrapped),
        )
        .await
    }
}

/// A backend-specific call: the interceptor sees it with its own operation and name, and running
/// it runs the inner slot (the next layer, or the backend's closure).
impl ExtensionCalls for Arounded<dyn DynExtensionCalls> {
    async fn run_extension(&self, call: Call<'_>) -> Result<CallOutput> {
        let i = &self.inner;
        let run = ErasedOutput(move || i.dyn_run_extension(call), std::marker::PhantomData);
        let wrapped = Call {
            part: PartKind::Extension,
            op: call.op,
            name: call.name,
            run: &run,
        };
        self.around.around(&self.cx, wrapped).await
    }
}

impl Part<'_> {
    /// Decorates this part, whatever its kind, so that every async method goes through
    /// `around` as a [`Call`]. The usual body of a [`Layer::part`](crate::Layer::part) that
    /// only needs to see operations: `part.wrap_around(cx, self.around.clone())`.
    pub fn wrap_around(self, cx: &LayerCx<'_>, around: Arc<dyn Around>) {
        let cx = Arc::new(CallCx::from(cx));
        macro_rules! wrap {
            ($p:ident) => {
                *$p = Arc::new(Arounded {
                    inner: $p.clone(),
                    around,
                    cx,
                })
            };
        }
        match self {
            Part::Aead(p) => wrap!(p),
            Part::Rewrap(p) => wrap!(p),
            Part::DataKeys(p) => wrap!(p),
            Part::DigestSigner(p) => wrap!(p),
            Part::MessageSigner(p) => wrap!(p),
            Part::DigestVerifier(p) => wrap!(p),
            Part::MessageVerifier(p) => wrap!(p),
            Part::Mac(p) => wrap!(p),
            Part::PublicKeys(p) => wrap!(p),
            Part::Describe(p) => wrap!(p),
            Part::KeyWrap(p) => wrap!(p),
            Part::WrappedDataKeys(p) => wrap!(p),
            Part::Extension(p) => wrap!(p),
            Part::Preflight(p) => wrap!(p),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::dynamic::{DescribeKey, Layer};
    use crate::{
        AeadKey, AsymmetricKeyType, Capabilities, DigestSignerKey, HashAlgorithm, KeyState,
        KeyWrapKey, MacKey, MessageSignerKey, PublicKeysKey,
    };

    /// One stand-in for every capability trait.
    struct All;

    impl Aead for All {
        async fn encrypt(&self, pt: &[u8], _: &[u8]) -> Result<Ciphertext> {
            Ok(Ciphertext::from_bytes(pt.to_vec()))
        }
        async fn decrypt(&self, ct: &Ciphertext, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(ct.as_bytes().to_vec()))
        }
        fn ciphertext_version(&self, _: &Ciphertext) -> Result<Option<KeyVersion>> {
            Ok(Some(KeyVersion::from_u64(7)))
        }
    }
    impl Rewrap for All {
        async fn rewrap(&self, ct: &Ciphertext, _: &[u8]) -> Result<Ciphertext> {
            Ok(ct.clone())
        }
    }
    impl DataKeys for All {
        async fn generate_data_key(&self, _: DataKeySpec, _: &[u8]) -> Result<DataKey> {
            DataKey::new(
                DataKeySpec::Aes256,
                Zeroizing::new(vec![0; 32]),
                Ciphertext::from_bytes(vec![1]),
            )
        }
    }
    impl WrappedDataKeys for All {
        async fn generate_wrapped_data_key(&self, _: DataKeySpec, _: &[u8]) -> Result<Ciphertext> {
            Ok(Ciphertext::from_bytes(vec![1]))
        }
    }
    fn sig() -> Signature {
        Signature::from_parts(SignatureAlgorithm::EcdsaP256Sha256, None, vec![1])
    }
    impl DigestSigner for All {
        fn signature_algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::EcdsaP256Sha256
        }
        async fn sign_digest(&self, _: &Digest) -> Result<Signature> {
            Ok(sig())
        }
    }
    impl MessageSigner for All {
        fn signature_algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::Ed25519
        }
        async fn sign_message(&self, _: &[u8]) -> Result<Signature> {
            Ok(sig())
        }
    }
    impl DigestVerifier for All {
        async fn verify_digest(&self, _: &Digest, _: &Signature) -> Result<()> {
            Ok(())
        }
    }
    impl MessageVerifier for All {
        async fn verify_message(&self, _: &[u8], _: &Signature) -> Result<()> {
            Ok(())
        }
    }
    impl Mac for All {
        fn mac_algorithm(&self) -> MacAlgorithm {
            MacAlgorithm::HmacSha256
        }
        async fn mac(&self, _: &[u8]) -> Result<Tag> {
            Ok(Tag::from_parts(MacAlgorithm::HmacSha256, None, vec![0; 32]))
        }
        async fn verify_mac(&self, _: &[u8], _: &Tag) -> Result<()> {
            Ok(())
        }
    }
    fn pk() -> PublicKey {
        PublicKey::new(AsymmetricKeyType::Ed25519, vec![1], None)
    }
    impl PublicKeys for All {
        async fn public_key(&self) -> Result<PublicKey> {
            Ok(pk())
        }
        async fn public_key_version(&self, _: &KeyVersion) -> Result<PublicKey> {
            Ok(pk())
        }
    }
    impl Describe for All {
        async fn describe(&self) -> Result<KeyInfo> {
            Ok(KeyInfo::new("all", Capabilities::AEAD).with_state(Some(KeyState::Enabled)))
        }
    }
    impl KeyWrap for All {
        fn wrapped_key_version(&self, _: &Ciphertext) -> Result<Option<KeyVersion>> {
            Ok(Some(KeyVersion::from_u64(9)))
        }
        async fn wrap_key(&self, key: &[u8]) -> Result<Ciphertext> {
            Ok(Ciphertext::from_bytes(key.to_vec()))
        }
        async fn unwrap_key(&self, w: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(w.as_bytes().to_vec()))
        }
    }

    type Seen = Arc<Mutex<Vec<(PartKind, Operation, &'static str)>>>;

    /// Records every call and runs it once.
    #[derive(Clone, Default)]
    struct Record(Seen);

    impl Around for Record {
        fn around<'a>(
            &'a self,
            cx: &'a CallCx,
            call: Call<'a>,
        ) -> BoxFuture<'a, Result<CallOutput>> {
            assert_eq!(cx.backend(), Some("all"));
            self.0
                .lock()
                .unwrap()
                .push((call.part(), call.operation(), call.name()));
            call.run()
        }
    }

    impl Layer for Record {
        fn part(&self, cx: &LayerCx<'_>, part: Part<'_>) {
            part.wrap_around(cx, Arc::new(self.clone()));
        }
    }

    /// A `part`-only layer intercepts every part kind, with the operation and method name of each
    /// async method; sync methods are forwarded through two layers without reaching them.
    #[tokio::test]
    async fn every_part_kind_goes_through_around() {
        let r = Record::default();
        let all = Arc::new(All);
        let ct = Ciphertext::from_bytes(vec![1]);
        let d = Digest::new(HashAlgorithm::Sha256, &[0; 32]).unwrap();
        let v = KeyVersion::from_u64(1);
        let spec = DataKeySpec::Aes256;

        let aead = AeadKey::new("all", all.clone())
            .with_rewrap(all.clone())
            .with_data_keys(all.clone())
            .with_describe(all.clone())
            .with_wrapped_data_keys(all.clone())
            .layer(&r)
            .layer(&r);
        aead.encrypt(b"p", b"").await.unwrap();
        aead.decrypt(&ct, b"").await.unwrap();
        aead.decrypt_with_info(&ct, b"").await.unwrap();
        aead.rewrap(&ct, b"").await.unwrap();
        aead.generate_data_key(spec, b"").await.unwrap();
        aead.generate_wrapped_data_key(spec, b"").await.unwrap();
        aead.describe().await.unwrap();
        // Sync methods never reach the layer, through two of them.
        assert_eq!(
            aead.ciphertext_version(&ct).unwrap(),
            Some(KeyVersion::from_u64(7))
        );

        let ds = DigestSignerKey::new("all", all.clone())
            .with_verifier(all.clone())
            .with_public_keys(all.clone())
            .layer(&r);
        ds.sign_digest(&d).await.unwrap();
        ds.verify_digest(&d, &sig()).await.unwrap();
        ds.public_key().await.unwrap();
        ds.public_key_version(&v).await.unwrap();
        assert_eq!(
            ds.signature_algorithm(),
            SignatureAlgorithm::EcdsaP256Sha256
        );

        let ms = MessageSignerKey::new("all", all.clone())
            .with_verifier(all.clone())
            .layer(&r);
        ms.sign_message(b"m").await.unwrap();
        ms.verify_message(b"m", &sig()).await.unwrap();

        let mac = MacKey::new("all", all.clone()).layer(&r);
        let t = mac.mac(b"m").await.unwrap();
        mac.verify_mac(b"m", &t).await.unwrap();
        assert_eq!(mac.mac_algorithm(), MacAlgorithm::HmacSha256);

        let kw = KeyWrapKey::new("all", all.clone()).layer(&r);
        let w = kw.wrap_key(b"k").await.unwrap();
        kw.unwrap_key(&w).await.unwrap();
        assert_eq!(
            kw.wrapped_key_version(&w).unwrap(),
            Some(KeyVersion::from_u64(9))
        );

        PublicKeysKey::new("all", all.clone())
            .layer(&r)
            .public_key()
            .await
            .unwrap();
        DescribeKey::new("all", all.clone())
            .layer(&r)
            .describe()
            .await
            .unwrap();
        aead.call_extension(Operation::Encrypt, "all.ext", || {
            Box::pin(async { Ok(1u8) })
        })
        .await
        .unwrap();

        use Operation as O;
        use PartKind as P;
        let seen = r.0.lock().unwrap().clone();
        let two = |p, o, n| [(p, o, n), (p, o, n)];
        let mut want = Vec::new();
        for (p, o, n) in [
            (P::Aead, O::Encrypt, "encrypt"),
            (P::Aead, O::Decrypt, "decrypt"),
            (P::Aead, O::Decrypt, "decrypt_with_info"),
            (P::Rewrap, O::Rewrap, "rewrap"),
            (P::DataKeys, O::GenerateDataKey, "generate_data_key"),
            (
                P::WrappedDataKeys,
                O::GenerateDataKey,
                "generate_wrapped_data_key",
            ),
            (P::Describe, O::Describe, "describe"),
        ] {
            // The AEAD handle has two layers: each sees the call.
            want.extend(two(p, o, n));
        }
        want.extend([
            (P::DigestSigner, O::Sign, "sign_digest"),
            (P::DigestVerifier, O::Verify, "verify_digest"),
            (P::PublicKeys, O::PublicKey, "public_key"),
            (P::PublicKeys, O::PublicKey, "public_key_version"),
            (P::MessageSigner, O::Sign, "sign_message"),
            (P::MessageVerifier, O::Verify, "verify_message"),
            (P::Mac, O::Mac, "mac"),
            (P::Mac, O::VerifyMac, "verify_mac"),
            (P::KeyWrap, O::WrapKey, "wrap_key"),
            (P::KeyWrap, O::UnwrapKey, "unwrap_key"),
            (P::PublicKeys, O::PublicKey, "public_key"),
            (P::Describe, O::Describe, "describe"),
        ]);
        want.extend(two(P::Extension, O::Encrypt, "all.ext"));
        assert_eq!(seen, want);
        let kinds: std::collections::HashSet<_> = seen.iter().map(|s| s.0).collect();
        assert_eq!(kinds.len(), 13, "every PartKind is intercepted: {kinds:?}");
    }

    /// An interceptor that returns another value than the call produced: `Backend`.
    #[tokio::test]
    async fn an_output_of_another_type_is_a_backend_error() {
        struct Swap;
        impl Around for Swap {
            fn around<'a>(
                &'a self,
                _: &'a CallCx,
                _: Call<'a>,
            ) -> BoxFuture<'a, Result<CallOutput>> {
                Box::pin(async { Ok(CallOutput::new("not a ciphertext")) })
            }
        }
        #[derive(Clone)]
        struct L;
        impl Layer for L {
            fn part(&self, cx: &LayerCx<'_>, part: Part<'_>) {
                part.wrap_around(cx, Arc::new(Swap));
            }
        }
        let k = AeadKey::new("all", Arc::new(All)).layer(&L);
        let e = k.encrypt(b"p", b"").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Backend);
        assert_eq!(e.operation(), Operation::Encrypt);
        assert!(e.to_string().contains("unexpected type"), "{e}");
    }

    fn assert_send<T: Send>(t: T) -> T {
        t
    }

    /// Calls through `Around` layers stay `Send`, with borrowed inputs.
    #[tokio::test]
    async fn futures_are_send() {
        let k = AeadKey::new("all", Arc::new(All))
            .layer(&Record::default())
            .layer(&crate::RetryLayer::new(crate::instant_sleep()));
        let pt = vec![1u8];
        let ct = assert_send(k.encrypt(&pt, b"aad")).await.unwrap();
        assert_send(k.decrypt(&ct, b"aad")).await.unwrap();
        let handle = tokio::spawn(async move { k.encrypt(b"x", b"").await.map(|_| ()) });
        handle.await.unwrap().unwrap();
    }
}

#[cfg(test)]
mod preflight_tests {
    use super::*;
    use crate::{AeadKey, Capabilities, KeyState, KeyWrapKey};

    #[derive(Debug, PartialEq)]
    struct BackendMeta(u32);

    /// A backend check: returns metadata with the backend's struct attached.
    struct Checked;
    impl Preflight for Checked {
        async fn preflight(&self) -> Result<KeyInfo> {
            Ok(
                KeyInfo::new("checked", Capabilities::AEAD | Capabilities::KEY_WRAP)
                    .with_backend_info(BackendMeta(7)),
            )
        }
    }

    /// A backend check that passes but reports the given capabilities and state.
    struct Reports(Capabilities, Option<KeyState>);
    impl Preflight for Reports {
        async fn preflight(&self) -> Result<KeyInfo> {
            Ok(KeyInfo::new("reports", self.0).with_state(self.1.clone()))
        }
    }
    struct Plain;
    impl Aead for Plain {
        async fn encrypt(&self, pt: &[u8], _: &[u8]) -> Result<Ciphertext> {
            Ok(Ciphertext::from_bytes(pt.to_vec()))
        }
        async fn decrypt(&self, ct: &Ciphertext, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(ct.as_bytes().to_vec()))
        }
    }

    #[test]
    fn key_info_carries_backend_metadata() {
        let a = KeyInfo::new("t", Capabilities::AEAD).with_backend_info(BackendMeta(1));
        assert_eq!(a.backend_info::<BackendMeta>(), Some(&BackendMeta(1)));
        assert_eq!(a.backend_info::<u8>(), None);
        assert_eq!(
            a.backend_info_type_id(),
            Some(std::any::TypeId::of::<BackendMeta>())
        );
        // Equality ignores it; Debug prints it.
        assert_eq!(a, KeyInfo::new("t", Capabilities::AEAD));
        assert!(format!("{a:?}").contains("BackendMeta(1)"));
        assert_eq!(
            KeyInfo::new("t", Capabilities::AEAD).backend_info_type_id(),
            None
        );
    }

    /// The part replaces the generic check, through layers and `from_aead`; without it, a handle
    /// with no describe part is `Unsupported`.
    #[tokio::test]
    async fn the_preflight_part_runs_the_backend_check() {
        let bare = AeadKey::new("t", Arc::new(Plain));
        assert!(!bare.supports_preflight());
        assert_eq!(
            bare.preflight().await.unwrap_err().kind(),
            ErrorKind::Unsupported
        );

        let k = AeadKey::new("t", Arc::new(Plain))
            .with_preflight(Arc::new(Checked))
            .layer(&crate::RetryLayer::new(crate::instant_sleep()));
        assert!(k.supports_preflight());
        let info = k.preflight().await.unwrap();
        assert_eq!(info.backend_info::<BackendMeta>(), Some(&BackendMeta(7)));
        let kek = KeyWrapKey::from_aead(k);
        assert!(kek.supports_preflight());
        assert_eq!(
            kek.preflight().await.unwrap().backend_info::<BackendMeta>(),
            Some(&BackendMeta(7))
        );
    }

    /// The capability and state checks run after the backend's part too, labelled `Describe`,
    /// both through the inherent method and through the `Preflight` trait.
    #[tokio::test]
    async fn the_preflight_part_is_post_checked() {
        let aead = |caps, state| {
            AeadKey::new("t", Arc::new(Plain)).with_preflight(Arc::new(Reports(caps, state)))
        };
        for state in [
            KeyState::Disabled,
            KeyState::PendingDeletion,
            KeyState::Destroyed,
        ] {
            let k = aead(Capabilities::AEAD, Some(state));
            let e = k.preflight().await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::KeyStateInvalid);
            assert_eq!(e.operation(), Operation::Describe);
            assert_eq!(e.backend(), "t");
            let e = Preflight::preflight(&k).await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::KeyStateInvalid);
        }
        aead(Capabilities::AEAD, Some(KeyState::Enabled))
            .preflight()
            .await
            .unwrap();

        // A KEK whose key cannot wrap.
        let kek = KeyWrapKey::from_aead(aead(Capabilities::AEAD, None));
        let e = kek.preflight().await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::KeyMismatch);
        assert_eq!(e.operation(), Operation::Describe);
        let kek = KeyWrapKey::from_aead(aead(Capabilities::AEAD | Capabilities::KEY_WRAP, None));
        Preflight::preflight(&kek).await.unwrap();

        // The part's own error passes through unchanged.
        struct Refuses;
        impl Preflight for Refuses {
            async fn preflight(&self) -> Result<KeyInfo> {
                Err(Error::new(
                    ErrorKind::NotFound,
                    "b",
                    Operation::Describe,
                    "no such key",
                ))
            }
        }
        let e = AeadKey::new("t", Arc::new(Plain))
            .with_preflight(Arc::new(Refuses))
            .preflight()
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotFound);
    }

    /// Every opaque handle implements `Preflight`.
    #[test]
    fn opaque_handles_implement_preflight() {
        fn check<K: Preflight>() {}
        check::<crate::AeadKey>();
        check::<crate::KeyWrapKey>();
        check::<crate::DataKeysKey>();
        check::<crate::DigestSignerKey>();
        check::<crate::MessageSignerKey>();
        check::<crate::DigestVerifierKey>();
        check::<crate::MessageVerifierKey>();
        check::<crate::MacKey>();
        check::<crate::PublicKeysKey>();
        check::<crate::DescribeKey>();
    }
}
