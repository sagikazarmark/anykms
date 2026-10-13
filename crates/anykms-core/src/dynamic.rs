//! Object-safe mirrors of the capability traits, and the opaque handles providers return.
//!
//! For each capability trait `X` there is a `DynX` trait with `dyn_*` methods returning boxed
//! futures, a blanket `impl<T: X> DynX for T`, and bridges `impl X for dyn DynX` and
//! `impl X for Arc<T>`, `&T` and `Box<T>`. Callers always use the static method names
//! (`encrypt`, not `dyn_encrypt`), so `Arc<dyn DynAead>` can be used exactly like a typed handle
//! and composed into recipes, and a handle can be lent to a recipe (`EnvelopeAead<&AeadKey>`).
//!
//! ```
//! use anykms_core::{Aead, AeadKey};
//! fn takes_aead<K: Aead>(_: K) {}
//! fn lend(k: &AeadKey, boxed: Box<AeadKey>, shared: std::sync::Arc<AeadKey>) {
//!     takes_aead(k);
//!     takes_aead(boxed);
//!     takes_aead(shared);
//! }
//! ```
//!
//! The `DynX` traits are sealed: implement the static trait and the blanket impl provides
//! `DynX`. That way new provided methods can be forwarded without breaking anyone.
//!
//! ```compile_fail
//! struct Mine;
//! impl anykms_core::DynDescribe for Mine {
//!     fn dyn_describe<'a>(
//!         &'a self,
//!     ) -> anykms_core::BoxFuture<'a, anykms_core::Result<anykms_core::KeyInfo>> {
//!         unimplemented!()
//!     }
//! }
//! ```
//!
//! Providers return opaque handles ([`AeadKey`], [`DigestSignerKey`], ...) rather than bare
//! `Arc<dyn DynX>`: each holds the main capability plus optional parts (public keys, describe,
//! ...) that fail with `Unsupported` before any I/O when missing. A [`Layer`] decorates every
//! part of a handle (retries, metrics) without changing which parts it has.

use std::any::Any;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::around::{Call, CallOutput, Erased};
use crate::error::{Error, ErrorKind, Operation, Result};
use crate::semantics::{KeySemantics, Semantics};
use crate::traits::*;
use crate::types::*;

/// A boxed, `Send` future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Seals the `DynX` traits: each has the supertrait `Sealed<marker>`, implemented only by the
/// blanket impls below, and this module is private.
mod sealed {
    pub trait Sealed<M> {}

    #[derive(Debug)]
    pub enum Aead {}
    #[derive(Debug)]
    pub enum Rewrap {}
    #[derive(Debug)]
    pub enum DataKeys {}
    #[derive(Debug)]
    pub enum DigestSigner {}
    #[derive(Debug)]
    pub enum MessageSigner {}
    #[derive(Debug)]
    pub enum DigestVerifier {}
    #[derive(Debug)]
    pub enum MessageVerifier {}
    #[derive(Debug)]
    pub enum Mac {}
    #[derive(Debug)]
    pub enum PublicKeys {}
    #[derive(Debug)]
    pub enum Describe {}
    #[derive(Debug)]
    pub enum KeyWrap {}
    #[derive(Debug)]
    pub enum WrappedDataKeys {}
    #[derive(Debug)]
    pub enum ExtensionCalls {}
    #[derive(Debug)]
    pub enum Preflight {}
    #[derive(Debug)]
    pub enum Handle {}
}

// Generates the sealed DynX trait, the blanket impls, the bridges (`dyn DynX`, `Arc<T>`, `&T`,
// `Box<T>`) and `Debug` for `dyn DynX`.
// Async methods take only reference arguments; sync methods (including provided ones such as
// `ciphertext_version`) are forwarded explicitly so dyn callers never fall back to a trait
// default.
macro_rules! dyn_layer {
    (
        $(#[$meta:meta])*
        $X:ident => $DynX:ident {
            $( sync fn $s:ident / $ds:ident ( $($sa:ident : $sty:ty),* ) -> $sr:ty; )*
            $( async fn $m:ident / $dm:ident ( $($a:ident : & $ty:ty),* ) -> $r:ty; )*
        }
    ) => {
        $(#[$meta])*
        ///
        #[doc = concat!("Sealed: implemented for every `T` that implements [`", stringify!($X), "`]; implement the static trait instead.")]
        pub trait $DynX: sealed::Sealed<sealed::$X> + Send + Sync {
            $( #[doc(hidden)] fn $ds(&self, $($sa: $sty),*) -> $sr; )*
            $( #[doc(hidden)] fn $dm<'a>(&'a self, $($a: &'a $ty),*) -> BoxFuture<'a, $r>; )*
        }

        impl<T: $X> sealed::Sealed<sealed::$X> for T {}

        impl<T: $X> $DynX for T {
            $( fn $ds(&self, $($sa: $sty),*) -> $sr { <T as $X>::$s(self, $($sa),*) } )*
            $( fn $dm<'a>(&'a self, $($a: &'a $ty),*) -> BoxFuture<'a, $r> {
                Box::pin(<T as $X>::$m(self, $($a),*))
            } )*
        }

        impl<'x> $X for dyn $DynX + 'x {
            $( fn $s(&self, $($sa: $sty),*) -> $sr { $DynX::$ds(self, $($sa),*) } )*
            $( async fn $m(&self, $($a: &$ty),*) -> $r { $DynX::$dm(self, $($a),*).await } )*
        }

        impl<T: $X + ?Sized> $X for Arc<T> {
            $( fn $s(&self, $($sa: $sty),*) -> $sr { <T as $X>::$s(&**self, $($sa),*) } )*
            $( async fn $m(&self, $($a: &$ty),*) -> $r { <T as $X>::$m(&**self, $($a),*).await } )*
        }

        impl<T: $X + ?Sized> $X for Box<T> {
            $( fn $s(&self, $($sa: $sty),*) -> $sr { <T as $X>::$s(&**self, $($sa),*) } )*
            $( async fn $m(&self, $($a: &$ty),*) -> $r { <T as $X>::$m(&**self, $($a),*).await } )*
        }

        impl<T: $X + ?Sized> $X for &T {
            $( fn $s(&self, $($sa: $sty),*) -> $sr { <T as $X>::$s(&**self, $($sa),*) } )*
            $( async fn $m(&self, $($a: &$ty),*) -> $r { <T as $X>::$m(&**self, $($a),*).await } )*
        }

        impl fmt::Debug for dyn $DynX + '_ {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($DynX)).finish_non_exhaustive()
            }
        }
    };
}

dyn_layer! {
    /// Object-safe [`Aead`].
    Aead => DynAead {
        sync fn ciphertext_version / dyn_ciphertext_version(ct: &Ciphertext) -> Result<Option<KeyVersion>>;
        async fn encrypt / dyn_encrypt(plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext>;
        async fn decrypt / dyn_decrypt(ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
        async fn decrypt_with_info / dyn_decrypt_with_info(ct: &Ciphertext, aad: &[u8]) -> Result<Decrypted>;
    }
}

dyn_layer! {
    /// Object-safe [`Rewrap`].
    Rewrap => DynRewrap {
        async fn rewrap / dyn_rewrap(ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext>;
    }
}

dyn_layer! {
    /// Object-safe [`DigestSigner`].
    DigestSigner => DynDigestSigner {
        sync fn signature_algorithm / dyn_signature_algorithm() -> SignatureAlgorithm;
        async fn sign_digest / dyn_sign_digest(digest: &Digest) -> Result<Signature>;
    }
}

dyn_layer! {
    /// Object-safe [`MessageSigner`].
    MessageSigner => DynMessageSigner {
        sync fn signature_algorithm / dyn_signature_algorithm() -> SignatureAlgorithm;
        async fn sign_message / dyn_sign_message(msg: &[u8]) -> Result<Signature>;
    }
}

dyn_layer! {
    /// Object-safe [`DigestVerifier`].
    DigestVerifier => DynDigestVerifier {
        async fn verify_digest / dyn_verify_digest(digest: &Digest, sig: &Signature) -> Result<()>;
    }
}

dyn_layer! {
    /// Object-safe [`MessageVerifier`].
    MessageVerifier => DynMessageVerifier {
        async fn verify_message / dyn_verify_message(msg: &[u8], sig: &Signature) -> Result<()>;
    }
}

dyn_layer! {
    /// Object-safe [`Mac`].
    Mac => DynMac {
        sync fn mac_algorithm / dyn_mac_algorithm() -> MacAlgorithm;
        async fn mac / dyn_mac(data: &[u8]) -> Result<Tag>;
        async fn verify_mac / dyn_verify_mac(data: &[u8], tag: &Tag) -> Result<()>;
    }
}

dyn_layer! {
    /// Object-safe [`PublicKeys`].
    PublicKeys => DynPublicKeys {
        async fn public_key / dyn_public_key() -> Result<PublicKey>;
        async fn public_key_version / dyn_public_key_version(version: &KeyVersion) -> Result<PublicKey>;
    }
}

dyn_layer! {
    /// Object-safe [`Describe`].
    Describe => DynDescribe {
        async fn describe / dyn_describe() -> Result<KeyInfo>;
    }
}

dyn_layer! {
    /// Object-safe [`Preflight`].
    Preflight => DynPreflight {
        async fn preflight / dyn_preflight() -> Result<KeyInfo>;
    }
}

// DataKeys takes `spec` by value, which the macro does not handle; written out by hand.

/// Object-safe [`DataKeys`].
///
/// Sealed: implemented for every `T` that implements [`DataKeys`]; implement the static
/// trait instead.
pub trait DynDataKeys: sealed::Sealed<sealed::DataKeys> + Send + Sync {
    #[doc(hidden)]
    fn dyn_generate_data_key<'a>(
        &'a self,
        spec: DataKeySpec,
        aad: &'a [u8],
    ) -> BoxFuture<'a, Result<DataKey>>;
}

impl<T: DataKeys> sealed::Sealed<sealed::DataKeys> for T {}

impl<T: DataKeys> DynDataKeys for T {
    fn dyn_generate_data_key<'a>(
        &'a self,
        spec: DataKeySpec,
        aad: &'a [u8],
    ) -> BoxFuture<'a, Result<DataKey>> {
        Box::pin(<T as DataKeys>::generate_data_key(self, spec, aad))
    }
}

impl<'x> DataKeys for dyn DynDataKeys + 'x {
    async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey> {
        DynDataKeys::dyn_generate_data_key(self, spec, aad).await
    }
}

impl<T: DataKeys + ?Sized> DataKeys for Arc<T> {
    async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey> {
        <T as DataKeys>::generate_data_key(&**self, spec, aad).await
    }
}

impl<T: DataKeys + ?Sized> DataKeys for Box<T> {
    async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey> {
        <T as DataKeys>::generate_data_key(&**self, spec, aad).await
    }
}

impl<T: DataKeys + ?Sized> DataKeys for &T {
    async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey> {
        <T as DataKeys>::generate_data_key(&**self, spec, aad).await
    }
}

impl fmt::Debug for dyn DynDataKeys + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynDataKeys").finish_non_exhaustive()
    }
}

// WrappedDataKeys takes `spec` by value too.

/// Object-safe [`WrappedDataKeys`].
///
/// Sealed: implemented for every `T` that implements [`WrappedDataKeys`]; implement the
/// static trait instead.
pub trait DynWrappedDataKeys: sealed::Sealed<sealed::WrappedDataKeys> + Send + Sync {
    #[doc(hidden)]
    fn dyn_generate_wrapped_data_key<'a>(
        &'a self,
        spec: DataKeySpec,
        aad: &'a [u8],
    ) -> BoxFuture<'a, Result<Ciphertext>>;
}

impl<T: WrappedDataKeys> sealed::Sealed<sealed::WrappedDataKeys> for T {}

impl<T: WrappedDataKeys> DynWrappedDataKeys for T {
    fn dyn_generate_wrapped_data_key<'a>(
        &'a self,
        spec: DataKeySpec,
        aad: &'a [u8],
    ) -> BoxFuture<'a, Result<Ciphertext>> {
        Box::pin(<T as WrappedDataKeys>::generate_wrapped_data_key(
            self, spec, aad,
        ))
    }
}

impl<'x> WrappedDataKeys for dyn DynWrappedDataKeys + 'x {
    async fn generate_wrapped_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<Ciphertext> {
        DynWrappedDataKeys::dyn_generate_wrapped_data_key(self, spec, aad).await
    }
}

impl<T: WrappedDataKeys + ?Sized> WrappedDataKeys for Arc<T> {
    async fn generate_wrapped_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<Ciphertext> {
        <T as WrappedDataKeys>::generate_wrapped_data_key(&**self, spec, aad).await
    }
}

impl<T: WrappedDataKeys + ?Sized> WrappedDataKeys for Box<T> {
    async fn generate_wrapped_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<Ciphertext> {
        <T as WrappedDataKeys>::generate_wrapped_data_key(&**self, spec, aad).await
    }
}

impl<T: WrappedDataKeys + ?Sized> WrappedDataKeys for &T {
    async fn generate_wrapped_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<Ciphertext> {
        <T as WrappedDataKeys>::generate_wrapped_data_key(&**self, spec, aad).await
    }
}

impl fmt::Debug for dyn DynWrappedDataKeys + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynWrappedDataKeys").finish_non_exhaustive()
    }
}

/// Object-safe [`ExtensionCalls`].
///
/// Sealed: implemented for every `T` that implements [`ExtensionCalls`]; implement the
/// static trait instead.
pub trait DynExtensionCalls: sealed::Sealed<sealed::ExtensionCalls> + Send + Sync {
    #[doc(hidden)]
    fn dyn_run_extension<'a>(&'a self, call: Call<'a>) -> BoxFuture<'a, Result<CallOutput>>;
}

impl<T: ExtensionCalls> sealed::Sealed<sealed::ExtensionCalls> for T {}

impl<T: ExtensionCalls> DynExtensionCalls for T {
    fn dyn_run_extension<'a>(&'a self, call: Call<'a>) -> BoxFuture<'a, Result<CallOutput>> {
        Box::pin(<T as ExtensionCalls>::run_extension(self, call))
    }
}

impl<'x> ExtensionCalls for dyn DynExtensionCalls + 'x {
    async fn run_extension(&self, call: Call<'_>) -> Result<CallOutput> {
        DynExtensionCalls::dyn_run_extension(self, call).await
    }
}

impl<T: ExtensionCalls + ?Sized> ExtensionCalls for Arc<T> {
    async fn run_extension(&self, call: Call<'_>) -> Result<CallOutput> {
        <T as ExtensionCalls>::run_extension(&**self, call).await
    }
}

impl<T: ExtensionCalls + ?Sized> ExtensionCalls for Box<T> {
    async fn run_extension(&self, call: Call<'_>) -> Result<CallOutput> {
        <T as ExtensionCalls>::run_extension(&**self, call).await
    }
}

impl<T: ExtensionCalls + ?Sized> ExtensionCalls for &T {
    async fn run_extension(&self, call: Call<'_>) -> Result<CallOutput> {
        <T as ExtensionCalls>::run_extension(&**self, call).await
    }
}

impl fmt::Debug for dyn DynExtensionCalls + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynExtensionCalls").finish_non_exhaustive()
    }
}

/// The undecorated extension slot every handle starts with: runs the call once.
struct Direct;

impl ExtensionCalls for Direct {
    async fn run_extension(&self, call: Call<'_>) -> Result<CallOutput> {
        call.run().await
    }
}

dyn_layer! {
    /// Object-safe [`KeyWrap`].
    KeyWrap => DynKeyWrap {
        sync fn wrapped_key_version / dyn_wrapped_key_version(wrapped: &Ciphertext) -> Result<Option<KeyVersion>>;
        async fn wrap_key / dyn_wrap_key(key: &[u8]) -> Result<Ciphertext>;
        async fn unwrap_key / dyn_unwrap_key(wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>>;
    }
}

/// One part of an opaque handle, lent to [`Layer::part`] to be replaced by a decorated one.
///
/// Each variant holds the part's slot, so a layer can only put a part of the same kind back:
/// `*slot = Arc::new(Decorator(slot.clone()))`. Parts added in later releases add variants
/// (the enum is `#[non_exhaustive]`), and reach existing layers through their catch-all arm.
#[non_exhaustive]
pub enum Part<'a> {
    /// A [`Aead`] part.
    Aead(&'a mut Arc<dyn DynAead>),
    /// A [`Rewrap`] part.
    Rewrap(&'a mut Arc<dyn DynRewrap>),
    /// A [`DataKeys`] part.
    DataKeys(&'a mut Arc<dyn DynDataKeys>),
    /// A [`DigestSigner`] part.
    DigestSigner(&'a mut Arc<dyn DynDigestSigner>),
    /// A [`MessageSigner`] part.
    MessageSigner(&'a mut Arc<dyn DynMessageSigner>),
    /// A [`DigestVerifier`] part.
    DigestVerifier(&'a mut Arc<dyn DynDigestVerifier>),
    /// A [`MessageVerifier`] part.
    MessageVerifier(&'a mut Arc<dyn DynMessageVerifier>),
    /// A [`Mac`] part.
    Mac(&'a mut Arc<dyn DynMac>),
    /// A [`PublicKeys`] part.
    PublicKeys(&'a mut Arc<dyn DynPublicKeys>),
    /// A [`Describe`] part.
    Describe(&'a mut Arc<dyn DynDescribe>),
    /// A [`KeyWrap`] part.
    KeyWrap(&'a mut Arc<dyn DynKeyWrap>),
    /// A [`WrappedDataKeys`] part (not set by `full`, whose bounds are frozen at the original
    /// part set; set it with `with_wrapped_data_keys`).
    WrappedDataKeys(&'a mut Arc<dyn DynWrappedDataKeys>),
    /// The [`ExtensionCalls`] slot every handle has: backend-specific
    /// operations reached with `call_extension` (e.g. [`AeadKey::call_extension`]).
    Extension(&'a mut Arc<dyn DynExtensionCalls>),
    /// A [`Preflight`] part (not set by `full`, whose bounds are frozen at the original part
    /// set; set it with `with_preflight`).
    Preflight(&'a mut Arc<dyn DynPreflight>),
}

impl Part<'_> {
    /// Which part this is.
    pub fn kind(&self) -> PartKind {
        match self {
            Part::Aead(_) => PartKind::Aead,
            Part::Rewrap(_) => PartKind::Rewrap,
            Part::DataKeys(_) => PartKind::DataKeys,
            Part::DigestSigner(_) => PartKind::DigestSigner,
            Part::MessageSigner(_) => PartKind::MessageSigner,
            Part::DigestVerifier(_) => PartKind::DigestVerifier,
            Part::MessageVerifier(_) => PartKind::MessageVerifier,
            Part::Mac(_) => PartKind::Mac,
            Part::PublicKeys(_) => PartKind::PublicKeys,
            Part::Describe(_) => PartKind::Describe,
            Part::KeyWrap(_) => PartKind::KeyWrap,
            Part::WrappedDataKeys(_) => PartKind::WrappedDataKeys,
            Part::Extension(_) => PartKind::Extension,
            Part::Preflight(_) => PartKind::Preflight,
        }
    }
}

impl fmt::Debug for Part<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Part").field(&self.kind()).finish()
    }
}

/// The kind of a [`Part`], e.g. to log or count parts a [`Layer`] does not decorate.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PartKind {
    /// [`Aead`].
    Aead,
    /// [`Rewrap`].
    Rewrap,
    /// [`DataKeys`].
    DataKeys,
    /// [`DigestSigner`].
    DigestSigner,
    /// [`MessageSigner`].
    MessageSigner,
    /// [`DigestVerifier`].
    DigestVerifier,
    /// [`MessageVerifier`].
    MessageVerifier,
    /// [`Mac`].
    Mac,
    /// [`PublicKeys`].
    PublicKeys,
    /// [`Describe`].
    Describe,
    /// [`KeyWrap`].
    KeyWrap,
    /// [`WrappedDataKeys`].
    WrappedDataKeys,
    /// [`ExtensionCalls`], backend-specific operations.
    Extension,
    /// [`Preflight`].
    Preflight,
}

impl PartKind {
    /// The part's stable name, as the [`Layer`] method that wraps it (`"aead"`, `"key_wrap"`, ...).
    pub fn as_str(&self) -> &'static str {
        match self {
            PartKind::Aead => "aead",
            PartKind::Rewrap => "rewrap",
            PartKind::DataKeys => "data_keys",
            PartKind::DigestSigner => "digest_signer",
            PartKind::MessageSigner => "message_signer",
            PartKind::DigestVerifier => "digest_verifier",
            PartKind::MessageVerifier => "message_verifier",
            PartKind::Mac => "mac",
            PartKind::PublicKeys => "public_keys",
            PartKind::Describe => "describe",
            PartKind::KeyWrap => "key_wrap",
            PartKind::WrappedDataKeys => "wrapped_data_keys",
            PartKind::Extension => "extension",
            PartKind::Preflight => "preflight",
        }
    }
}

impl fmt::Display for PartKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a [`Layer`] knows about the handle whose parts it decorates.
///
/// `#[non_exhaustive]`: later releases may add fields. Build one with [`new`](Self::new) to test
/// a layer.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct LayerCx<'a> {
    /// The backend name, as in errors and `Debug` output.
    pub backend: &'static str,
    /// The key the handle opens, as its errors name it (see
    /// [`Error::resource`](crate::Error::resource)): set by the provider or, for handles a
    /// [`Registry`](crate::Registry) opens, from the key URI without its query. `None` for a
    /// handle built without one (see [`AeadKey::with_resource`]). Non-secret, and stable per key,
    /// so it suits metric labels.
    pub resource: Option<&'a str>,
}

impl<'a> LayerCx<'a> {
    /// A context for a handle of `backend` with no resource.
    pub fn new(backend: &'static str) -> Self {
        Self {
            backend,
            resource: None,
        }
    }

    /// Sets the resource.
    pub fn with_resource(mut self, resource: &'a str) -> Self {
        self.resource = Some(resource);
        self
    }
}

/// Wraps every part of an opaque handle with a decorator, keeping the handle's exact set of
/// optional parts.
///
/// Wrapping a whole handle in a generic decorator loses capability tracking: `Retry<AeadKey>`
/// implements `Rewrap` whether or not the `AeadKey` has a rewrap part, and is no longer an
/// `AeadKey`. A `Layer` instead wraps each part separately (`AeadKey::layer`, and
/// [`RegistryBuilder::layer`](crate::RegistryBuilder::layer) for every handle a registry
/// opens), so `supports_*` keeps answering truthfully and the result is the same handle type.
///
/// Every part goes through the required [`part`](Self::part). Parts added in later releases (a
/// new handle kind, a new optional part) reach every existing layer there, as a [`Part`] variant
/// its catch-all arm sees, so a metrics or auth layer never silently skips them.
///
/// A layer that only needs to see operations (count, time, retry or authorize them) implements
/// [`Around`](crate::Around) once and wraps every part with [`Part::wrap_around`]: core builds
/// a [`Call`](crate::Call) for each async method, so there is no decorator per capability trait
/// to write and no provided method to forget. [`RetryLayer`](crate::RetryLayer) and
/// [`ObserveLayer`](crate::ObserveLayer) are built this way:
///
/// ```
/// use std::sync::Arc;
/// use std::sync::atomic::{AtomicU64, Ordering};
/// use anykms_core::*;
///
/// /// Counts calls (a stand-in for a metrics decorator).
/// #[derive(Clone, Default)]
/// struct Metrics(Arc<AtomicU64>);
///
/// impl Around for Metrics {
///     fn around<'a>(&'a self, cx: &'a CallCx, call: Call<'a>) -> BoxFuture<'a, Result<CallOutput>> {
///         // `cx.backend()`/`cx.resource()` and `call.part()`/`call.operation()` label the call.
///         self.0.fetch_add(1, Ordering::Relaxed);
///         call.run()
///     }
/// }
///
/// impl Layer for Metrics {
///     fn part(&self, cx: &LayerCx<'_>, part: Part<'_>) {
///         part.wrap_around(cx, Arc::new(self.clone()));
///     }
/// }
///
/// # struct Plain;
/// # impl Aead for Plain {
/// #     async fn encrypt(&self, _: &[u8], _: &[u8]) -> Result<Ciphertext> { Ok(Ciphertext::from_bytes(vec![1])) }
/// #     async fn decrypt(&self, _: &Ciphertext, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> { unimplemented!() }
/// # }
/// # futures_lite_block_on(async {
/// let metrics = Metrics::default();
/// let key = AeadKey::new("test", Arc::new(Plain)).layer(&metrics);
/// key.encrypt(b"pt", b"").await?;
/// assert_eq!(metrics.0.load(Ordering::Relaxed), 1);
/// # Ok::<(), Error>(()) }).unwrap();
/// # fn futures_lite_block_on<F: std::future::Future>(f: F) -> F::Output {
/// #     tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
/// # }
/// ```
///
/// A layer may also replace a part's slot itself (`*slot = Arc::new(Decorator(slot.clone()))`
/// in a match on the [`Part`] variant), e.g. to change behavior rather than observe it; such a
/// decorator must forward every provided method of the trait.
///
/// Layers apply to the parts only: the concrete key reached through `downcast_ref` is never
/// wrapped.
///
/// A handle takes at most one *retrying* layer (see [`retries`](Self::retries)): once one is
/// applied, by the registry or on the handle, later ones are skipped.
///
/// A layer must not change a behavior that the handle's [`KeySemantics`] describes (version
/// choice, limits, data-key AAD, where verification happens): the handle keeps reporting the
/// value its provider declared, and layers cannot replace it.
pub trait Layer: Send + Sync {
    /// Whether this layer retries failed operations ([`RetryLayer`](crate::RetryLayer) does).
    ///
    /// A handle applies at most one retrying layer and skips later ones, so retries never nest:
    /// a registry layer plus a per-handle layer of 6 attempts each would otherwise make up to 36
    /// attempts against a struggling backend, with two separate budgets. Return `true` from a
    /// custom retry layer to get the same protection.
    fn retries(&self) -> bool {
        false
    }

    /// The catch-all: decorates any part this layer does not handle with its own method, by
    /// replacing the part in its slot. Leaving the slot untouched passes the part through.
    ///
    /// Required, so that every part, including ones added in later releases, is seen by the
    /// layer: match the kinds you decorate and decide explicitly what the rest (`_`) gets.
    ///
    /// `cx` describes the handle: its backend and the key it opens, e.g. for metric labels.
    fn part(&self, cx: &LayerCx<'_>, part: Part<'_>);
}

/// A shared layer (e.g. one whose state the caller also reads) is a layer too.
impl<L: Layer + ?Sized> Layer for Arc<L> {
    fn retries(&self) -> bool {
        (**self).retries()
    }
    fn part(&self, cx: &LayerCx<'_>, part: Part<'_>) {
        (**self).part(cx, part)
    }
}

/// Applies a layer to one part (what the removed per-part `Layer` methods did).
mod wrap {
    use super::*;

    macro_rules! wrap_fns {
        ($($f:ident: $Dyn:ident => $V:ident),* $(,)?) => {$(
            pub(super) fn $f(layer: &dyn Layer, cx: &LayerCx<'_>, mut inner: Arc<dyn $Dyn>) -> Arc<dyn $Dyn> {
                layer.part(cx, Part::$V(&mut inner));
                inner
            }
        )*};
    }

    wrap_fns! {
        aead: DynAead => Aead,
        rewrap: DynRewrap => Rewrap,
        data_keys: DynDataKeys => DataKeys,
        digest_signer: DynDigestSigner => DigestSigner,
        message_signer: DynMessageSigner => MessageSigner,
        digest_verifier: DynDigestVerifier => DigestVerifier,
        message_verifier: DynMessageVerifier => MessageVerifier,
        mac: DynMac => Mac,
        public_keys: DynPublicKeys => PublicKeys,
        describe: DynDescribe => Describe,
        key_wrap: DynKeyWrap => KeyWrap,
        wrapped_data_keys: DynWrappedDataKeys => WrappedDataKeys,
        extension: DynExtensionCalls => Extension,
        preflight: DynPreflight => Preflight,
    }
}

impl fmt::Debug for dyn Layer + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Layer").finish_non_exhaustive()
    }
}

/// The operations every opaque handle ([`AeadKey`], [`DigestSignerKey`], ...) shares, for code
/// generic over handle types.
///
/// Sealed: implemented by the handles in this crate only.
pub trait OpaqueHandle: sealed::Sealed<sealed::Handle> + Clone + fmt::Debug + Send + Sync {
    /// Wraps every part with `layer`; see [`Layer`].
    fn layer<L: Layer + Clone + 'static>(self, layer: &L) -> Self;

    /// Like [`layer`](Self::layer), with a layer that is already shared (the registry's).
    #[doc(hidden)]
    fn layer_shared(self, layer: Arc<dyn Layer>) -> Self;

    /// The backend name used in errors and `Debug` output.
    fn backend_name(&self) -> &'static str;

    /// Names the key this handle opens; see [`AeadKey::with_resource`].
    fn with_resource(self, resource: Arc<str>) -> Self;

    /// The key this handle opens, if known; see [`AeadKey::resource`].
    fn resource(&self) -> Option<&str>;

    /// What this handle does where backends differ, if declared; see [`AeadKey::semantics`].
    fn semantics(&self) -> Option<&KeySemantics>;
}

/// The layer context of a handle.
fn layer_cx<'a>(backend: &'static str, resource: &'a Option<Arc<str>>) -> LayerCx<'a> {
    LayerCx {
        backend,
        resource: resource.as_deref(),
    }
}

/// The concrete key behind a handle, for [`downcast_ref`](AeadKey::downcast_ref).
type Concrete = Arc<dyn Any + Send + Sync>;

// The `with_*` and `supports_*` methods of one optional part of a handle (inside `handle!`).
macro_rules! part_methods {
    ($opt:ident : $DynOpt:ident [$lopt:ident] / $with:ident / $supports:ident; $note:literal) => {
        #[doc = concat!("Adds the optional `", stringify!($opt), "` part, wrapped with every layer already applied to the handle. ", $note)]
        #[doc = ""]
        #[doc = concat!("Pass the backend's own handle that implements this part. Opaque handles implement the part's `Dyn` trait even when they lack the part, so passing another handle without it makes [`", stringify!($supports), "`](Self::", stringify!($supports), ") true while calls still fail with `Unsupported`.")]
        pub fn $with(mut self, $opt: Arc<dyn $DynOpt>) -> Self {
            let resource = self.resource.clone();
            let cx = layer_cx(self.backend, &resource);
            self.parts.$opt = Some(
                self.layers
                    .iter()
                    .fold($opt.clone(), |p, layer| wrap::$lopt(&**layer, &cx, p)),
            );
            self.raw.$opt = Some($opt);
            self
        }

        #[doc = concat!("Whether the `", stringify!($opt), "` part is available.")]
        pub fn $supports(&self) -> bool {
            self.parts.$opt.is_some()
        }
    };
}

// Generates an opaque handle: one required part, optional parts (each with `with_*` and
// `supports_*`), `new`, `full`, `layer`, the concrete-key slot, `backend_name` and `Debug`. Each
// part names the `Layer` method that wraps it.
//
// Optional parts come in two groups. The first are the parts of 0.1, which `full` sets: `full`
// is bounded by the traits listed after `full:`, frozen at those parts. Parts added later go in
// the `later { .. }` group, which `full` never sets (so its bounds never grow, see
// `full_bounds_are_frozen` in the tests): backends add them with their `with_*` method. Both
// groups are otherwise alike (`with_*`, `supports_*`, layers, `Debug`).
//
// The trait impls of the required part are written by hand; those of optional parts come from
// `optional_part!`.
//
// A handle keeps its parts twice: as the backend provided them (`raw`) and with every applied
// layer (`parts`), plus the layers themselves, so a part added after layering and a replaced
// retry layer get exactly the handle's current layers.
macro_rules! handle {
    (
        $(#[$meta:meta])*
        $Name:ident / $Parts:ident {
            $main:ident : $DynMain:ident [$lmain:ident];
            $( $opt:ident : $DynOpt:ident [$lopt:ident] / $with:ident / $supports:ident ),* ;
            later { $( $lat:ident : $DynLat:ident [$llat:ident] / $lwith:ident / $lsupports:ident ),* $(,)? }
        }
        full: $($Bound:ident)+
    ) => {
        /// The parts of one handle.
        #[derive(Clone)]
        struct $Parts {
            $main: Arc<dyn $DynMain>,
            $( $opt: Option<Arc<dyn $DynOpt>>, )*
            $( $lat: Option<Arc<dyn $DynLat>>, )*
            extension: Arc<dyn DynExtensionCalls>,
        }

        impl $Parts {
            /// Every part wrapped with `layer`.
            fn apply(&self, layer: &dyn Layer, cx: &LayerCx<'_>) -> Self {
                Self {
                    $main: wrap::$lmain(layer, cx, self.$main.clone()),
                    $( $opt: self.$opt.clone().map(|p| wrap::$lopt(layer, cx, p)), )*
                    $( $lat: self.$lat.clone().map(|p| wrap::$llat(layer, cx, p)), )*
                    extension: wrap::extension(layer, cx, self.extension.clone()),
                }
            }
        }

        $(#[$meta])*
        ///
        /// Cheap to clone: a clone shares the backend key and the parts (each an `Arc`), so pass
        /// clones to tasks and recipes instead of wrapping the handle in an `Arc`.
        #[non_exhaustive]
        #[derive(Clone)]
        pub struct $Name {
            raw: $Parts,
            parts: $Parts,
            layers: Vec<Arc<dyn Layer>>,
            concrete: Option<Concrete>,
            backend: &'static str,
            resource: Option<Arc<str>>,
            semantics: Option<Arc<KeySemantics>>,
        }

        impl $Name {
            /// A handle with only the required part. `backend` names the backend in `Unsupported`
            /// errors and `Debug` output.
            pub fn new(backend: &'static str, $main: Arc<dyn $DynMain>) -> Self {
                let raw = $Parts {
                    $main,
                    $( $opt: None, )*
                    $( $lat: None, )*
                    extension: Arc::new(Direct),
                };
                Self {
                    parts: raw.clone(),
                    raw,
                    layers: Vec::new(),
                    concrete: None,
                    backend,
                    resource: None,
                    semantics: None,
                }
            }

            /// A handle with every part of the original part set, sharing one `Arc`, which is also the concrete key
            /// [`downcast_ref`](Self::downcast_ref) returns.
            ///
            /// For a key that lacks a part, use [`new`](Self::new), the `with_*` methods of the
            /// parts it has and [`with_concrete`](Self::with_concrete).
            ///
            /// The bounds are frozen at the original part set: a newer part is not set by `full`
            /// (set it with its `with_*` method), so a backend that calls `full` keeps
            /// compiling.
            pub fn full<K>(backend: &'static str, key: K) -> Self
            where
                K: $($Bound +)+ 'static,
            {
                let k = Arc::new(key);
                let raw = $Parts {
                    $( $opt: Some(k.clone()), )*
                    $( $lat: None, )*
                    $main: k.clone(),
                    extension: Arc::new(Direct),
                };
                Self {
                    parts: raw.clone(),
                    raw,
                    layers: Vec::new(),
                    concrete: Some(k),
                    backend,
                    resource: None,
                    semantics: None,
                }
            }

            $( part_methods!($opt: $DynOpt [$lopt] / $with / $supports;
                "Set by [`full`](Self::full)."); )*
            $( part_methods!($lat: $DynLat [$llat] / $lwith / $lsupports;
                "Not set by [`full`](Self::full), whose bounds are frozen at the original part set: a backend whose key has it calls this method."); )*

            /// Runs a backend-specific operation through this handle's layers.
            ///
            /// For backend extension traits on opaque handles (e.g. an AWS
            /// `encrypt_with_context` on [`AeadKey`]): `f` starts one attempt of the operation
            /// on the backend's concrete key (reached with [`downcast_arc`](Self::downcast_arc))
            /// and may be called again for a retry, so it borrows its inputs rather than moving
            /// them. Every layer of the handle sees the call as a [`Part::Extension`]: a
            /// [`RetryLayer`](crate::RetryLayer) retries it, an
            /// [`ObserveLayer`](crate::ObserveLayer) reports it under `op` with
            /// [`OpEvent::extension_name`](crate::OpEvent::extension_name) `name`. `name` is
            /// the backend's stable, non-secret name of the call (`"aws.encrypt_with_context"`).
            ///
            /// ```
            /// # use std::sync::Arc;
            /// # use anykms_core::*;
            /// /// A backend's own key type, with an operation the portable traits lack.
            /// struct NativeKey;
            /// impl NativeKey {
            ///     async fn encrypt_with_context(&self, pt: &[u8], ctx: &str) -> Result<Ciphertext> {
            ///         Ok(Ciphertext::from_bytes([pt, ctx.as_bytes()].concat()))
            ///     }
            /// }
            /// # impl Aead for NativeKey {
            /// #     async fn encrypt(&self, pt: &[u8], _: &[u8]) -> Result<Ciphertext> { unimplemented!() }
            /// #     async fn decrypt(&self, _: &Ciphertext, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> { unimplemented!() }
            /// # }
            ///
            /// /// The backend's extension trait, implemented for the opaque handle.
            /// trait EncryptWithContext {
            ///     async fn encrypt_with_context(&self, pt: &[u8], ctx: &str) -> Result<Ciphertext>;
            /// }
            /// impl EncryptWithContext for AeadKey {
            ///     async fn encrypt_with_context(&self, pt: &[u8], ctx: &str) -> Result<Ciphertext> {
            ///         let key = self
            ///             .downcast_arc::<NativeKey>()
            ///             .ok_or_else(|| Error::unsupported("not a native key"))?;
            ///         self.call_extension(Operation::Encrypt, "native.encrypt_with_context", || {
            ///             let key = key.clone();
            ///             Box::pin(async move { key.encrypt_with_context(pt, ctx).await })
            ///         })
            ///         .await
            ///     }
            /// }
            /// # async fn demo() -> Result<()> {
            /// let native = Arc::new(NativeKey);
            /// let key = AeadKey::new("native", native.clone())
            ///     .with_concrete(native)
            ///     .layer(&RetryLayer::new(instant_sleep()));
            /// key.encrypt_with_context(b"pt", "ctx").await?; // retried like `encrypt`
            /// # Ok(()) }
            /// ```
            ///
            /// A result of another type than `R` cannot come back (only a layer that swaps the
            /// output could cause it); it would be a `Backend` error.
            pub async fn call_extension<'a, R: Send + 'static>(
                &'a self,
                op: Operation,
                name: &'static str,
                f: impl Fn() -> BoxFuture<'a, Result<R>> + Send + Sync + 'a,
            ) -> Result<R> {
                let erased = Erased(f, std::marker::PhantomData);
                let call = Call {
                    part: PartKind::Extension,
                    op,
                    name,
                    run: &erased,
                };
                let out = (*self.parts.extension).dyn_run_extension(call).await?;
                out.downcast::<R>().map_err(|_| {
                    Error::new(
                        ErrorKind::Backend,
                        self.backend,
                        op,
                        "an extension call returned a value of an unexpected type",
                    )
                })
            }

            /// Records the backend's concrete key type behind this handle, so callers can reach
            /// backend-specific APIs with [`downcast_ref`](Self::downcast_ref). Set by
            /// [`full`](Self::full); call it after [`new`](Self::new) with the same `Arc` the
            /// parts use.
            pub fn with_concrete<K: Any + Send + Sync>(mut self, key: Arc<K>) -> Self {
                self.concrete = Some(key);
                self
            }

            /// The backend's concrete key, if it is a `T` (e.g. `TransitAeadKey` for a transit
            /// key), for backend-specific APIs the portable traits do not cover.
            ///
            /// `None` when the provider did not record a concrete key (see
            /// [`with_concrete`](Self::with_concrete)) or it has another type. Calls through the
            /// concrete key bypass every [`Layer`] (retries, metrics) applied to this handle:
            /// run them through [`call_extension`](Self::call_extension), which applies the
            /// handle's layers.
            pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
                self.concrete.as_deref()?.downcast_ref()
            }

            /// Like [`downcast_ref`](Self::downcast_ref), but returns a shared `Arc` (e.g. to
            /// move into a task).
            pub fn downcast_arc<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
                self.concrete.clone()?.downcast().ok()
            }

            /// Wraps every part with `layer`, keeping exactly the parts this handle has; see
            /// [`Layer`]. Layers applied later wrap earlier ones, and parts added later with the
            /// `with_*` methods get every layer applied so far. The handle keeps a clone of
            /// `layer` (an `Arc<L>` works for layers with shared state).
            ///
            /// A retrying layer ([`RetryLayer`](crate::RetryLayer)) is skipped when the handle
            /// already retries (see [`is_retrying`](Self::is_retrying)), so retries never nest:
            /// the first retrying layer, usually the registry's, wins. To give one handle another
            /// retry policy, use [`replace_retry`](Self::replace_retry).
            pub fn layer<L: Layer + Clone + 'static>(self, layer: &L) -> Self {
                self.push_layer(Arc::new(layer.clone()))
            }

            fn push_layer(mut self, layer: Arc<dyn Layer>) -> Self {
                if layer.retries() && self.is_retrying() {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        backend = self.backend,
                        handle = stringify!($Name),
                        "handle already retries; retrying layer skipped (use replace_retry)"
                    );
                    return self;
                }
                self.parts = self.parts.apply(&*layer, &layer_cx(self.backend, &self.resource));
                self.layers.push(layer);
                self
            }

            /// Replaces the handle's retrying layer with `layer`, in the same position among the
            /// handle's layers (or adds it last when the handle does not retry yet), and
            /// rebuilds every part from the backend's parts. Use it to give one handle of a
            /// retrying registry its own policy (e.g. a tighter deadline on a request path).
            pub fn replace_retry<L: Layer + Clone + 'static>(mut self, layer: &L) -> Self {
                let layer: Arc<dyn Layer> = Arc::new(layer.clone());
                match self.layers.iter().position(|l| l.retries()) {
                    Some(i) => self.layers[i] = layer,
                    None => self.layers.push(layer),
                }
                // At most one retrying layer: drop any later ones (only possible when `layer`
                // itself does not retry).
                let mut seen = false;
                self.layers.retain(|l| !(l.retries() && std::mem::replace(&mut seen, true)));
                self.rebuild()
            }

            /// Every part rebuilt from the backend's parts with the handle's layers.
            fn rebuild(mut self) -> Self {
                let cx = layer_cx(self.backend, &self.resource);
                self.parts = self
                    .layers
                    .iter()
                    .fold(self.raw.clone(), |parts, l| parts.apply(&**l, &cx));
                self
            }

            /// Names the key this handle opens, for layers ([`LayerCx::resource`]). Providers
            /// set it, and a [`Registry`](crate::Registry) sets the key URI (without its query)
            /// when the provider did not. Layers already applied are re-applied with it.
            pub fn with_resource(mut self, resource: impl Into<Arc<str>>) -> Self {
                self.resource = Some(resource.into());
                self.rebuild()
            }

            /// The key this handle opens, if known (see [`with_resource`](Self::with_resource)).
            pub fn resource(&self) -> Option<&str> {
                self.resource.as_deref()
            }

            /// Whether a retrying [`Layer`] has been applied to this handle (by the registry
            /// that opened it or with [`layer`](Self::layer)).
            pub fn is_retrying(&self) -> bool {
                self.layers.iter().any(|l| l.retries())
            }

            /// The backend name used in errors and `Debug` output.
            pub fn backend_name(&self) -> &'static str {
                self.backend
            }

            /// Declares what this handle does where backends differ ([`KeySemantics`]).
            /// Providers set it at open (`AeadKey::full(..).with_semantics(k.semantics().clone())`);
            /// [`Layer`]s cannot replace it, and every layer applied keeps it.
            pub fn with_semantics(mut self, semantics: KeySemantics) -> Self {
                self.semantics = Some(Arc::new(semantics));
                self
            }

            /// What this handle does where backends differ, as its provider declared it; `None`
            /// when undeclared (see [`Semantics`]).
            pub fn semantics(&self) -> Option<&KeySemantics> {
                self.semantics.as_deref()
            }
        }

        impl Semantics for $Name {
            fn semantics(&self) -> Option<&KeySemantics> {
                self.semantics.as_deref()
            }
        }

        impl sealed::Sealed<sealed::Handle> for $Name {}

        impl OpaqueHandle for $Name {
            fn layer<L: Layer + Clone + 'static>(self, layer: &L) -> Self {
                $Name::layer(self, layer)
            }

            fn layer_shared(self, layer: Arc<dyn Layer>) -> Self {
                self.push_layer(layer)
            }

            fn backend_name(&self) -> &'static str {
                self.backend
            }

            fn with_resource(self, resource: Arc<str>) -> Self {
                $Name::with_resource(self, resource)
            }

            fn resource(&self) -> Option<&str> {
                self.resource.as_deref()
            }

            fn semantics(&self) -> Option<&KeySemantics> {
                self.semantics.as_deref()
            }
        }

        impl fmt::Debug for $Name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($Name))
                    .field("backend", &self.backend)
                    .field("resource", &self.resource)
                    $( .field(stringify!($opt), &self.parts.$opt.is_some()) )*
                    $( .field(stringify!($lat), &self.parts.$lat.is_some()) )*
                    .finish()
            }
        }
    };
}

// Trait impls forwarding to an optional part, or `Unsupported` before I/O when it is missing.
macro_rules! optional_part {
    ($Name:ident . rewrap) => {
        impl Rewrap for $Name {
            async fn rewrap(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext> {
                match &self.parts.rewrap {
                    Some(r) => (**r).dyn_rewrap(ct, aad).await,
                    None => Err(missing(
                        self.backend,
                        Operation::Rewrap,
                        "key does not support rewrap: decrypt and encrypt again (recipes' \
                         ClientRewrap); for an envelope KEK, use EnvelopeAead::rewrap_local, or \
                         rewrap_current, which falls back to it",
                    )),
                }
            }
        }
    };
    ($Name:ident . data_keys) => {
        impl DataKeys for $Name {
            async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey> {
                match &self.parts.data_keys {
                    Some(d) => (**d).dyn_generate_data_key(spec, aad).await,
                    None => Err(missing(
                        self.backend,
                        Operation::GenerateDataKey,
                        "key does not support data keys",
                    )),
                }
            }
        }
    };
    ($Name:ident . wrapped_data_keys) => {
        impl WrappedDataKeys for $Name {
            async fn generate_wrapped_data_key(
                &self,
                spec: DataKeySpec,
                aad: &[u8],
            ) -> Result<Ciphertext> {
                match &self.parts.wrapped_data_keys {
                    Some(d) => (**d).dyn_generate_wrapped_data_key(spec, aad).await,
                    None => Err(missing(
                        self.backend,
                        Operation::GenerateDataKey,
                        "key does not support wrapped-only data keys",
                    )),
                }
            }
        }
    };
    ($Name:ident . digest_verifier) => {
        impl DigestVerifier for $Name {
            async fn verify_digest(&self, digest: &Digest, sig: &Signature) -> Result<()> {
                match &self.parts.verifier {
                    Some(v) => (**v).dyn_verify_digest(digest, sig).await,
                    None => Err(missing(
                        self.backend,
                        Operation::Verify,
                        "handle was opened without a verifier",
                    )),
                }
            }
        }
    };
    ($Name:ident . message_verifier) => {
        impl MessageVerifier for $Name {
            async fn verify_message(&self, msg: &[u8], sig: &Signature) -> Result<()> {
                match &self.parts.verifier {
                    Some(v) => (**v).dyn_verify_message(msg, sig).await,
                    None => Err(missing(
                        self.backend,
                        Operation::Verify,
                        "handle was opened without a verifier",
                    )),
                }
            }
        }
    };
    ($Name:ident . public_keys) => {
        impl PublicKeys for $Name {
            async fn public_key(&self) -> Result<PublicKey> {
                match &self.parts.public_keys {
                    Some(p) => (**p).dyn_public_key().await,
                    None => Err(missing(
                        self.backend,
                        Operation::PublicKey,
                        "key does not support public keys",
                    )),
                }
            }

            async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
                match &self.parts.public_keys {
                    Some(p) => (**p).dyn_public_key_version(version).await,
                    None => Err(missing(
                        self.backend,
                        Operation::PublicKey,
                        "key does not support public keys",
                    )),
                }
            }
        }
    };
    ($Name:ident . describe) => {
        impl Describe for $Name {
            async fn describe(&self) -> Result<KeyInfo> {
                match &self.parts.describe {
                    Some(d) => (**d).dyn_describe().await,
                    None => Err(missing(
                        self.backend,
                        Operation::Describe,
                        "key does not support describe",
                    )),
                }
            }
        }
    };
}

fn missing(backend: &'static str, op: Operation, message: &'static str) -> Error {
    Error::new(ErrorKind::Unsupported, backend, op, message)
}

handle! {
    /// A symmetric key opened through a [`Provider`](crate::Provider): always [`Aead`], plus
    /// [`Rewrap`], [`DataKeys`], [`Describe`] and [`WrappedDataKeys`] where the backend supports
    /// them.
    ///
    /// This concrete composite exists because Rust cannot express `dyn DynAead + DynRewrap`, and
    /// a blanket impl cannot detect whether a type also implements `Rewrap`. A missing part
    /// returns `Unsupported` before any I/O; check with [`AeadKey::supports_rewrap`] and friends.
    /// Decorate it part by part with [`layer`](Self::layer) (e.g. a
    /// [`RetryLayer`](crate::RetryLayer)) rather than wrapping the whole handle, which would
    /// claim every part. Reach the backend's
    /// own key type with [`downcast_ref`](Self::downcast_ref).
    AeadKey / AeadKeyParts {
        aead: DynAead [aead];
        rewrap: DynRewrap [rewrap] / with_rewrap / supports_rewrap,
        data_keys: DynDataKeys [data_keys] / with_data_keys / supports_data_keys,
        describe: DynDescribe [describe] / with_describe / supports_describe;
        later {
            wrapped_data_keys: DynWrappedDataKeys [wrapped_data_keys]
                / with_wrapped_data_keys / supports_wrapped_data_keys,
            preflight: DynPreflight [preflight] / with_preflight / supports_preflight,
        }
    }
    full: Aead Rewrap DataKeys Describe
}

impl Aead for AeadKey {
    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
        (*self.parts.aead).dyn_encrypt(plaintext, aad).await
    }

    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        (*self.parts.aead).dyn_decrypt(ct, aad).await
    }

    fn ciphertext_version(&self, ct: &Ciphertext) -> Result<Option<KeyVersion>> {
        (*self.parts.aead).dyn_ciphertext_version(ct)
    }

    async fn decrypt_with_info(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Decrypted> {
        (*self.parts.aead).dyn_decrypt_with_info(ct, aad).await
    }
}

optional_part!(AeadKey.rewrap);
optional_part!(AeadKey.data_keys);
optional_part!(AeadKey.describe);
optional_part!(AeadKey.wrapped_data_keys);

handle! {
    /// A digest signer opened through a [`Provider`](crate::Provider): always [`DigestSigner`],
    /// plus [`DigestVerifier`], [`PublicKeys`] and [`Describe`] where the backend supports them,
    /// so one open serves signing, verifying, publishing the public key and inspecting the key.
    /// A missing part returns `Unsupported` before any I/O.
    DigestSignerKey / DigestSignerKeyParts {
        signer: DynDigestSigner [digest_signer];
        public_keys: DynPublicKeys [public_keys] / with_public_keys / supports_public_keys,
        describe: DynDescribe [describe] / with_describe / supports_describe,
        verifier: DynDigestVerifier [digest_verifier] / with_verifier / supports_verifier;
        later {
            preflight: DynPreflight [preflight] / with_preflight / supports_preflight,
        }
    }
    full: DigestSigner DigestVerifier PublicKeys Describe
}

impl DigestSigner for DigestSignerKey {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        (*self.parts.signer).dyn_signature_algorithm()
    }

    async fn sign_digest(&self, digest: &Digest) -> Result<Signature> {
        (*self.parts.signer).dyn_sign_digest(digest).await
    }
}

/// The algorithm the signer was opened for.
impl PinnedVerifier for DigestSignerKey {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        self.signature_algorithm()
    }
}

optional_part!(DigestSignerKey.digest_verifier);
optional_part!(DigestSignerKey.public_keys);
optional_part!(KeyWrapKey.public_keys);
optional_part!(DigestSignerKey.describe);

handle! {
    /// A message signer opened through a [`Provider`](crate::Provider): always
    /// [`MessageSigner`], plus [`MessageVerifier`], [`PublicKeys`] and [`Describe`] where the
    /// backend supports them. A missing part returns `Unsupported` before any I/O.
    MessageSignerKey / MessageSignerKeyParts {
        signer: DynMessageSigner [message_signer];
        public_keys: DynPublicKeys [public_keys] / with_public_keys / supports_public_keys,
        describe: DynDescribe [describe] / with_describe / supports_describe,
        verifier: DynMessageVerifier [message_verifier] / with_verifier / supports_verifier;
        later {
            preflight: DynPreflight [preflight] / with_preflight / supports_preflight,
        }
    }
    full: MessageSigner MessageVerifier PublicKeys Describe
}

impl MessageSigner for MessageSignerKey {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        (*self.parts.signer).dyn_signature_algorithm()
    }

    async fn sign_message(&self, msg: &[u8]) -> Result<Signature> {
        (*self.parts.signer).dyn_sign_message(msg).await
    }
}

/// The algorithm the signer was opened for.
impl PinnedVerifier for MessageSignerKey {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        self.signature_algorithm()
    }
}

optional_part!(MessageSignerKey.message_verifier);
optional_part!(MessageSignerKey.public_keys);
optional_part!(MessageSignerKey.describe);

handle! {
    /// A digest verifier opened through a [`Provider`](crate::Provider): always
    /// [`DigestVerifier`], plus [`PublicKeys`] and [`Describe`] where the backend supports them.
    /// A missing part returns `Unsupported` before any I/O.
    DigestVerifierKey / DigestVerifierKeyParts {
        verifier: DynDigestVerifier [digest_verifier];
        public_keys: DynPublicKeys [public_keys] / with_public_keys / supports_public_keys,
        describe: DynDescribe [describe] / with_describe / supports_describe;
        later {
            preflight: DynPreflight [preflight] / with_preflight / supports_preflight,
        }
    }
    full: DigestVerifier PublicKeys Describe
}

impl DigestVerifier for DigestVerifierKey {
    async fn verify_digest(&self, digest: &Digest, sig: &Signature) -> Result<()> {
        (*self.parts.verifier).dyn_verify_digest(digest, sig).await
    }
}

optional_part!(DigestVerifierKey.public_keys);
optional_part!(DigestVerifierKey.describe);

handle! {
    /// A message verifier opened through a [`Provider`](crate::Provider): always
    /// [`MessageVerifier`], plus [`PublicKeys`] and [`Describe`] where the backend supports
    /// them. A missing part returns `Unsupported` before any I/O.
    MessageVerifierKey / MessageVerifierKeyParts {
        verifier: DynMessageVerifier [message_verifier];
        public_keys: DynPublicKeys [public_keys] / with_public_keys / supports_public_keys,
        describe: DynDescribe [describe] / with_describe / supports_describe;
        later {
            preflight: DynPreflight [preflight] / with_preflight / supports_preflight,
        }
    }
    full: MessageVerifier PublicKeys Describe
}

impl MessageVerifier for MessageVerifierKey {
    async fn verify_message(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        (*self.parts.verifier).dyn_verify_message(msg, sig).await
    }
}

optional_part!(MessageVerifierKey.public_keys);
optional_part!(MessageVerifierKey.describe);

handle! {
    /// A MAC key opened through a [`Provider`](crate::Provider): always [`Mac`], plus
    /// [`Describe`] where the backend supports it. A missing part returns `Unsupported` before
    /// any I/O.
    MacKey / MacKeyParts {
        mac: DynMac [mac];
        describe: DynDescribe [describe] / with_describe / supports_describe;
        later {
            preflight: DynPreflight [preflight] / with_preflight / supports_preflight,
        }
    }
    full: Mac Describe
}

impl Mac for MacKey {
    fn mac_algorithm(&self) -> MacAlgorithm {
        (*self.parts.mac).dyn_mac_algorithm()
    }

    async fn mac(&self, data: &[u8]) -> Result<Tag> {
        (*self.parts.mac).dyn_mac(data).await
    }

    async fn verify_mac(&self, data: &[u8], tag: &Tag) -> Result<()> {
        (*self.parts.mac).dyn_verify_mac(data, tag).await
    }
}

optional_part!(MacKey.describe);

handle! {
    /// A public-key source opened through a [`Provider`](crate::Provider): always
    /// [`PublicKeys`], plus [`Describe`] where the backend supports it. A missing part returns
    /// `Unsupported` before any I/O.
    PublicKeysKey / PublicKeysKeyParts {
        public_keys: DynPublicKeys [public_keys];
        describe: DynDescribe [describe] / with_describe / supports_describe;
        later {
            preflight: DynPreflight [preflight] / with_preflight / supports_preflight,
        }
    }
    full: PublicKeys Describe
}

impl PublicKeys for PublicKeysKey {
    async fn public_key(&self) -> Result<PublicKey> {
        (*self.parts.public_keys).dyn_public_key().await
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        (*self.parts.public_keys)
            .dyn_public_key_version(version)
            .await
    }
}

optional_part!(PublicKeysKey.describe);

handle! {
    /// A describe handle opened through a [`Provider`](crate::Provider): [`Describe`] only.
    DescribeKey / DescribeKeyParts {
        describe: DynDescribe [describe];
        ;
        later {
            preflight: DynPreflight [preflight] / with_preflight / supports_preflight,
        }
    }
    full: Describe
}

impl Describe for DescribeKey {
    async fn describe(&self) -> Result<KeyInfo> {
        (*self.parts.describe).dyn_describe().await
    }
}

handle! {
    /// A key-wrapping key (an envelope KEK) opened through a [`Provider`](crate::Provider):
    /// always [`KeyWrap`], plus [`Rewrap`] (server-side rewrap of a wrapped key under the current
    /// version, with empty AAD: other AAD is `InvalidArgument` before any I/O), [`Describe`] and,
    /// for RSA keys, [`PublicKeys`] (to wrap offline) where the backend supports them. A missing part returns `Unsupported` before any I/O.
    ///
    /// Keys with a native wrap operation (RSA-OAEP, AES key wrap) fill the `KeyWrap` part
    /// directly; AEAD keys are opened as one through [`AeadKeyWrap`] (wrapping with empty AAD),
    /// most simply with [`from_aead`](Self::from_aead).
    KeyWrapKey / KeyWrapKeyParts {
        key_wrap: DynKeyWrap [key_wrap];
        rewrap: DynRewrap [rewrap] / with_rewrap / supports_rewrap,
        describe: DynDescribe [describe] / with_describe / supports_describe;
        later {
            preflight: DynPreflight [preflight] / with_preflight / supports_preflight,
            public_keys: DynPublicKeys [public_keys] / with_public_keys / supports_public_keys,
        }
    }
    full: KeyWrap Rewrap Describe
}

impl KeyWrap for KeyWrapKey {
    async fn wrap_key(&self, key: &[u8]) -> Result<Ciphertext> {
        (*self.parts.key_wrap).dyn_wrap_key(key).await
    }

    async fn unwrap_key(&self, wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
        (*self.parts.key_wrap).dyn_unwrap_key(wrapped).await
    }

    fn wrapped_key_version(&self, wrapped: &Ciphertext) -> Result<Option<KeyVersion>> {
        (*self.parts.key_wrap).dyn_wrapped_key_version(wrapped)
    }
}

impl KeyWrapKey {
    /// An AEAD key as a key-wrapping key, wrapping with empty AAD ([`AeadKeyWrap`]). Keeps the
    /// key's rewrap (restricted to empty AAD), describe and preflight parts, its concrete key,
    /// backend name and [`KeySemantics`] (without [`data_keys`](KeySemantics::data_keys) and
    /// [`max_plaintext`](KeySemantics::max_plaintext): a key-wrapping key has neither), and
    /// whether it retries; the parts keep any layer already applied to them.
    ///
    /// For providers whose AEAD keys double as KEKs:
    /// `self.aead(uri, opts).map(KeyWrapKey::from_aead)` implements
    /// [`Provider::key_wrap`](crate::Provider::key_wrap).
    pub fn from_aead(key: AeadKey) -> Self {
        let raw = KeyWrapKeyParts {
            key_wrap: Arc::new(AeadKeyWrap::new(key.raw.aead)),
            rewrap: key.raw.rewrap,
            describe: key.raw.describe,
            preflight: key.raw.preflight,
            public_keys: None,
            extension: key.raw.extension,
        };
        // The AEAD key's layers now wrap the key-wrap part instead of the AEAD part.
        let cx = layer_cx(key.backend, &key.resource);
        let parts = key
            .layers
            .iter()
            .fold(raw.clone(), |parts, l| parts.apply(&**l, &cx));
        Self {
            raw,
            parts,
            layers: key.layers,
            concrete: key.concrete,
            backend: key.backend,
            resource: key.resource,
            semantics: key
                .semantics
                .map(|s| Arc::new((*s).clone().with_data_keys(None).with_max_plaintext(None))),
        }
    }
}

impl From<AeadKey> for KeyWrapKey {
    fn from(key: AeadKey) -> Self {
        Self::from_aead(key)
    }
}

impl Rewrap for KeyWrapKey {
    /// Rewraps a wrapped key with empty AAD. A non-empty `aad` is `InvalidArgument` before any
    /// I/O, whatever the part: wrapped keys have no AAD, so a KEK opened from an AEAD key cannot
    /// be used to rewrap that key's ordinary ciphertexts.
    async fn rewrap(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext> {
        crate::traits::check_kek_rewrap_aad(self.backend, aad)?;
        match &self.parts.rewrap {
            Some(r) => (**r).dyn_rewrap(ct, b"").await,
            None => Err(missing(
                self.backend,
                Operation::Rewrap,
                "key does not support rewrap: use EnvelopeAead::rewrap_local, or rewrap_current, \
                 which falls back to it",
            )),
        }
    }
}

optional_part!(KeyWrapKey.describe);

handle! {
    /// A data-key source opened through [`Provider::data_keys`](crate::Provider::data_keys):
    /// always [`DataKeys`], plus [`Describe`] where the backend supports it. A missing part
    /// returns `Unsupported` before any I/O.
    ///
    /// For code that only hands out data keys (an envelope writer, a service that encrypts
    /// locally with keys the KMS issues). Backends with native data keys fill the part with
    /// their AEAD key; backends without them may fill it with a recipe over a key-wrapping key
    /// (a fresh random key, wrapped), which then refuses AAD. Unwrap the data keys through the
    /// same key opened for that purpose ([`AeadKey`] or [`KeyWrapKey`], as the backend
    /// documents).
    DataKeysKey / DataKeysKeyParts {
        data_keys: DynDataKeys [data_keys];
        describe: DynDescribe [describe] / with_describe / supports_describe;
        later {
            preflight: DynPreflight [preflight] / with_preflight / supports_preflight,
        }
    }
    full: DataKeys Describe
}

impl DataKeys for DataKeysKey {
    async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey> {
        (*self.parts.data_keys)
            .dyn_generate_data_key(spec, aad)
            .await
    }
}

optional_part!(DataKeysKey.describe);

/// Describes the key behind a handle for the generic preflight (no [`Preflight`] part); see
/// [`AeadKey::preflight`].
async fn describe_for_preflight(
    describe: Option<&Arc<dyn DynDescribe>>,
    backend: &'static str,
) -> Result<KeyInfo> {
    let Some(describe) = describe else {
        return Err(Error::new(
            ErrorKind::Unsupported,
            backend,
            Operation::Describe,
            "preflight needs a describe part, which this handle lacks",
        ));
    };
    (**describe).dyn_describe().await
}

/// Checks that the key `info` describes can do what the handle is for (`need`, and `alg` for a
/// signer) and is usable. Runs after the generic describe and after a backend's [`Preflight`]
/// part alike; every error is labelled [`Operation::Describe`].
fn check_preflight(
    info: &KeyInfo,
    backend: &'static str,
    need: Capabilities,
    alg: Option<SignatureAlgorithm>,
) -> Result<()> {
    let fail = |kind, message| Err(Error::new(kind, backend, Operation::Describe, message));
    if !info.capabilities().contains(need) {
        return fail(
            ErrorKind::KeyMismatch,
            "the key does not support the operation the handle was opened for",
        );
    }
    if let Some(alg) = alg {
        let algs = info.signature_algorithms();
        if !algs.is_empty() && !algs.contains(&alg) {
            return fail(
                ErrorKind::KeyMismatch,
                "the key does not sign with the algorithm the handle was opened for",
            );
        }
    }
    if matches!(
        info.state(),
        Some(KeyState::Disabled | KeyState::PendingDeletion | KeyState::Destroyed)
    ) {
        return fail(ErrorKind::KeyStateInvalid, "the key cannot be used");
    }
    // The version writes use, where `info` lists it: with per-version state, an enabled key can
    // have an unusable primary version.
    if let Some(primary) = info.primary_version()
        && let Some(v) = info.versions().iter().find(|v| v.version() == primary)
        && *v.state() != KeyState::Enabled
    {
        return fail(
            ErrorKind::KeyStateInvalid,
            "the key's primary version, which writes use, is not enabled",
        );
    }
    Ok(())
}

// `preflight` for each handle: the capability its required part needs, and the algorithm it was
// opened for where the handle knows it.
macro_rules! preflight {
    ($Name:ident, $need:expr, |$h:ident| $describe:expr, $alg:expr) => {
        impl $Name {
            /// Checks now, with one describe request, that the key behind this handle exists,
            /// supports the operation the handle was opened for (and, for signers, its
            /// algorithm) and is not disabled or scheduled for deletion, and that its primary
            /// version, where the describe lists it, is enabled; returns what it read.
            ///
            /// Opening a handle does no I/O, so a misconfigured key otherwise shows up on first
            /// use. Call this at startup for config-driven keys to fail fast. It fails with
            /// `KeyMismatch` when the key cannot do the handle's operation, `KeyStateInvalid`
            /// when it is disabled, deleted or scheduled for deletion or its listed primary
            /// version is not enabled, `Unsupported` when the handle has no describe part, and
            /// with any error of the describe request itself
            /// (`NotFound`, `PermissionDenied`, ...). Its own refusals are labelled
            /// [`Operation::Describe`]. Backends that check the key type before the first
            /// operation (transit) still do; this only moves the failure earlier.
            ///
            /// With a [`Preflight`] part (see `with_preflight`), the backend's check runs first
            /// (instead of the generic describe), then the same capability, algorithm and state
            /// checks over the [`KeyInfo`] it returned; that [`KeyInfo`] carries the backend's
            /// metadata ([`KeyInfo::backend_info`]).
            pub async fn preflight(&self) -> Result<KeyInfo> {
                let $h = self;
                let info = match &$h.parts.preflight {
                    Some(p) => (**p).dyn_preflight().await?,
                    None => describe_for_preflight($describe, $h.backend).await?,
                };
                check_preflight(&info, $h.backend, $need, $alg)?;
                Ok(info)
            }
        }

        /// Forwards to the inherent [`preflight`](Self::preflight), so the capability and state
        /// checks run after any backend part.
        impl Preflight for $Name {
            async fn preflight(&self) -> Result<KeyInfo> {
                $Name::preflight(self).await
            }
        }
    };
}

preflight!(
    AeadKey,
    Capabilities::AEAD,
    |h| h.parts.describe.as_ref(),
    None
);
preflight!(
    KeyWrapKey,
    Capabilities::KEY_WRAP,
    |h| h.parts.describe.as_ref(),
    None
);
preflight!(
    DigestSignerKey,
    Capabilities::SIGN,
    |h| h.parts.describe.as_ref(),
    Some(h.signature_algorithm())
);
preflight!(
    MessageSignerKey,
    Capabilities::SIGN,
    |h| h.parts.describe.as_ref(),
    Some(h.signature_algorithm())
);
preflight!(
    DigestVerifierKey,
    Capabilities::VERIFY,
    |h| h.parts.describe.as_ref(),
    None
);
preflight!(
    MessageVerifierKey,
    Capabilities::VERIFY,
    |h| h.parts.describe.as_ref(),
    None
);
preflight!(
    MacKey,
    Capabilities::MAC,
    |h| h.parts.describe.as_ref(),
    None
);
preflight!(
    PublicKeysKey,
    Capabilities::PUBLIC_KEY,
    |h| h.parts.describe.as_ref(),
    None
);
preflight!(
    DescribeKey,
    Capabilities::NONE,
    |h| Some(&h.parts.describe),
    None
);
// Data keys may come from a native operation (`DATA_KEYS`) or a recipe over a key-wrapping key
// (`KEY_WRAP`), so no capability is required: existence and state only.
preflight!(
    DataKeysKey,
    Capabilities::NONE,
    |h| h.parts.describe.as_ref(),
    None
);

#[cfg(test)]
mod tests {
    use super::*;

    /// `full`'s bounds are frozen at the parts of 0.1, so backends that call it keep compiling
    /// when a part is added. Adding a bound to any `full` breaks this function: set the new part
    /// with its `with_*` method instead.
    #[allow(dead_code)]
    fn full_bounds_are_frozen() {
        trait B: Send + Sync + 'static {}
        fn aead<K: Aead + Rewrap + DataKeys + Describe + B>(k: K) -> AeadKey {
            AeadKey::full("x", k)
        }
        fn digest_signer<K: DigestSigner + DigestVerifier + PublicKeys + Describe + B>(
            k: K,
        ) -> DigestSignerKey {
            DigestSignerKey::full("x", k)
        }
        fn message_signer<K: MessageSigner + MessageVerifier + PublicKeys + Describe + B>(
            k: K,
        ) -> MessageSignerKey {
            MessageSignerKey::full("x", k)
        }
        fn digest_verifier<K: DigestVerifier + PublicKeys + Describe + B>(
            k: K,
        ) -> DigestVerifierKey {
            DigestVerifierKey::full("x", k)
        }
        fn message_verifier<K: MessageVerifier + PublicKeys + Describe + B>(
            k: K,
        ) -> MessageVerifierKey {
            MessageVerifierKey::full("x", k)
        }
        fn mac<K: Mac + Describe + B>(k: K) -> MacKey {
            MacKey::full("x", k)
        }
        fn public_keys<K: PublicKeys + Describe + B>(k: K) -> PublicKeysKey {
            PublicKeysKey::full("x", k)
        }
        fn describe<K: Describe + B>(k: K) -> DescribeKey {
            DescribeKey::full("x", k)
        }
        fn key_wrap<K: KeyWrap + Rewrap + Describe + B>(k: K) -> KeyWrapKey {
            KeyWrapKey::full("x", k)
        }
        fn data_keys<K: DataKeys + Describe + B>(k: K) -> DataKeysKey {
            DataKeysKey::full("x", k)
        }
    }
    use crate::ErrorKind;

    /// A handle whose describe part is outside the `full` bounds, to test the later group.
    #[allow(dead_code)]
    mod later_key {
        use super::super::*;

        handle! {
            /// A test handle.
            LaterKey / LaterKeyParts {
                aead: DynAead [aead];
                rewrap: DynRewrap [rewrap] / with_rewrap / supports_rewrap;
                later { describe: DynDescribe [describe] / with_describe / supports_describe }
            }
            full: Aead Rewrap
        }

        optional_part!(LaterKey.describe);
    }
    use later_key::LaterKey;

    /// An AEAD key that rewraps and describes.
    struct Everything;
    impl Aead for Everything {
        async fn encrypt(&self, pt: &[u8], _: &[u8]) -> Result<Ciphertext> {
            Ok(Ciphertext::from_bytes(pt.to_vec()))
        }
        async fn decrypt(&self, ct: &Ciphertext, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(ct.as_bytes().to_vec()))
        }
    }
    impl Rewrap for Everything {
        async fn rewrap(&self, ct: &Ciphertext, _: &[u8]) -> Result<Ciphertext> {
            Ok(ct.clone())
        }
    }
    impl Describe for Everything {
        async fn describe(&self) -> Result<KeyInfo> {
            Ok(KeyInfo::new("everything", Capabilities::AEAD))
        }
    }

    /// `full` sets the parts of 0.1 only, even for a key that has a later part too; the later
    /// part is added with `with_*`, gets the layers applied before and after it, and shows in
    /// `Debug`.
    #[test]
    fn full_leaves_later_parts_unset() {
        let k = LaterKey::full("t", Everything);
        assert!(k.supports_rewrap() && !k.supports_describe());
        assert_eq!(
            format!("{k:?}"),
            "LaterKey { backend: \"t\", resource: None, rewrap: true, describe: false }"
        );

        #[derive(Default)]
        struct Kinds(std::sync::Mutex<Vec<PartKind>>);
        impl Layer for Kinds {
            fn part(&self, _: &LayerCx<'_>, part: Part<'_>) {
                self.0.lock().unwrap().push(part.kind());
            }
        }
        let before = Arc::new(Kinds::default());
        let after = Arc::new(Kinds::default());
        let k = k
            .layer(&before)
            .with_describe(Arc::new(Everything))
            .layer(&after);
        assert!(k.supports_describe());
        let seen = |l: &Kinds| l.0.lock().unwrap().clone();
        // The layer applied before the part reached it when it was added (after the parts the
        // handle had then, including the extension slot).
        assert_eq!(
            seen(&before),
            [
                PartKind::Aead,
                PartKind::Rewrap,
                PartKind::Extension,
                PartKind::Describe
            ]
        );
        assert_eq!(
            seen(&after),
            [
                PartKind::Aead,
                PartKind::Rewrap,
                PartKind::Describe,
                PartKind::Extension
            ]
        );
        // `new` has no optional part at all.
        let bare = LaterKey::new("t", Arc::new(Everything));
        assert!(!bare.supports_rewrap() && !bare.supports_describe());
    }

    /// A later part added with `with_*` is retried by a retry layer applied before or after it.
    #[tokio::test]
    async fn later_parts_are_layered() {
        let layer = crate::RetryLayer::new(crate::instant_sleep())
            .with_policy(crate::RetryPolicy::immediate());
        let flaky = || {
            Arc::new(FlakyDescribe {
                calls: Default::default(),
            })
        };
        let first = flaky();
        let k = LaterKey::full("t", Everything)
            .layer(&layer)
            .with_describe(first.clone());
        assert_eq!(k.describe().await.unwrap_err().kind(), ErrorKind::NotFound);
        assert_eq!(first.calls.load(std::sync::atomic::Ordering::SeqCst), 3);
        let second = flaky();
        let k = LaterKey::full("t", Everything)
            .with_describe(second.clone())
            .layer(&layer);
        assert_eq!(k.describe().await.unwrap_err().kind(), ErrorKind::NotFound);
        assert_eq!(second.calls.load(std::sync::atomic::Ordering::SeqCst), 3);
        // Without it, the call is `Unsupported` before any I/O.
        let e = LaterKey::full("t", Everything)
            .describe()
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported);
    }

    /// Wraps data keys as `wrapped:<aad>` after `fail` transient failures.
    struct Wrapped {
        fail: std::sync::Mutex<u32>,
        calls: std::sync::atomic::AtomicU32,
    }
    impl WrappedDataKeys for Wrapped {
        async fn generate_wrapped_data_key(
            &self,
            _: DataKeySpec,
            aad: &[u8],
        ) -> Result<Ciphertext> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut fail = self.fail.lock().unwrap();
            if *fail > 0 {
                *fail -= 1;
                return Err(Error::app(ErrorKind::Unavailable, "down"));
            }
            Ok(Ciphertext::from_bytes([b"wrapped:", aad].concat()))
        }
    }

    /// The wrapped-data-keys part of `AeadKey`: not set by `full`, added with `with_*`, retried
    /// and observed by the layers, and `Unsupported` before any I/O when missing.
    #[tokio::test]
    async fn wrapped_data_keys_part() {
        let full = AeadKey::full("t", FullAead);
        assert!(full.supports_data_keys() && !full.supports_wrapped_data_keys());
        let e = full
            .generate_wrapped_data_key(DataKeySpec::Aes256, b"")
            .await
            .unwrap_err();
        assert_eq!(
            (e.kind(), e.operation(), e.backend()),
            (ErrorKind::Unsupported, Operation::GenerateDataKey, "t")
        );

        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ev = events.clone();
        let observe = crate::ObserveLayer::new(move |e: &crate::OpEvent<'_>| {
            ev.lock()
                .unwrap()
                .push((e.part(), e.operation(), e.error_kind()))
        });
        let retry = crate::RetryLayer::new(crate::instant_sleep())
            .with_policy(crate::RetryPolicy::immediate());
        let inner = Arc::new(Wrapped {
            fail: std::sync::Mutex::new(2),
            calls: 0.into(),
        });
        let k = full
            .layer(&observe)
            .layer(&retry)
            .with_wrapped_data_keys(inner.clone());
        assert!(k.supports_wrapped_data_keys());
        assert!(
            format!("{k:?}").ends_with("wrapped_data_keys: true, preflight: false }"),
            "{k:?}"
        );
        let ct = k
            .generate_wrapped_data_key(DataKeySpec::Aes256, b"ctx")
            .await
            .unwrap();
        assert_eq!(ct.as_bytes(), b"wrapped:ctx");
        assert_eq!(inner.calls.load(std::sync::atomic::Ordering::SeqCst), 3);
        // Observed below the retry layer: every attempt.
        let want = |kind| (PartKind::WrappedDataKeys, Operation::GenerateDataKey, kind);
        assert_eq!(
            *events.lock().unwrap(),
            [
                want(Some(ErrorKind::Unavailable)),
                want(Some(ErrorKind::Unavailable)),
                want(None)
            ]
        );
        assert_eq!(PartKind::WrappedDataKeys.as_str(), "wrapped_data_keys");

        // Typed path and bridges.
        let typed = crate::RetryLayer::new(crate::instant_sleep())
            .with_policy(crate::RetryPolicy::immediate())
            .wrap(Wrapped {
                fail: std::sync::Mutex::new(1),
                calls: 0.into(),
            });
        assert!(
            typed
                .generate_wrapped_data_key(DataKeySpec::Aes256, b"")
                .await
                .is_ok()
        );
        let dynamic: Arc<dyn DynWrappedDataKeys> = Arc::new(Wrapped {
            fail: std::sync::Mutex::new(0),
            calls: 0.into(),
        });
        assert_eq!(format!("{dynamic:?}"), "DynWrappedDataKeys { .. }");
        let boxed: Box<dyn DynWrappedDataKeys> = Box::new(&*dynamic);
        assert_eq!(
            boxed
                .generate_wrapped_data_key(DataKeySpec::Aes256, b"b")
                .await
                .unwrap()
                .as_bytes(),
            b"wrapped:b"
        );
    }

    /// A backend key with an operation the portable traits lack, failing `fail` times first.
    struct Native {
        fail: std::sync::Mutex<u32>,
        calls: std::sync::atomic::AtomicU32,
    }
    impl Native {
        fn new(fail: u32) -> Arc<Self> {
            Arc::new(Self {
                fail: std::sync::Mutex::new(fail),
                calls: 0.into(),
            })
        }
        async fn tag(&self, input: &[u8], label: &str) -> Result<Vec<u8>> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut fail = self.fail.lock().unwrap();
            if *fail > 0 {
                *fail -= 1;
                return Err(Error::app(ErrorKind::Throttled, "slow down"));
            }
            Ok([input, label.as_bytes()].concat())
        }
        fn calls(&self) -> u32 {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
    impl Aead for Native {
        async fn encrypt(&self, pt: &[u8], _: &[u8]) -> Result<Ciphertext> {
            Ok(Ciphertext::from_bytes(pt.to_vec()))
        }
        async fn decrypt(&self, ct: &Ciphertext, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(ct.as_bytes().to_vec()))
        }
    }

    /// A backend's extension trait, implemented for the opaque handle through the layered slot
    /// and for its typed decorators.
    trait Tagging {
        async fn tag(&self, input: &[u8], label: &str) -> Result<Vec<u8>>;
    }
    impl Tagging for AeadKey {
        async fn tag(&self, input: &[u8], label: &str) -> Result<Vec<u8>> {
            let key = self
                .downcast_arc::<Native>()
                .ok_or_else(|| Error::unsupported("not a native key"))?;
            // Borrowed inputs, reused by every attempt.
            self.call_extension(Operation::Mac, "native.tag", || {
                let key = key.clone();
                Box::pin(async move { key.tag(input, label).await })
            })
            .await
        }
    }
    impl Tagging for crate::Retry<Arc<Native>> {
        async fn tag(&self, input: &[u8], label: &str) -> Result<Vec<u8>> {
            self.call(|| self.inner().tag(input, label)).await
        }
    }
    impl<T: Tagging + Sync> Tagging for crate::Observed<T> {
        async fn tag(&self, input: &[u8], label: &str) -> Result<Vec<u8>> {
            self.call(Operation::Mac, "native.tag", self.inner().tag(input, label))
                .await
        }
    }

    type Events = Arc<std::sync::Mutex<Vec<(PartKind, Operation, Option<&'static str>, bool)>>>;

    fn observing() -> (crate::ObserveLayer, Events) {
        let events = Events::default();
        let ev = events.clone();
        let layer = crate::ObserveLayer::new(move |e: &crate::OpEvent<'_>| {
            ev.lock()
                .unwrap()
                .push((e.part(), e.operation(), e.extension_name(), e.is_ok()))
        });
        (layer, events)
    }

    /// An extension call goes through the handle's layers: retried by the retry layer, observed
    /// once per attempt below it and once per call above it, with its name.
    #[tokio::test]
    async fn extension_calls_are_layered() {
        let retry = crate::RetryLayer::new(crate::instant_sleep())
            .with_policy(crate::RetryPolicy::immediate());
        let (below, attempts) = observing();
        let (above, calls) = observing();
        let native = Native::new(2);
        let k = AeadKey::new("native", native.clone())
            .with_concrete(native.clone())
            .layer(&below)
            .layer(&retry)
            .layer(&above);
        let input = b"in".to_vec();
        let label = String::from("l");
        assert_eq!(k.tag(&input, &label).await.unwrap(), b"inl");
        assert_eq!(native.calls(), 3);
        let event = |ok| (PartKind::Extension, Operation::Mac, Some("native.tag"), ok);
        assert_eq!(
            *attempts.lock().unwrap(),
            [event(false), event(false), event(true)]
        );
        assert_eq!(*calls.lock().unwrap(), [event(true)]);
        // Portable operations carry no extension name.
        k.encrypt(b"x", b"").await.unwrap();
        assert_eq!(
            calls.lock().unwrap().last(),
            Some(&(PartKind::Aead, Operation::Encrypt, None, true))
        );

        // Non-retryable errors are returned at once; the retry budget applies as for any part.
        let native = Native::new(0);
        let k = AeadKey::new("native", native.clone()).layer(&retry);
        let e = k.tag(b"", "").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported, "no concrete key: {e}");
        assert_eq!(native.calls(), 0);

        // Without layers the call runs once, directly.
        let native = Native::new(1);
        let k = AeadKey::new("native", native.clone()).with_concrete(native.clone());
        assert_eq!(
            k.tag(b"a", "b").await.unwrap_err().kind(),
            ErrorKind::Throttled
        );
        assert_eq!(native.calls(), 1);

        // Through a key-wrap handle made from the AEAD key, the slot keeps its layers.
        let native = Native::new(1);
        let kw = KeyWrapKey::from_aead(
            AeadKey::new("native", native.clone())
                .with_concrete(native.clone())
                .layer(&retry),
        );
        let out = kw
            .call_extension(Operation::Mac, "native.tag", || {
                let n = native.clone();
                Box::pin(async move { n.tag(b"k", "w").await })
            })
            .await
            .unwrap();
        assert_eq!(out, b"kw");
        assert_eq!(native.calls(), 2);
    }

    /// The typed path: `Retry::call` and `Observed::call` give a backend's extension trait on
    /// its typed handle the same retries and events.
    #[tokio::test]
    async fn typed_extension_calls_are_retried_and_observed() {
        let (observe, events) = observing();
        let native = Native::new(2);
        let retried = crate::RetryLayer::new(crate::instant_sleep())
            .with_policy(crate::RetryPolicy::immediate())
            .wrap(native.clone());
        let k = observe.wrap(retried);
        assert_eq!(k.tag(b"t", "y").await.unwrap(), b"ty");
        assert_eq!(native.calls(), 3);
        assert_eq!(
            *events.lock().unwrap(),
            [(
                PartKind::Extension,
                Operation::Mac,
                Some("native.tag"),
                true
            )]
        );
    }

    /// The slot is a part like any other: a layer's catch-all sees it and may replace it, and
    /// the dyn bridges forward it.
    #[tokio::test]
    async fn extension_slot_bridges_and_debug() {
        struct Counting(
            Arc<std::sync::atomic::AtomicU32>,
            Arc<dyn DynExtensionCalls>,
        );
        impl ExtensionCalls for Counting {
            async fn run_extension(&self, call: Call<'_>) -> Result<CallOutput> {
                assert_eq!(
                    format!("{call:?}"),
                    "Call { part: Extension, op: Mac, name: \"native.tag\", .. }"
                );
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Box and `&` forward too.
                let boxed: Box<&dyn DynExtensionCalls> = Box::new(&*self.1);
                boxed.run_extension(call).await
            }
        }
        #[derive(Clone, Default)]
        struct CountExtensions(Arc<std::sync::atomic::AtomicU32>);
        impl Layer for CountExtensions {
            fn part(&self, _: &LayerCx<'_>, part: Part<'_>) {
                if let Part::Extension(p) = part {
                    *p = Arc::new(Counting(self.0.clone(), p.clone()));
                }
            }
        }
        let count = CountExtensions::default();
        let native = Native::new(0);
        let k = AeadKey::new("native", native.clone())
            .with_concrete(native)
            .layer(&count);
        k.tag(b"", "").await.unwrap();
        // The future is `Send`, borrowed inputs and all.
        let input = vec![1u8];
        let n = k.downcast_arc::<Native>().unwrap();
        assert_send(k.call_extension(Operation::Mac, "native.tag", || {
            let n = n.clone();
            let input = &input;
            Box::pin(async move { n.tag(input, "").await })
        }))
        .await
        .unwrap();
        assert_eq!(count.0.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(PartKind::Extension.to_string(), "extension");
        assert_eq!(format!("{:?}", CallOutput::new(1u8)), "CallOutput { .. }");
        let slot: Arc<dyn DynExtensionCalls> = Arc::new(Direct);
        assert_eq!(format!("{slot:?}"), "DynExtensionCalls { .. }");
    }

    /// Data keys fail `fail` times, then succeed.
    struct FlakyDataKeys(std::sync::Mutex<u32>);
    impl DataKeys for FlakyDataKeys {
        async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey> {
            let mut fail = self.0.lock().unwrap();
            if *fail > 0 {
                *fail -= 1;
                return Err(Error::app(ErrorKind::Unavailable, "down"));
            }
            DataKey::new(
                spec,
                Zeroizing::new(vec![7; 32]),
                Ciphertext::from_bytes(aad.to_vec()),
            )
        }
    }

    /// A registry routes `data_keys` to the provider, labels and layers the handle; a missing
    /// describe part is `Unsupported`, and `full` sets describe.
    #[tokio::test]
    async fn data_keys_handles() {
        struct P;
        impl crate::Provider for P {
            fn schemes(&self) -> &[&'static str] {
                &["p"]
            }
            fn data_keys(&self, _: &crate::KeyUri, _: &crate::OpenOptions) -> Result<DataKeysKey> {
                Ok(DataKeysKey::new(
                    "p",
                    Arc::new(FlakyDataKeys(std::sync::Mutex::new(2))),
                ))
            }
        }
        let (observe, events) = observing();
        let reg = crate::Registry::builder()
            .provider(P)
            .layer(observe)
            .layer(
                crate::RetryLayer::new(crate::instant_sleep())
                    .with_policy(crate::RetryPolicy::immediate()),
            )
            .build()
            .unwrap();
        let k = reg.data_keys("p://k?x=1").unwrap();
        assert_eq!(k.resource(), Some("p://k"));
        assert!(k.is_retrying() && !k.supports_describe());
        let dk = k
            .generate_data_key(DataKeySpec::Aes256, b"ctx")
            .await
            .unwrap();
        assert_eq!(dk.ciphertext().as_bytes(), b"ctx");
        assert_eq!(events.lock().unwrap().len(), 3);
        assert_eq!(
            events.lock().unwrap()[0].0,
            PartKind::DataKeys,
            "the main part is layered as DataKeys"
        );
        let e = k.describe().await.unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::Unsupported, Operation::Describe)
        );
        assert_eq!(
            k.preflight().await.unwrap_err().kind(),
            ErrorKind::Unsupported
        );
        assert_eq!(
            format!("{k:?}"),
            "DataKeysKey { backend: \"p\", resource: Some(\"p://k\"), describe: false, preflight: false }"
        );

        let full = DataKeysKey::full("t", FullAead);
        assert!(full.supports_describe());
        full.preflight().await.unwrap();
        assert_eq!(
            full.generate_data_key(DataKeySpec::Aes256, b"")
                .await
                .unwrap()
                .plaintext()
                .len(),
            32
        );
        assert!(full.downcast_ref::<FullAead>().is_some());
    }

    /// An AEAD key with every part of 0.1.
    struct FullAead;
    impl Aead for FullAead {
        async fn encrypt(&self, pt: &[u8], _: &[u8]) -> Result<Ciphertext> {
            Ok(Ciphertext::from_bytes(pt.to_vec()))
        }
        async fn decrypt(&self, ct: &Ciphertext, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(ct.as_bytes().to_vec()))
        }
    }
    impl Rewrap for FullAead {
        async fn rewrap(&self, ct: &Ciphertext, _: &[u8]) -> Result<Ciphertext> {
            Ok(ct.clone())
        }
    }
    impl DataKeys for FullAead {
        async fn generate_data_key(&self, spec: DataKeySpec, _: &[u8]) -> Result<DataKey> {
            DataKey::new(
                spec,
                Zeroizing::new(vec![0; 32]),
                Ciphertext::from_bytes(vec![1]),
            )
        }
    }
    impl Describe for FullAead {
        async fn describe(&self) -> Result<KeyInfo> {
            Ok(KeyInfo::new("everything", Capabilities::AEAD))
        }
    }

    struct Echo;
    impl Aead for Echo {
        async fn encrypt(&self, pt: &[u8], _: &[u8]) -> Result<Ciphertext> {
            Ok(Ciphertext::from_bytes(pt.to_vec()))
        }
        async fn decrypt(&self, ct: &Ciphertext, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(ct.as_bytes().to_vec()))
        }
        fn ciphertext_version(&self, _: &Ciphertext) -> Result<Option<KeyVersion>> {
            Ok(Some(KeyVersion::from(7)))
        }
    }

    fn assert_send<T: Send>(t: T) -> T {
        t
    }

    #[tokio::test]
    async fn dyn_bridges_and_provided_methods() {
        let d: Arc<dyn DynAead> = Arc::new(Echo);
        let ct = assert_send(d.encrypt(b"x", b"")).await.unwrap();
        // Provided method is forwarded, not defaulted.
        assert_eq!(
            d.ciphertext_version(&ct).unwrap(),
            Some(KeyVersion::from(7))
        );
        let k = AeadKey::new("echo", d);
        assert_eq!(
            k.ciphertext_version(&ct).unwrap(),
            Some(KeyVersion::from(7))
        );
        assert_eq!(&*k.decrypt(&ct, b"").await.unwrap(), b"x");
        assert_eq!(
            k.rewrap(&ct, b"").await.unwrap_err().kind(),
            ErrorKind::Unsupported
        );
        // Futures are Send and 'static-capable through tokio::spawn.
        let h = tokio::spawn(async move { k.encrypt(b"y", b"a").await.map(|c| c.into_bytes()) });
        assert_eq!(h.await.unwrap().unwrap(), b"y");
    }

    /// Static path: the future of a generic `K: Aead` (no `dyn`, no boxing) is `Send` and can be
    /// spawned. This only typechecks because `#[trait_variant::make(Send)]` puts a `Send` bound on
    /// the trait's futures, and because `Aead` requires `Send + Sync`, which makes `Arc<K>` `Send`
    /// with no bound beyond `K: Aead + 'static`.
    fn spawn_encrypt<K>(k: Arc<K>, pt: &'static [u8]) -> tokio::task::JoinHandle<Result<Vec<u8>>>
    where
        K: Aead + 'static,
    {
        tokio::spawn(async move { k.encrypt(pt, b"a").await.map(|c| c.into_bytes()) })
    }

    #[tokio::test]
    async fn static_futures_are_spawnable() {
        let h = spawn_encrypt(Arc::new(Echo), b"s");
        assert_eq!(h.await.unwrap().unwrap(), b"s");
        // Generic decorators keep it: `Retry<K>` over a generic `K`.
        let h = spawn_encrypt(
            Arc::new(crate::RetryLayer::new(crate::instant_sleep()).wrap(Echo)),
            b"r",
        );
        assert_eq!(h.await.unwrap().unwrap(), b"r");
    }

    struct Signer;
    impl DigestSigner for Signer {
        fn signature_algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::EcdsaP256Sha256
        }
        async fn sign_digest(&self, _: &Digest) -> Result<Signature> {
            Ok(Signature::from_parts(
                self.signature_algorithm(),
                None,
                vec![1],
            ))
        }
    }
    impl PublicKeys for Signer {
        async fn public_key(&self) -> Result<PublicKey> {
            Ok(PublicKey::new(AsymmetricKeyType::EcP256, vec![2], None))
        }
        async fn public_key_version(&self, _: &KeyVersion) -> Result<PublicKey> {
            self.public_key().await
        }
    }
    impl Describe for Signer {
        async fn describe(&self) -> Result<KeyInfo> {
            Ok(KeyInfo::new("test", Capabilities::SIGN))
        }
    }

    #[tokio::test]
    async fn handles_have_optional_parts() {
        let d = Digest::new(HashAlgorithm::Sha256, &[0; 32]).unwrap();
        let full = DigestSignerKey::full("test", Signer);
        assert!(full.supports_public_keys() && full.supports_describe());
        assert_eq!(full.sign_digest(&d).await.unwrap().as_bytes(), [1]);
        assert_eq!(full.public_key().await.unwrap().spki_der(), [2]);
        assert_eq!(full.describe().await.unwrap().backend_key_type(), "test");

        let bare = DigestSignerKey::new("test", Arc::new(Signer));
        assert!(!bare.supports_public_keys());
        let e = bare.public_key().await.unwrap_err();
        assert_eq!((e.kind(), e.backend()), (ErrorKind::Unsupported, "test"));
        assert_eq!(
            bare.describe().await.unwrap_err().operation(),
            Operation::Describe
        );
        let bare = bare.with_describe(Arc::new(Signer));
        assert!(bare.describe().await.is_ok());

        // Debug, including through `Retry` and as a bare `Arc<dyn DynX>`.
        assert_eq!(
            format!("{full:?}"),
            "DigestSignerKey { backend: \"test\", resource: None, public_keys: true, describe: true, verifier: true, preflight: false }"
        );
        let r = crate::RetryLayer::new(crate::instant_sleep()).wrap(full.clone());
        assert!(format!("{r:?}").contains("DigestSignerKey"));
        let dynamic: Arc<dyn DynDigestSigner> = Arc::new(full);
        assert_eq!(format!("{dynamic:?}"), "DynDigestSigner { .. }");
    }

    /// The handles are themselves usable as `DynX` (the sealed traits still reach them through
    /// the blanket impls), and an `Aead` wraps keys with empty AAD once adapted.
    #[tokio::test]
    async fn handles_are_dyn_and_aeads_wrap_keys() {
        fn takes_dyn(_: Arc<dyn DynPublicKeys>) {}
        takes_dyn(Arc::new(PublicKeysKey::full("test", Signer)));

        let k = AeadKey::new("echo", Arc::new(Echo));
        let w = (&k).into_key_wrap().wrap_key(b"dek").await.unwrap();
        assert_eq!(w, k.encrypt(b"dek", b"").await.unwrap());
        let kw = k.clone().into_key_wrap();
        assert_eq!(&*kw.unwrap_key(&w).await.unwrap(), b"dek");
        assert_eq!(
            kw.wrapped_key_version(&w).unwrap(),
            Some(KeyVersion::from(7))
        );
        let kw: Arc<dyn DynKeyWrap> = Arc::new(kw);
        assert_eq!(kw.wrap_key(b"x").await.unwrap().as_bytes(), b"x");
        assert_eq!(
            kw.wrapped_key_version(&w).unwrap(),
            Some(KeyVersion::from(7))
        );
        // `Box` and `&` of the object are `KeyWrap` too.
        let boxed: Box<dyn DynKeyWrap> = Box::new(AeadKeyWrap::new(k));
        assert_eq!(boxed.wrap_key(b"b").await.unwrap().as_bytes(), b"b");
        let borrowed: &dyn DynKeyWrap = &*kw;
        assert_eq!(borrowed.unwrap_key(&w).await.unwrap().as_slice(), b"dek");
        // A decorator wraps `KeyWrap` on its own.
        let retried = crate::RetryLayer::new(crate::instant_sleep()).wrap(kw);
        assert_eq!(&*retried.unwrap_key(&w).await.unwrap(), b"dek");
    }

    struct Fails {
        calls: std::sync::atomic::AtomicU32,
    }
    impl Aead for Fails {
        async fn encrypt(&self, pt: &[u8], _: &[u8]) -> Result<Ciphertext> {
            if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                return Err(Error::app(ErrorKind::Unavailable, "down"));
            }
            Ok(Ciphertext::from_bytes(pt.to_vec()))
        }
        async fn decrypt(&self, ct: &Ciphertext, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(ct.as_bytes().to_vec()))
        }
    }

    /// Describes as a key of the given capabilities and state.
    struct Described(Capabilities, Option<KeyState>);
    impl Describe for Described {
        async fn describe(&self) -> Result<KeyInfo> {
            Ok(KeyInfo::new("t", self.0)
                .with_state(self.1.clone())
                .with_signature_algorithms(vec![SignatureAlgorithm::EcdsaP256Sha256]))
        }
    }

    #[tokio::test]
    async fn preflight_checks_capability_algorithm_and_state() {
        let aead = |caps, state| {
            AeadKey::new("t", Arc::new(Echo)).with_describe(Arc::new(Described(caps, state)))
        };
        let info = aead(Capabilities::AEAD | Capabilities::REWRAP, None)
            .preflight()
            .await
            .unwrap();
        assert!(info.capabilities().contains(Capabilities::AEAD));
        let kind = async |k: AeadKey| k.preflight().await.unwrap_err().kind();
        assert_eq!(
            kind(aead(Capabilities::SIGN, None)).await,
            ErrorKind::KeyMismatch
        );
        assert_eq!(
            kind(aead(Capabilities::AEAD, Some(KeyState::Disabled))).await,
            ErrorKind::KeyStateInvalid
        );
        assert_eq!(
            kind(AeadKey::new("t", Arc::new(Echo))).await,
            ErrorKind::Unsupported
        );
        // Signers also check their algorithm against the key's.
        let signer = |alg| {
            struct S(SignatureAlgorithm);
            impl DigestSigner for S {
                fn signature_algorithm(&self) -> SignatureAlgorithm {
                    self.0
                }
                async fn sign_digest(&self, _: &Digest) -> Result<Signature> {
                    unimplemented!()
                }
            }
            DigestSignerKey::new("t", Arc::new(S(alg)))
                .with_describe(Arc::new(Described(Capabilities::SIGN, None)))
        };
        signer(SignatureAlgorithm::EcdsaP256Sha256)
            .preflight()
            .await
            .unwrap();
        assert_eq!(
            signer(SignatureAlgorithm::EcdsaP384Sha384)
                .preflight()
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::KeyMismatch
        );
        // A describe handle only describes.
        DescribeKey::new("t", Arc::new(Described(Capabilities::NONE, None)))
            .preflight()
            .await
            .unwrap();
    }

    /// Describes an enabled AEAD key (no key-level state) with versions 1 and 2, the primary
    /// version 2 in the given state; `listed: false` omits the primary from the versions.
    struct Versioned(KeyState, bool);
    impl Describe for Versioned {
        async fn describe(&self) -> Result<KeyInfo> {
            let v = |n, s| KeyVersionInfo::new(KeyVersion::from_u64(n), s);
            let mut versions = vec![v(1, KeyState::Disabled)];
            if self.1 {
                versions.push(v(2, self.0.clone()));
            }
            Ok(KeyInfo::new("t", Capabilities::AEAD)
                .with_primary_version(Some(KeyVersion::from_u64(2)))
                .with_versions(versions))
        }
    }

    /// R-49: the generic preflight refuses a key whose listed primary version is not enabled,
    /// where state is per version only; another disabled version, or a primary the describe
    /// does not list, passes.
    #[tokio::test]
    async fn preflight_refuses_an_unusable_primary_version() {
        let aead = |state, listed| {
            AeadKey::new("t", Arc::new(Echo)).with_describe(Arc::new(Versioned(state, listed)))
        };
        aead(KeyState::Enabled, true).preflight().await.unwrap();
        aead(KeyState::Disabled, false).preflight().await.unwrap();
        for state in [
            KeyState::Disabled,
            KeyState::PendingDeletion,
            KeyState::Destroyed,
            KeyState::Unknown("PENDING_GENERATION".into()),
        ] {
            let e = aead(state.clone(), true).preflight().await.unwrap_err();
            assert_eq!(
                (e.kind(), e.operation()),
                (ErrorKind::KeyStateInvalid, Operation::Describe),
                "{state:?}: {e}"
            );
            assert!(e.message().contains("primary version"), "{e}");
        }
    }

    /// Describes after two transient failures.
    struct FlakyDescribe {
        calls: std::sync::atomic::AtomicU32,
    }
    impl Describe for FlakyDescribe {
        async fn describe(&self) -> Result<KeyInfo> {
            if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                return Err(Error::app(ErrorKind::Unavailable, "down"));
            }
            Err(Error::app(ErrorKind::NotFound, "described"))
        }
    }

    /// A part added after layering gets the handle's layers, retries included.
    #[tokio::test]
    async fn parts_added_after_layering_are_layered() {
        let layer = crate::RetryLayer::new(crate::instant_sleep())
            .with_policy(crate::RetryPolicy::immediate());
        let fails = Arc::new(Fails {
            calls: Default::default(),
        });
        let flaky = Arc::new(FlakyDescribe {
            calls: Default::default(),
        });
        let k = AeadKey::new("t", fails)
            .layer(&layer)
            .with_describe(flaky.clone());
        assert!(k.is_retrying() && k.supports_describe());
        // Two transient failures retried away: the third call answers.
        assert_eq!(k.describe().await.unwrap_err().kind(), ErrorKind::NotFound);
        assert_eq!(flaky.calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    /// `replace_retry` swaps the retry policy of one handle, keeping its other layers.
    #[tokio::test]
    async fn replace_retry_swaps_the_policy() {
        let patient = crate::RetryLayer::new(crate::instant_sleep())
            .with_policy(crate::RetryPolicy::immediate());
        let impatient = crate::RetryLayer::new(crate::instant_sleep())
            .with_policy(crate::RetryPolicy::immediate().with_max_attempts(1));
        let tally = Arc::new(Tally::default());
        let fails = Arc::new(Fails {
            calls: Default::default(),
        });
        let k = AeadKey::new("t", fails.clone())
            .layer(&patient)
            .layer(&tally)
            .replace_retry(&impatient);
        assert!(k.is_retrying());
        // One attempt: the first transient failure is returned.
        assert_eq!(
            k.encrypt(b"x", b"").await.unwrap_err().kind(),
            ErrorKind::Unavailable
        );
        assert_eq!(fails.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        // The tally layer was applied again when the parts were rebuilt, and still counts.
        assert_eq!(tally.0.load(std::sync::atomic::Ordering::SeqCst), 2);
        // On a handle that does not retry yet, it adds the layer.
        let k = AeadKey::new("t", Arc::new(Echo)).replace_retry(&patient);
        assert!(k.is_retrying());
        // A key-wrap key made from a retrying AEAD key retries through its key-wrap part.
        let fails = Arc::new(Fails {
            calls: Default::default(),
        });
        let kw = KeyWrapKey::from_aead(AeadKey::new("t", fails.clone()).layer(&patient));
        assert!(kw.is_retrying());
        assert_eq!(kw.wrap_key(b"dek").await.unwrap().as_bytes(), b"dek");
        assert_eq!(fails.calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    /// A layer wraps each part, keeps the handle type and its exact parts, and leaves the
    /// concrete key reachable.
    #[tokio::test]
    async fn layers_keep_parts_and_concrete_key() {
        let layer = crate::RetryLayer::new(crate::instant_sleep())
            .with_policy(crate::RetryPolicy::immediate());
        let fails = Arc::new(Fails {
            calls: Default::default(),
        });
        let k: AeadKey = AeadKey::new("t", fails.clone())
            .with_concrete(fails)
            .layer(&layer);
        assert!(!k.supports_rewrap() && !k.supports_data_keys());
        assert_eq!(
            k.rewrap(&Ciphertext::from_bytes(vec![]), b"")
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::Unsupported
        );
        // Two failures retried away by the layer.
        assert_eq!(k.encrypt(b"x", b"").await.unwrap().as_bytes(), b"x");
        let concrete = k.downcast_ref::<Fails>().expect("concrete key");
        assert_eq!(concrete.calls.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert!(k.downcast_ref::<Echo>().is_none());
        assert!(k.downcast_arc::<Fails>().is_some());

        // `full` records the concrete key and every part; the layer keeps them all.
        let s = DigestSignerKey::full("test", Signer).layer(&layer);
        assert!(s.supports_public_keys() && s.supports_describe() && s.supports_verifier());
        assert!(s.downcast_ref::<Signer>().is_some());
        assert!(
            DigestSignerKey::new("t", Arc::new(Signer))
                .downcast_ref::<Signer>()
                .is_none()
        );

        // Generic over handle types.
        fn relayer<H: OpaqueHandle, L: Layer + Clone + 'static>(h: H, l: &L) -> H {
            h.layer(l)
        }
        assert_eq!(relayer(s, &layer).backend_name(), "test");
    }

    struct Down {
        calls: std::sync::atomic::AtomicU32,
    }
    impl Aead for Down {
        async fn encrypt(&self, _: &[u8], _: &[u8]) -> Result<Ciphertext> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(Error::app(ErrorKind::Unavailable, "down"))
        }
        async fn decrypt(&self, _: &Ciphertext, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Err(Error::app(ErrorKind::Unavailable, "down"))
        }
    }

    /// Counts how often it was applied (a stand-in for a non-retrying layer such as metrics).
    #[derive(Default)]
    struct Tally(std::sync::atomic::AtomicU32);
    impl Layer for Tally {
        fn part(&self, _: &LayerCx<'_>, part: Part<'_>) {
            if part.kind() == PartKind::Aead {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }

    /// An AEAD handle becomes a key-wrapping handle with the same parts, concrete key and retry
    /// state; the key-wrap part is layered like any other.
    #[tokio::test]
    async fn key_wrap_handles_from_aead_keys() {
        let fails = Arc::new(Fails {
            calls: Default::default(),
        });
        let layer = crate::RetryLayer::new(crate::instant_sleep())
            .with_policy(crate::RetryPolicy::immediate());
        let k = KeyWrapKey::from(AeadKey::new("t", fails.clone()).with_concrete(fails.clone()))
            .layer(&layer);
        assert!(k.is_retrying() && !k.supports_rewrap() && !k.supports_describe());
        assert!(k.downcast_ref::<Fails>().is_some());
        // Two failures retried away through the key-wrap part.
        let w = k.wrap_key(b"dek").await.unwrap();
        assert_eq!(w.as_bytes(), b"dek");
        assert_eq!(fails.calls.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert_eq!(&*k.unwrap_key(&w).await.unwrap(), b"dek");
        let e = k.rewrap(&w, b"").await.unwrap_err();
        assert_eq!(
            (e.kind(), e.operation(), e.backend()),
            (ErrorKind::Unsupported, Operation::Rewrap, "t")
        );
        // The message names the recipe that rewraps envelopes on any KEK.
        assert!(e.message().contains("EnvelopeAead::rewrap_local"), "{e}");
        let full = KeyWrapKey::from_aead(AeadKey::new("echo", Arc::new(Echo)));
        assert_eq!(
            full.wrapped_key_version(&w).unwrap(),
            Some(KeyVersion::from(7))
        );
        assert_eq!(
            format!("{full:?}"),
            "KeyWrapKey { backend: \"echo\", resource: None, rewrap: false, describe: false, preflight: false, public_keys: false }"
        );
    }

    /// An AEAD key that rewraps, recording the AAD of every rewrap call.
    #[derive(Default)]
    struct Rewraps(std::sync::Mutex<Vec<Vec<u8>>>);
    impl Aead for Rewraps {
        async fn encrypt(&self, pt: &[u8], _: &[u8]) -> Result<Ciphertext> {
            Ok(Ciphertext::from_bytes(pt.to_vec()))
        }
        async fn decrypt(&self, ct: &Ciphertext, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(ct.as_bytes().to_vec()))
        }
    }
    impl Rewrap for Rewraps {
        async fn rewrap(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext> {
            self.0.lock().unwrap().push(aad.to_vec());
            Ok(ct.clone())
        }
    }

    /// A KEK rewraps wrapped keys with empty AAD only: other AAD is `InvalidArgument` before the
    /// backend is called, through the handle and through the adapter.
    #[tokio::test]
    async fn kek_rewrap_requires_empty_aad() {
        let inner = Arc::new(Rewraps::default());
        let ct = Ciphertext::from_bytes(b"wrapped".to_vec());
        let kek =
            KeyWrapKey::from_aead(AeadKey::new("t", inner.clone()).with_rewrap(inner.clone()));
        let adapted = AeadKeyWrap::new(inner.clone());
        assert_eq!(kek.rewrap(&ct, b"").await.unwrap(), ct);
        assert_eq!(adapted.rewrap(&ct, b"").await.unwrap(), ct);
        for e in [
            kek.rewrap(&ct, b"ctx").await.unwrap_err(),
            adapted.rewrap(&ct, b"ctx").await.unwrap_err(),
        ] {
            assert_eq!(
                (e.kind(), e.operation()),
                (ErrorKind::InvalidArgument, Operation::Rewrap)
            );
        }
        assert_eq!(*inner.0.lock().unwrap(), [b"", b""]);
        // The AEAD handle itself still rewraps ordinary ciphertexts with their AAD.
        let aead = AeadKey::new("t", inner.clone()).with_rewrap(inner.clone());
        aead.rewrap(&ct, b"ctx").await.unwrap();
        assert_eq!(inner.0.lock().unwrap().last().unwrap(), b"ctx");
    }

    /// Every part reaches the layer's `part`, which sees its kind.
    #[test]
    fn layer_parts_route_through_the_catch_all() {
        #[derive(Default)]
        struct Kinds(std::sync::Mutex<Vec<PartKind>>);
        impl Layer for Kinds {
            fn part(&self, _: &LayerCx<'_>, part: Part<'_>) {
                self.0.lock().unwrap().push(part.kind());
            }
        }
        // Shared, so the test can read what the handle's copy recorded.
        let l = Arc::new(Kinds::default());
        let k = DigestSignerKey::full("test", Signer).layer(&l);
        assert!(k.supports_public_keys() && k.supports_describe() && k.supports_verifier());
        assert_eq!(
            *l.0.lock().unwrap(),
            [
                PartKind::DigestSigner,
                PartKind::PublicKeys,
                PartKind::Describe,
                PartKind::DigestVerifier,
                // Every handle's extension slot.
                PartKind::Extension,
            ]
        );
        let mut kw: Arc<dyn DynKeyWrap> = Arc::new(Echo.into_key_wrap());
        l.part(&LayerCx::new("test"), Part::KeyWrap(&mut kw));
        assert_eq!(l.0.lock().unwrap().last(), Some(&PartKind::KeyWrap));
        assert_eq!(PartKind::KeyWrap.to_string(), "key_wrap");
        let mut slot: Arc<dyn DynDescribe> = Arc::new(Signer);
        assert_eq!(format!("{:?}", Part::Describe(&mut slot)), "Part(Describe)");
    }

    /// A second retrying layer is a no-op: 6 attempts stay 6 (not 36) and only the first
    /// layer's budget is spent. Other layers still apply.
    #[tokio::test]
    async fn retry_layers_do_not_nest() {
        let layer = || {
            crate::RetryLayer::new(crate::instant_sleep())
                .with_policy(crate::RetryPolicy::immediate().with_max_attempts(6))
        };
        let down = Arc::new(Down {
            calls: Default::default(),
        });
        let first = layer();
        let second = layer();
        let tally = Arc::new(Tally::default());
        let k = AeadKey::new("t", down.clone());
        assert!(!k.is_retrying());
        let k = k.layer(&first).layer(&tally).layer(&second).layer(&first);
        assert!(k.is_retrying());
        assert_eq!(tally.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            k.encrypt(b"x", b"").await.unwrap_err().kind(),
            ErrorKind::Unavailable
        );
        assert_eq!(down.calls.load(std::sync::atomic::Ordering::SeqCst), 6);
        // The second layer's budget is untouched; the first paid for 5 retries.
        assert_eq!(
            format!("{:?}", second.budget()),
            format!("{:?}", layer().budget())
        );
        assert_ne!(
            format!("{:?}", first.budget()),
            format!("{:?}", layer().budget())
        );

        // The same through a registry: its retry layer applies, the handle's is skipped.
        struct P(Arc<Down>);
        impl crate::Provider for P {
            fn schemes(&self) -> &[&'static str] {
                &["p"]
            }
            fn aead(&self, _: &crate::KeyUri, _: &crate::OpenOptions) -> Result<AeadKey> {
                Ok(AeadKey::new("p", self.0.clone()))
            }
        }
        let down = Arc::new(Down {
            calls: Default::default(),
        });
        let reg = crate::Registry::builder()
            .provider(P(down.clone()))
            .layer(layer())
            .layer(layer())
            .build()
            .unwrap();
        let k = reg.aead("p://k").unwrap().layer(&layer());
        assert!(k.encrypt(b"x", b"").await.is_err());
        assert_eq!(down.calls.load(std::sync::atomic::Ordering::SeqCst), 6);
    }

    impl DigestVerifier for Signer {
        async fn verify_digest(&self, _: &Digest, sig: &Signature) -> Result<()> {
            if sig.as_bytes() == [1] {
                Ok(())
            } else {
                Err(Error::app(ErrorKind::VerificationFailed, "bad"))
            }
        }
    }

    #[tokio::test]
    async fn signer_handles_have_an_optional_verifier() {
        let d = Digest::new(HashAlgorithm::Sha256, &[0; 32]).unwrap();
        let k = DigestSignerKey::new("test", Arc::new(Signer));
        let sig = k.sign_digest(&d).await.unwrap();
        let e = k.verify_digest(&d, &sig).await.unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::Unsupported, Operation::Verify)
        );
        let k = DigestSignerKey::full("test", Signer);
        assert!(k.supports_verifier());
        k.verify_digest(&d, &sig).await.unwrap();
        let k = k.with_verifier(Arc::new(Signer));
        assert!(k.verify_digest(&d, &sig).await.is_ok());
    }

    struct Primary;
    impl Aead for Primary {
        async fn encrypt(&self, pt: &[u8], _: &[u8]) -> Result<Ciphertext> {
            Ok(Ciphertext::from_bytes(pt.to_vec()))
        }
        async fn decrypt(&self, ct: &Ciphertext, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(ct.as_bytes().to_vec()))
        }
        async fn decrypt_with_info(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Decrypted> {
            Ok(Decrypted::new(self.decrypt(ct, aad).await?)
                .with_version(Some(KeyVersion::from(3)))
                .with_used_primary(Some(true)))
        }
    }

    /// `decrypt_with_info` defaults to `ciphertext_version`, and an override is forwarded
    /// through every bridge, handle and decorator.
    #[tokio::test]
    async fn decrypt_with_info_is_forwarded() {
        let ct = Ciphertext::from_bytes(b"pt".to_vec());
        let d = Echo.decrypt_with_info(&ct, b"").await.unwrap();
        assert_eq!(d.plaintext(), b"pt");
        assert_eq!(
            (d.key_version(), d.used_primary()),
            (Some(&KeyVersion::from(7)), None)
        );

        async fn info<K: Aead>(k: K, ct: &Ciphertext) -> (Option<KeyVersion>, Option<bool>) {
            let d = k.decrypt_with_info(ct, b"").await.unwrap();
            (d.key_version().cloned(), d.used_primary())
        }
        let want = (Some(KeyVersion::from(3)), Some(true));
        let dynamic: Arc<dyn DynAead> = Arc::new(Primary);
        assert_eq!(info(dynamic.clone(), &ct).await, want);
        let key = AeadKey::new("p", dynamic);
        assert_eq!(info(&key, &ct).await, want);
        assert_eq!(info(Box::new(key.clone()), &ct).await, want);
        let layered = key.layer(&crate::RetryLayer::new(crate::instant_sleep()));
        assert_eq!(info(layered, &ct).await, want);
        assert_eq!(
            info(
                crate::RetryLayer::new(crate::instant_sleep()).wrap(Primary),
                &ct
            )
            .await,
            want
        );
    }

    #[tokio::test]
    async fn decrypt_utf8() {
        let k = AeadKey::new("echo", Arc::new(Echo));
        let s = k
            .decrypt_utf8(&Ciphertext::from_bytes("héllo".as_bytes().to_vec()), b"")
            .await
            .unwrap();
        assert_eq!(s.as_str(), "héllo");
        let e = k
            .decrypt_utf8(&Ciphertext::from_bytes(vec![0xff, 0xfe]), b"")
            .await
            .unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::InvalidArgument, Operation::Decrypt)
        );
    }

    /// A KEK made from an AEAD key declares no data keys and no plaintext limit.
    #[test]
    fn from_aead_drops_data_keys_and_max_plaintext() {
        use crate::{DataKeyAad, DataKeySource, KeySemantics, VersionModel, VersionShape};
        let sem = KeySemantics::new(VersionModel::Floating, VersionShape::Numeric)
            .with_data_keys(Some(DataKeySource::native(DataKeyAad::Bound)))
            .with_max_plaintext(Some(4096))
            .with_ciphertext_reveals_version(true);
        let kek = KeyWrapKey::from_aead(AeadKey::new("t", Arc::new(Echo)).with_semantics(sem));
        let s = kek.semantics().unwrap();
        assert_eq!(s.data_keys(), None);
        assert_eq!(s.max_plaintext(), None);
        assert!(s.ciphertext_reveals_version());
    }

    /// The declared semantics survive every way a handle is decorated or converted: layers
    /// (including `replace_retry` and `with_resource`), parts added later, `from_aead`, the
    /// typed decorators and smart pointers; a handle without them reports `None`.
    #[test]
    fn semantics_are_carried() {
        use crate::{KeySemantics, Semantics, VersionModel, VersionShape};
        fn via_trait<S: Semantics>(s: S) -> Option<KeySemantics> {
            s.semantics().cloned()
        }
        fn via_handle<H: OpaqueHandle>(h: &H) -> Option<KeySemantics> {
            h.semantics().cloned()
        }
        let sem = KeySemantics::new(VersionModel::Floating, VersionShape::Numeric)
            .with_ciphertext_reveals_version(true);
        let want = Some(sem.clone());

        let bare = AeadKey::new("t", Arc::new(Everything));
        assert_eq!(bare.semantics(), None);
        assert_eq!(via_trait(&bare), None);
        assert_eq!(via_handle(&bare), None);

        #[derive(Clone)]
        struct Pass;
        impl Layer for Pass {
            fn part(&self, _: &LayerCx<'_>, _: Part<'_>) {}
        }
        let retry = crate::RetryLayer::new(crate::instant_sleep());
        let observe = crate::ObserveLayer::new(|_| {});
        let key = AeadKey::new("t", Arc::new(Everything))
            .with_semantics(sem.clone())
            .layer(&retry)
            .layer(&observe)
            .with_rewrap(Arc::new(Everything))
            .layer(&Pass)
            .with_resource("k")
            .replace_retry(&retry)
            .layer_shared(Arc::new(Pass));
        assert_eq!(key.semantics(), want.as_ref());
        assert_eq!(via_handle(&key), want);
        assert_eq!(via_trait(&key), want);
        assert_eq!(via_trait(key.clone()), want);
        assert_eq!(via_trait(Box::new(key.clone())), want);
        assert_eq!(via_trait(Arc::new(key.clone())), want);
        assert_eq!(via_trait(retry.wrap(key.clone())), want);
        assert_eq!(via_trait(observe.wrap(key.clone())), want);
        assert_eq!(via_trait(retry.wrap(bare.clone())), None);

        let kek = KeyWrapKey::from_aead(key.clone());
        assert_eq!(kek.semantics(), want.as_ref());
        let kek: KeyWrapKey = key.into();
        assert_eq!(via_handle(&kek), want);

        // Every handle kind carries it.
        struct Mx;
        impl Mac for Mx {
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
        let mac = MacKey::new("t", Arc::new(Mx)).with_semantics(sem.clone());
        assert_eq!(via_handle(&mac.layer(&retry)), want);
        let d = DescribeKey::full("t", Everything).with_semantics(sem);
        assert_eq!(via_trait(&d), want);
    }
}
