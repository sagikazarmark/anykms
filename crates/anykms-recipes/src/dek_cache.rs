//! A decrypt-side cache of unwrapped data keys.
//!
//! **Emulates:** nothing; it saves KMS calls. **Enforced by:** the KMS unwraps each distinct
//! wrapped key once per TTL; repeats are answered from this process's memory.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
#[cfg(target_arch = "wasm32")]
use web_time::Instant;

use anykms_core::{Ciphertext, KeyVersion, KeyWrap, Result, Rewrap};
use zeroize::Zeroizing;

const DEFAULT_TTL: Duration = Duration::from_secs(60);
const DEFAULT_MAX_ENTRIES: usize = 1000;

#[derive(Default)]
struct Cache {
    /// Wrapped key → (when it was unwrapped, the data key). The data keys are `Zeroizing`, so
    /// they are wiped when evicted, replaced, invalidated or dropped with the cache.
    entries: HashMap<Vec<u8>, (Instant, Zeroizing<Vec<u8>>)>,
    /// Bumped by `invalidate`, so an unwrap that started before it does not cache its result.
    epoch: u64,
}

/// A [`KeyWrap`] decorator that caches **unwrapped** data keys, keyed by the wrapped key's bytes,
/// so decrypting many envelopes that share a data key, or the same envelope repeatedly, costs one
/// KMS call per TTL instead of one per decrypt.
///
/// ```
/// # use anykms_recipes::CachingKeyWrap;
/// # use std::time::Duration;
/// # fn f(registry: anykms_core::Registry) -> anykms_core::Result<()> {
/// let kek = CachingKeyWrap::new(registry.key_wrap("local://default/kek")?)
///     .with_ttl(Duration::from_secs(30))
///     .with_max_entries(10_000);
/// // let envelope = EnvelopeAead::new("app-kek", kek)?;
/// # Ok(()) }
/// ```
///
/// Only `unwrap_key` is cached. `wrap_key` always calls the KMS: [`EnvelopeAead`] makes a fresh
/// data key per message, so there is nothing to reuse, and reusing data keys across messages is a
/// different trade-off this decorator does not make. Failures are never cached. [`Rewrap`] (the
/// KMS's own rewrap) is forwarded uncached, but the envelope's local rewraps unwrap through this
/// cache. One decorator caches for one KEK: in an [`EnvelopeKeyring`], decorate each
/// KEK (the keyring routes by `kek_id` before any unwrap, so the caches never mix KEKs).
///
/// Clones share the cache.
///
/// # Security trade-offs
///
/// Read these before enabling it:
///
/// - **Revocation is delayed by up to the TTL.** Disabling the KEK, revoking a version or
///   removing a caller's decrypt permission stops this process from decrypting only once the
///   cached data keys expire. Call [`invalidate`](Self::invalidate) to apply such a change at once.
/// - **Fewer audit records.** A cache hit makes no KMS request, so the KMS audit log records one
///   unwrap per data key per TTL rather than one per decrypt.
/// - **Plaintext data keys stay in memory** for up to the TTL (bounded by `max_entries`), where a
///   memory-disclosure bug or a core dump can expose them. They are zeroized on eviction.
///
/// What it does **not** weaken: the cache maps exactly the wrapped-key bytes the KMS unwrapped to
/// the data key it returned, so a cached answer is the KMS's answer for those bytes. Everything
/// [`EnvelopeAead`] checks after unwrapping (data-key length, key commitment, AES-GCM with the
/// caller's AAD) still runs on every decrypt.
///
/// Needs a working `std::time::Instant`, so it is not usable on `wasm32-unknown-unknown`. Expiry
/// is checked on lookup and eviction scans the whole map only when it is full. Concurrent misses
/// for the same wrapped key are not coalesced: each calls the KMS once.
///
#[cfg_attr(feature = "envelope", doc = "[`EnvelopeAead`]: crate::EnvelopeAead")]
#[cfg_attr(
    feature = "envelope",
    doc = "[`EnvelopeKeyring`]: crate::EnvelopeKeyring"
)]
#[cfg_attr(
    not(feature = "envelope"),
    doc = "[`EnvelopeAead`]: <https://docs.rs/anykms-recipes>"
)]
#[cfg_attr(
    not(feature = "envelope"),
    doc = "[`EnvelopeKeyring`]: <https://docs.rs/anykms-recipes>"
)]
pub struct CachingKeyWrap<K> {
    inner: K,
    ttl: Duration,
    max_entries: usize,
    cache: Arc<Mutex<Cache>>,
}

impl<K: Clone> Clone for CachingKeyWrap<K> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            ttl: self.ttl,
            max_entries: self.max_entries,
            cache: self.cache.clone(),
        }
    }
}

impl<K: std::fmt::Debug> std::fmt::Debug for CachingKeyWrap<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachingKeyWrap")
            .field("inner", &self.inner)
            .field("ttl", &self.ttl)
            .field("max_entries", &self.max_entries)
            .field("cached", &self.len())
            .finish()
    }
}

impl<K> CachingKeyWrap<K> {
    /// Caches unwrapped data keys of `inner` for 60 seconds, at most 1000 of them.
    pub fn new(inner: K) -> Self {
        Self {
            inner,
            ttl: DEFAULT_TTL,
            max_entries: DEFAULT_MAX_ENTRIES,
            cache: Arc::default(),
        }
    }

    /// How long an unwrapped data key is reused (default 60 seconds); bounds how long a
    /// revocation takes to apply in this process.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// The maximum number of cached data keys (default 1000, at least 1). When full, expired
    /// entries are evicted first, then the oldest.
    pub fn with_max_entries(mut self, n: usize) -> Self {
        self.max_entries = n.max(1);
        self
    }

    /// The decorated KEK.
    pub fn inner(&self) -> &K {
        &self.inner
    }

    /// Drops (and zeroizes) every cached data key, e.g. after disabling or revoking the KEK.
    ///
    /// Unwraps already in flight still return their data key, but do not cache it.
    pub fn invalidate(&self) {
        let mut c = self.lock();
        c.entries.clear();
        c.epoch = c.epoch.wrapping_add(1);
    }

    /// The number of cached data keys (expired ones included until evicted).
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Whether no data key is cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The cached data key, or the current epoch to pass to `put` after a miss.
    fn get(&self, wrapped: &[u8]) -> std::result::Result<Zeroizing<Vec<u8>>, u64> {
        let mut c = self.lock();
        match c.entries.get(wrapped) {
            Some((at, dek)) if at.elapsed() < self.ttl => Ok(dek.clone()),
            Some(_) => {
                c.entries.remove(wrapped);
                Err(c.epoch)
            }
            None => Err(c.epoch),
        }
    }

    fn put(&self, wrapped: &[u8], dek: &Zeroizing<Vec<u8>>, epoch: u64) {
        let mut c = self.lock();
        if c.epoch != epoch {
            return;
        }
        if c.entries.len() >= self.max_entries && !c.entries.contains_key(wrapped) {
            let ttl = self.ttl;
            c.entries.retain(|_, (at, _)| at.elapsed() < ttl);
            while c.entries.len() >= self.max_entries {
                let oldest = c
                    .entries
                    .iter()
                    .min_by_key(|(_, (at, _))| *at)
                    .map(|(k, _)| k.clone());
                match oldest {
                    Some(k) => c.entries.remove(&k),
                    None => break,
                };
            }
        }
        c.entries
            .insert(wrapped.to_vec(), (Instant::now(), dek.clone()));
    }
}

impl<K: KeyWrap> KeyWrap for CachingKeyWrap<K> {
    async fn wrap_key(&self, key: &[u8]) -> Result<Ciphertext> {
        self.inner.wrap_key(key).await
    }

    async fn unwrap_key(&self, wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
        let epoch = match self.get(wrapped.as_bytes()) {
            Ok(dek) => return Ok(dek),
            Err(epoch) => epoch,
        };
        let dek = self.inner.unwrap_key(wrapped).await?;
        self.put(wrapped.as_bytes(), &dek, epoch);
        Ok(dek)
    }

    fn wrapped_key_version(&self, wrapped: &Ciphertext) -> Result<Option<KeyVersion>> {
        self.inner.wrapped_key_version(wrapped)
    }
}

impl<K: Rewrap> Rewrap for CachingKeyWrap<K> {
    /// Forwarded uncached: the data key never leaves the KMS.
    async fn rewrap(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext> {
        self.inner.rewrap(ct, aad).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use anykms_core::{Error, ErrorKind, Operation};

    use super::*;

    /// XOR "wrapping" that counts unwraps and fails them while `fail` is set.
    #[derive(Default)]
    struct Counting {
        unwraps: AtomicUsize,
        fail: std::sync::atomic::AtomicBool,
    }

    impl KeyWrap for Counting {
        async fn wrap_key(&self, key: &[u8]) -> Result<Ciphertext> {
            Ok(Ciphertext::from_bytes(
                key.iter().map(|b| b ^ 0x5a).collect::<Vec<_>>(),
            ))
        }

        async fn unwrap_key(&self, wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
            self.unwraps.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(Error::new(
                    ErrorKind::Unavailable,
                    "test",
                    Operation::Decrypt,
                    "down",
                ));
            }
            Ok(Zeroizing::new(
                wrapped.as_bytes().iter().map(|b| b ^ 0x5a).collect(),
            ))
        }
    }

    fn unwraps(c: &CachingKeyWrap<Arc<Counting>>) -> usize {
        c.inner().unwraps.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn repeated_unwraps_hit_the_cache() {
        let c = CachingKeyWrap::new(Arc::new(Counting::default()));
        let w = c.wrap_key(&[1; 32]).await.unwrap();
        for _ in 0..3 {
            assert_eq!(&*c.unwrap_key(&w).await.unwrap(), &[1; 32]);
        }
        assert_eq!(unwraps(&c), 1);
        // Clones share the cache.
        c.clone().unwrap_key(&w).await.unwrap();
        assert_eq!(unwraps(&c), 1);
        c.invalidate();
        c.unwrap_key(&w).await.unwrap();
        assert_eq!(unwraps(&c), 2);
    }

    /// Unwraps that wait for `release` before answering.
    #[derive(Default)]
    struct Gated {
        release: tokio::sync::Notify,
    }

    impl KeyWrap for Gated {
        async fn wrap_key(&self, key: &[u8]) -> Result<Ciphertext> {
            Ok(Ciphertext::from_bytes(key.to_vec()))
        }

        async fn unwrap_key(&self, wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
            self.release.notified().await;
            Ok(Zeroizing::new(wrapped.as_bytes().to_vec()))
        }
    }

    #[tokio::test]
    async fn invalidate_during_an_unwrap_does_not_cache_its_result() {
        let c = CachingKeyWrap::new(Arc::new(Gated::default()));
        let w = c.wrap_key(&[3; 32]).await.unwrap();
        let (dek, ()) = tokio::join!(c.unwrap_key(&w), async {
            tokio::task::yield_now().await;
            c.invalidate();
            c.inner().release.notify_one();
        });
        assert_eq!(&*dek.unwrap(), &[3; 32]);
        assert!(c.is_empty());
    }

    #[tokio::test]
    async fn entries_expire_and_failures_are_not_cached() {
        let c = CachingKeyWrap::new(Arc::new(Counting::default())).with_ttl(Duration::ZERO);
        let w = c.wrap_key(&[2; 32]).await.unwrap();
        c.unwrap_key(&w).await.unwrap();
        c.unwrap_key(&w).await.unwrap();
        assert_eq!(unwraps(&c), 2);

        let c = CachingKeyWrap::new(Arc::new(Counting::default()));
        c.inner().fail.store(true, Ordering::SeqCst);
        assert!(c.unwrap_key(&w).await.is_err());
        assert!(c.is_empty());
        c.inner().fail.store(false, Ordering::SeqCst);
        c.unwrap_key(&w).await.unwrap();
        assert_eq!(unwraps(&c), 2);
    }

    #[tokio::test]
    async fn the_cache_is_bounded() {
        let c = CachingKeyWrap::new(Arc::new(Counting::default())).with_max_entries(2);
        for i in 0..5u8 {
            let w = c.wrap_key(&[i; 32]).await.unwrap();
            c.unwrap_key(&w).await.unwrap();
            assert!(c.len() <= 2);
        }
        // The newest stayed.
        let w = c.wrap_key(&[4; 32]).await.unwrap();
        c.unwrap_key(&w).await.unwrap();
        assert_eq!(unwraps(&c), 5);
    }

    #[cfg(feature = "envelope")]
    #[tokio::test]
    async fn envelopes_decrypt_through_the_cache() {
        use anykms_core::Aead as _;
        let kek = CachingKeyWrap::new(Arc::new(Counting::default()));
        let env = crate::EnvelopeAead::new("k", kek.clone()).unwrap();
        let ct = env.encrypt(b"hi", b"a").await.unwrap();
        for _ in 0..3 {
            assert_eq!(&*env.decrypt(&ct, b"a").await.unwrap(), b"hi");
        }
        assert_eq!(unwraps(&kek), 1);
        // The envelope's own checks still run on a cache hit.
        assert_eq!(
            env.decrypt(&ct, b"b").await.unwrap_err().kind(),
            ErrorKind::DecryptFailed
        );
    }
}
