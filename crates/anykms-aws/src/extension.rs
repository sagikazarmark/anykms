//! Native encryption contexts, reachable from the opaque `AeadKey` through its layers.

use anykms_core::{AeadKey, Ciphertext, DataKey, DataKeySpec, Error, ErrorKind, Operation, Result};
use zeroize::Zeroizing;

use crate::BACKEND;
use crate::context::EncryptionContext;
use crate::handles::AwsAeadKey;

/// AWS encryption-context operations, for ciphertexts shared with other AWS tools (the AWS
/// Encryption SDK, S3, ...): the context is sent as given, unlike the portable `aad`, which
/// travels under the reserved key `associatedData` (Tink's).
///
/// Implemented by [`AwsAeadKey`] and by the opaque [`AeadKey`] a registry opens for an
/// `aws-kms://` key. On `AeadKey` each call goes through the handle's layers (a `RetryLayer`
/// retries it, an `ObserveLayer` reports it under the portable operation with the extension
/// name `aws.encrypt_with_context`, ...), so prefer it over `downcast_ref::<AwsAeadKey>()`,
/// which bypasses them. On an `AeadKey` of another backend the calls are `Unsupported`.
///
/// The context may not use the reserved key `associatedData`, keys and values must be non-empty,
/// and the total is capped at [`MAX_CONTEXT_BYTES`](crate::MAX_CONTEXT_BYTES)
/// (`InvalidArgument` before any request). An empty context sends none.
#[trait_variant::make(Send)]
pub trait EncryptionContextAead: Send + Sync {
    /// `Encrypt` with `ctx` as the encryption context.
    async fn encrypt_with_context(
        &self,
        plaintext: &[u8],
        ctx: &EncryptionContext,
    ) -> Result<Ciphertext>;

    /// `Decrypt` with `ctx` (naming this key).
    async fn decrypt_with_context(
        &self,
        ct: &Ciphertext,
        ctx: &EncryptionContext,
    ) -> Result<Zeroizing<Vec<u8>>>;

    /// `ReEncrypt` under this key from context `from` to context `to`.
    async fn rewrap_with_context(
        &self,
        ct: &Ciphertext,
        from: &EncryptionContext,
        to: &EncryptionContext,
    ) -> Result<Ciphertext>;

    /// `GenerateDataKey` bound to `ctx`.
    async fn generate_data_key_with_context(
        &self,
        spec: DataKeySpec,
        ctx: &EncryptionContext,
    ) -> Result<DataKey>;
}

impl EncryptionContextAead for AwsAeadKey {
    async fn encrypt_with_context(
        &self,
        plaintext: &[u8],
        ctx: &EncryptionContext,
    ) -> Result<Ciphertext> {
        self.encrypt_ctx(plaintext, ctx).await
    }

    async fn decrypt_with_context(
        &self,
        ct: &Ciphertext,
        ctx: &EncryptionContext,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.decrypt_ctx(ct, ctx).await
    }

    async fn rewrap_with_context(
        &self,
        ct: &Ciphertext,
        from: &EncryptionContext,
        to: &EncryptionContext,
    ) -> Result<Ciphertext> {
        self.rewrap_ctx(ct, from, to).await
    }

    async fn generate_data_key_with_context(
        &self,
        spec: DataKeySpec,
        ctx: &EncryptionContext,
    ) -> Result<DataKey> {
        self.data_key_ctx(spec, ctx).await
    }
}

fn concrete(key: &AeadKey, op: Operation) -> Result<std::sync::Arc<AwsAeadKey>> {
    key.downcast_arc::<AwsAeadKey>().ok_or_else(|| {
        let e = Error::new(
            ErrorKind::Unsupported,
            BACKEND,
            op,
            "encryption contexts need an aws-kms key",
        );
        match key.resource() {
            Some(r) => e.with_resource(r),
            None => e,
        }
    })
}

impl EncryptionContextAead for AeadKey {
    async fn encrypt_with_context(
        &self,
        plaintext: &[u8],
        ctx: &EncryptionContext,
    ) -> Result<Ciphertext> {
        let op = Operation::Encrypt;
        let key = concrete(self, op)?;
        self.call_extension(op, "aws.encrypt_with_context", || {
            let key = key.clone();
            Box::pin(async move { key.encrypt_ctx(plaintext, ctx).await })
        })
        .await
    }

    async fn decrypt_with_context(
        &self,
        ct: &Ciphertext,
        ctx: &EncryptionContext,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let op = Operation::Decrypt;
        let key = concrete(self, op)?;
        self.call_extension(op, "aws.decrypt_with_context", || {
            let key = key.clone();
            Box::pin(async move { key.decrypt_ctx(ct, ctx).await })
        })
        .await
    }

    async fn rewrap_with_context(
        &self,
        ct: &Ciphertext,
        from: &EncryptionContext,
        to: &EncryptionContext,
    ) -> Result<Ciphertext> {
        let op = Operation::Rewrap;
        let key = concrete(self, op)?;
        self.call_extension(op, "aws.rewrap_with_context", || {
            let key = key.clone();
            Box::pin(async move { key.rewrap_ctx(ct, from, to).await })
        })
        .await
    }

    async fn generate_data_key_with_context(
        &self,
        spec: DataKeySpec,
        ctx: &EncryptionContext,
    ) -> Result<DataKey> {
        let op = Operation::GenerateDataKey;
        let key = concrete(self, op)?;
        self.call_extension(op, "aws.generate_data_key_with_context", || {
            let key = key.clone();
            Box::pin(async move { key.data_key_ctx(spec, ctx).await })
        })
        .await
    }
}
