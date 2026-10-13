//! Signing messages with digest signers by hashing locally.
//!
//! **Emulates:** message signing for ECDSA/RSA keys. **Enforced by:** the hash is computed in this
//! process; the KMS signs the digest. Hashing locally also avoids server request-size limits.

pub use anykms_core::PinnedVerifier;
use anykms_core::{
    Digest, DigestSigner, DigestVerifier, Error, ErrorKind, Operation, Result, Signature,
    SignatureAlgorithm,
};

fn hash_of(alg: SignatureAlgorithm, op: Operation) -> Result<anykms_core::HashAlgorithm> {
    alg.hash().ok_or_else(|| {
        Error::new(
            ErrorKind::KeyMismatch,
            "recipes",
            op,
            "Ed25519 signs messages; use MessageSigner",
        )
    })
}

/// Hashes `msg` with the signer's hash and signs the digest.
pub async fn sign_message_hashed<S: DigestSigner + ?Sized>(
    signer: &S,
    msg: &[u8],
) -> Result<Signature> {
    let h = hash_of(signer.signature_algorithm(), Operation::Sign)?;
    signer.sign_digest(&Digest::compute(h, msg)).await
}

/// Hashes `msg` with the hash of the verifier's algorithm and verifies the digest signature, the
/// counterpart of [`sign_message_hashed`]. A signature of any other algorithm fails with
/// `InvalidArgument` before hashing: the hash is chosen by the verifier, never by the (untrusted)
/// signature.
pub async fn verify_message_hashed<V: DigestVerifier + PinnedVerifier + ?Sized>(
    verifier: &V,
    msg: &[u8],
    sig: &Signature,
) -> Result<()> {
    verify_message_hashed_as(verifier, verifier.pinned_algorithm(), msg, sig).await
}

/// Like [`verify_message_hashed`], with the algorithm given by the caller, for verifiers not
/// bound to one ([`PinnedVerifier`]). A signature of any other algorithm than `expected` fails
/// with `InvalidArgument` before hashing.
pub async fn verify_message_hashed_as<V: DigestVerifier + ?Sized>(
    verifier: &V,
    expected: SignatureAlgorithm,
    msg: &[u8],
    sig: &Signature,
) -> Result<()> {
    let h = hash_of(expected, Operation::Verify)?;
    if sig.algorithm() != expected {
        return Err(Error::new(
            ErrorKind::InvalidArgument,
            "recipes",
            Operation::Verify,
            "signature algorithm is not the expected algorithm",
        ));
    }
    verifier.verify_digest(&Digest::compute(h, msg), sig).await
}
