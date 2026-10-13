//! `Serialize`/`Deserialize` for the stored types (the `serde` feature).
//!
//! Each type serializes to its canonical storage encoding: in human-readable formats (JSON,
//! YAML, TOML) the standard base64 string of `to_base64`, in binary formats the bytes
//! ([`Ciphertext::as_bytes`], [`encoding::encode_signature`](crate::encoding::encode_signature),
//! [`encoding::encode_tag`](crate::encoding::encode_tag)). Deserializing anything else fails with
//! the message of the error the matching `from_base64` gives.
//!
//! Names from configuration ([`SignatureAlgorithm`], [`MacAlgorithm`], [`KeyUri`]) serialize to
//! their string form and deserialize through `FromStr`, so a malformed value fails when the
//! configuration is loaded.

use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, Deserializer, Visitor};
use serde::ser::{self, Serializer};
use serde::{Deserialize, Serialize};

use crate::encoding::{decode_signature, decode_tag, encode_signature, encode_tag};
use crate::error::Result;
use crate::types::{Ciphertext, MacAlgorithm, Signature, SignatureAlgorithm, Tag};
use crate::uri::KeyUri;

/// How one stored type maps to and from its two encodings.
trait Stored: Sized {
    const EXPECTING: &'static str;
    fn to_text(&self) -> Result<String>;
    fn to_binary(&self) -> Result<Vec<u8>>;
    fn from_text(s: &str) -> Result<Self>;
    fn from_binary(b: &[u8]) -> Result<Self>;
}

impl Stored for Ciphertext {
    const EXPECTING: &'static str = "a base64 ciphertext";
    fn to_text(&self) -> Result<String> {
        Ok(self.to_base64())
    }
    fn to_binary(&self) -> Result<Vec<u8>> {
        Ok(self.as_bytes().to_vec())
    }
    fn from_text(s: &str) -> Result<Self> {
        Self::from_base64(s)
    }
    fn from_binary(b: &[u8]) -> Result<Self> {
        Ok(Self::from_bytes(b))
    }
}

impl Stored for Signature {
    const EXPECTING: &'static str = "a base64 anykms signature encoding";
    fn to_text(&self) -> Result<String> {
        self.to_base64()
    }
    fn to_binary(&self) -> Result<Vec<u8>> {
        encode_signature(self)
    }
    fn from_text(s: &str) -> Result<Self> {
        Self::from_base64(s)
    }
    fn from_binary(b: &[u8]) -> Result<Self> {
        decode_signature(b)
    }
}

impl Stored for Tag {
    const EXPECTING: &'static str = "a base64 anykms MAC tag encoding";
    fn to_text(&self) -> Result<String> {
        self.to_base64()
    }
    fn to_binary(&self) -> Result<Vec<u8>> {
        encode_tag(self)
    }
    fn from_text(s: &str) -> Result<Self> {
        Self::from_base64(s)
    }
    fn from_binary(b: &[u8]) -> Result<Self> {
        decode_tag(b)
    }
}

fn serialize<T: Stored, S: Serializer>(v: &T, s: S) -> Result<S::Ok, S::Error> {
    if s.is_human_readable() {
        s.serialize_str(&v.to_text().map_err(ser::Error::custom)?)
    } else {
        s.serialize_bytes(&v.to_binary().map_err(ser::Error::custom)?)
    }
}

struct StoredVisitor<T>(PhantomData<T>);

impl<T: Stored> Visitor<'_> for StoredVisitor<T> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(T::EXPECTING)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<T, E> {
        T::from_text(v).map_err(E::custom)
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<T, E> {
        T::from_binary(v).map_err(E::custom)
    }
}

fn deserialize<'de, T: Stored, D: Deserializer<'de>>(d: D) -> Result<T, D::Error> {
    if d.is_human_readable() {
        d.deserialize_str(StoredVisitor(PhantomData))
    } else {
        d.deserialize_bytes(StoredVisitor(PhantomData))
    }
}

macro_rules! serde_stored {
    ($($T:ty),*) => {
        $(
            impl Serialize for $T {
                fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                    serialize(self, s)
                }
            }

            impl<'de> Deserialize<'de> for $T {
                fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                    deserialize(d)
                }
            }
        )*
    };
}

serde_stored!(Ciphertext, Signature, Tag);

/// Serializes and deserializes a configuration name through `Display`/`as_str` and `FromStr`.
macro_rules! named {
    ($T:ty, $expecting:literal, $to_str:expr) => {
        impl Serialize for $T {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                let f: fn(&$T) -> String = $to_str;
                s.serialize_str(&f(self))
            }
        }

        impl<'de> Deserialize<'de> for $T {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                struct V;
                impl Visitor<'_> for V {
                    type Value = $T;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str($expecting)
                    }
                    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<$T, E> {
                        v.parse().map_err(|e: crate::Error| E::custom(e.message()))
                    }
                }
                d.deserialize_str(V)
            }
        }
    };
}

named!(SignatureAlgorithm, "a signature algorithm name", |a| a
    .as_str()
    .to_owned());
named!(MacAlgorithm, "a MAC algorithm name", |a| a
    .as_str()
    .to_owned());
named!(KeyUri, "a key URI", |u| u.to_string());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyVersion;

    #[test]
    fn json_uses_the_base64_storage_encoding() {
        let ct = Ciphertext::from_bytes(b"vault:v1:abc".to_vec());
        let json = serde_json::to_string(&ct).unwrap();
        assert_eq!(json, format!("\"{}\"", ct.to_base64()));
        assert_eq!(serde_json::from_str::<Ciphertext>(&json).unwrap(), ct);

        let sig = Signature::from_parts(
            SignatureAlgorithm::Ed25519,
            Some(KeyVersion::from_u64(3)),
            vec![7; 64],
        );
        let json = serde_json::to_string(&sig).unwrap();
        assert_eq!(json, format!("\"{}\"", sig.to_base64().unwrap()));
        assert_eq!(serde_json::from_str::<Signature>(&json).unwrap(), sig);

        let tag = Tag::from_parts(MacAlgorithm::HmacSha256, None, vec![1; 32]);
        let json = serde_json::to_string(&tag).unwrap();
        assert_eq!(serde_json::from_str::<Tag>(&json).unwrap(), tag);

        // Inside a struct, as an application would store them.
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Row {
            secret: Ciphertext,
            sig: Signature,
        }
        let row = Row { secret: ct, sig };
        let back: Row = serde_json::from_str(&serde_json::to_string(&row).unwrap()).unwrap();
        assert_eq!(back, row);
    }

    #[test]
    fn configuration_names() {
        #[derive(Deserialize, Serialize)]
        struct Config {
            key: KeyUri,
            alg: SignatureAlgorithm,
            mac: MacAlgorithm,
        }
        let c: Config = serde_json::from_str(
            r#"{"key":"hashivault:///transit/keys/k","alg":"ES256","mac":"hmac-sha256"}"#,
        )
        .unwrap();
        assert_eq!(c.key.scheme(), "hashivault");
        assert_eq!(c.alg, SignatureAlgorithm::EcdsaP256Sha256);
        assert_eq!(c.mac, MacAlgorithm::HmacSha256);
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"{"key":"hashivault:///transit/keys/k","alg":"ecdsa-p256-sha256","mac":"hmac-sha256"}"#
        );
        let e = serde_json::from_str::<SignatureAlgorithm>(r#""ES999""#).unwrap_err();
        assert!(e.to_string().contains("unknown signature algorithm"), "{e}");
        assert!(serde_json::from_str::<KeyUri>(r#""no colon""#).is_err());
        assert!(serde_json::from_str::<MacAlgorithm>(r#""HS256""#).is_err());
    }

    #[test]
    fn corrupt_values_are_rejected() {
        assert!(serde_json::from_str::<Ciphertext>("\"not base64!\"").is_err());
        assert!(serde_json::from_str::<Ciphertext>("42").is_err());
        let e = serde_json::from_str::<Signature>("\"AAAA\"").unwrap_err();
        assert!(e.to_string().contains("verification_failed"), "{e}");
        assert!(serde_json::from_str::<Tag>("\"AAAA\"").is_err());
    }
}
