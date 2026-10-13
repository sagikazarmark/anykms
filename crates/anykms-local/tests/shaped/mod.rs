//! Shape proof fixtures: providers over the local backend that expose only what a GCP Cloud KMS
//! or an Azure Key Vault (standard) key has, with their version and state conventions, so the
//! conformance suite is shown to run green on those shapes without `Unsupported` stubs (see
//! `docs/cloud/shared.md` §1.4). They are test fixtures, not emulators: the cloud facts they model
//! are the ones the suite's declarations describe.

#![allow(dead_code)]

pub mod azure;
pub mod gcp;

use anykms_core::{Error, ErrorKind, KeyUri, Operation, Result};

/// An error of a shaped handle, naming the key.
pub fn err(
    backend: &'static str,
    kind: ErrorKind,
    op: Operation,
    resource: &str,
    msg: &'static str,
) -> Error {
    Error::new(kind, backend, op, msg).with_resource(resource)
}

/// The part of `uri` after `<scheme>://`, split at `/`. A malformed URI is `Configuration`
/// with `Operation::ParseUri` (A3(c)).
pub fn segments<'a>(backend: &'static str, scheme: &str, uri: &'a KeyUri) -> Result<Vec<&'a str>> {
    let bad = || {
        Error::new(
            ErrorKind::Configuration,
            backend,
            Operation::ParseUri,
            "malformed key URI",
        )
    };
    if uri.scheme() != scheme {
        return Err(bad());
    }
    let rest = uri.rest().strip_prefix("//").ok_or_else(bad)?;
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(bad());
    }
    Ok(parts)
}
