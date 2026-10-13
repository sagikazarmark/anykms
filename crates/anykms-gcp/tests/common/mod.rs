//! Shared test helpers: the fake Cloud KMS server and providers pointed at it.

#![allow(dead_code)]

pub mod fake;
pub mod fixture;

use std::time::Duration;

use anykms_gcp::{Credentials, Endpoint, GcpProvider, GcpProviderBuilder};

pub use fake::FakeKms;

/// A provider builder for the fake: its endpoint, a static token, no public-key cache.
pub fn builder(fake: &FakeKms) -> GcpProviderBuilder {
    cached_builder(fake).public_key_ttl(Duration::ZERO)
}

/// [`builder`] with the default public-key cache (`public_key_ttl` not set).
pub fn cached_builder(fake: &FakeKms) -> GcpProviderBuilder {
    GcpProvider::builder()
        .credentials(Credentials::static_token(fake::TOKEN))
        .endpoint(Endpoint::custom(fake.uri()))
        .allow_loopback_http()
        .allowed_projects(["fake-project"])
}

/// A provider for the fake.
pub fn provider(fake: &FakeKms) -> GcpProvider {
    builder(fake).build().expect("provider")
}

/// `gcp-kms://<name>`.
pub fn uri(name: &str) -> String {
    format!("gcp-kms://{name}")
}

/// `gcp-kms://<name>/cryptoKeyVersions/<v>`.
pub fn vuri(name: &str, v: u64) -> String {
    format!("gcp-kms://{name}/cryptoKeyVersions/{v}")
}
