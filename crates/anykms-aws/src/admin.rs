//! Hidden administrative calls for test fixtures (key creation, disabling, deletion). Not part of
//! the public API: applications manage keys with infrastructure as code. Compiled only with the
//! hidden, non-default `__test-fixtures` feature (refused in release builds), so production
//! builds cannot send the provider's credentials anywhere but its key endpoints.

use std::sync::Arc;

use anykms_core::{Operation, Result};
use zeroize::Zeroizing;

use crate::client::{Call, Kms};

/// Signed KMS calls with arbitrary JSON, through the provider's credentials and HTTP client.
#[doc(hidden)]
#[derive(Clone)]
pub struct Admin {
    pub(crate) kms: Arc<Kms>,
    /// The provider's `allow_loopback_http`: no more endpoints than the provider allows.
    pub(crate) allow_loopback_http: bool,
}

impl std::fmt::Debug for Admin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Admin")
    }
}

impl Admin {
    /// Sends `TrentService.<target>` with `body` to `endpoint`, signed for `region`.
    pub async fn call(
        &self,
        endpoint: &str,
        region: &str,
        target: &'static str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let url = crate::endpoint::validate_url(
            endpoint,
            self.allow_loopback_http,
            "the admin endpoint",
        )?;
        let bytes = Zeroizing::new(serde_json::to_vec(body).expect("serializes"));
        let resp = self
            .kms
            .call(Call {
                endpoint: &url,
                region,
                target,
                body: bytes,
                op: Operation::Describe,
                resource: None,
                key_version: None,
            })
            .await?;
        Ok(serde_json::from_slice(&resp).unwrap_or(serde_json::Value::Null))
    }

    /// Like [`call`](Self::call), returning the raw response: status, headers (name, value) and
    /// body, whatever the status.
    pub async fn raw(
        &self,
        endpoint: &str,
        region: &str,
        target: &'static str,
        body: &[u8],
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
        let url = crate::endpoint::validate_url(
            endpoint,
            self.allow_loopback_http,
            "the admin endpoint",
        )?;
        let (status, headers, body) = self
            .kms
            .raw(&Call {
                endpoint: &url,
                region,
                target,
                body: Zeroizing::new(body.to_vec()),
                op: Operation::Describe,
                resource: None,
                key_version: None,
            })
            .await?;
        let headers = headers
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_owned(),
                    v.to_str().unwrap_or("<binary>").to_owned(),
                )
            })
            .collect();
        Ok((status.as_u16(), headers, body.to_vec()))
    }

    /// Shifts the signing clock by `ms` milliseconds (negative: behind).
    pub fn set_clock_offset(&self, ms: i64) {
        self.kms.set_clock_offset(ms);
    }
}
