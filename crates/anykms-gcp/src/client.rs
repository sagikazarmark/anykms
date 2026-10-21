//! The REST client: one per provider, shared by every handle.

use std::sync::Arc;

use anykms_core::{Error, ErrorKind, Operation, Result};
use anykms_http::HttpTransport;
use anykms_http::http::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap};
use anykms_http::http::{Method, StatusCode};
use anykms_http::url::Url;
use zeroize::Zeroizing;

use crate::BACKEND;
use crate::auth::{CredentialSource, Token};
use crate::errors::{Failure, classify};
use crate::handles::Origin;
use crate::uri::GcpKeyRef;

pub(crate) struct Client {
    pub(crate) http: Arc<dyn HttpTransport>,
    pub(crate) creds: Arc<dyn CredentialSource>,
    /// The configured quota project; wins over the credential's.
    pub(crate) quota_project: Option<String>,
    pub(crate) max_response: usize,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("credentials", &self.creds)
            .field("quota_project", &self.quota_project)
            .finish_non_exhaustive()
    }
}

/// One request.
pub(crate) struct Call<'a> {
    pub(crate) method: Method,
    pub(crate) base: &'a Url,
    /// The key the request is about (the path).
    pub(crate) key: &'a GcpKeyRef,
    /// The handle's `gcp-kms://` URI, the span's `resource`.
    pub(crate) resource: &'a str,
    /// `Some(n)`: the request names `.../cryptoKeyVersions/<n>`.
    pub(crate) version: Option<u64>,
    /// Ends the path: `cryptoKeyVersions` (a collection, for `list`) or `publicKey` (a version's
    /// sub-resource).
    pub(crate) collection: Option<&'static str>,
    /// The custom method (`encrypt`, `asymmetricSign`, ...), appended as `:<verb>`.
    pub(crate) verb: Option<&'static str>,
    pub(crate) query: Vec<(&'static str, String)>,
    pub(crate) body: Option<Zeroizing<Vec<u8>>>,
    pub(crate) op: Operation,
    /// Where the request's key version came from (classification, A3).
    pub(crate) origin: Origin,
}

fn config_err(m: &'static str) -> Error {
    Error::new(ErrorKind::Configuration, BACKEND, Operation::Configure, m)
}

impl Call<'_> {
    /// `<base>/v1/projects/.../cryptoKeys/<k>[/cryptoKeyVersions/<n>][/<collection>][:<verb>]`.
    /// Every segment is percent-encoded as a single path segment (defence in depth: the URI
    /// grammar already rules out `/`, `%`, `?` and `#`).
    pub(crate) fn url(&self) -> Result<Url> {
        let version = self.version.map(|v| v.to_string());
        let mut segs: Vec<&str> = self.key.key_segments().to_vec();
        if let Some(v) = &version {
            segs.push("cryptoKeyVersions");
            segs.push(v);
        }
        if let Some(c) = self.collection {
            segs.push(c);
        }
        if segs.iter().any(|s| matches!(*s, "" | "." | "..")) {
            return Err(config_err("invalid request path"));
        }
        let last = match self.verb {
            Some(verb) => format!("{}:{verb}", segs.pop().expect("non-empty")),
            None => segs.pop().expect("non-empty").to_owned(),
        };
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|()| config_err("invalid request path"))?
            .pop_if_empty()
            .push("v1")
            .extend(segs)
            .push(&last);
        if !self.query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(self.query.iter().map(|(k, v)| (*k, v.as_str())));
        }
        Ok(url)
    }
}

pub(crate) type Response = (StatusCode, HeaderMap, Zeroizing<Vec<u8>>);

impl Client {
    async fn send(&self, call: &Call<'_>, token: Option<&Token>) -> Result<Response> {
        let url = call.url()?;
        let mut req = anykms_http::client::request(call.method.clone(), &url);
        if let Some(t) = token {
            req = req.header(
                AUTHORIZATION,
                crate::auth::bearer_header(t.expose()).map_err(|e| e.with_operation(call.op))?,
            );
        }
        if let Some(q) = self
            .quota_project
            .as_deref()
            .or_else(|| self.creds.quota_project())
        {
            req = req.header("x-goog-user-project", q);
        }
        // The body stays in a zeroizing buffer up to the transport (which may copy it; see the
        // crate docs on zeroization limits).
        let body = match &call.body {
            Some(body) => {
                req = req.header(CONTENT_TYPE, "application/json");
                body.clone()
            }
            None => anykms_http::client::empty(),
        };
        // `send` records `http_status` into the request span for every response.
        use anykms_http::SendError;
        let r = anykms_http::client::send(&*self.http, req.body(body), self.max_response)
            .await
            .map_err(|e| match e {
                SendError::TooLarge { status } => crate::errors::unusable_response(
                    call.op,
                    Some(status.as_u16()),
                    "response exceeds the maximum size",
                ),
                e => e.into_error(BACKEND, call.op),
            })?;
        Ok((r.status, r.headers, r.body))
    }

    /// Performs a call, retrying once after a 401 if the credential source then yields another
    /// token. Returns the success body; every non-success response is classified.
    /// Runs inside the request span (`anykms.gcp`, the shared schema of [`anykms_http::span`]).
    pub(crate) async fn call(&self, call: Call<'_>) -> Result<Zeroizing<Vec<u8>>> {
        let version = call.version.map(|v| v.to_string());
        let span = anykms_http::request_span!(
            "anykms.gcp",
            backend = BACKEND,
            op = call.op.as_str(),
            resource = call.resource,
            key_version = version.as_deref(),
        );
        let guard = anykms_http::span::start_request(&span);
        let r = anykms_http::span::instrument(self.call_inner(&call), &span).await;
        // Encrypt names no version in the request; the response names the primary.
        #[cfg(feature = "tracing")]
        if let Ok(body) = &r
            && call.version.is_none()
            && call.op == Operation::Encrypt
            && let Some(v) = response_version(call.key, body)
        {
            span.record("key_version", v);
        }
        guard.finish(None, &r);
        r
    }

    async fn call_inner(&self, call: &Call<'_>) -> Result<Zeroizing<Vec<u8>>> {
        // First: a transport that cannot send from this context (reqwest outside a Tokio
        // runtime) fails here, before the credential source is asked.
        self.http
            .ready()
            .map_err(|e| e.into_error(BACKEND, call.op))?;
        let token = self
            .creds
            .token()
            .await
            .map_err(|e| e.with_operation(call.op))?;
        anykms_http::span::record_attempt(1);
        let (mut status, mut headers, mut body) = self.send(call, token.as_ref()).await?;
        if status == StatusCode::UNAUTHORIZED
            && let Some(rejected) = &token
        {
            self.creds.invalidate(rejected);
            // If the source cannot produce a token now, report the original 401 rather than
            // the (possibly retryable) credential error.
            if let Ok(fresh) = self.creds.token().await {
                let changed = match &fresh {
                    Some(f) => f.expose() != rejected.expose(),
                    None => true,
                };
                if changed {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(reason = "token refreshed after 401", "retrying once");
                    anykms_http::span::record_attempt(2);
                    (status, headers, body) = self.send(call, fresh.as_ref()).await?;
                }
            }
        }
        if status.is_success() {
            return Ok(body);
        }
        let e = classify(Failure {
            http: status.as_u16(),
            body: &body,
            retry_after: anykms_http::client::retry_after(&headers),
            op: call.op,
            origin: call.origin,
        });
        Err(e)
    }
}

/// The version a success response names (`name` = `<key>/cryptoKeyVersions/<n>`), for tracing.
#[cfg(feature = "tracing")]
fn response_version(key: &GcpKeyRef, body: &[u8]) -> Option<u64> {
    #[derive(serde::Deserialize)]
    struct Named {
        #[serde(default)]
        name: String,
    }
    let n: Named = serde_json::from_slice(body).ok()?;
    n.name
        .strip_prefix(key.key_name().as_str())?
        .strip_prefix("/cryptoKeyVersions/")
        .and_then(crate::uri::parse_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_built_from_segments() {
        let key =
            GcpKeyRef::parse_rest("//projects/my-project/locations/global/keyRings/r/cryptoKeys/k")
                .unwrap();
        let base = Url::parse("http://127.0.0.1:1234/").unwrap();
        let mut call = Call {
            method: Method::POST,
            base: &base,
            key: &key,
            resource: "gcp-kms://projects/my-project/locations/global/keyRings/r/cryptoKeys/k",
            version: None,
            collection: None,
            verb: Some("encrypt"),
            query: Vec::new(),
            body: None,
            op: Operation::Encrypt,
            origin: Origin::Handle,
        };
        assert_eq!(
            call.url().unwrap().as_str(),
            "http://127.0.0.1:1234/v1/projects/my-project/locations/global/keyRings/r/cryptoKeys/k:encrypt"
        );
        call.version = Some(3);
        call.verb = Some("asymmetricSign");
        assert_eq!(
            call.url().unwrap().as_str(),
            "http://127.0.0.1:1234/v1/projects/my-project/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/3:asymmetricSign"
        );
        call.verb = None;
        call.collection = Some("publicKey");
        assert_eq!(
            call.url().unwrap().as_str(),
            "http://127.0.0.1:1234/v1/projects/my-project/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/3/publicKey"
        );
        call.version = None;
        call.collection = Some("cryptoKeyVersions");
        call.query = vec![("pageSize", "1000".into()), ("pageToken", "a b&c".into())];
        assert_eq!(
            call.url().unwrap().as_str(),
            "http://127.0.0.1:1234/v1/projects/my-project/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions?pageSize=1000&pageToken=a+b%26c"
        );
    }
}
