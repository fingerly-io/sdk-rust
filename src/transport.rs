//! Authenticated JSON reads against one regional Fingerly API.

use std::time::Duration;

use crate::config::{
    normalize_api_version, normalize_origin, parse_key, positive_duration, regional_origin, KeyKind,
};
use crate::errors::{ApiError, Error, Operation, Result};

/// The SDK build that made the request, sent on every call.
pub(crate) const USER_AGENT: &str = concat!("fingerly-rust/", env!("CARGO_PKG_VERSION"));

pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Caps how much of a failed response is parsed for metadata. An error body is
/// small; anything larger is not one worth reading.
const MAX_ERROR_BODY: usize = 1 << 20;

/// Every request carries a deadline that covers receiving the body, refuses
/// redirects so the key is never replayed to another host, and reports
/// failures as [`Error::Api`] without echoing the response body.
pub(crate) struct Transport {
    /// Versioned base URL, e.g. `https://us.api.fingerly.io/api/v1`.
    base_url: String,
    /// Deadline covering both the request and reading its JSON body.
    timeout: Duration,
    /// HTTP implementation; redirects are disabled on it at build time.
    http: reqwest::Client,
    /// Server-only read key, sent as `x-api-key` and redacted from errors.
    secret_key: String,
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key is deliberately absent: a client is easy to end up inside
        // the debug output of whatever is holding it.
        f.debug_struct("Transport")
            .field("base_url", &self.base_url)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl Transport {
    /// Validates every option, so a misconfigured client never reaches the
    /// network.
    ///
    /// The key is validated even when an endpoint is given, so a public, proxy
    /// or management key can never reach an API that would accept it.
    pub(crate) fn new(
        secret_key: String,
        endpoint: Option<String>,
        api_version: Option<String>,
        timeout: Option<Duration>,
        builder: Option<reqwest::ClientBuilder>,
    ) -> Result<Self> {
        let scope = parse_key(&secret_key, KeyKind::Secret)?;
        let origin = normalize_origin(&endpoint.unwrap_or_else(|| regional_origin(scope)))?;
        let api_version = normalize_api_version(api_version.as_deref().unwrap_or("v1"))?;
        let timeout = positive_duration(timeout.unwrap_or(DEFAULT_TIMEOUT), "timeout")?;

        // Redirects are refused here rather than per request, because reqwest
        // fixes the policy when the client is built. A caller's builder is
        // accepted; a caller's finished Client is not, for exactly this reason.
        let http = builder
            .unwrap_or_else(reqwest::Client::builder)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(USER_AGENT)
            .build()
            .map_err(|error| Error::config(format!("could not build the HTTP client: {error}")))?;

        Ok(Transport {
            base_url: format!("{origin}/api/{api_version}"),
            timeout,
            http,
            secret_key,
        })
    }

    /// Performs one GET and parses its JSON body. Never retries.
    ///
    /// Dropping the returned future cancels the request, which is how a caller
    /// cancels one.
    pub(crate) async fn get_json(&self, path: &str) -> Result<serde_json::Value> {
        let request = self.http.get(format!("{}{path}", self.base_url));
        match tokio::time::timeout(self.timeout, self.send(request)).await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout {
                operation: Operation::Request,
            }),
        }
    }

    /// Sends one request and reads its whole body inside the caller's deadline.
    async fn send(&self, request: reqwest::RequestBuilder) -> Result<serde_json::Value> {
        let response = request
            .header("x-api-key", &self.secret_key)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|error| Error::connection(self.redact(&error.to_string())))?;

        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| Error::connection(self.redact(&error.to_string())))?;

        if !status.is_success() {
            return Err(Error::Api(self.api_error(status.as_u16(), &body)));
        }
        serde_json::from_slice(&body)
            .map_err(|error| Error::decode(self.redact(&error.to_string())))
    }

    /// Maps an error response to a redacted [`ApiError`].
    ///
    /// Only the status and the structured fields the API documents are
    /// surfaced. The raw body is deliberately dropped rather than echoed.
    fn api_error(&self, status: u16, body: &[u8]) -> ApiError {
        let mut error = ApiError {
            status,
            code: None,
            details: None,
            request_id: None,
        };

        let envelope: serde_json::Value =
            match serde_json::from_slice(&body[..body.len().min(MAX_ERROR_BODY)]) {
                Ok(value) => value,
                // A non-JSON or truncated body still reports its HTTP status, and
                // its contents are deliberately dropped rather than surfaced.
                Err(_) => return error,
            };

        if let Some(code) = envelope.pointer("/error/code").and_then(|v| v.as_str()) {
            error.code = Some(self.redact(code));
        }
        if let Some(details) = envelope.pointer("/error/details") {
            // A JSON round-trip redacts nested values without walking the tree.
            error.details = serde_json::from_str(&self.redact(&details.to_string())).ok();
        }
        if let Some(request_id) = envelope.get("request_id").and_then(|v| v.as_str()) {
            error.request_id = Some(self.redact(request_id));
        }
        error
    }

    /// Strips the secret key from anything an error may carry to logs.
    fn redact(&self, value: &str) -> String {
        value.replace(&self.secret_key, "[redacted]")
    }
}
