//! The same-origin proxy, as a [`tower_service::Service`] over `http` types.

use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::request::Parts;
use http::{Request, Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};

use crate::config::{
    normalize_api_version, normalize_origin, normalize_path, parse_key, positive_duration, KeyKind,
    KeyScope, DEFAULT_ENDPOINT,
};
use crate::errors::{Error, Result};
use crate::transport::USER_AGENT;

const DEFAULT_MAX_BODY_BYTES: usize = 1 << 20;
/// Caps the upstream answer held for relaying. An ingest answer is a few
/// kilobytes; anything past this is not one.
const MAX_RELAY_BYTES: usize = 4 << 20;

/// Reported, once, for a `client_ip` callback that returned no address.
const NO_CLIENT_IP: &str = "the client IP callback returned no valid address";
const NO_CLIENT_IP_ANSWER: &str = "The client IP callback returned no valid address";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// What this proxy reports itself as upstream; shown per proxy in the
/// dashboard.
const PROXY_VERSION: &str = concat!("rust/", env!("CARGO_PKG_VERSION"));

/// The response headers relayed to the browser, and nothing else. A content
/// blocker can match a response header by name, so an allowlist is what keeps
/// anything naming Fingerly off the page, whatever the API adds in future. It
/// also leaves out the headers that described the upstream connection, which
/// would misdescribe the body reqwest has already decoded and framed.
const RELAYED_HEADERS: [&str; 5] = [
    "content-type",
    "x-request-id",
    "ratelimit-limit",
    "ratelimit-remaining",
    "retry-after",
];

/// Resolves the visitor's address from the parts of the incoming request.
///
/// It is given [`Parts`] rather than the whole request because the body is
/// forwarded, not inspected. Framework extensions live there too, so axum's
/// `ConnectInfo` is reachable from inside it.
pub type ClientIpFn = dyn Fn(&Parts) -> String + Send + Sync + 'static;

/// Receives every failure the proxy answered for; see
/// [`FingerlyProxyBuilder::on_error`].
pub type ProxyErrorHook = dyn Fn(&ProxyError) + Send + Sync + 'static;

/// What went wrong, for a [`ProxyError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProxyErrorKind {
    /// The deadline passed before Fingerly answered in full. Answered `504`.
    Timeout,
    /// Fingerly could not be reached, or its answer broke off. Answered `502`.
    Upstream,
    /// Fingerly's answer was over 4 MiB. Answered `502`.
    ResponseTooLarge,
    /// The `client_ip` callback returned something other than one address.
    /// Answered `500`, and reported once rather than per request.
    InvalidClientIp,
}

/// A failure the proxy answered for with a 5xx of its own. It never carries a
/// key or a response body.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ProxyError {
    /// The status the browser was answered.
    pub status: StatusCode,
    /// What went wrong.
    pub kind: ProxyErrorKind,
    /// A one-line description of the cause.
    pub message: String,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fingerly proxy: answered {}: {}",
            self.status.as_u16(),
            self.message
        )
    }
}

impl std::error::Error for ProxyError {}

/// Same-origin handler for the browser SDK.
///
/// It exists so the browser SDK can post to a path on your own domain instead
/// of Fingerly, because content blockers refuse third-party requests and a
/// refused identification is a visitor never identified. The SDK posts both of
/// its calls to that one path, and this forwards each to Fingerly's one ingest
/// URL, never anywhere else and never to event reads: reading events needs a
/// secret key and must stay unreachable from a browser. It sends only vetted
/// visitor metadata, never passes on customer cookies or authorization
/// headers, and relays nothing back that names Fingerly.
///
/// It implements [`tower_service::Service`] over [`http::Request`], which is
/// what axum, hyper, warp and tonic all take. Mount it at the path the
/// dashboard issued for the proxy:
///
/// ```no_run
/// # fn build() -> fingerly::Result<axum::Router> {
/// use fingerly::FingerlyProxy;
///
/// let proxy = FingerlyProxy::builder()
///     .proxy_key(std::env::var("FINGERLY_PROXY_KEY").unwrap())
///     .client_ip(|parts| {
///         parts
///             .headers
///             .get("x-real-ip")
///             .and_then(|value| value.to_str().ok())
///             .unwrap_or_default()
///             .to_owned()
///     })
///     .build()?;
///
/// Ok(axum::Router::new().route_service("/k7x2qm4a", proxy))
/// # }
/// ```
#[derive(Clone)]
pub struct FingerlyProxy {
    inner: Arc<ProxyInner>,
}

struct ProxyInner {
    /// Server-held proxy key, or deprecated secret key, sent only to Fingerly.
    key: String,
    /// The key's environment, matched against the browser's key.
    scope: KeyScope,
    /// Proxy keys authenticate the browser's public key; secret keys do not.
    uses_proxy_key: bool,
    /// The one URL requests are forwarded to.
    upstream_url: String,
    /// The one path answered, or `None` to answer wherever the router sends.
    path: Option<String>,
    /// Request body limit in bytes; larger requests get HTTP 413.
    max_body_bytes: usize,
    /// Deadline for reading the body and forwarding it.
    timeout: Duration,
    /// Customer callback resolving the visitor IP from trusted infrastructure.
    client_ip: Arc<ClientIpFn>,
    /// HTTP implementation for the upstream call.
    http: reqwest::Client,
    /// Where failures are reported; `None` logs one line through `tracing`.
    on_error: Option<Arc<ProxyErrorHook>>,
    /// Set once an invalid `client_ip` result has been reported.
    reported_bad_ip: AtomicBool,
}

impl fmt::Debug for FingerlyProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key is deliberately absent: a proxy often ends up in a debug log
        // of the router it was mounted on.
        f.debug_struct("FingerlyProxy")
            .field("key", &"[redacted]")
            .field("path", &self.inner.path)
            .field("upstream_url", &self.inner.upstream_url)
            .finish_non_exhaustive()
    }
}

impl FingerlyProxy {
    /// Starts a builder. A proxy key and a `client_ip` callback are required.
    pub fn builder() -> FingerlyProxyBuilder {
        FingerlyProxyBuilder::default()
    }

    /// Handles one browser request.
    ///
    /// Every refusal is produced here, before anything reaches Fingerly. Use
    /// it directly on a framework that does not speak [`tower_service`].
    pub async fn handle<B>(&self, request: Request<B>) -> Response<Full<Bytes>>
    where
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let inner = &self.inner;
        let (parts, body) = request.into_parts();

        if !inner.answers(parts.uri.path()) {
            return refuse(StatusCode::NOT_FOUND);
        }

        if parts.method != http::Method::POST {
            let mut response = refuse(StatusCode::METHOD_NOT_ALLOWED);
            response
                .headers_mut()
                .insert(http::header::ALLOW, HeaderValue::from_static("POST"));
            return response;
        }

        let presented = parts
            .headers
            .get("x-api-key")
            .and_then(|value| value.to_str().ok());
        let Some(api_key) = inner.upstream_key_for(presented) else {
            return refuse(StatusCode::UNAUTHORIZED);
        };

        // A `client_ip` that returns anything but one address is a bug in the
        // integration, not something the visitor did. Nothing goes upstream,
        // and it is reported once rather than on every request.
        let Some(client_ip) = inner.visitor_ip(&parts) else {
            if !inner.reported_bad_ip.swap(true, Ordering::Relaxed) {
                inner.report(&ProxyError {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    kind: ProxyErrorKind::InvalidClientIp,
                    message: NO_CLIENT_IP.to_owned(),
                });
            }
            return refuse_with(StatusCode::INTERNAL_SERVER_ERROR, NO_CLIENT_IP_ANSWER);
        };

        // Refuse on the declared size first; the limited read enforces the
        // real one.
        if declared_length(&parts).is_some_and(|length| length > inner.max_body_bytes) {
            return refuse(StatusCode::PAYLOAD_TOO_LARGE);
        }

        let headers = match inner.upstream_headers(&parts, &api_key, client_ip) {
            Ok(headers) => headers,
            Err(_) => return refuse(StatusCode::INTERNAL_SERVER_ERROR),
        };

        // One deadline covers reading the browser's body and the whole
        // upstream exchange. A visitor who disconnects drops this future,
        // which cancels the upstream call with it.
        let deadline = tokio::time::Instant::now() + inner.timeout;
        let read = Limited::new(body, inner.max_body_bytes).collect();
        let body = match tokio::time::timeout_at(deadline, read).await {
            Ok(Ok(collected)) => collected.to_bytes(),
            // Streaming the read means an oversized body is cut off at the
            // limit instead of being held in memory first. Anything else is a
            // browser that went away mid-body.
            Ok(Err(error)) if error.downcast_ref::<LengthLimitError>().is_some() => {
                return refuse(StatusCode::PAYLOAD_TOO_LARGE)
            }
            Ok(Err(_)) => return refuse(StatusCode::BAD_REQUEST),
            // The visitor, not Fingerly, was too slow.
            Err(_) => return refuse(StatusCode::REQUEST_TIMEOUT),
        };

        let forward = async {
            let response = inner
                .http
                .post(&inner.upstream_url)
                .headers(headers)
                .body(body)
                .send()
                .await
                .map_err(|error| (ProxyErrorKind::Upstream, error.to_string()))?;
            relay(response).await
        };
        let failure = match tokio::time::timeout_at(deadline, forward).await {
            Ok(Ok(response)) => return response,
            Ok(Err((kind, message))) => ProxyError {
                status: StatusCode::BAD_GATEWAY,
                kind,
                message,
            },
            Err(_) => ProxyError {
                status: StatusCode::GATEWAY_TIMEOUT,
                kind: ProxyErrorKind::Timeout,
                message: format!("no complete answer within {:?}", inner.timeout),
            },
        };
        inner.report(&failure);
        refuse(failure.status)
    }
}

impl ProxyInner {
    /// Runs the `client_ip` callback and accepts exactly one IPv4 or IPv6
    /// literal: no list, no port, no zone, no surrounding space.
    fn visitor_ip(&self, parts: &Parts) -> Option<IpAddr> {
        (self.client_ip)(parts).parse().ok()
    }

    /// Hands a failure to the hook, or logs one line about it.
    fn report(&self, failure: &ProxyError) {
        match &self.on_error {
            Some(hook) => hook(failure),
            None => tracing::warn!(
                target: "fingerly::proxy",
                status = failure.status.as_u16(),
                "{}",
                failure.message
            ),
        }
    }

    /// Whether this request's path is the one the proxy answers.
    ///
    /// Without a configured path, whatever the router sent is answered: the
    /// route already chose it. With one, only that exact path is: no trailing
    /// or doubled slash, no dot segment, no percent-encoding (the path is
    /// compared undecoded), and case matters.
    fn answers(&self, path: &str) -> bool {
        self.path.as_deref().is_none_or(|expected| path == expected)
    }

    /// Decides which key to present upstream.
    ///
    /// With a proxy key the browser must supply a public key for the same
    /// environment, which the proxy forwards alongside its own. The deprecated
    /// secret-key mode authenticates on its own and accepts anything.
    fn upstream_key_for(&self, presented: Option<&str>) -> Option<String> {
        if !self.uses_proxy_key {
            return Some(self.key.clone());
        }
        let presented = presented?;
        let browser = parse_key(presented, KeyKind::Public).ok()?;
        (browser == self.scope).then(|| presented.to_owned())
    }

    /// Builds the upstream headers.
    ///
    /// Nothing is copied wholesale: only the body's content type, the visitor
    /// metadata Fingerly needs, and an idempotency key when the SDK sent one.
    fn upstream_headers(
        &self,
        parts: &Parts,
        api_key: &str,
        client_ip: IpAddr,
    ) -> Result<http::HeaderMap> {
        let client_ip = HeaderValue::from_str(&client_ip.to_string())
            .map_err(|_| Error::config("client_ip must resolve to a plain address"))?;

        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            parts
                .headers
                .get(http::header::CONTENT_TYPE)
                .cloned()
                .unwrap_or_else(|| HeaderValue::from_static("application/json")),
        );
        headers.insert(
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_str(api_key)
                .map_err(|_| Error::config("the API key is not a valid header value"))?,
        );
        headers.insert(HeaderName::from_static("x-fingerly-client-ip"), client_ip);
        headers.insert(
            HeaderName::from_static("x-fingerly-origin"),
            parts
                .headers
                .get(http::header::ORIGIN)
                .cloned()
                .unwrap_or_else(|| HeaderValue::from_static("")),
        );
        headers.insert(
            HeaderName::from_static("x-fingerly-user-agent"),
            parts
                .headers
                .get(http::header::USER_AGENT)
                .cloned()
                .unwrap_or_else(|| HeaderValue::from_static("")),
        );
        headers.insert(
            HeaderName::from_static("x-fingerly-proxy-version"),
            HeaderValue::from_static(PROXY_VERSION),
        );
        headers.insert(
            http::header::USER_AGENT,
            HeaderValue::from_static(USER_AGENT),
        );
        if self.uses_proxy_key {
            headers.insert(
                HeaderName::from_static("x-fingerly-proxy-key"),
                HeaderValue::from_str(&self.key)
                    .map_err(|_| Error::config("the proxy key is not a valid header value"))?,
            );
        }
        if let Some(idempotency) = parts.headers.get("idempotency-key") {
            headers.insert(
                HeaderName::from_static("idempotency-key"),
                idempotency.clone(),
            );
        }
        Ok(headers)
    }
}

impl<B> tower_service::Service<Request<B>> for FingerlyProxy
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let proxy = self.clone();
        Box::pin(async move { Ok(proxy.handle(request).await) })
    }
}

/// Configures a [`FingerlyProxy`]. Start one with [`FingerlyProxy::builder`].
#[derive(Default)]
pub struct FingerlyProxyBuilder {
    proxy_key: Option<String>,
    secret_key: Option<String>,
    api_version: Option<String>,
    upstream: Option<String>,
    path: Option<String>,
    max_body_bytes: Option<usize>,
    timeout: Option<Duration>,
    client_ip: Option<Arc<ClientIpFn>>,
    http_client_builder: Option<reqwest::ClientBuilder>,
    on_error: Option<Arc<ProxyErrorHook>>,
}

impl fmt::Debug for FingerlyProxyBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redact = |key: &Option<String>| key.as_ref().map(|_| "[redacted]");
        f.debug_struct("FingerlyProxyBuilder")
            .field("proxy_key", &redact(&self.proxy_key))
            .field("secret_key", &redact(&self.secret_key))
            .field("path", &self.path)
            .field("upstream", &self.upstream)
            .finish_non_exhaustive()
    }
}

impl FingerlyProxyBuilder {
    /// The write-only credential, `fly_px_…`, created for customer-owned proxy
    /// infrastructure and held only on your server.
    pub fn proxy_key(mut self, key: impl Into<String>) -> Self {
        self.proxy_key = Some(key.into());
        self
    }

    /// The deprecated alternative to [`FingerlyProxyBuilder::proxy_key`].
    ///
    /// Secret read keys will be refused in the next major version. Do not pass
    /// both.
    #[deprecated(
        note = "use proxy_key; secret read keys will be refused in the next major version"
    )]
    pub fn secret_key(mut self, key: impl Into<String>) -> Self {
        self.secret_key = Some(key.into());
        self
    }

    /// Resolves the visitor's address. Required.
    ///
    /// It must return exactly one IPv4 or IPv6 address. Read it from a header
    /// your own infrastructure sets, such as your load balancer's or CDN's,
    /// and fall back to the TCP peer (axum's `ConnectInfo`, from the parts'
    /// extensions). Never use the left-most `X-Forwarded-For` value: the
    /// visitor writes it. Anything that is not one address is answered `500`
    /// without calling Fingerly, and reported once.
    pub fn client_ip<F>(mut self, resolve: F) -> Self
    where
        F: Fn(&Parts) -> String + Send + Sync + 'static,
    {
        self.client_ip = Some(Arc::new(resolve));
        self
    }

    /// The path the dashboard issued for this proxy, such as `/k7x2qm4a`,
    /// matched exactly. Anything else gets `404`.
    ///
    /// Leave it unset when the router already sends only that path to the
    /// service, as `route_service("/k7x2qm4a", proxy)` does. Set it when the
    /// service sees more than that one path, as a fallback does. Do not set it
    /// under `nest_service`, which strips the path before the service sees it.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// The API route version forwarded upstream. Defaults to `v1`.
    pub fn api_version(mut self, version: impl Into<String>) -> Self {
        self.api_version = Some(version.into());
        self
    }

    /// Overrides the upstream origin implied by the key.
    pub fn upstream(mut self, upstream: impl Into<String>) -> Self {
        self.upstream = Some(upstream.into());
        self
    }

    /// Refuses larger request bodies with `413`. Defaults to 1 MiB.
    pub fn max_body_bytes(mut self, bytes: usize) -> Self {
        self.max_body_bytes = Some(bytes);
        self
    }

    /// Bounds the body read and the upstream call. Defaults to 5 seconds.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Receives every failure the proxy answers for with a 5xx of its own:
    /// `504` when the deadline passed, `502` for any other upstream failure,
    /// `500` for a `client_ip` that returned no valid address (once). Without
    /// it, each is logged as one `tracing` warning under `fingerly::proxy`. A
    /// visitor who disconnects is not a failure and is not reported.
    pub fn on_error<F>(mut self, hook: F) -> Self
    where
        F: Fn(&ProxyError) + Send + Sync + 'static,
    {
        self.on_error = Some(Arc::new(hook));
        self
    }

    /// Supplies the HTTP stack for the upstream call. Redirects are refused
    /// either way; see [`FingerlyBuilder::http_client_builder`].
    ///
    /// [`FingerlyBuilder::http_client_builder`]: crate::FingerlyBuilder::http_client_builder
    pub fn http_client_builder(mut self, builder: reqwest::ClientBuilder) -> Self {
        self.http_client_builder = Some(builder);
        self
    }

    /// Validates every option and builds the handler.
    ///
    /// Unlike a request, a proxy is wired up once at start-up, so a bad
    /// credential, path or limit is reported here.
    pub fn build(self) -> Result<FingerlyProxy> {
        let uses_proxy_key = match (&self.proxy_key, &self.secret_key) {
            (None, None) => return Err(Error::config("a Fingerly proxy key is required")),
            (Some(_), Some(_)) => {
                return Err(Error::config(
                    "pass proxy_key or the deprecated secret_key, not both",
                ))
            }
            (Some(_), None) => true,
            (None, Some(_)) => false,
        };
        let Some(client_ip) = self.client_ip else {
            return Err(Error::config("client_ip is required"));
        };

        let key = self.proxy_key.or(self.secret_key).expect("checked above");
        let kind = if uses_proxy_key {
            KeyKind::Proxy
        } else {
            KeyKind::Secret
        };
        let scope = parse_key(&key, kind)?;

        let upstream =
            normalize_origin(&self.upstream.unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned()))?;
        let api_version = normalize_api_version(self.api_version.as_deref().unwrap_or("v1"))?;
        let upstream_url = format!("{upstream}/api/{api_version}/ingest");
        let path = self.path.as_deref().map(normalize_path).transpose()?;
        let max_body_bytes = match self.max_body_bytes {
            Some(0) => return Err(Error::config("max_body_bytes must be a positive integer")),
            Some(bytes) => bytes,
            None => DEFAULT_MAX_BODY_BYTES,
        };
        let timeout = positive_duration(self.timeout.unwrap_or(DEFAULT_TIMEOUT), "timeout")?;

        let http = crate::pool::client_from(self.http_client_builder)
            .map_err(|error| Error::config(format!("could not build the HTTP client: {error}")))?;

        Ok(FingerlyProxy {
            inner: Arc::new(ProxyInner {
                key,
                scope,
                uses_proxy_key,
                upstream_url,
                path,
                max_body_bytes,
                timeout,
                client_ip,
                http,
                on_error: self.on_error,
                reported_bad_ip: AtomicBool::new(false),
            }),
        })
    }
}

/// Reads the declared body size, when the browser sent a usable one.
fn declared_length(parts: &Parts) -> Option<usize> {
    parts
        .headers
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// Builds a short plain-text answer that names nobody.
fn refuse(status: StatusCode) -> Response<Full<Bytes>> {
    let reason = match status {
        StatusCode::BAD_GATEWAY => "Bad gateway",
        StatusCode::GATEWAY_TIMEOUT => "Gateway timeout",
        _ => status.canonical_reason().unwrap_or("Error"),
    };
    refuse_with(status, reason)
}

/// Builds `status` with a one-line plain-text body, uncacheable.
fn refuse_with(status: StatusCode, reason: &'static str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from_static(reason.as_bytes())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
}

/// Returns the upstream answer to the browser, uncacheable and with only the
/// allowlisted headers.
///
/// The body is read in full, up to 4 MiB and inside the caller's deadline,
/// before anything is answered, so a stalled or broken upstream becomes an
/// error rather than a truncated success.
async fn relay(
    mut response: reqwest::Response,
) -> std::result::Result<Response<Full<Bytes>>, (ProxyErrorKind, String)> {
    let status = response.status();
    let mut headers = http::HeaderMap::new();
    for name in RELAYED_HEADERS {
        if let Some(value) = response.headers().get(name) {
            headers.insert(name, value.clone());
        }
    }
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    let too_large = || {
        (
            ProxyErrorKind::ResponseTooLarge,
            "upstream answer exceeds 4 MiB".to_owned(),
        )
    };
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RELAY_BYTES as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| (ProxyErrorKind::Upstream, error.to_string()))?
    {
        if body.len() + chunk.len() > MAX_RELAY_BYTES {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    let bytes = Bytes::from(body);

    let bodiless = matches!(
        status,
        StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
    );
    let mut relayed = Response::new(Full::new(if bodiless { Bytes::new() } else { bytes }));
    *relayed.status_mut() = status;
    *relayed.headers_mut() = headers;
    Ok(relayed)
}
