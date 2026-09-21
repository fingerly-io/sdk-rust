//! The same-origin proxy, as a [`tower_service::Service`] over `http` types.

use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
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
    normalize_api_version, normalize_origin, normalize_prefix, parse_key, positive_duration,
    KeyKind, KeyScope, DEFAULT_ENDPOINT,
};
use crate::errors::{Error, Result};
use crate::transport::USER_AGENT;

const DEFAULT_PREFIX: &str = "/api/fingerly";
const DEFAULT_MAX_BODY_BYTES: usize = 1 << 20;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Upstream headers that describe that connection rather than our response.
/// reqwest has already decoded and framed the body, so replaying them would
/// misdescribe the bytes we hand back.
const CONNECTION_HEADERS: [&str; 10] = [
    "connection",
    "content-encoding",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Resolves the visitor's address from the parts of the incoming request.
///
/// It is given [`Parts`] rather than the whole request because the body is
/// forwarded, not inspected. Framework extensions live there too, so axum's
/// `ConnectInfo` is reachable from inside it.
pub type ClientIpFn = dyn Fn(&Parts) -> String + Send + Sync + 'static;

/// Same-origin handler for the browser SDK's identify and supplement calls.
///
/// It exists so the browser SDK can post to your own domain instead of
/// Fingerly, because content blockers refuse third-party requests and a
/// refused identification is a visitor never identified. Only those two routes
/// are forwarded, never event reads: reading events needs a secret key and
/// must stay unreachable from a browser. It sends only vetted visitor
/// metadata, and never passes on customer cookies or authorization headers.
///
/// It implements [`tower_service::Service`] over [`http::Request`], which is
/// what axum, hyper, warp and tonic all take:
///
/// ```no_run
/// # fn build() -> fingerly::Result<axum::Router> {
/// use fingerly::FingerlyProxy;
///
/// let proxy = FingerlyProxy::builder()
///     .proxy_key(std::env::var("FINGERLY_PROXY_KEY").unwrap())
///     .prefix("/metrics")
///     .client_ip(|parts| {
///         parts
///             .headers
///             .get("cf-connecting-ip")
///             .and_then(|value| value.to_str().ok())
///             .unwrap_or_default()
///             .to_owned()
///     })
///     .build()?;
///
/// Ok(axum::Router::new().nest_service("/metrics", proxy))
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
    /// Fingerly origin requests are forwarded to.
    upstream: String,
    /// Local mount path, such as `/api/fingerly`, stripped before forwarding.
    prefix: String,
    /// API version accepted locally and sent upstream.
    api_version: String,
    /// Request body limit in bytes; larger requests get HTTP 413.
    max_body_bytes: usize,
    /// Deadline for reading the body and forwarding it.
    timeout: Duration,
    /// Customer callback resolving the visitor IP from trusted infrastructure.
    client_ip: Arc<ClientIpFn>,
    /// HTTP implementation for the upstream call.
    http: reqwest::Client,
}

impl fmt::Debug for FingerlyProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key is deliberately absent: a proxy often ends up in a debug log
        // of the router it was mounted on.
        f.debug_struct("FingerlyProxy")
            .field("prefix", &self.inner.prefix)
            .field("upstream", &self.inner.upstream)
            .field("api_version", &self.inner.api_version)
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

        if parts.method != http::Method::POST {
            let mut response = refuse(StatusCode::METHOD_NOT_ALLOWED);
            response
                .headers_mut()
                .insert(http::header::ALLOW, HeaderValue::from_static("POST"));
            return response;
        }

        let Some(upstream_path) = inner.route_for(parts.uri.path()) else {
            return refuse(StatusCode::NOT_FOUND);
        };

        let presented = parts
            .headers
            .get("x-api-key")
            .and_then(|value| value.to_str().ok());
        let Some(api_key) = inner.upstream_key_for(presented) else {
            return refuse(StatusCode::UNAUTHORIZED);
        };

        // Refuse on the declared size first; the limited read enforces the
        // real one.
        if declared_length(&parts).is_some_and(|length| length > inner.max_body_bytes) {
            return refuse(StatusCode::PAYLOAD_TOO_LARGE);
        }

        let headers = match inner.upstream_headers(&parts, &api_key) {
            Ok(headers) => headers,
            // A `client_ip` that cannot be a header value is a bug in the
            // integration, not something the visitor did.
            Err(_) => return refuse(StatusCode::INTERNAL_SERVER_ERROR),
        };

        let forward = async {
            let body = match Limited::new(body, inner.max_body_bytes).collect().await {
                Ok(collected) => collected.to_bytes(),
                // Streaming the read means an oversized body is cut off at the
                // limit instead of being held in memory first. Anything else
                // is a browser that went away mid-body.
                Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => {
                    return refuse(StatusCode::PAYLOAD_TOO_LARGE)
                }
                Err(_) => return refuse(StatusCode::BAD_REQUEST),
            };
            match inner
                .http
                .post(format!("{}{upstream_path}", inner.upstream))
                .headers(headers)
                .body(body)
                .send()
                .await
            {
                Ok(response) => relay(response).await,
                Err(_) => refuse(StatusCode::BAD_GATEWAY),
            }
        };

        match tokio::time::timeout(inner.timeout, forward).await {
            Ok(response) => response,
            // The documented behaviour is to give Fingerly its deadline and
            // then answer 502, not to hold the browser's connection open.
            Err(_) => refuse(StatusCode::BAD_GATEWAY),
        }
    }
}

impl ProxyInner {
    /// Maps a local path to its upstream path.
    ///
    /// Event reads need a secret key and must stay unreachable from a browser,
    /// so only identify and supplement are proxyable. The prefix is tolerated
    /// as either present or already stripped, because `nest_service` and
    /// friends remove the mount before the service sees it and give no way to
    /// detect that they did.
    fn route_for(&self, path: &str) -> Option<String> {
        let versioned = format!("/api/{}", self.api_version);
        let mount = format!("{}{versioned}", self.prefix);
        let resource = path
            .strip_prefix(&mount)
            .or_else(|| path.strip_prefix(&versioned))?;

        if resource != "/identify" && !is_supplement_path(resource) {
            return None;
        }
        Some(format!("{versioned}{resource}"))
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
    fn upstream_headers(&self, parts: &Parts, api_key: &str) -> Result<http::HeaderMap> {
        let client_ip = (self.client_ip)(parts);
        let client_ip = HeaderValue::from_str(&client_ip)
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
    prefix: Option<String>,
    max_body_bytes: Option<usize>,
    timeout: Option<Duration>,
    client_ip: Option<Arc<ClientIpFn>>,
    http_client_builder: Option<reqwest::ClientBuilder>,
}

impl fmt::Debug for FingerlyProxyBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FingerlyProxyBuilder")
            .field("prefix", &self.prefix)
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
    /// Read it from a header your own infrastructure sets, such as your load
    /// balancer's or CDN's. Never use the left-most `X-Forwarded-For` value:
    /// the visitor writes it.
    pub fn client_ip<F>(mut self, resolve: F) -> Self
    where
        F: Fn(&Parts) -> String + Send + Sync + 'static,
    {
        self.client_ip = Some(Arc::new(resolve));
        self
    }

    /// The path the proxy is mounted under. Defaults to `/api/fingerly`.
    ///
    /// Choose a neutral one: blockers look for words such as `fingerprint`,
    /// `tracking` and `fingerly`.
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// The API route version accepted locally and forwarded upstream.
    /// Defaults to `v1`.
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
    /// credential, route or limit is reported here.
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
        let prefix = normalize_prefix(self.prefix.as_deref().unwrap_or(DEFAULT_PREFIX))?;
        let max_body_bytes = match self.max_body_bytes {
            Some(0) => return Err(Error::config("max_body_bytes must be a positive integer")),
            Some(bytes) => bytes,
            None => DEFAULT_MAX_BODY_BYTES,
        };
        let timeout = positive_duration(self.timeout.unwrap_or(DEFAULT_TIMEOUT), "timeout")?;

        let http = self
            .http_client_builder
            .unwrap_or_else(reqwest::Client::builder)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| Error::config(format!("could not build the HTTP client: {error}")))?;

        Ok(FingerlyProxy {
            inner: Arc::new(ProxyInner {
                key,
                scope,
                uses_proxy_key,
                upstream,
                prefix,
                api_version,
                max_body_bytes,
                timeout,
                client_ip,
                http,
            }),
        })
    }
}

/// Whether a resource is `/events/{request_id}/supplement` with exactly one id
/// segment.
fn is_supplement_path(resource: &str) -> bool {
    resource
        .strip_prefix("/events/")
        .and_then(|rest| rest.strip_suffix("/supplement"))
        .is_some_and(|request_id| !request_id.is_empty() && !request_id.contains('/'))
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

/// Builds a plain-text refusal that never reaches Fingerly.
fn refuse(status: StatusCode) -> Response<Full<Bytes>> {
    let reason = status.canonical_reason().unwrap_or("Error");
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

/// Returns the upstream response to the browser, uncacheable and without the
/// headers that described the upstream connection.
///
/// The body is always drained, inside the caller's deadline, so a stalled
/// upstream times out instead of holding a connection open.
async fn relay(response: reqwest::Response) -> Response<Full<Bytes>> {
    let status = response.status();
    let mut headers = response.headers().clone();
    let Ok(bytes) = response.bytes().await else {
        return refuse(StatusCode::BAD_GATEWAY);
    };

    for name in CONNECTION_HEADERS {
        headers.remove(name);
    }
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );

    let bodiless = matches!(
        status,
        StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
    );
    let mut relayed = Response::new(Full::new(if bodiless { Bytes::new() } else { bytes }));
    *relayed.status_mut() = status;
    *relayed.headers_mut() = headers;
    relayed
}
