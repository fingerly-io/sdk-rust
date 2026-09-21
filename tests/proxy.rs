//! The same-origin proxy: what it refuses, what it forwards, and what it
//! relays back.

mod common;

use std::time::Duration;

use axum::Router;
use bytes::Bytes;
use common::{Canned, TestServer, PROXY_KEY, PUBLIC_KEY, SECRET_KEY};
use fingerly::{Error, FingerlyProxy};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};

const CLIENT_IP: &str = "203.0.113.7";

/// A proxy pointed at a test server, mounted under `/metrics`.
fn proxy(server: &TestServer) -> FingerlyProxy {
    FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .prefix("/metrics")
        .upstream(&server.base_url)
        .client_ip(|_parts| CLIENT_IP.to_owned())
        .build()
        .expect("the test options are valid")
}

/// Builds an identify request as the browser SDK sends one.
fn identify(path: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("x-api-key", PUBLIC_KEY)
        .header("content-type", "application/json")
        .header("origin", "https://shop.example.com")
        .header("user-agent", "Mozilla/5.0")
        .header("cookie", "session=secret")
        .header("authorization", "Bearer customer-token")
        .body(Full::new(Bytes::from_static(b"{\"signals\":{}}")))
        .unwrap()
}

/// The upstream answer to a successful identify.
fn identified() -> Canned {
    Canned::json(200, r#"{"request_id":"req_1","visitor_id":"vis_1"}"#)
}

async fn body_of(response: Response<Full<Bytes>>) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn requires_a_credential_and_a_client_ip() {
    let missing_key = FingerlyProxy::builder()
        .client_ip(|_| CLIENT_IP.to_owned())
        .build()
        .unwrap_err();
    assert!(matches!(missing_key, Error::Config { .. }));

    let missing_ip = FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .build()
        .unwrap_err();
    assert!(matches!(missing_ip, Error::Config { .. }));

    #[allow(deprecated)]
    let both = FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .secret_key(SECRET_KEY)
        .client_ip(|_| CLIENT_IP.to_owned())
        .build()
        .unwrap_err();
    assert!(matches!(both, Error::Config { .. }));
}

#[test]
fn refuses_options_it_could_not_honour() {
    for build in [
        FingerlyProxy::builder().proxy_key(SECRET_KEY),
        FingerlyProxy::builder()
            .proxy_key(PROXY_KEY)
            .prefix("metrics"),
        FingerlyProxy::builder().proxy_key(PROXY_KEY).prefix("/a?b"),
        FingerlyProxy::builder().proxy_key(PROXY_KEY).prefix("/a#b"),
        FingerlyProxy::builder()
            .proxy_key(PROXY_KEY)
            .api_version("beta"),
        FingerlyProxy::builder()
            .proxy_key(PROXY_KEY)
            .max_body_bytes(0),
        FingerlyProxy::builder()
            .proxy_key(PROXY_KEY)
            .timeout(Duration::ZERO),
        FingerlyProxy::builder()
            .proxy_key(PROXY_KEY)
            .upstream("https://user:pass@example.com"),
    ] {
        assert!(build.client_ip(|_| CLIENT_IP.to_owned()).build().is_err());
    }
}

#[tokio::test]
async fn forwards_identify_and_sends_only_vetted_metadata() {
    let server = TestServer::always(identified()).await;
    let response = proxy(&server)
        .handle(identify("/metrics/api/v1/identify"))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_of(response).await,
        r#"{"request_id":"req_1","visitor_id":"vis_1"}"#
    );

    let forwarded = server.first();
    assert_eq!(forwarded.method, "POST");
    assert_eq!(forwarded.path, "/api/v1/identify");
    assert_eq!(forwarded.body, Bytes::from_static(b"{\"signals\":{}}"));
    assert_eq!(forwarded.header("x-api-key"), PUBLIC_KEY);
    assert_eq!(forwarded.header("x-fingerly-proxy-key"), PROXY_KEY);
    assert_eq!(forwarded.header("x-fingerly-client-ip"), CLIENT_IP);
    assert_eq!(
        forwarded.header("x-fingerly-origin"),
        "https://shop.example.com"
    );
    assert_eq!(forwarded.header("x-fingerly-user-agent"), "Mozilla/5.0");
    assert_eq!(forwarded.header("content-type"), "application/json");
    assert!(forwarded.header("user-agent").starts_with("fingerly-rust/"));

    // The customer's own credentials are never passed on.
    assert_eq!(forwarded.header("cookie"), "");
    assert_eq!(forwarded.header("authorization"), "");
}

#[tokio::test]
async fn forwards_a_supplement_for_one_request_id() {
    let server = TestServer::always(Canned::json(202, "{}")).await;
    let response = proxy(&server)
        .handle(identify("/metrics/api/v1/events/req_1/supplement"))
        .await;

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(server.first().path, "/api/v1/events/req_1/supplement");
}

#[tokio::test]
async fn passes_on_an_idempotency_key_when_the_sdk_sent_one() {
    let server = TestServer::always(identified()).await;
    let mut request = identify("/metrics/api/v1/identify");
    request
        .headers_mut()
        .insert("idempotency-key", "abc-123".parse().unwrap());

    proxy(&server).handle(request).await;
    assert_eq!(server.first().header("idempotency-key"), "abc-123");
}

/// `nest_service` and friends remove the mount before the service sees it, and
/// give no way to detect that they did, so both shapes have to work.
#[tokio::test]
async fn accepts_the_prefix_present_or_already_stripped() {
    for path in ["/metrics/api/v1/identify", "/api/v1/identify"] {
        let server = TestServer::always(identified()).await;
        let response = proxy(&server).handle(identify(path)).await;
        assert_eq!(response.status(), StatusCode::OK, "{path} was refused");
        assert_eq!(server.first().path, "/api/v1/identify");
    }
}

#[tokio::test]
async fn refuses_every_method_but_post() {
    let server = TestServer::always(identified()).await;
    let request = Request::builder()
        .method("GET")
        .uri("/metrics/api/v1/identify")
        .header("x-api-key", PUBLIC_KEY)
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = proxy(&server).handle(request).await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()["allow"], "POST");
    assert_eq!(server.request_count(), 0);
}

/// Event reads need a secret key and must stay unreachable from a browser.
#[tokio::test]
async fn refuses_every_route_but_identify_and_supplement() {
    let server = TestServer::always(identified()).await;
    for path in [
        "/metrics/api/v1/events",
        "/metrics/api/v1/events/req_1",
        "/metrics/api/v1/events/req_1/supplement/extra",
        "/metrics/api/v1/events//supplement",
        "/metrics/api/v1/identify/extra",
        "/metrics/api/v2/identify",
        "/api/v1/../events",
        "/other/api/v1/identify",
        "/metrics/identify",
        "/",
    ] {
        let response = proxy(&server).handle(identify(path)).await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{path} was proxied"
        );
    }
    assert_eq!(server.request_count(), 0);
}

/// With a proxy key the browser must present a public key for the same
/// deployment; the proxy forwards it alongside its own.
#[tokio::test]
async fn requires_a_matching_public_key_from_the_browser() {
    let server = TestServer::always(identified()).await;
    for presented in [
        None,
        Some(""),
        Some(SECRET_KEY),
        Some(PROXY_KEY),
        Some("fly_pk_staging_otherenvironment"),
        Some("not-a-key"),
    ] {
        let mut request = identify("/metrics/api/v1/identify");
        request.headers_mut().remove("x-api-key");
        if let Some(value) = presented {
            request
                .headers_mut()
                .insert("x-api-key", value.parse().unwrap());
        }

        let response = proxy(&server).handle(request).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{presented:?} was accepted"
        );
    }
    assert_eq!(server.request_count(), 0);
}

/// The deprecated mode authenticates on its own, so it accepts whatever the
/// browser presents and never forwards it.
#[tokio::test]
async fn the_deprecated_secret_key_mode_authenticates_on_its_own() {
    let server = TestServer::always(identified()).await;
    #[allow(deprecated)]
    let proxy = FingerlyProxy::builder()
        .secret_key(SECRET_KEY)
        .prefix("/metrics")
        .upstream(&server.base_url)
        .client_ip(|_| CLIENT_IP.to_owned())
        .build()
        .unwrap();

    let mut request = identify("/metrics/api/v1/identify");
    request.headers_mut().remove("x-api-key");
    let response = proxy.handle(request).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(server.first().header("x-api-key"), SECRET_KEY);
    assert_eq!(server.first().header("x-fingerly-proxy-key"), "");
}

#[tokio::test]
async fn refuses_a_body_that_declares_itself_too_large() {
    let server = TestServer::always(identified()).await;
    let mut request = identify("/metrics/api/v1/identify");
    request
        .headers_mut()
        .insert("content-length", "2000000".parse().unwrap());

    let response = proxy(&server).handle(request).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(server.request_count(), 0);
}

/// The declared size is only a hint; the real one is enforced while reading.
#[tokio::test]
async fn refuses_a_body_that_turns_out_too_large() {
    let server = TestServer::always(identified()).await;
    let proxy = FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .prefix("/metrics")
        .upstream(&server.base_url)
        .max_body_bytes(16)
        .client_ip(|_| CLIENT_IP.to_owned())
        .build()
        .unwrap();

    let request = Request::builder()
        .method("POST")
        .uri("/metrics/api/v1/identify")
        .header("x-api-key", PUBLIC_KEY)
        .body(Full::new(Bytes::from(vec![b'x'; 64])))
        .unwrap();

    let response = proxy.handle(request).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(server.request_count(), 0);
}

/// The body has already been framed by the time it is relayed, so the upstream
/// framing headers would misdescribe the bytes we hand back. Everything else
/// the API said is passed through.
#[tokio::test]
async fn strips_the_headers_that_described_the_upstream_connection() {
    let server =
        TestServer::always(identified().header("x-fingerly-request-id", "req_trace")).await;

    let response = proxy(&server)
        .handle(identify("/metrics/api/v1/identify"))
        .await;

    assert_eq!(response.headers().get("content-length"), None);
    assert_eq!(response.headers().get("transfer-encoding"), None);
    assert_eq!(response.headers().get("connection"), None);
    assert_eq!(response.headers()["x-fingerly-request-id"], "req_trace");
    assert_eq!(response.headers()["cache-control"], "no-store");
}

/// The proxy strips `content-encoding`, so the bytes it relays have to really
/// be decoded. reqwest only decodes what it asked for, which is why the SDK
/// builds its client with compression on.
#[tokio::test]
async fn relays_a_compressed_answer_decoded() {
    use std::io::Write;

    let payload = r#"{"request_id":"req_1","visitor_id":"vis_1"}"#;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(payload.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();

    let server =
        TestServer::always(Canned::bytes(200, compressed).header("content-encoding", "gzip")).await;

    let response = proxy(&server)
        .handle(identify("/metrics/api/v1/identify"))
        .await;

    assert_eq!(
        server.first().header("accept-encoding"),
        "gzip",
        "the proxy did not ask for what it claims to decode"
    );
    assert_eq!(response.headers().get("content-encoding"), None);
    assert_eq!(body_of(response).await, payload);
}

#[tokio::test]
async fn relays_an_upstream_refusal_unchanged() {
    let server = TestServer::always(Canned::json(
        429,
        r#"{"error":{"code":"rate_limited","message":"slow down","status":429}}"#,
    ))
    .await;

    let response = proxy(&server)
        .handle(identify("/metrics/api/v1/identify"))
        .await;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(body_of(response).await.contains("rate_limited"));
}

#[tokio::test]
async fn sends_no_body_on_a_status_that_may_not_carry_one() {
    let server = TestServer::always(Canned::json(204, "")).await;
    let response = proxy(&server)
        .handle(identify("/metrics/api/v1/identify"))
        .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(body_of(response).await, "");
}

/// The documented behaviour is to give Fingerly its deadline and then answer,
/// not to hold the browser's connection open.
#[tokio::test]
async fn answers_502_when_the_upstream_stalls() {
    let server = TestServer::always(identified().delay(Duration::from_secs(30))).await;
    let proxy = FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .prefix("/metrics")
        .upstream(&server.base_url)
        .timeout(Duration::from_millis(100))
        .client_ip(|_| CLIENT_IP.to_owned())
        .build()
        .unwrap();

    let response = proxy.handle(identify("/metrics/api/v1/identify")).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn answers_502_when_the_upstream_is_unreachable() {
    let proxy = FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .prefix("/metrics")
        // Port 1 is reserved and nothing listens on it.
        .upstream("http://127.0.0.1:1")
        .client_ip(|_| CLIENT_IP.to_owned())
        .build()
        .unwrap();

    let response = proxy.handle(identify("/metrics/api/v1/identify")).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

/// A `client_ip` that cannot be a header value is a bug in the integration,
/// and it must not become a header injection.
#[tokio::test]
async fn refuses_a_client_ip_that_is_not_a_plain_address() {
    let server = TestServer::always(identified()).await;
    let proxy = FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .prefix("/metrics")
        .upstream(&server.base_url)
        .client_ip(|_| "1.2.3.4\r\nx-injected: yes".to_owned())
        .build()
        .unwrap();

    let response = proxy.handle(identify("/metrics/api/v1/identify")).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(server.request_count(), 0);
}

/// The callback sees the request parts, so a framework extension such as
/// axum's `ConnectInfo` is reachable from inside it.
#[tokio::test]
async fn reads_the_address_from_the_request_the_integration_chose() {
    let server = TestServer::always(identified()).await;
    let proxy = FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .prefix("/metrics")
        .upstream(&server.base_url)
        .client_ip(|parts| {
            parts
                .headers
                .get("cf-connecting-ip")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        })
        .build()
        .unwrap();

    let mut request = identify("/metrics/api/v1/identify");
    request
        .headers_mut()
        .insert("cf-connecting-ip", "198.51.100.9".parse().unwrap());

    proxy.handle(request).await;
    assert_eq!(
        server.first().header("x-fingerly-client-ip"),
        "198.51.100.9"
    );
}

/// The whole point of the tower::Service impl: axum takes it directly, and
/// `nest_service` strips the mount on the way in.
#[tokio::test]
async fn mounts_straight_into_an_axum_router() {
    let upstream = TestServer::always(identified()).await;
    let app = Router::new().nest_service("/metrics", proxy(&upstream));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let serving = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let response = reqwest::Client::new()
        .post(format!("http://{address}/metrics/api/v1/identify"))
        .header("x-api-key", PUBLIC_KEY)
        .header("content-type", "application/json")
        .body(r#"{"signals":{}}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(response.text().await.unwrap().contains("req_1"));
    assert_eq!(upstream.first().path, "/api/v1/identify");

    serving.abort();
}

#[test]
fn a_proxy_never_prints_its_key() {
    let printed = format!(
        "{:?}",
        FingerlyProxy::builder()
            .proxy_key(PROXY_KEY)
            .client_ip(|_| CLIENT_IP.to_owned())
            .build()
            .unwrap()
    );
    assert!(!printed.contains(PROXY_KEY), "{printed}");
}
