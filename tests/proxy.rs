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

/// The path the dashboard issued for the proxy.
const PATH: &str = "/k7x2qm4a";

/// The one URL path every forwarded request goes to.
const INGEST: &str = "/api/v1/ingest";

/// A proxy pointed at a test server, answering only [`PATH`].
fn proxy(server: &TestServer) -> FingerlyProxy {
    FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .path(PATH)
        .upstream(&server.base_url)
        .client_ip(|_parts| CLIENT_IP.to_owned())
        .build()
        .expect("the test options are valid")
}

/// Builds an identification as the browser SDK posts one.
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

/// The upstream answer to a successful identification.
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
    let mut builds = vec![
        FingerlyProxy::builder().proxy_key(SECRET_KEY),
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
    ];
    for path in ["k7x2qm4a", "/a?b", "/a#b", "/", "//", "", "   "] {
        builds.push(FingerlyProxy::builder().proxy_key(PROXY_KEY).path(path));
    }
    for build in builds {
        let result = build.client_ip(|_| CLIENT_IP.to_owned()).build();
        assert!(matches!(result, Err(Error::Config { .. })));
    }
}

#[tokio::test]
async fn forwards_to_the_one_ingest_url_with_only_vetted_metadata() {
    let server = TestServer::always(identified()).await;
    let response = proxy(&server).handle(identify(PATH)).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_of(response).await,
        r#"{"request_id":"req_1","visitor_id":"vis_1"}"#
    );

    let forwarded = server.first();
    assert_eq!(forwarded.method, "POST");
    assert_eq!(forwarded.path, INGEST);
    assert_eq!(forwarded.body, Bytes::from_static(b"{\"signals\":{}}"));
    assert_eq!(forwarded.header("x-api-key"), PUBLIC_KEY);
    assert_eq!(forwarded.header("x-fingerly-proxy-key"), PROXY_KEY);
    assert_eq!(forwarded.header("x-fingerly-client-ip"), CLIENT_IP);
    assert_eq!(
        forwarded.header("x-fingerly-origin"),
        "https://shop.example.com"
    );
    assert_eq!(forwarded.header("x-fingerly-user-agent"), "Mozilla/5.0");
    assert_eq!(
        forwarded.header("x-fingerly-proxy-version"),
        concat!("rust/", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(forwarded.header("content-type"), "application/json");
    assert!(forwarded.header("user-agent").starts_with("fingerly-rust/"));

    // The customer's own credentials are never passed on.
    assert_eq!(forwarded.header("cookie"), "");
    assert_eq!(forwarded.header("authorization"), "");
}

/// The browser SDK posts its deferred report to the same path, and Fingerly
/// tells the two apart by the body, so the proxy forwards it unchanged.
#[tokio::test]
async fn forwards_a_deferred_report_to_the_same_url() {
    let server = TestServer::always(Canned::json(202, "{}")).await;
    let mut request = identify(PATH);
    *request.body_mut() = Full::new(Bytes::from_static(b"{\"token\":\"t_1\"}"));

    let response = proxy(&server).handle(request).await;

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(server.first().path, INGEST);
    assert_eq!(
        server.first().body,
        Bytes::from_static(b"{\"token\":\"t_1\"}")
    );
}

#[tokio::test]
async fn forwards_to_the_configured_version() {
    let server = TestServer::always(identified()).await;
    let proxy = FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .api_version("v2")
        .upstream(&server.base_url)
        .client_ip(|_| CLIENT_IP.to_owned())
        .build()
        .unwrap();

    let response = proxy.handle(identify(PATH)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(server.first().path, "/api/v2/ingest");
}

#[tokio::test]
async fn passes_on_an_idempotency_key_when_the_sdk_sent_one() {
    let server = TestServer::always(identified()).await;
    let mut request = identify(PATH);
    request
        .headers_mut()
        .insert("idempotency-key", "abc-123".parse().unwrap());

    proxy(&server).handle(request).await;
    assert_eq!(server.first().header("idempotency-key"), "abc-123");
}

#[tokio::test]
async fn ignores_a_trailing_slash() {
    let server = TestServer::always(identified()).await;
    let proxy = FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .path("/k7x2qm4a/")
        .upstream(&server.base_url)
        .client_ip(|_| CLIENT_IP.to_owned())
        .build()
        .unwrap();

    for path in [PATH, "/k7x2qm4a/"] {
        let response = proxy.handle(identify(path)).await;
        assert_eq!(response.status(), StatusCode::OK, "{path} was refused");
    }
    assert_eq!(server.request_count(), 2);
}

/// Without a path the router already chose what reaches the service, which
/// is the shape `route_service` and `nest_service` give.
#[tokio::test]
async fn answers_wherever_it_is_routed_without_a_path() {
    let server = TestServer::always(identified()).await;
    let proxy = FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .upstream(&server.base_url)
        .client_ip(|_| CLIENT_IP.to_owned())
        .build()
        .unwrap();

    for path in [PATH, "/", "/anything/else"] {
        let response = proxy.handle(identify(path)).await;
        assert_eq!(response.status(), StatusCode::OK, "{path} was refused");
    }
    assert!(server.requests().iter().all(|seen| seen.path == INGEST));
}

#[tokio::test]
async fn refuses_every_method_but_post() {
    let server = TestServer::always(identified()).await;
    let request = Request::builder()
        .method("GET")
        .uri(PATH)
        .header("x-api-key", PUBLIC_KEY)
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = proxy(&server).handle(request).await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()["allow"], "POST");
    assert_eq!(server.request_count(), 0);
}

/// The path is matched exactly, so nothing under it or beside it reaches
/// Fingerly, whatever the method.
#[tokio::test]
async fn refuses_every_path_but_the_configured_one() {
    let server = TestServer::always(identified()).await;
    for path in [
        "/k7x2qm4a/admin",
        "/k7x2qm4a/api/v1/identify",
        "/k7x2qm4ab",
        "/K7X2QM4A",
        "/other",
        "/api/v1/ingest",
        "/api/v1/events",
        "/",
    ] {
        let response = proxy(&server).handle(identify(path)).await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{path} was proxied"
        );
    }

    let mut wrong_method = identify("/other");
    *wrong_method.method_mut() = http::Method::GET;
    let response = proxy(&server).handle(wrong_method).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
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
        let mut request = identify(PATH);
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
        .path(PATH)
        .upstream(&server.base_url)
        .client_ip(|_| CLIENT_IP.to_owned())
        .build()
        .unwrap();

    let mut request = identify(PATH);
    request.headers_mut().remove("x-api-key");
    let response = proxy.handle(request).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(server.first().path, INGEST);
    assert_eq!(server.first().header("x-api-key"), SECRET_KEY);
    assert_eq!(server.first().header("x-fingerly-proxy-key"), "");
}

#[tokio::test]
async fn refuses_a_body_that_declares_itself_too_large() {
    let server = TestServer::always(identified()).await;
    let mut request = identify(PATH);
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
        .path(PATH)
        .upstream(&server.base_url)
        .max_body_bytes(16)
        .client_ip(|_| CLIENT_IP.to_owned())
        .build()
        .unwrap();

    let request = Request::builder()
        .method("POST")
        .uri(PATH)
        .header("x-api-key", PUBLIC_KEY)
        .body(Full::new(Bytes::from(vec![b'x'; 64])))
        .unwrap();

    let response = proxy.handle(request).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(server.request_count(), 0);
}

/// A content blocker can match a response header by name, so only an
/// allowlist is relayed. That also drops the upstream framing headers, which
/// would misdescribe the bytes we hand back.
#[tokio::test]
async fn relays_only_the_allowlisted_headers() {
    let server = TestServer::always(
        identified()
            .header("x-request-id", "req_1")
            .header("ratelimit-limit", "100")
            .header("ratelimit-remaining", "99")
            .header("retry-after", "1")
            .header("fingerly-balance-micros", "100")
            .header("x-fingerly-request-id", "req_trace")
            .header("set-cookie", "a=b")
            .header("x-powered-by", "fingerly"),
    )
    .await;

    let response = proxy(&server).handle(identify(PATH)).await;
    let headers = response.headers();

    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(headers["x-request-id"], "req_1");
    assert_eq!(headers["ratelimit-limit"], "100");
    assert_eq!(headers["ratelimit-remaining"], "99");
    assert_eq!(headers["retry-after"], "1");
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers.len(), 6, "{headers:?}");

    // Nothing relayed may name Fingerly: a blocker can match it.
    for (name, value) in headers {
        let value = value.to_str().unwrap().to_ascii_lowercase();
        assert!(!name.as_str().contains("fingerly"), "{name} was relayed");
        assert!(!value.contains("fingerly"), "{name}: {value} was relayed");
    }
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

    let response = proxy(&server).handle(identify(PATH)).await;

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

    let response = proxy(&server).handle(identify(PATH)).await;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(body_of(response).await.contains("rate_limited"));
}

#[tokio::test]
async fn sends_no_body_on_a_status_that_may_not_carry_one() {
    let server = TestServer::always(Canned::json(204, "")).await;
    let response = proxy(&server).handle(identify(PATH)).await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(body_of(response).await, "");
}

/// The documented behaviour is to give Fingerly its deadline and then answer,
/// not to hold the browser's connection open.
#[tokio::test]
async fn answers_504_when_the_upstream_stalls() {
    let server = TestServer::always(identified().delay(Duration::from_secs(30))).await;
    let proxy = FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .path(PATH)
        .upstream(&server.base_url)
        .timeout(Duration::from_millis(100))
        .client_ip(|_| CLIENT_IP.to_owned())
        .build()
        .unwrap();

    let response = proxy.handle(identify(PATH)).await;
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(body_of(response).await, "Gateway timeout");
}

#[tokio::test]
async fn answers_502_when_the_upstream_is_unreachable() {
    let proxy = FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .path(PATH)
        // Port 1 is reserved and nothing listens on it.
        .upstream("http://127.0.0.1:1")
        .client_ip(|_| CLIENT_IP.to_owned())
        .build()
        .unwrap();

    let response = proxy.handle(identify(PATH)).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

/// A `client_ip` that returns anything but one address is a bug in the
/// integration: nothing goes upstream, and it is reported once.
#[tokio::test]
async fn refuses_a_client_ip_that_is_not_one_address() {
    for address in [
        "1.2.3.4\r\nx-injected: yes",
        "",
        "null",
        "203.0.113.5, 198.51.100.7",
        "203.0.113.5:443",
        " 203.0.113.5",
        "fe80::1%en0",
        "not-an-ip",
    ] {
        let server = TestServer::always(identified()).await;
        let reported = fingerly_hook::Hook::default();
        let hook = reported.clone();
        let proxy = FingerlyProxy::builder()
            .proxy_key(PROXY_KEY)
            .path(PATH)
            .upstream(&server.base_url)
            .client_ip(move |_| address.to_owned())
            .on_error(move |failure| hook.lock().unwrap().push(failure.clone()))
            .build()
            .unwrap();

        for _ in 0..3 {
            let response = proxy.handle(identify(PATH)).await;
            assert_eq!(
                response.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "{address:?}"
            );
            assert_eq!(
                body_of(response).await,
                "The client IP callback returned no valid address"
            );
        }
        assert_eq!(server.request_count(), 0, "{address:?} reached Fingerly");
        let reported = reported.lock().unwrap();
        assert_eq!(reported.len(), 1, "{address:?} was not reported once");
        assert_eq!(reported[0].kind, fingerly::ProxyErrorKind::InvalidClientIp);
    }
}

#[tokio::test]
async fn forwards_a_valid_client_ip_canonically() {
    for (given, forwarded) in [
        ("203.0.113.5", "203.0.113.5"),
        ("2001:DB8::1", "2001:db8::1"),
        ("::ffff:203.0.113.5", "::ffff:203.0.113.5"),
    ] {
        let server = TestServer::always(identified()).await;
        let proxy = FingerlyProxy::builder()
            .proxy_key(PROXY_KEY)
            .path(PATH)
            .upstream(&server.base_url)
            .client_ip(move |_| given.to_owned())
            .build()
            .unwrap();
        assert_eq!(proxy.handle(identify(PATH)).await.status(), StatusCode::OK);
        assert_eq!(server.first().header("x-fingerly-client-ip"), forwarded);
    }
}

/// The callback sees the request parts, so a framework extension such as
/// axum's `ConnectInfo` is reachable from inside it.
#[tokio::test]
async fn reads_the_address_from_the_request_the_integration_chose() {
    let server = TestServer::always(identified()).await;
    let proxy = FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .path(PATH)
        .upstream(&server.base_url)
        .client_ip(|parts| {
            parts
                .headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        })
        .build()
        .unwrap();

    let mut request = identify(PATH);
    request
        .headers_mut()
        .insert("x-real-ip", "198.51.100.9".parse().unwrap());

    proxy.handle(request).await;
    assert_eq!(
        server.first().header("x-fingerly-client-ip"),
        "198.51.100.9"
    );
}

/// Posts an identification to a live server and returns the status and the
/// relayed header names.
async fn post_to(address: std::net::SocketAddr, path: &str) -> (u16, Vec<String>) {
    let response = reqwest::Client::new()
        .post(format!("http://{address}{path}"))
        .header("x-api-key", PUBLIC_KEY)
        .header("content-type", "application/json")
        .body(r#"{"signals":{}}"#)
        .send()
        .await
        .unwrap();
    let names = response.headers().keys().map(|name| name.to_string());
    (response.status().as_u16(), names.collect())
}

/// Serves an axum app on a real socket for as long as the handle lives.
async fn serve(app: Router) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let serving = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (address, serving)
}

/// The whole point of the tower::Service impl: axum takes it directly. The
/// documented shape routes the one path to a proxy that sets none.
#[tokio::test]
async fn mounts_straight_into_an_axum_router() {
    let upstream = TestServer::always(identified().header("fingerly-balance-micros", "100")).await;
    let proxy = FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .upstream(&upstream.base_url)
        .client_ip(|_| CLIENT_IP.to_owned())
        .build()
        .unwrap();
    let (address, serving) = serve(Router::new().route_service(PATH, proxy)).await;

    let (status, names) = post_to(address, PATH).await;
    assert_eq!(status, 200);
    assert!(
        names.iter().all(|name| !name.contains("fingerly")),
        "{names:?}"
    );
    assert_eq!(upstream.first().path, INGEST);

    let (status, _) = post_to(address, "/other").await;
    assert_eq!(status, 404);
    assert_eq!(upstream.request_count(), 1);

    serving.abort();
}

/// As a fallback the service sees every path, which is what `path` is for.
#[tokio::test]
async fn answers_only_its_path_as_an_axum_fallback() {
    let upstream = TestServer::always(identified()).await;
    let (address, serving) = serve(Router::new().fallback_service(proxy(&upstream))).await;

    assert_eq!(post_to(address, PATH).await.0, 200);
    assert_eq!(post_to(address, "/k7x2qm4a/admin").await.0, 404);
    assert_eq!(post_to(address, "/other").await.0, 404);
    assert_eq!(upstream.request_count(), 1);

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

/// Starts a raw upstream that answers every connection with `answer` and then
/// keeps the socket open for `hold`, so a declared length is never met.
async fn raw_upstream(answer: &'static [u8], hold: Duration, trickle: bool) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 8192];
                let _ = socket.read(&mut buffer).await;
                if trickle {
                    for byte in answer {
                        if socket.write_all(&[*byte]).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                } else {
                    let _ = socket.write_all(answer).await;
                }
                tokio::time::sleep(hold).await;
            });
        }
    });
    format!("http://{address}")
}

fn proxy_to(upstream: &str, timeout: Duration, hook: fingerly_hook::Hook) -> FingerlyProxy {
    FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .path(PATH)
        .upstream(upstream)
        .timeout(timeout)
        .client_ip(|_| CLIENT_IP.to_owned())
        .on_error(move |failure| hook.lock().unwrap().push(failure.clone()))
        .build()
        .unwrap()
}

mod fingerly_hook {
    pub type Hook = std::sync::Arc<std::sync::Mutex<Vec<fingerly::ProxyError>>>;
}

#[tokio::test]
async fn never_relays_a_truncated_answer_as_a_success() {
    let reported = fingerly_hook::Hook::default();
    let upstream = raw_upstream(
        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{\"request_id\":",
        Duration::from_millis(0),
        false,
    )
    .await;
    let response = proxy_to(&upstream, Duration::from_secs(2), reported.clone())
        .handle(identify(PATH))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(body_of(response).await, "Bad gateway");
    let reported = reported.lock().unwrap();
    assert_eq!(reported.len(), 1);
    assert_eq!(reported[0].kind, fingerly::ProxyErrorKind::Upstream);
    assert!(!reported[0].to_string().contains(PROXY_KEY));
}

#[tokio::test]
async fn a_trickling_answer_cannot_stretch_the_deadline() {
    let reported = fingerly_hook::Hook::default();
    let upstream = raw_upstream(
        b"HTTP/1.1 200 OK\r\ncontent-length: 40\r\n\r\n0123456789012345678901234567890123456789",
        Duration::from_secs(5),
        true,
    )
    .await;
    let started = std::time::Instant::now();
    let response = proxy_to(&upstream, Duration::from_millis(300), reported.clone())
        .handle(identify(PATH))
        .await;
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(
        reported.lock().unwrap()[0].kind,
        fingerly::ProxyErrorKind::Timeout
    );
}

#[tokio::test]
async fn refuses_an_answer_over_4_mib() {
    let size = (4 << 20) + 1;
    // Declared up front, and streamed without a length.
    let declared = TestServer::always(Canned::bytes(200, vec![b'a'; size])).await;
    let mut chunked =
        format!("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n{size:x}\r\n").into_bytes();
    chunked.extend(vec![b'a'; size]);
    chunked.extend_from_slice(b"\r\n0\r\n\r\n");
    let streamed = raw_upstream(
        Box::leak(chunked.into_boxed_slice()),
        Duration::from_millis(0),
        false,
    )
    .await;

    for upstream in [declared.base_url.clone(), streamed] {
        let reported = fingerly_hook::Hook::default();
        let response = proxy_to(&upstream, Duration::from_secs(5), reported.clone())
            .handle(identify(PATH))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{upstream}");
        assert_eq!(
            reported.lock().unwrap()[0].kind,
            fingerly::ProxyErrorKind::ResponseTooLarge,
            "{upstream}"
        );
    }
}

/// Dropping the service future, which is what a server does when the visitor
/// disconnects, cancels the upstream call and reports nothing.
#[tokio::test]
async fn a_visitor_who_disconnects_cancels_the_upstream_call_quietly() {
    let reported = fingerly_hook::Hook::default();
    let server = TestServer::always(identified().delay(Duration::from_secs(30))).await;
    let proxy = proxy_to(&server.base_url, Duration::from_secs(10), reported.clone());
    let pending = tokio::time::timeout(Duration::from_millis(200), proxy.handle(identify(PATH)));
    assert!(
        pending.await.is_err(),
        "the call should still have been waiting"
    );
    assert!(reported.lock().unwrap().is_empty());
}
