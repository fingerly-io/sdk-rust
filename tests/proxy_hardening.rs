//! Proxy rules for the channel header, the upstream option, upstream status
//! and redirects, failure reports, and the answers near the proxy path. Every
//! upstream here is a mock on 127.0.0.1; nothing else is contacted.

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::{Canned, TestServer, PROXY_KEY, PUBLIC_KEY};
use fingerly::FingerlyProxy;
use http::{Request, StatusCode};
use http_body_util::Full;

const PATH: &str = "/k7x2qm4a";
const CLIENT_IP: &str = "203.0.113.7";

fn builder(upstream: &str) -> fingerly::FingerlyProxyBuilder {
    FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .path(PATH)
        .upstream(upstream)
        .allow_insecure_loopback(true)
        .client_ip(|_| CLIENT_IP.to_owned())
}

fn strict(upstream: &str) -> fingerly::FingerlyProxyBuilder {
    FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .upstream(upstream)
        .client_ip(|_| CLIENT_IP.to_owned())
}

fn browser(path: &str) -> http::request::Builder {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("x-api-key", PUBLIC_KEY)
        .header("content-type", "application/json")
        .header("origin", "https://shop.example.com")
}

fn body() -> Full<Bytes> {
    Full::new(Bytes::from_static(b"{\"signals\":{}}"))
}

fn ok() -> Canned {
    Canned::json(200, r#"{"request_id":"req_1"}"#)
}

#[tokio::test]
async fn origin_wins_over_the_sdk_platform_header() {
    let server = TestServer::always(ok()).await;
    let proxy = builder(&server.base_url).build().unwrap();
    let request = browser(PATH)
        .header("x-fingerly-sdk-platform", "ios")
        .body(body())
        .unwrap();
    let response = proxy.handle(request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let seen = server.first();
    assert_eq!(seen.header("x-fingerly-origin"), "https://shop.example.com");
    assert!(!seen.headers.contains_key("x-fingerly-sdk-platform"));
}

#[tokio::test]
async fn a_native_request_without_origin_keeps_its_platform() {
    let server = TestServer::always(ok()).await;
    let proxy = builder(&server.base_url).build().unwrap();
    let request = Request::builder()
        .method("POST")
        .uri(PATH)
        .header("x-api-key", PUBLIC_KEY)
        .header("x-fingerly-sdk-platform", "android")
        .body(body())
        .unwrap();
    assert_eq!(proxy.handle(request).await.status(), StatusCode::OK);
    let seen = server.first();
    assert_eq!(seen.header("x-fingerly-sdk-platform"), "android");
    assert!(!seen.headers.contains_key("x-fingerly-origin"));
}

#[test]
fn a_plain_http_upstream_is_refused_without_the_loopback_flag() {
    for upstream in [
        "http://upstream.invalid",
        "http://192.0.2.10:8080",
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "http://[::1]:8080",
    ] {
        assert!(
            strict(upstream).build().is_err(),
            "{upstream:?} was accepted without allow_insecure_loopback"
        );
    }
}

#[test]
fn the_loopback_flag_admits_loopback_hosts_only() {
    for upstream in [
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "http://[::1]:8080",
    ] {
        assert!(
            builder(upstream).build().is_ok(),
            "{upstream:?} was refused"
        );
    }
    for upstream in [
        "http://upstream.invalid",
        "http://192.0.2.10:8080",
        "http://127.0.0.2",
        "http://localhost.invalid",
    ] {
        assert!(
            builder(upstream).build().is_err(),
            "{upstream:?} was accepted"
        );
    }
    assert!(strict("https://upstream.invalid").build().is_ok());
    assert!(strict("https://upstream.invalid:8443/").build().is_ok());
}

/// A raw upstream that answers every connection with `answer`.
async fn raw_upstream(answer: &'static [u8]) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 8192];
                let _ = socket.read(&mut buffer).await;
                let _ = socket.write_all(answer).await;
                tokio::time::sleep(Duration::from_millis(300)).await;
            });
        }
    });
    format!("http://{address}")
}

#[tokio::test]
async fn an_upstream_status_outside_200_to_599_is_a_502() {
    for (answer, label) in [
        (
            &b"HTTP/1.1 600 Odd\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}"[..],
            "600",
        ),
        (
            &b"HTTP/1.1 700 Odd\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}"[..],
            "700",
        ),
        (
            &b"HTTP/1.1 999 Odd\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}"[..],
            "999",
        ),
        (
            &b"HTTP/1.1 099 Odd\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}"[..],
            "099",
        ),
    ] {
        let upstream = raw_upstream(answer).await;
        let proxy = builder(&upstream).on_error(|_| {}).build().unwrap();
        let response = proxy.handle(browser(PATH).body(body()).unwrap()).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "an upstream {label} was relayed as {}",
            response.status()
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
}

#[tokio::test]
async fn an_upstream_redirect_is_a_502_and_never_followed_by_a_supplied_stack() {
    let target = TestServer::always(ok()).await;
    for status in [301u16, 302, 303, 307, 308] {
        let hop = TestServer::always(
            Canned::json(status, "{}").header("location", &format!("{}/steal", target.base_url)),
        )
        .await;
        let proxy = builder(&hop.base_url)
            .http_client_builder(
                reqwest::Client::builder().redirect(reqwest::redirect::Policy::limited(10)),
            )
            .on_error(|_| {})
            .build()
            .unwrap();
        let response = proxy.handle(browser(PATH).body(body()).unwrap()).await;
        assert_eq!(hop.request_count(), 1);
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{status}");
        assert!(response.headers().get("location").is_none());
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    assert_eq!(target.request_count(), 0, "the redirect was followed");
}

#[tokio::test]
async fn only_an_exact_uppercase_post_is_forwarded() {
    let server = TestServer::always(ok()).await;
    let proxy = builder(&server.base_url).build().unwrap();
    for method in ["post", "Post", "GET", "PUT", "OPTIONS"] {
        let response = proxy
            .handle(browser(PATH).method(method).body(body()).unwrap())
            .await;
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method}"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["allow"], "POST");
    }
    assert_eq!(server.request_count(), 0);
}

#[tokio::test]
async fn mounted_as_route_and_fallback_every_near_miss_is_the_proxys_own_404() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let upstream = TestServer::always(ok()).await;
    let service = builder(&upstream.base_url).build().unwrap();
    let app = axum::Router::new()
        .route_service(PATH, service.clone())
        .fallback_service(service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let send = |raw: String| async move {
        let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
        socket.write_all(raw.as_bytes()).await.unwrap();
        let mut answer = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(3), socket.read_to_end(&mut answer)).await;
        String::from_utf8_lossy(&answer).into_owned()
    };

    for path in [
        format!("{PATH}/"),
        format!("/{PATH}"),
        format!("{PATH}x"),
        format!("{PATH}/.."),
        "/k7x2qm4%61".to_owned(),
        "/x/../k7x2qm4a".to_owned(),
    ] {
        let answer = send(format!(
            "POST {path} HTTP/1.1\r\nHost: h\r\nOrigin: https://shop.example.com\r\n\
             X-Api-Key: {PUBLIC_KEY}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ))
        .await;
        assert!(answer.starts_with("HTTP/1.1 404"), "{path}: {answer}");
        assert!(
            answer
                .to_ascii_lowercase()
                .contains("cache-control: no-store"),
            "{path}: {answer}"
        );
    }
    let answer = send(format!(
        "GET {PATH} HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n"
    ))
    .await;
    assert!(answer.starts_with("HTTP/1.1 405"), "{answer}");
    assert!(answer
        .to_ascii_lowercase()
        .contains("cache-control: no-store"));
    assert_eq!(upstream.request_count(), 0);
}
