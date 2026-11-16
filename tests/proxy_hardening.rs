//! Proxy rules for the channel header, the upstream option, upstream status
//! and redirects, failure reports, and the answers near the proxy path. Every
//! upstream here is a mock on 127.0.0.1; nothing else is contacted.

mod common;

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
