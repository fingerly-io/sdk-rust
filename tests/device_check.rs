//! Reading and writing the DeviceCheck bits of an event.

mod common;

use std::time::Duration;

use common::{Canned, TestServer, SECRET_KEY};
use fingerly::{DeviceCheckWrite, Error, Fingerly};

fn client(server: &TestServer) -> Fingerly {
    Fingerly::builder(SECRET_KEY)
        .endpoint(&server.base_url)
        .allow_insecure_loopback(true)
        .build()
        .unwrap()
}

fn error_body(status: u16, code: &str) -> String {
    format!(
        r#"{{"error":{{"code":"{code}","message":"m","status":{status}}},"request_id":"req_trace"}}"#
    )
}

#[tokio::test]
async fn queries_the_bits_with_the_secret_key_and_no_body() {
    let server = TestServer::always(Canned::json(
        200,
        r#"{"found":true,"bit0":true,"bit1":false,"last_update":"2026-10"}"#,
    ))
    .await;
    let bits = client(&server).device_check().query("req/1").await.unwrap();

    assert!(bits.found && bits.bit0 && !bits.bit1);
    assert_eq!(bits.last_update.as_deref(), Some("2026-10"));
    let request = server.first();
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/v1/events/req%2F1/device-check/query");
    assert_eq!(request.header("x-api-key"), SECRET_KEY);
    assert!(request.body.is_empty());
}

#[tokio::test]
async fn reads_a_device_apple_holds_nothing_for() {
    let server = TestServer::always(Canned::json(
        200,
        r#"{"found":false,"bit0":false,"bit1":false}"#,
    ))
    .await;
    let bits = client(&server).device_check().query("req_1").await.unwrap();
    assert!(!bits.found && !bits.bit0 && !bits.bit1);
    assert_eq!(bits.last_update, None);
}

#[tokio::test]
async fn writes_only_the_bits_it_names() {
    let server = TestServer::always(Canned::json(200, r#"{"bit0":true}"#)).await;
    let result = client(&server)
        .device_check()
        .write("req_1", DeviceCheckWrite::new().bit0(true))
        .await
        .unwrap();

    assert_eq!(result.bit0, Some(true));
    assert_eq!(result.bit1, None);
    let request = server.first();
    assert_eq!(request.method, "PUT");
    assert_eq!(request.path, "/api/v1/events/req_1/device-check");
    assert_eq!(request.header("content-type"), "application/json");
    assert_eq!(request.header("x-api-key"), SECRET_KEY);
    assert_eq!(&request.body[..], br#"{"bit0":true}"#);
}

#[tokio::test]
async fn refuses_a_write_that_names_no_bit_without_sending_it() {
    let server = TestServer::always(Canned::json(200, "{}")).await;
    let error = client(&server)
        .device_check()
        .write("req_1", DeviceCheckWrite::new())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Config { .. }), "{error:?}");
    for id in ["", ".", ".."] {
        let error = client(&server).device_check().query(id).await.unwrap_err();
        assert!(matches!(error, Error::Config { .. }), "{id:?}");
    }
    assert_eq!(server.request_count(), 0);
}

#[tokio::test]
async fn types_every_error_code() {
    type Case = (u16, &'static str, fn(&Error) -> bool);
    let cases: [Case; 7] = [
        (
            404,
            "device_check_not_held",
            Error::is_device_check_not_held,
        ),
        (409, "device_check_spent", Error::is_device_check_spent),
        (409, "device_check_busy", Error::is_device_check_busy),
        (
            409,
            "credential_unavailable",
            Error::is_credential_unavailable,
        ),
        (422, "bits_required", Error::is_bits_required),
        (422, "apple_rejected", Error::is_apple_rejected),
        (
            503,
            "device_check_unavailable",
            Error::is_device_check_unavailable,
        ),
    ];
    for (status, code, check) in cases {
        let server = TestServer::always(Canned::json(status, error_body(status, code))).await;
        let error = client(&server)
            .device_check()
            .write("req_1", DeviceCheckWrite::new().bit1(false))
            .await
            .unwrap_err();
        assert!(check(&error), "{code}: {error:?}");
        assert_eq!(error.status(), Some(status));
        assert_eq!(error.code(), Some(code));
        assert_eq!(error.apple_status(), None, "{code}");
        for (_, other, other_check) in cases {
            if other != code {
                assert!(!other_check(&error), "{code} read as {other}");
            }
        }
    }
}

#[tokio::test]
async fn reads_apples_status_from_an_apple_rejection() {
    let server = TestServer::always(Canned::json(
        422,
        r#"{"error":{"code":"apple_rejected","message":"Apple rejected the request (HTTP 400)","status":422,
            "details":[{"field":"apple_status","location":"upstream","issue":"400"}]}}"#,
    ))
    .await;
    let error = client(&server)
        .device_check()
        .query("req_1")
        .await
        .unwrap_err();
    assert!(error.is_apple_rejected());
    assert_eq!(error.apple_status(), Some(400));
    assert_eq!(server.request_count(), 1);
}

/// A 503 leaves the token held, and the API accepts a retry only when it
/// repeats the first request, so the retry is byte for byte the same.
#[tokio::test]
async fn retries_a_503_with_the_identical_request() {
    let server = TestServer::start(vec![
        Canned::json(503, error_body(503, "device_check_unavailable")),
        Canned::json(503, error_body(503, "device_check_unavailable")).header("retry-after", "0"),
        Canned::json(200, r#"{"bit0":false,"bit1":true}"#),
    ])
    .await;
    let result = client(&server)
        .device_check()
        .write("req_1", DeviceCheckWrite::new().bit0(false).bit1(true))
        .await
        .unwrap();
    assert_eq!((result.bit0, result.bit1), (Some(false), Some(true)));

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    for request in &requests {
        assert_eq!(request.method, "PUT");
        assert_eq!(request.path, "/api/v1/events/req_1/device-check");
        assert_eq!(request.body, requests[0].body);
    }
    assert_eq!(&requests[0].body[..], br#"{"bit0":false,"bit1":true}"#);
}

#[tokio::test]
async fn gives_up_after_two_retries() {
    let server = TestServer::always(Canned::json(
        503,
        error_body(503, "device_check_unavailable"),
    ))
    .await;
    let error = client(&server)
        .device_check()
        .query("req_1")
        .await
        .unwrap_err();
    assert!(error.is_device_check_unavailable());
    assert_eq!(server.request_count(), 3);
    assert!(server.requests().iter().all(|r| r.method == "POST"));
}

/// A lost answer is no answer: the token may still be held, so it is retried
/// like a 503.
#[tokio::test]
async fn retries_a_timeout() {
    let server = TestServer::start(vec![
        Canned::json(200, r#"{"found":true,"bit0":true,"bit1":true}"#)
            .delay(Duration::from_millis(500)),
        Canned::json(200, r#"{"found":true,"bit0":true,"bit1":true}"#),
    ])
    .await;
    let fingerly = Fingerly::builder(SECRET_KEY)
        .endpoint(&server.base_url)
        .allow_insecure_loopback(true)
        .timeout(Duration::from_millis(100))
        .build()
        .unwrap();
    let bits = fingerly.device_check().query("req_1").await.unwrap();
    assert!(bits.bit1);
    assert_eq!(server.request_count(), 2);
}

#[tokio::test]
async fn retries_a_connection_failure() {
    // Nothing listens on a port just released.
    let address = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let fingerly = Fingerly::builder(SECRET_KEY)
        .endpoint(format!("http://{address}"))
        .allow_insecure_loopback(true)
        .build()
        .unwrap();
    let started = std::time::Instant::now();
    let error = fingerly.device_check().query("req_1").await.unwrap_err();
    assert!(matches!(error, Error::Connection { .. }), "{error:?}");
    // Two backoffs of 250 ms and 500 ms show the retries happened.
    assert!(started.elapsed() >= Duration::from_millis(700));
}

/// Only an answer that keeps the token held is retried. Everything else is
/// a definite answer, or one a retry cannot change.
#[tokio::test]
async fn does_not_retry_any_other_failure() {
    for (status, code) in [
        (409, "device_check_spent"),
        (409, "device_check_busy"),
        (409, "credential_unavailable"),
        (422, "apple_rejected"),
        (429, "rate_limited"),
        (500, "internal_error"),
        (404, "device_check_not_held"),
    ] {
        let server = TestServer::always(Canned::json(status, error_body(status, code))).await;
        let error = client(&server)
            .device_check()
            .write("req_1", DeviceCheckWrite::new().bit0(true))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(code));
        assert_eq!(server.request_count(), 1, "{code} was retried");
    }
}
