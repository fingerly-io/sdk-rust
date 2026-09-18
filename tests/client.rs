//! Construction, credentials and the shape of a single request.

mod common;

use std::time::Duration;

use common::{event_body, Canned, TestServer, PUBLIC_KEY, SECRET_KEY};
use fingerly::{Error, Fingerly, Operation};

/// Builds a client pointed at a test server.
fn client(server: &TestServer) -> Fingerly {
    Fingerly::builder(SECRET_KEY)
        .endpoint(&server.base_url)
        .build()
        .expect("the test key and endpoint are valid")
}

#[test]
fn refuses_every_key_that_is_not_a_secret_key() {
    for key in [
        PUBLIC_KEY,
        "fly_px_us_production_proxy",
        "fly_mk_us_production_management",
        "fly_sk_ap_production_wrongregion",
        "fly_sk_us_testing_wrongenvironment",
        "fly_sk_us_production_",
        "fly_sk_us_production_has spaces",
        "fly_sk_us_production_has\nnewline",
        "sk_us_production_missingprefix",
        "",
    ] {
        let error = Fingerly::new(key).expect_err("this key should be refused");
        assert!(
            matches!(error, Error::Config { .. }),
            "{key:?} produced {error:?}"
        );
    }
}

#[test]
fn accepts_a_secret_key_for_either_region() {
    for key in [
        "fly_sk_us_production_abc",
        "fly_sk_eu_staging_abc-DEF_123",
        "fly_sk_eu_development_abc",
    ] {
        assert!(Fingerly::new(key).is_ok(), "{key} should be accepted");
    }
}

/// The key is validated even when an endpoint is given, so a public key can
/// never reach an API that would accept it.
#[test]
fn validates_the_key_even_with_an_endpoint() {
    let error = Fingerly::builder(PUBLIC_KEY)
        .endpoint("http://127.0.0.1:1")
        .build()
        .expect_err("a public key is not a secret key");
    assert!(matches!(error, Error::Config { .. }));
}

#[test]
fn refuses_an_endpoint_that_would_leak_or_rewrite_the_request() {
    for endpoint in [
        "https://user:pass@api.example.com",
        "https://api.example.com?token=x",
        "https://api.example.com#fragment",
        "ftp://api.example.com",
        "not a url",
        "",
    ] {
        let error = Fingerly::builder(SECRET_KEY)
            .endpoint(endpoint)
            .build()
            .expect_err("this endpoint should be refused");
        assert!(
            matches!(error, Error::Config { .. }),
            "{endpoint:?} produced {error:?}"
        );
    }
}

#[test]
fn refuses_an_api_version_that_is_not_one() {
    for version in ["", "1", "v0", "v01", "v1beta", "v1\n", " v1"] {
        assert!(
            Fingerly::builder(SECRET_KEY)
                .api_version(version)
                .build()
                .is_err(),
            "{version:?} should be refused"
        );
    }
    assert!(Fingerly::builder(SECRET_KEY)
        .api_version("v2")
        .build()
        .is_ok());
}

#[test]
fn refuses_a_deadline_that_has_already_passed() {
    let error = Fingerly::builder(SECRET_KEY)
        .timeout(Duration::ZERO)
        .build()
        .expect_err("zero is not a deadline");
    assert!(matches!(error, Error::Config { .. }));
}

#[tokio::test]
async fn sends_the_key_and_identifies_the_sdk() {
    let server = TestServer::always(Canned::json(200, event_body("req_1"))).await;
    client(&server).events().get("req_1").await.unwrap();

    let request = server.first();
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/api/v1/events/req_1");
    assert_eq!(request.header("x-api-key"), SECRET_KEY);
    assert_eq!(request.header("accept"), "application/json");
    assert!(
        request.header("user-agent").starts_with("fingerly-rust/"),
        "user agent was {:?}",
        request.header("user-agent")
    );
}

#[tokio::test]
async fn honours_a_custom_api_version() {
    let server = TestServer::always(Canned::json(200, event_body("req_1"))).await;
    Fingerly::builder(SECRET_KEY)
        .endpoint(&server.base_url)
        .api_version("v2")
        .build()
        .unwrap()
        .events()
        .get("req_1")
        .await
        .unwrap();

    assert_eq!(server.first().path, "/api/v2/events/req_1");
}

/// A redirect would replay the key to another host, so it is surfaced as the
/// status it is rather than followed.
#[tokio::test]
async fn never_follows_a_redirect() {
    let server = TestServer::always(
        Canned::json(302, "").header("location", "https://attacker.example.com/api/v1/events"),
    )
    .await;

    let error = client(&server).events().get("req_1").await.unwrap_err();
    assert_eq!(error.status(), Some(302));
    assert_eq!(server.request_count(), 1, "the redirect was followed");
}

#[tokio::test]
async fn maps_an_error_envelope_without_echoing_the_body() {
    let server = TestServer::always(Canned::json(
        422,
        r#"{"error":{"code":"invalid_request","message":"secret sauce","status":422,
             "details":[{"field":"limit"}]},"request_id":"req_trace"}"#,
    ))
    .await;

    let error = client(&server).events().get("req_1").await.unwrap_err();
    let Error::Api(api) = &error else {
        panic!("expected an API error, got {error:?}");
    };
    assert_eq!(api.status, 422);
    assert_eq!(api.code.as_deref(), Some("invalid_request"));
    assert_eq!(api.request_id.as_deref(), Some("req_trace"));
    assert_eq!(
        api.details.as_ref().unwrap()[0]["field"],
        serde_json::json!("limit")
    );
    assert!(
        !error.to_string().contains("secret sauce"),
        "the response body reached the error message"
    );
}

/// An error body the SDK cannot parse still reports its status, and its
/// contents are dropped rather than surfaced.
#[tokio::test]
async fn reports_the_status_of_an_unparsable_error_body() {
    let server = TestServer::always(Canned::json(503, "<html>upstream down</html>")).await;

    let error = client(&server).events().get("req_1").await.unwrap_err();
    assert_eq!(error.status(), Some(503));
    assert_eq!(error.code(), None);
    assert!(!error.to_string().contains("upstream"));
}

/// Anything an error carries to a log is scrubbed of the key, including a code
/// or trace id the API echoed it into.
#[tokio::test]
async fn redacts_the_secret_key_from_error_metadata() {
    let server = TestServer::always(Canned::json(
        400,
        format!(
            r#"{{"error":{{"code":"bad_key_{SECRET_KEY}","message":"x","status":400,
                 "details":{{"seen":"{SECRET_KEY}"}}}},"request_id":"{SECRET_KEY}"}}"#
        ),
    ))
    .await;

    let error = client(&server).events().get("req_1").await.unwrap_err();
    let Error::Api(api) = &error else {
        panic!("expected an API error");
    };
    assert_eq!(api.code.as_deref(), Some("bad_key_[redacted]"));
    assert_eq!(api.request_id.as_deref(), Some("[redacted]"));
    assert_eq!(api.details.as_ref().unwrap()["seen"], "[redacted]");
}

/// The deadline covers reading the body, so a server that answers and then
/// stalls times out like one that never answered.
#[tokio::test]
async fn times_out_a_response_that_never_finishes() {
    let server =
        TestServer::always(Canned::json(200, event_body("req_1")).delay(Duration::from_secs(30)))
            .await;

    let error = Fingerly::builder(SECRET_KEY)
        .endpoint(&server.base_url)
        .timeout(Duration::from_millis(100))
        .build()
        .unwrap()
        .events()
        .get("req_1")
        .await
        .unwrap_err();

    assert!(error.is_timeout(), "got {error:?}");
    assert!(matches!(
        error,
        Error::Timeout {
            operation: Operation::Request
        }
    ));
}

/// An unreachable API is a connection failure, not a malformed response.
#[tokio::test]
async fn reports_an_unreachable_api_as_a_connection_failure() {
    let error = Fingerly::builder(SECRET_KEY)
        // Port 1 is reserved and nothing listens on it.
        .endpoint("http://127.0.0.1:1")
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap()
        .events()
        .get("req_1")
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Connection { .. }), "got {error:?}");
}

#[tokio::test]
async fn reports_a_body_that_is_not_an_event() {
    let server = TestServer::always(Canned::json(200, r#"{"unexpected":true}"#)).await;
    let error = client(&server).events().get("req_1").await.unwrap_err();
    assert!(matches!(error, Error::Decode { .. }), "got {error:?}");
}

#[test]
fn a_client_is_cheap_to_clone_and_debug_safe() {
    let fingerly = Fingerly::new(SECRET_KEY).unwrap();
    let copy = fingerly.clone();
    assert!(!format!("{copy:?}").contains(SECRET_KEY));
}
