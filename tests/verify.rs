//! Consuming an event, and verifying one for a backend decision.

mod common;

use common::{not_found_body, pending_body, Canned, TestServer, SECRET_KEY};
use fingerly::{Error, Fingerly, VerifyOptions, VerifyReason, DEFAULT_MAX_AGE_SECONDS};

fn client(server: &TestServer) -> Fingerly {
    Fingerly::builder(SECRET_KEY)
        .endpoint(&server.base_url)
        .allow_insecure_loopback(true)
        .build()
        .unwrap()
}

/// RFC 3339 for `seconds` ago; negative is the future.
fn ago(seconds: i64) -> String {
    (time::OffsetDateTime::now_utc() - time::Duration::seconds(seconds))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

/// An event body whose checked fields the test chooses. `None` leaves the
/// field out.
fn event(
    occurred_at: Option<&str>,
    tag: Option<&str>,
    visitor_id: Option<&str>,
    score: Option<i32>,
) -> Canned {
    let mut body = serde_json::json!({
        "request_id": "req_1",
        "state": "enriched",
        "environment": "production",
        "platform": "web",
        "sdk_platform": "web",
        "sdk_version": "1.0.0",
        "triggers": [],
        "has_document": false,
    });
    let object = body.as_object_mut().unwrap();
    if let Some(visitor_id) = visitor_id {
        object.insert("visitor_id".into(), visitor_id.into());
    }
    if let Some(occurred_at) = occurred_at {
        object.insert("occurred_at".into(), occurred_at.into());
    }
    if let Some(tag) = tag {
        object.insert("tag".into(), tag.into());
    }
    if let Some(score) = score {
        object.insert("suspect_score".into(), score.into());
        object.insert("suspect_level".into(), "low".into());
    }
    Canned::json(200, body.to_string())
}

/// An event that passes every check with the tag `checkout`.
fn good_event() -> Canned {
    event(Some(&ago(10)), Some("checkout"), Some("vis_1"), Some(12))
}

fn consumed() -> Canned {
    Canned::json(
        200,
        r#"{"request_id":"req_1","consumed_at":"2026-11-17T10:00:00Z","first":true}"#,
    )
}

const ALREADY_CONSUMED_FLAT: &str =
    r#"{"code":"event_already_consumed","consumed_at":"2026-11-17T10:00:00Z"}"#;
const ALREADY_CONSUMED_ENVELOPE: &str = r#"{"error":{"code":"event_already_consumed","message":"m","status":409,"details":[{"field":"consumed_at","issue":"2026-11-17T10:00:00Z","location":"body"}]},"request_id":"req_trace"}"#;

fn consume_requests(server: &TestServer) -> usize {
    server
        .requests()
        .iter()
        .filter(|r| r.method == "POST" && r.path.ends_with("/consume"))
        .count()
}

#[tokio::test]
async fn consumes_with_one_post_and_the_secret_key() {
    let server = TestServer::always(consumed()).await;
    let result = client(&server).events().consume("req/1").await.unwrap();

    assert_eq!(result.request_id, "req_1");
    assert_eq!(result.consumed_at, "2026-11-17T10:00:00Z");
    assert!(result.first);
    assert_eq!(server.request_count(), 1);
    let request = server.first();
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/v1/events/req%2F1/consume");
    assert_eq!(request.header("x-api-key"), SECRET_KEY);
    assert!(request.body.is_empty());
}

#[tokio::test]
async fn types_already_consumed_in_both_body_shapes() {
    for body in [ALREADY_CONSUMED_FLAT, ALREADY_CONSUMED_ENVELOPE] {
        let server = TestServer::always(Canned::json(409, body)).await;
        let error = client(&server).events().consume("req_1").await.unwrap_err();

        assert!(error.is_event_already_consumed(), "{body}: {error:?}");
        assert_eq!(error.consumed_at(), Some("2026-11-17T10:00:00Z"), "{body}");
        assert_eq!(error.status(), Some(409));
        assert_eq!(error.code(), Some("event_already_consumed"));
        let Error::Api(api) = &error else {
            panic!("{error:?}")
        };
        assert!(api.is_already_consumed());
        assert_eq!(api.consumed_at(), Some("2026-11-17T10:00:00Z"));
        // Retried by nobody: one request, and the body is not echoed.
        assert_eq!(server.request_count(), 1);
        assert!(!error.to_string().contains("2026-11-17"), "{error}");
    }
}

#[tokio::test]
async fn already_consumed_without_a_time_has_none() {
    let server =
        TestServer::always(Canned::json(409, r#"{"code":"event_already_consumed"}"#)).await;
    let error = client(&server).events().consume("req_1").await.unwrap_err();
    assert!(error.is_event_already_consumed());
    assert_eq!(error.consumed_at(), None);
}

#[tokio::test]
async fn consume_of_an_unknown_event_is_the_normal_api_error() {
    let server = TestServer::always(Canned::json(404, not_found_body())).await;
    let error = client(&server).events().consume("req_1").await.unwrap_err();
    assert!(error.is_event_not_found(), "{error:?}");
    assert!(!error.is_event_already_consumed());
    assert_eq!(error.consumed_at(), None);
}

#[tokio::test]
async fn consume_refuses_a_bad_request_id_without_a_request() {
    let server = TestServer::always(consumed()).await;
    for id in ["", ".", ".."] {
        let error = client(&server).events().consume(id).await.unwrap_err();
        assert!(matches!(error, Error::Config { .. }), "{id:?}");
    }
    assert_eq!(server.request_count(), 0);
}

#[tokio::test]
async fn verifies_reads_then_consumes_once() {
    let server = TestServer::start(vec![good_event(), consumed()]).await;
    let verification = client(&server)
        .events()
        .verify("req_1", VerifyOptions::new().tag("checkout"))
        .await
        .unwrap();

    assert!(verification.ok);
    assert_eq!(verification.reason, VerifyReason::Ok);
    assert_eq!(verification.reason_str(), "");
    assert_eq!(verification.event.unwrap().visitor_id, "vis_1");
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, "/api/v1/events/req_1");
    assert_eq!(requests[1].method, "POST");
    assert_eq!(requests[1].path, "/api/v1/events/req_1/consume");
    assert_eq!(requests[1].header("x-api-key"), SECRET_KEY);
}

#[tokio::test]
async fn verifies_without_a_tag_check_when_none_is_given() {
    let server = TestServer::start(vec![
        event(Some(&ago(10)), None, Some("vis_1"), Some(0)),
        consumed(),
    ])
    .await;
    let verification = client(&server)
        .events()
        .verify("req_1", VerifyOptions::default())
        .await
        .unwrap();
    assert!(verification.ok, "{:?}", verification.reason);
    assert_eq!(consume_requests(&server), 1);
}

#[tokio::test]
async fn never_consumes_when_consume_is_off() {
    let server = TestServer::always(good_event()).await;
    let verification = client(&server)
        .events()
        .verify("req_1", VerifyOptions::new().tag("checkout").consume(false))
        .await
        .unwrap();
    assert!(verification.ok);
    assert_eq!(server.request_count(), 1);
    assert_eq!(consume_requests(&server), 0);
}

/// Runs `verify` against one event answer and returns the reason, asserting
/// that nothing was consumed.
async fn refused(answer: Canned, options: VerifyOptions) -> (VerifyReason, bool) {
    let server = TestServer::start(vec![answer, consumed()]).await;
    let verification = client(&server)
        .events()
        .verify("req_1", options)
        .await
        .unwrap();
    assert!(!verification.ok);
    assert_eq!(
        consume_requests(&server),
        0,
        "consumed after a failed check"
    );
    assert_eq!(server.request_count(), 1);
    let reason = verification.reason;
    assert_ne!(
        reason,
        VerifyReason::Ok,
        "a failed verification has a reason"
    );
    assert_eq!(verification.reason_str(), reason.as_str());
    (reason, verification.event.is_some())
}

#[tokio::test]
async fn not_found_has_no_event() {
    let (reason, has_event) = refused(
        Canned::json(404, not_found_body()),
        VerifyOptions::new().tag("checkout"),
    )
    .await;
    assert_eq!(reason, VerifyReason::NotFound);
    assert_eq!(reason.as_str(), "not_found");
    assert!(!has_event);
}

#[tokio::test]
async fn too_old() {
    let (reason, has_event) = refused(
        event(Some(&ago(400)), Some("checkout"), Some("vis_1"), Some(12)),
        VerifyOptions::new().tag("checkout"),
    )
    .await;
    assert_eq!(reason, VerifyReason::TooOld);
    assert_eq!(reason.as_str(), "too_old");
    assert!(has_event);
}

#[tokio::test]
async fn an_unreadable_or_missing_time_is_too_old() {
    for occurred_at in [None, Some("yesterday"), Some("2026-11-17T10:00:00")] {
        let (reason, _) = refused(
            event(occurred_at, Some("checkout"), Some("vis_1"), Some(12)),
            VerifyOptions::new(),
        )
        .await;
        assert_eq!(reason, VerifyReason::TooOld, "{occurred_at:?}");
    }
}

#[tokio::test]
async fn a_time_in_the_future_passes_the_age_check() {
    let server = TestServer::start(vec![
        event(Some(&ago(-3600)), Some("checkout"), Some("vis_1"), Some(12)),
        consumed(),
    ])
    .await;
    let verification = client(&server)
        .events()
        .verify("req_1", VerifyOptions::new())
        .await
        .unwrap();
    assert!(verification.ok, "{:?}", verification.reason);
}

#[tokio::test]
async fn the_default_maximum_age_is_300_seconds() {
    assert_eq!(DEFAULT_MAX_AGE_SECONDS, 300);
    let server = TestServer::start(vec![
        event(Some(&ago(200)), None, Some("vis_1"), Some(12)),
        consumed(),
    ])
    .await;
    let verification = client(&server)
        .events()
        .verify("req_1", VerifyOptions::default())
        .await
        .unwrap();
    assert!(verification.ok, "{:?}", verification.reason);

    let (reason, _) = refused(
        event(Some(&ago(400)), None, Some("vis_1"), Some(12)),
        VerifyOptions::default(),
    )
    .await;
    assert_eq!(reason, VerifyReason::TooOld);
}

#[tokio::test]
async fn honours_a_custom_maximum_age() {
    let (reason, _) = refused(
        event(Some(&ago(100)), None, Some("vis_1"), Some(12)),
        VerifyOptions::new().max_age_seconds(30),
    )
    .await;
    assert_eq!(reason, VerifyReason::TooOld);
}

#[tokio::test]
async fn tag_mismatch() {
    for tag in [Some("signup"), Some("Checkout"), None] {
        let (reason, has_event) = refused(
            event(Some(&ago(10)), tag, Some("vis_1"), Some(12)),
            VerifyOptions::new().tag("checkout"),
        )
        .await;
        assert_eq!(reason, VerifyReason::TagMismatch, "{tag:?}");
        assert_eq!(reason.as_str(), "tag_mismatch");
        assert!(has_event);
    }
}

#[tokio::test]
async fn unidentifiable() {
    for visitor_id in [Some(""), None] {
        let (reason, has_event) = refused(
            event(Some(&ago(10)), Some("checkout"), visitor_id, Some(12)),
            VerifyOptions::new().tag("checkout"),
        )
        .await;
        assert_eq!(reason, VerifyReason::Unidentifiable, "{visitor_id:?}");
        assert_eq!(reason.as_str(), "unidentifiable");
        assert!(has_event);
    }
}

#[tokio::test]
async fn unscored() {
    let (reason, has_event) = refused(
        event(Some(&ago(10)), Some("checkout"), Some("vis_1"), None),
        VerifyOptions::new().tag("checkout"),
    )
    .await;
    assert_eq!(reason, VerifyReason::Unscored);
    assert_eq!(reason.as_str(), "unscored");
    assert!(has_event);
}

#[tokio::test]
async fn stops_at_the_first_failing_check() {
    // Too old, mistagged, unidentifiable and unscored at once.
    let (reason, _) = refused(
        event(Some(&ago(4000)), Some("signup"), None, None),
        VerifyOptions::new().tag("checkout"),
    )
    .await;
    assert_eq!(reason, VerifyReason::TooOld);
    // Mistagged, unidentifiable and unscored.
    let (reason, _) = refused(
        event(Some(&ago(10)), Some("signup"), None, None),
        VerifyOptions::new().tag("checkout"),
    )
    .await;
    assert_eq!(reason, VerifyReason::TagMismatch);
    // Unidentifiable and unscored.
    let (reason, _) = refused(
        event(Some(&ago(10)), Some("checkout"), None, None),
        VerifyOptions::new().tag("checkout"),
    )
    .await;
    assert_eq!(reason, VerifyReason::Unidentifiable);
}

#[tokio::test]
async fn already_consumed_keeps_the_event() {
    for body in [ALREADY_CONSUMED_FLAT, ALREADY_CONSUMED_ENVELOPE] {
        let server = TestServer::start(vec![good_event(), Canned::json(409, body)]).await;
        let verification = client(&server)
            .events()
            .verify("req_1", VerifyOptions::new().tag("checkout"))
            .await
            .unwrap();
        assert!(!verification.ok);
        assert_eq!(verification.reason, VerifyReason::AlreadyConsumed);
        assert_eq!(verification.reason_str(), "already_consumed");
        assert!(verification.event.is_some());
        assert_eq!(consume_requests(&server), 1);
    }
}

#[tokio::test]
async fn not_found_on_consume_has_no_event() {
    let server = TestServer::start(vec![good_event(), Canned::json(404, not_found_body())]).await;
    let verification = client(&server)
        .events()
        .verify("req_1", VerifyOptions::new())
        .await
        .unwrap();
    assert_eq!(verification.reason, VerifyReason::NotFound);
    assert!(verification.event.is_none());
}

#[tokio::test]
async fn raises_every_other_read_failure() {
    for (status, body) in [
        (404, pending_body()),
        (
            401,
            r#"{"error":{"code":"unauthorized","message":"m","status":401}}"#.to_owned(),
        ),
        (
            429,
            r#"{"error":{"code":"rate_limited","message":"m","status":429}}"#.to_owned(),
        ),
        (500, "oops".to_owned()),
    ] {
        let server = TestServer::start(vec![Canned::json(status, body), consumed()]).await;
        let error = client(&server)
            .events()
            .verify("req_1", VerifyOptions::new())
            .await
            .unwrap_err();
        assert_eq!(error.status(), Some(status), "{error:?}");
        assert_eq!(server.request_count(), 1);
    }
    let server = TestServer::always(Canned::json(404, pending_body())).await;
    let error = client(&server)
        .events()
        .verify("req_1", VerifyOptions::new())
        .await
        .unwrap_err();
    assert!(error.is_event_pending(), "{error:?}");
}

#[tokio::test]
async fn raises_every_other_consume_failure() {
    let server = TestServer::start(vec![
        good_event(),
        Canned::json(
            503,
            r#"{"error":{"code":"unavailable","message":"m","status":503}}"#,
        ),
    ])
    .await;
    let error = client(&server)
        .events()
        .verify("req_1", VerifyOptions::new())
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(503));
    // Never retried.
    assert_eq!(consume_requests(&server), 1);
}

#[tokio::test]
async fn refuses_invalid_options_before_any_request() {
    let server = TestServer::always(good_event()).await;
    for options in [
        VerifyOptions::new().max_age_seconds(0),
        VerifyOptions::new().tag(""),
    ] {
        let error = client(&server)
            .events()
            .verify("req_1", options)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Config { .. }), "{error:?}");
    }
    for id in ["", ".", ".."] {
        let error = client(&server)
            .events()
            .verify(id, VerifyOptions::new())
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Config { .. }), "{id:?}");
    }
    assert_eq!(server.request_count(), 0);
}
