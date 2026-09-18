//! Event reads and the list filters.

mod common;

use std::time::Duration;

use common::{event_body, not_found_body, Canned, TestServer, SECRET_KEY};
use fingerly::{Error, EventListParams, Fingerly, SuspectLevel};

fn client(server: &TestServer) -> Fingerly {
    Fingerly::builder(SECRET_KEY)
        .endpoint(&server.base_url)
        .build()
        .unwrap()
}

#[tokio::test]
async fn reads_one_event() {
    let server = TestServer::always(Canned::json(200, event_body("req_1"))).await;
    let event = client(&server).events().get("req_1").await.unwrap();

    assert_eq!(event.request_id, "req_1");
    assert_eq!(event.visitor_id, "vis_1");
    assert_eq!(event.score(), Some(12));
    assert!(event.is_scored());
    assert_eq!(event.suspect_level.as_deref(), Some("low"));
}

/// A request id is part of a URL path, so it is escaped rather than trusted to
/// contain no separator of its own.
#[tokio::test]
async fn escapes_the_request_id_in_the_path() {
    let server = TestServer::always(Canned::json(200, event_body("req/../secret"))).await;
    client(&server)
        .events()
        .get("req/../secret?x=1")
        .await
        .unwrap();

    let request = server.first();
    assert_eq!(request.path, "/api/v1/events/req%2F..%2Fsecret%3Fx%3D1");
    assert_eq!(request.query, "");
}

/// `None` means unscored and must never be read as zero.
#[tokio::test]
async fn an_unscored_event_is_not_a_zero() {
    let server = TestServer::always(Canned::json(
        200,
        r#"{"request_id":"req_1","visitor_id":"vis_1","occurred_at":"2026-09-18T08:00:00Z",
            "state":"unavailable","environment":"production","platform":"web","sdk_platform":"web",
            "sdk_version":"1.0.0","ip_address":"203.0.113.7","suspect_score":null,
            "triggers":[],"has_document":false}"#,
    ))
    .await;

    let event = client(&server).events().get("req_1").await.unwrap();
    assert_eq!(event.score(), None);
    assert!(!event.is_scored());
    assert_eq!(event.suspect_level, None);
}

/// A field the API adds after this build shipped is still reachable.
#[tokio::test]
async fn keeps_the_response_body_as_it_arrived() {
    let server = TestServer::always(Canned::json(
        200,
        r#"{"request_id":"req_1","visitor_id":"vis_1","occurred_at":"2026-09-18T08:00:00Z",
            "state":"enriched","environment":"production","platform":"web","sdk_platform":"web",
            "sdk_version":"1.0.0","ip_address":"203.0.113.7","suspect_score":3,
            "triggers":[],"has_document":false,"invented_later":"still here"}"#,
    ))
    .await;

    let event = client(&server).events().get("req_1").await.unwrap();
    assert_eq!(event.raw["invented_later"], "still here");
}

#[tokio::test]
async fn sends_no_query_when_nothing_is_filtered() {
    let server =
        TestServer::always(Canned::json(200, r#"{"rows":[],"page":1,"page_size":50}"#)).await;

    let page = client(&server)
        .events()
        .list(EventListParams::new())
        .await
        .unwrap();

    assert_eq!(server.first().path, "/api/v1/events");
    assert_eq!(server.first().query, "");
    assert_eq!(page.page, 1);
    assert_eq!(page.page_size, 50);
    assert!(page.rows.is_empty());
}

#[tokio::test]
async fn sends_only_the_filters_that_were_set() {
    let server = TestServer::always(Canned::json(
        200,
        format!(
            r#"{{"rows":[{}],"page":2,"page_size":25}}"#,
            event_body("req_1")
        ),
    ))
    .await;

    let page = client(&server)
        .events()
        .list(
            EventListParams::new()
                .from("2026-09-17T00:00:00Z")
                .to("2026-09-18T00:00:00Z")
                .page(2)
                .limit(25)
                .visitor("vis_1")
                .level(SuspectLevel::High),
        )
        .await
        .unwrap();

    let query = server.first().query;
    for expected in [
        "from=2026-09-17T00%3A00%3A00Z",
        "to=2026-09-18T00%3A00%3A00Z",
        "page=2",
        "limit=25",
        "visitor=vis_1",
        "level=high",
    ] {
        assert!(query.contains(expected), "{query} is missing {expected}");
    }
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].request_id, "req_1");
}

#[tokio::test]
async fn refuses_a_page_or_limit_of_zero() {
    let server =
        TestServer::always(Canned::json(200, r#"{"rows":[],"page":1,"page_size":1}"#)).await;
    let fingerly = client(&server);

    for params in [
        EventListParams::new().page(0),
        EventListParams::new().limit(0),
    ] {
        let error = fingerly.events().list(params).await.unwrap_err();
        assert!(matches!(error, Error::Config { .. }), "got {error:?}");
    }
    assert_eq!(server.request_count(), 0, "an invalid filter was sent");
}

/// An event is readable as soon as identification answers, so a missing one is
/// a request id that was never issued. There is nothing to wait for, and one
/// call makes exactly one request.
#[tokio::test]
async fn reports_a_missing_event_rather_than_waiting_for_one() {
    let server = TestServer::always(Canned::json(404, not_found_body())).await;

    let error = client(&server).events().get("req_1").await.unwrap_err();

    assert!(error.is_event_not_found(), "got {error:?}");
    assert_eq!(server.request_count(), 1, "the read was retried");
}

/// Every other failure is one request too, whatever it is.
#[tokio::test]
async fn never_retries_whatever_comes_back() {
    for status in [400, 401, 403, 429, 500] {
        let server = TestServer::always(Canned::json(
            status,
            r#"{"error":{"code":"other","message":"no","status":0}}"#,
        ))
        .await;

        let error = client(&server).events().get("req_1").await.unwrap_err();
        assert_eq!(error.status(), Some(status));
        assert_eq!(server.request_count(), 1, "HTTP {status} was retried");
    }
}

/// A caller cancels by dropping the future; nothing else is needed.
#[tokio::test]
async fn dropping_the_future_stops_the_read() {
    let server =
        TestServer::always(Canned::json(200, event_body("req_1")).delay(Duration::from_secs(30)))
            .await;
    let fingerly = client(&server);

    {
        let reading = fingerly.events().get("req_1");
        tokio::select! {
            _ = reading => panic!("the read should not have finished"),
            _ = tokio::time::sleep(Duration::from_millis(40)) => {}
        }
    }

    let seen = server.request_count();
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        server.request_count(),
        seen,
        "work continued after the drop"
    );
}

#[cfg(feature = "time")]
#[tokio::test]
async fn renders_a_window_from_typed_timestamps() {
    use time::macros::datetime;

    let server =
        TestServer::always(Canned::json(200, r#"{"rows":[],"page":1,"page_size":1}"#)).await;
    client(&server)
        .events()
        .list(
            EventListParams::new()
                .from_time(datetime!(2026-09-17 00:00:00 UTC))
                .unwrap()
                .to_time(datetime!(2026-09-18 00:00:00 UTC))
                .unwrap(),
        )
        .await
        .unwrap();

    let query = server.first().query;
    assert!(query.contains("from=2026-09-17T00%3A00%3A00Z"), "{query}");
    assert!(query.contains("to=2026-09-18T00%3A00%3A00Z"), "{query}");
}

#[cfg(feature = "time")]
#[tokio::test]
async fn parses_the_event_timestamp_on_request() {
    use time::macros::datetime;

    let server = TestServer::always(Canned::json(200, event_body("req_1"))).await;
    let event = client(&server).events().get("req_1").await.unwrap();

    assert_eq!(
        event.occurred_at_time().unwrap(),
        datetime!(2026-09-18 08:00:00 UTC)
    );
}
