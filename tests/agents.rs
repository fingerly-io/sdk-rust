//! The low-level agent sightings call: what it sends and how refusals map.

mod common;

use common::{Canned, TestServer, SECRET_KEY};
use fingerly::{AgentSighting, Error, Fingerly, VisitorKind};

fn client(server: &TestServer) -> Fingerly {
    Fingerly::builder(SECRET_KEY)
        .endpoint(&server.base_url)
        .allow_insecure_loopback(true)
        .build()
        .unwrap()
}

#[tokio::test]
async fn posts_the_items_under_the_secret_key() {
    let server = TestServer::always(Canned::json(
        200,
        r#"{"rules_version":"r1","items":[{"ttl":900,"visitor_kind":"ai_bot","agent":"GPTBot"},
            {"ttl":0,"visitor_kind":"human"}]}"#,
    ))
    .await;
    let items = [
        AgentSighting::new("GPTBot/1.4", "20.171.206.9")
            .host("shop.example")
            .method("GET")
            .count(3),
        AgentSighting::new("", "2001:db8::1")
            .signature("sig1=:abc:")
            .signature_input("sig1=()")
            .signature_agent("\"https://chatgpt.com\""),
    ];
    let answers = client(&server).agents().sightings(&items).await.unwrap();
    assert_eq!(answers.rules_version, "r1");
    assert_eq!(answers.items[0].visitor_kind, VisitorKind::AiBot);
    assert_eq!(answers.items[0].ttl, 900);
    assert_eq!(answers.items[1].ttl, 0);

    let recorded = server.first();
    assert_eq!(recorded.method, "POST");
    assert_eq!(recorded.path, "/api/v1/agents/sightings");
    assert_eq!(recorded.header("x-api-key"), SECRET_KEY);
    assert_eq!(recorded.header("content-type"), "application/json");
    let body: serde_json::Value = serde_json::from_slice(&recorded.body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"items": [
            {"user_agent": "GPTBot/1.4", "client_ip": "20.171.206.9", "host": "shop.example",
             "method": "GET", "count": 3},
            {"user_agent": "", "client_ip": "2001:db8::1", "signature": "sig1=:abc:",
             "signature_input": "sig1=()", "signature_agent": "\"https://chatgpt.com\""},
        ]})
    );
}

#[tokio::test]
async fn a_429_carries_retry_after_and_its_scope() {
    let server = TestServer::always(
        Canned::json(
            429,
            r#"{"error":{"code":"rate_limited","message":"slow down","status":429}}"#,
        )
        .header("retry-after", "120")
        .header("fingerly-ratelimit-scope", "daily"),
    )
    .await;
    let error = client(&server)
        .agents()
        .sightings(&[AgentSighting::new("curl/8.7.1", "198.51.100.1")])
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(429));
    assert_eq!(error.code(), Some("rate_limited"));
    assert_eq!(error.retry_after(), Some(120));
    assert_eq!(error.rate_limit_scope(), Some("daily"));
}

#[tokio::test]
async fn refusals_are_api_errors() {
    for (status, code) in [
        (401, "unauthorized"),
        (403, "forbidden"),
        (422, "invalid_request"),
        (503, "unavailable"),
    ] {
        let server = TestServer::always(Canned::json(
            status,
            format!(r#"{{"error":{{"code":"{code}","message":"no","status":{status}}}}}"#),
        ))
        .await;
        let error = client(&server)
            .agents()
            .sightings(&[AgentSighting::new("curl/8.7.1", "198.51.100.1")])
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::Api(api) if api.status == status),
            "{error}"
        );
        assert_eq!(error.code(), Some(code));
        assert_eq!(error.rate_limit_scope(), None);
    }
}
