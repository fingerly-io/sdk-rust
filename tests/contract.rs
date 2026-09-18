//! The SDK against the server's own contract fixtures.
//!
//! The vendored snapshot in `contract/` makes these tests independent of
//! sibling repositories. Refresh it with:
//!
//! ```sh
//! cargo run --example sync_contract
//! ```

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{Canned, TestServer, SECRET_KEY};
use fingerly::{Error, EventListParams, Fingerly, WebhookVerifier};
use serde::Deserialize;
use sha2::{Digest, Sha256};

fn contract_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("contract")
}

#[derive(Deserialize)]
struct Fixtures {
    responses: Vec<ResponseFixture>,
    webhooks: Vec<WebhookFixture>,
}

#[derive(Deserialize)]
struct ResponseFixture {
    name: String,
    schema: String,
    status: u16,
    body: serde_json::Value,
}

#[derive(Deserialize)]
struct WebhookFixture {
    name: String,
    secret: String,
    payload: String,
    timestamp: String,
    signature: String,
    valid: bool,
}

fn fixtures() -> Fixtures {
    let raw = std::fs::read(contract_dir().join("fixtures.json")).expect("read fixtures.json");
    serde_json::from_slice(&raw).expect("decode fixtures.json")
}

/// Answers with a fixture body exactly as the server recorded it.
async fn serving(fixture: &ResponseFixture) -> TestServer {
    TestServer::always(Canned::json(fixture.status, fixture.body.to_string())).await
}

fn client(server: &TestServer) -> Fingerly {
    Fingerly::builder(SECRET_KEY)
        .endpoint(&server.base_url)
        .build()
        .unwrap()
}

/// The snapshot must be the one the server recorded, or the tests below prove
/// nothing about the real contract.
#[test]
fn the_snapshot_matches_its_manifest() {
    #[derive(Deserialize)]
    struct Manifest {
        files: std::collections::BTreeMap<String, String>,
    }

    let raw = std::fs::read(contract_dir().join("manifest.json")).expect("read manifest.json");
    let manifest: Manifest = serde_json::from_slice(&raw).expect("decode manifest.json");
    assert!(!manifest.files.is_empty(), "the manifest records no files");

    for (name, expected) in manifest.files {
        let content = std::fs::read(contract_dir().join(&name)).expect("read a recorded file");
        let actual = format!("{:x}", Sha256::digest(&content));
        assert_eq!(
            actual, expected,
            "{name} is stale; run `cargo run --example sync_contract`"
        );
    }
}

#[tokio::test]
async fn reads_every_event_fixture() {
    let fixtures = fixtures();
    let events: Vec<_> = fixtures
        .responses
        .iter()
        .filter(|f| f.schema == "SDKEventOut")
        .collect();
    assert!(!events.is_empty(), "the snapshot records no event fixtures");

    for fixture in events {
        let server = serving(fixture).await;
        let event = client(&server)
            .events()
            .get("req_1")
            .await
            .unwrap_or_else(|error| panic!("{}: {error}", fixture.name));

        assert_eq!(event.request_id, fixture.body["request_id"]);
        assert_eq!(event.visitor_id, fixture.body["visitor_id"]);
        assert!(!event.occurred_at.is_empty(), "{}", fixture.name);

        // A fixture without a score must not decode as zero.
        match fixture.body.get("suspect_score") {
            None | Some(serde_json::Value::Null) => assert_eq!(
                event.score(),
                None,
                "{} decoded an unscored event as a number",
                fixture.name
            ),
            Some(score) => assert_eq!(
                event.score().map(i64::from),
                score.as_i64(),
                "{}",
                fixture.name
            ),
        }
        // The archived submission stays opaque rather than becoming a second
        // public contract.
        assert_eq!(
            event.document.is_some(),
            fixture.body.get("document").is_some_and(|d| !d.is_null()),
            "{}",
            fixture.name
        );
        // Whatever this build did not model is still reachable.
        assert_eq!(event.raw, fixture.body, "{}", fixture.name);
    }
}

#[tokio::test]
async fn reads_every_page_fixture() {
    let fixtures = fixtures();
    let pages: Vec<_> = fixtures
        .responses
        .iter()
        .filter(|f| f.schema == "SDKEventsOut")
        .collect();
    assert!(!pages.is_empty(), "the snapshot records no page fixtures");

    for fixture in pages {
        let server = serving(fixture).await;
        let page = client(&server)
            .events()
            .list(EventListParams::new())
            .await
            .unwrap_or_else(|error| panic!("{}: {error}", fixture.name));

        assert_eq!(page.page, fixture.body["page"].as_i64().unwrap());
        assert_eq!(page.page_size, fixture.body["page_size"].as_i64().unwrap());

        let rows = fixture.body["rows"].as_array().unwrap();
        assert_eq!(page.rows.len(), rows.len(), "{}", fixture.name);
        for (decoded, expected) in page.rows.iter().zip(rows) {
            assert_eq!(decoded.request_id, expected["request_id"]);
        }
    }
}

#[tokio::test]
async fn maps_every_error_fixture() {
    let fixtures = fixtures();
    let errors: Vec<_> = fixtures
        .responses
        .iter()
        .filter(|f| f.schema == "ErrorResponse")
        .collect();
    assert!(!errors.is_empty(), "the snapshot records no error fixtures");

    for fixture in errors {
        let server = serving(fixture).await;
        let error = client(&server)
            .events()
            .get("req_1")
            .await
            .expect_err(&fixture.name);

        let Error::Api(api) = &error else {
            panic!("{} produced {error:?}", fixture.name);
        };
        assert_eq!(api.status, fixture.status, "{}", fixture.name);
        assert_eq!(
            api.code.as_deref(),
            fixture.body["error"]["code"].as_str(),
            "{}",
            fixture.name
        );
        assert_eq!(
            api.request_id.as_deref(),
            fixture.body.get("request_id").and_then(|v| v.as_str()),
            "{}",
            fixture.name
        );
    }
}

/// The retryable failure is recognised from the fixture the server records for
/// it, not from a status alone.
#[tokio::test]
async fn recognises_the_not_found_fixture_as_retryable() {
    let fixtures = fixtures();
    let fixture = fixtures
        .responses
        .iter()
        .find(|f| f.schema == "ErrorResponse" && f.status == 404)
        .expect("the snapshot records no 404 fixture");

    let server = serving(fixture).await;
    let error = client(&server).events().get("req_1").await.unwrap_err();
    assert!(error.is_event_not_found(), "got {error:?}");
}

#[test]
fn verifies_every_webhook_fixture() {
    let fixtures = fixtures();
    assert!(
        !fixtures.webhooks.is_empty(),
        "the snapshot records no webhook fixtures"
    );

    for fixture in &fixtures.webhooks {
        let signed_at: u64 = fixture.timestamp.parse().expect("a signing timestamp");
        let verified = WebhookVerifier::new(&fixture.secret)
            // Verify each delivery at the instant it was signed.
            .at_unix_seconds(signed_at)
            .verify(
                fixture.payload.as_bytes(),
                Some(&fixture.timestamp),
                Some(&fixture.signature),
            );
        assert_eq!(verified, fixture.valid, "{}", fixture.name);
    }

    // The same fixture, past the replay window, must be refused.
    let stale = fixtures
        .webhooks
        .iter()
        .find(|f| f.valid)
        .expect("the snapshot records no valid webhook");
    let signed_at: u64 = stale.timestamp.parse().unwrap();
    assert!(
        !WebhookVerifier::new(&stale.secret)
            .at_unix_seconds(signed_at + 301)
            .verify(
                stale.payload.as_bytes(),
                Some(&stale.timestamp),
                Some(&stale.signature)
            ),
        "a stale delivery was accepted"
    );
    // And it is accepted again with a window wide enough to cover it.
    assert!(WebhookVerifier::new(&stale.secret)
        .at_unix_seconds(signed_at + 301)
        .tolerance(Duration::from_secs(600))
        .verify(
            stale.payload.as_bytes(),
            Some(&stale.timestamp),
            Some(&stale.signature)
        ));
}
