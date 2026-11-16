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
use fingerly::{signals, Error, Event, EventListParams, Fingerly, WebhookVerifier};
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
        assert_eq!(
            event.project_id.as_deref(),
            fixture.body.get("project_id").and_then(|p| p.as_str()),
            "{}",
            fixture.name
        );

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
        assert_eq!(
            event.reason.as_deref(),
            fixture.body.get("reason").and_then(|r| r.as_str()),
            "{}",
            fixture.name
        );
        assert_eq!(
            event.is_identifiable(),
            !event.visitor_id.is_empty(),
            "{}",
            fixture.name
        );
        if event.document.is_some() {
            let parsed = event
                .parse_document()
                .unwrap_or_else(|error| panic!("{}: {error}", fixture.name))
                .expect("parsed document");
            assert_eq!(parsed.request_id, event.request_id, "{}", fixture.name);
        }
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
            assert_eq!(
                decoded.project_id.as_deref(),
                expected.get("project_id").and_then(|p| p.as_str()),
                "{}",
                fixture.name
            );
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

#[tokio::test]
async fn v3_openapi_and_models_match_single_path_contract() {
    let raw = std::fs::read(contract_dir().join("openapi.json")).expect("read openapi.json");
    let openapi: serde_json::Value = serde_json::from_slice(&raw).expect("decode openapi.json");

    let paths = openapi["paths"].as_object().expect("openapi paths");
    assert!(paths.contains_key("/api/v1/ingest"));
    assert!(!paths.contains_key("/api/v1/events/{request_id}/supplement"));

    let schemas = openapi["components"]["schemas"]
        .as_object()
        .expect("openapi schemas");
    assert!(schemas.contains_key("AttestEnvelope"));
    assert!(!schemas.contains_key("SupplementOut"));

    let event_props = schemas["SDKEventOut"]["properties"]
        .as_object()
        .expect("SDKEventOut properties");
    assert!(!event_props.contains_key("supplements"));
    assert!(!event_props.contains_key("deferred_token"));

    let v3_signals = [
        signals::ATTESTATION_FAILED,
        signals::DEVICE_INCONSISTENT,
        signals::REPORT_INCOMPLETE,
        signals::TAMPERING,
        signals::CUSTOM_ROOT_CA,
        signals::SECONDARY_USER_PROFILE,
    ];
    let payload = serde_json::json!({
        "request_id": "req_v3_unidentifiable",
        "visitor_id": "",
        "occurred_at": "2026-11-16T08:00:00Z",
        "state": "enriched",
        "environment": "production",
        "platform": "android",
        "sdk_platform": "react-native-android",
        "sdk_version": "0.3.0",
        "suspect_score": 88,
        "suspect_level": "high",
        "triggers": [
            {"signal": signals::ATTESTATION_FAILED, "weight": 35, "confidence": "high"},
            {"signal": signals::DEVICE_INCONSISTENT, "weight": 20, "confidence": "high"},
            {"signal": signals::REPORT_INCOMPLETE, "weight": 15, "confidence": "medium"},
            {"signal": signals::TAMPERING, "weight": 10, "confidence": "high"},
            {"signal": signals::CUSTOM_ROOT_CA, "weight": 4, "confidence": "medium"},
            {"signal": signals::SECONDARY_USER_PROFILE, "weight": 4, "confidence": "low"}
        ],
        "has_document": true,
        "document": {
            "schema": 1,
            "request_id": "req_v3_unidentifiable",
            "occurred_at": "2026-11-16T08:00:00Z",
            "sdk": {"platform": "react-native-android", "version": "0.3.0"},
            "attestation": {
                "state": "failed",
                "platform": "android",
                "status": "invalid",
                "reason": "bootloader_unlocked",
                "mode": "android_key_register",
                "chain_length": 4,
                "attestation_security_level": "trusted_environment",
                "keymint_security_level": "trusted_environment",
                "device_locked": false,
                "verified_boot_state": "orange",
                "revocation_checked": true,
                "package_bound": true,
                "signer_bound": false
            },
            "risk": {
                "platform": "android",
                "score": 88,
                "level": "high",
                "threshold": 50,
                "source": "default",
                "triggers": [
                    {
                        "signal": signals::ATTESTATION_FAILED,
                        "weight": 35,
                        "confidence": "high",
                        "reason": "bootloader_unlocked"
                    }
                ]
            }
        }
    });

    let server = TestServer::always(Canned::json(200, payload.to_string())).await;
    let event: Event = client(&server)
        .events()
        .get("req_v3_unidentifiable")
        .await
        .expect("decode v3 unidentifiable event");

    assert_eq!(event.visitor_id, "");
    assert!(!event.is_identifiable());
    assert_eq!(event.score(), Some(88));
    let seen_signals: Vec<&str> = event.triggers.iter().map(|t| t.signal.as_str()).collect();
    assert_eq!(seen_signals, v3_signals);

    let doc = event
        .parse_document()
        .expect("parse v3 document")
        .expect("document present");
    assert_eq!(doc.sdk.platform, "react-native-android");
    let attestation = doc.attestation.expect("attestation present");
    assert_eq!(attestation.state, "failed");
    assert_eq!(attestation.status, "invalid");
    assert_eq!(attestation.platform.as_deref(), Some("android"));
    assert_eq!(attestation.reason.as_deref(), Some("bootloader_unlocked"));
    assert_eq!(attestation.device_locked, Some(false));
    assert!(attestation.revocation_checked);
    assert!(attestation.package_bound);
    assert!(!attestation.signer_bound);
}
