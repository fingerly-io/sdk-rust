//! Webhook signature verification.

mod common;

use std::time::Duration;

use common::WEBHOOK_SECRET;
use fingerly::{verify_webhook, WebhookEvent, WebhookVerifier};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const NOW: u64 = 1_789_646_400;
const PAYLOAD: &[u8] = br#"{"id":"evt_1","type":"identification.completed"}"#;

/// Signs a payload the way Fingerly does: the timestamp, a dot, then the bytes.
fn sign(secret: &str, timestamp: &str, payload: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(payload);
    let digest = mac.finalize().into_bytes();
    format!(
        "sha256={}",
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

fn verifier() -> WebhookVerifier {
    WebhookVerifier::new(WEBHOOK_SECRET).at_unix_seconds(NOW)
}

fn timestamp() -> String {
    NOW.to_string()
}

#[test]
fn accepts_a_delivery_it_signed() {
    let stamp = timestamp();
    let signature = sign(WEBHOOK_SECRET, &stamp, PAYLOAD);
    assert!(verifier().verify(PAYLOAD, Some(&stamp), Some(&signature)));
}

/// During a rotation Fingerly sends several signatures; any one matching is
/// enough.
#[test]
fn accepts_any_signature_in_a_rotation_header() {
    let stamp = timestamp();
    let current = sign(WEBHOOK_SECRET, &stamp, PAYLOAD);
    let previous = sign("whsec_previous", &stamp, PAYLOAD);

    for header in [
        format!("{previous},{current}"),
        format!("{current},{previous}"),
        format!("{previous}, {current}"),
    ] {
        assert!(
            verifier().verify(PAYLOAD, Some(&stamp), Some(&header)),
            "{header} was refused"
        );
    }
    assert!(!verifier().verify(PAYLOAD, Some(&stamp), Some(&previous)));
}

/// The signature covers the body, so one changed byte invalidates it.
#[test]
fn refuses_a_tampered_body() {
    let stamp = timestamp();
    let signature = sign(WEBHOOK_SECRET, &stamp, PAYLOAD);
    assert!(!verifier().verify(
        br#"{"id":"evt_1","type":"identification.failed"}"#,
        Some(&stamp),
        Some(&signature)
    ));
}

/// It covers the timestamp too, so a replay cannot be re-dated.
#[test]
fn refuses_a_signature_lifted_onto_another_timestamp() {
    let signature = sign(WEBHOOK_SECRET, &timestamp(), PAYLOAD);
    let moved = (NOW + 1).to_string();
    assert!(!verifier().verify(PAYLOAD, Some(&moved), Some(&signature)));
}

#[test]
fn refuses_a_delivery_outside_the_replay_window() {
    for drift in [301_i64, -301] {
        let stamp = (NOW as i64 + drift).to_string();
        let signature = sign(WEBHOOK_SECRET, &stamp, PAYLOAD);
        assert!(
            !verifier().verify(PAYLOAD, Some(&stamp), Some(&signature)),
            "a delivery {drift}s away was accepted"
        );
    }
}

#[test]
fn accepts_a_delivery_at_the_edge_of_the_window() {
    for drift in [300_i64, -300] {
        let stamp = (NOW as i64 + drift).to_string();
        let signature = sign(WEBHOOK_SECRET, &stamp, PAYLOAD);
        assert!(verifier().verify(PAYLOAD, Some(&stamp), Some(&signature)));
    }
}

#[test]
fn honours_a_custom_tolerance() {
    let stamp = (NOW - 600).to_string();
    let signature = sign(WEBHOOK_SECRET, &stamp, PAYLOAD);

    assert!(!verifier().verify(PAYLOAD, Some(&stamp), Some(&signature)));
    assert!(verifier().tolerance(Duration::from_secs(900)).verify(
        PAYLOAD,
        Some(&stamp),
        Some(&signature)
    ));
}

/// Malformed or missing input is a false result, never a panic.
#[test]
fn refuses_anything_that_is_not_a_signature_we_send() {
    let stamp = timestamp();
    let valid = sign(WEBHOOK_SECRET, &stamp, PAYLOAD);
    let digest = valid.strip_prefix("sha256=").unwrap().to_owned();

    let cases: Vec<(Option<&str>, Option<&str>)> = vec![
        (None, Some(valid.as_str())),
        (Some(stamp.as_str()), None),
        (None, None),
        (Some(""), Some(valid.as_str())),
        (Some(stamp.as_str()), Some("")),
        (Some("not-a-number"), Some(valid.as_str())),
        (Some("-1"), Some(valid.as_str())),
        (Some("1.5"), Some(valid.as_str())),
        (Some(&stamp), Some(&digest)),
        (Some(&stamp), Some("sha256=")),
        (Some(&stamp), Some("sha1=abc")),
        (Some(&stamp), Some("sha256=zz")),
        (Some(&stamp), Some(",,,")),
    ];
    for (stamp, signature) in cases {
        assert!(
            !verifier().verify(PAYLOAD, stamp, signature),
            "{stamp:?}/{signature:?} was accepted"
        );
    }
}

/// Fingerly sends lowercase hex; a lenient parser would be one more shape to
/// reason about.
#[test]
fn refuses_an_uppercase_digest() {
    let stamp = timestamp();
    let signature = sign(WEBHOOK_SECRET, &stamp, PAYLOAD).to_uppercase();
    assert!(!verifier().verify(PAYLOAD, Some(&stamp), Some(&signature)));
}

#[test]
fn refuses_an_empty_secret() {
    let stamp = timestamp();
    let signature = sign("", &stamp, PAYLOAD);
    assert!(!WebhookVerifier::new("").at_unix_seconds(NOW).verify(
        PAYLOAD,
        Some(&stamp),
        Some(&signature)
    ));
}

/// The free function is the verifier with the defaults, checked against the
/// real clock.
#[test]
fn the_free_function_verifies_a_fresh_delivery() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let signature = sign(WEBHOOK_SECRET, &stamp, PAYLOAD);

    assert!(verify_webhook(
        WEBHOOK_SECRET,
        PAYLOAD,
        Some(&stamp),
        Some(&signature)
    ));
}

/// The envelope decodes, and `data` stays raw so a new event type needs no SDK
/// upgrade.
#[test]
fn decodes_the_delivery_envelope() {
    let event: WebhookEvent = serde_json::from_str(
        r#"{"id":"evt_1","type":"identification.completed","version":1,
            "organization_id":"org_1","environment":"production",
            "created_at":"2026-09-18T08:00:00Z",
            "data":{"request_id":"req_1","invented_later":true}}"#,
    )
    .unwrap();

    assert_eq!(event.id, "evt_1");
    assert_eq!(event.event_type, "identification.completed");
    assert_eq!(event.version, 1);
    assert_eq!(event.data["request_id"], "req_1");
    assert_eq!(event.data["invented_later"], true);
}

/// Only the first 32 candidates are checked, so a header stuffed with
/// thousands costs no more than a rotation does.
#[test]
fn checks_at_most_32_signatures() {
    let stamp = timestamp();
    let good = sign(WEBHOOK_SECRET, &stamp, PAYLOAD);
    let decoy = sign("whsec_decoy", &stamp, PAYLOAD);
    let within = format!("{}{good}", format!("{decoy},").repeat(31));
    let past = format!("{}{good}", format!("{decoy},").repeat(32));
    assert!(verifier().verify(PAYLOAD, Some(&stamp), Some(&within)));
    assert!(!verifier().verify(PAYLOAD, Some(&stamp), Some(&past)));
}
