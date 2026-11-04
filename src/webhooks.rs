//! Webhook signature verification.
//!
//! This module needs neither an HTTP stack nor an async runtime, so it is
//! available even with default features turned off.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// How far a delivery's timestamp may be from now before it is refused as a
/// replay.
pub const DEFAULT_WEBHOOK_TOLERANCE: Duration = Duration::from_secs(300);

const SIGNATURE_PREFIX: &str = "sha256=";
const DIGEST_HEX_LEN: usize = 64;

/// Caps how many comma-separated candidates are checked. A rotation sends two;
/// a header with thousands is someone making the receiver compare each.
const MAX_SIGNATURES: usize = 32;

/// The envelope every webhook delivery shares.
///
/// `data` is left as raw JSON, so a new event type needs no SDK upgrade.
/// Deserialise it into the shape that event documents.
#[derive(Clone, Debug, Default, Deserialize)]
#[non_exhaustive]
pub struct WebhookEvent {
    /// Identifies this delivery. Persist it to deduplicate: a webhook may
    /// arrive more than once.
    pub id: String,
    /// The event name, such as `identification.completed`.
    #[serde(rename = "type")]
    pub event_type: String,
    /// The envelope version.
    #[serde(default)]
    pub version: i64,
    /// The organisation the event belongs to.
    #[serde(default)]
    pub organization_id: String,
    /// The deployment the event came from.
    #[serde(default)]
    pub environment: String,
    /// When Fingerly recorded the event, as RFC 3339.
    #[serde(default)]
    pub created_at: String,
    /// The event-specific payload.
    #[serde(default)]
    pub data: serde_json::Value,
}

/// Verifies a webhook delivery against the raw request body.
///
/// Pass the exact bytes received, before any JSON parsing: re-serialising them
/// changes the digest. During a signing-secret rotation Fingerly sends several
/// comma-separated signatures, and any one of the first 32 matching is
/// accepted.
///
/// Verification proves the delivery came from Fingerly and is recent. It does
/// not deduplicate, so persist processed [`WebhookEvent::id`] values as well.
///
/// Malformed or missing input is a `false` result, never a panic.
///
/// ```no_run
/// # fn handle(body: &[u8], headers: &http::HeaderMap) -> bool {
/// fingerly::verify_webhook(
///     &std::env::var("FINGERLY_WEBHOOK_SECRET").unwrap(),
///     body,
///     headers.get("x-fingerly-timestamp").and_then(|v| v.to_str().ok()),
///     headers.get("x-fingerly-signature").and_then(|v| v.to_str().ok()),
/// )
/// # }
/// ```
pub fn verify_webhook(
    secret: &str,
    payload: &[u8],
    timestamp: Option<&str>,
    signature: Option<&str>,
) -> bool {
    WebhookVerifier::new(secret).verify(payload, timestamp, signature)
}

/// A reusable verifier, for a non-default replay window or a fixed clock.
///
/// [`verify_webhook`] is this with the defaults; reach for the verifier when
/// you need to change one.
#[derive(Clone)]
pub struct WebhookVerifier {
    secret: String,
    tolerance: Duration,
    now: Option<u64>,
}

impl std::fmt::Debug for WebhookVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A verifier held in shared state ends up in debug logs; the signing
        // secret must not.
        f.debug_struct("WebhookVerifier")
            .field("secret", &"[redacted]")
            .field("tolerance", &self.tolerance)
            .field("now", &self.now)
            .finish()
    }
}

impl WebhookVerifier {
    /// Verifies against one endpoint's signing secret.
    pub fn new(secret: impl Into<String>) -> Self {
        WebhookVerifier {
            secret: secret.into(),
            tolerance: DEFAULT_WEBHOOK_TOLERANCE,
            now: None,
        }
    }

    /// Sets the replay window. The default is five minutes.
    pub fn tolerance(mut self, tolerance: Duration) -> Self {
        self.tolerance = tolerance;
        self
    }

    /// Fixes the current time, in whole seconds since the Unix epoch.
    /// Override it only in tests.
    pub fn at_unix_seconds(mut self, seconds: u64) -> Self {
        self.now = Some(seconds);
        self
    }

    /// Verifies one delivery.
    ///
    /// The header arguments are [`Option`] because that is what a header
    /// lookup gives back; a missing header is simply `false`.
    pub fn verify(&self, payload: &[u8], timestamp: Option<&str>, signature: Option<&str>) -> bool {
        let (Some(timestamp), Some(signature)) = (timestamp, signature) else {
            return false;
        };
        if self.secret.is_empty() || timestamp.is_empty() || signature.is_empty() {
            return false;
        }
        // Check freshness before spending an HMAC on an obvious replay.
        if !self.is_fresh(timestamp) {
            return false;
        }

        let expected = sign(&self.secret, timestamp, payload);
        signature
            .split(',')
            .take(MAX_SIGNATURES)
            .any(|candidate| matches(candidate, &expected))
    }

    /// Rejects replays: the signed time must be within tolerance of now.
    fn is_fresh(&self, timestamp: &str) -> bool {
        if timestamp.is_empty() || !timestamp.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        let Ok(signed_at) = timestamp.parse::<u64>() else {
            return false;
        };
        let now = self.now.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|since| since.as_secs())
                .unwrap_or(0)
        });
        let drift = now.abs_diff(signed_at);
        drift <= self.tolerance.as_secs()
    }
}

/// Computes the expected digest.
///
/// Fingerly signs the timestamp, a literal dot, then the raw body bytes.
fn sign(secret: &str, timestamp: &str, payload: &[u8]) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

/// Compares one candidate signature in constant time.
///
/// The candidate must be a lowercase hex digest behind `sha256=`, exactly as
/// Fingerly sends it.
fn matches(candidate: &str, expected: &[u8; 32]) -> bool {
    let value = candidate.trim();
    let Some(hex) = value.strip_prefix(SIGNATURE_PREFIX) else {
        return false;
    };
    if hex.len() != DIGEST_HEX_LEN {
        return false;
    }
    let Some(actual) = decode_hex(hex) else {
        return false;
    };
    actual.ct_eq(expected).into()
}

/// Decodes a lowercase hex digest. Uppercase is refused rather than accepted,
/// because Fingerly never sends it and a lenient parser is one more shape to
/// reason about.
///
/// The caller has already checked the length, so the pairs line up with the
/// output exactly.
fn decode_hex(value: &str) -> Option<[u8; 32]> {
    let bytes = value.as_bytes();
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = (nibble(bytes[index * 2])? << 4) | nibble(bytes[index * 2 + 1])?;
    }
    Some(out)
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
