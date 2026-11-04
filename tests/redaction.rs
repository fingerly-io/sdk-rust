//! No SDK value prints a credential, whatever is holding it.

mod common;

use common::{PROXY_KEY, SECRET_KEY, WEBHOOK_SECRET};
use fingerly::{Fingerly, FingerlyProxy, WebhookVerifier};

fn assert_redacted(name: &str, printed: String) {
    for secret in [SECRET_KEY, PROXY_KEY, WEBHOOK_SECRET] {
        assert!(
            !printed.contains(secret),
            "{name} prints a credential: {printed}"
        );
    }
    assert!(
        printed.contains("[redacted]"),
        "{name} does not mark the credential: {printed}"
    );
}

#[test]
fn debug_output_never_contains_a_credential() {
    let builder = Fingerly::builder(SECRET_KEY);
    assert_redacted("FingerlyBuilder", format!("{builder:?} {builder:#?}"));

    let client = Fingerly::new(SECRET_KEY).unwrap();
    assert_redacted("Fingerly", format!("{client:?} {client:#?}"));

    let proxy_builder = FingerlyProxy::builder().proxy_key(PROXY_KEY);
    assert_redacted("FingerlyProxyBuilder", format!("{proxy_builder:?}"));

    let proxy = FingerlyProxy::builder()
        .proxy_key(PROXY_KEY)
        .client_ip(|_| "203.0.113.7".to_owned())
        .build()
        .unwrap();
    assert_redacted("FingerlyProxy", format!("{proxy:?} {proxy:#?}"));

    let verifier = WebhookVerifier::new(WEBHOOK_SECRET);
    assert_redacted("WebhookVerifier", format!("{verifier:?} {verifier:#?}"));
}
