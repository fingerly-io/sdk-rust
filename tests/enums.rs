//! The wire values are the server's own and permanent: a stored weight map and
//! every customer's comparisons are keyed on them.

use fingerly::{
    AiPurpose, AiRuntime, AiVerificationMethod, AiVerificationResult, AnonymityNetwork,
    AttestSkippedReason, AttestationState, AttestationStatus, Confidence, Environment, EventState,
    EventTrigger, RiskPlatform, RiskSource, Signal, SuspectLevel, VisitorKind, WebhookEnvironment,
    WebhookEvent, WebhookEventType,
};

/// Every known variant's wire value, in declaration order, and each one
/// survives a serde round trip and `From` back to the same variant.
fn assert_wire<T>(known: &[T], want: &[&str])
where
    T: Clone
        + std::fmt::Debug
        + PartialEq
        + AsRef<str>
        + for<'a> From<&'a str>
        + serde::Serialize
        + serde::de::DeserializeOwned,
{
    let got: Vec<&str> = known.iter().map(AsRef::as_ref).collect();
    assert_eq!(got, want);
    for variant in known {
        let json = serde_json::to_string(variant).unwrap();
        assert_eq!(json, format!("\"{}\"", variant.as_ref()));
        assert_eq!(&serde_json::from_str::<T>(&json).unwrap(), variant);
        assert_eq!(&T::from(variant.as_ref()), variant);
    }
}

#[test]
fn signal_wire_values() {
    assert_wire(
        Signal::KNOWN,
        &[
            "tor",
            "datacenter_proxy",
            "residential_proxy",
            "vpn",
            "ip_blocklist",
            "ip_reputation",
            "network_anomaly",
            "location_spoofing",
            "ios_simulator",
            "android_emulator",
            "virtual_machine",
            "jailbroken_device",
            "rooted_device",
            "bootloader_unlocked",
            "cloned_app",
            "device_farm",
            "mitm_attack",
            "frida_detected",
            "browser_tampering",
            "fingerprint_suppressed",
            "identity_obfuscated",
            "developer_tools",
            "remote_control",
            "bot",
            "high_activity",
            "incognito_mode",
            "privacy_settings",
            "embedded_web_view",
            "active_call",
            "attestation_missing",
            "attestation_failed",
            "device_inconsistent",
            "report_incomplete",
            "custom_root_ca",
            "secondary_user_profile",
            "proxy",
            "datacenter_ip",
            "residential_proxy_low_confidence",
            "residential_proxy_medium_confidence",
            "residential_proxy_high_confidence",
            "vpn_public",
            "vpn_relay",
            "vpn_mobile",
            "vpn_os_mismatch",
            "vpn_low_confidence",
            "vpn_medium_confidence",
            "vpn_high_confidence",
            "ip_blocklist_email_spam",
            "ip_blocklist_attack_source",
            "ip_abuser",
            "bogon_ip",
            "anycast_ip",
            "geo_mismatch",
            "simulator",
            "emulator",
            "jailbreak",
            "root_apps",
            "play_device_integrity_failed",
            "app_cloner",
            "play_app_unrecognized",
            "repeated_reinstall",
            "device_activity_high",
            "device_activity_very_high",
            "frida",
            "tampering",
            "antidetect_browser",
            "automation",
            "bad_bot",
            "ai_spoofed",
            "fetch_metadata_missing",
            "web_ticket_missing",
            "web_ticket_invalid",
            "incognito",
            "attestation_downgrade",
            "probe_errors",
        ],
    );
    assert_eq!(Signal::KNOWN.len(), 75);
}

#[test]
fn other_wire_values() {
    assert_wire(SuspectLevel::KNOWN, &["low", "medium", "high"]);
    assert_wire(Confidence::KNOWN, &["low", "medium", "high"]);
    assert_wire(
        AttestationState::KNOWN,
        &["attested", "not_attested", "failed"],
    );
    assert_wire(
        AttestationStatus::KNOWN,
        &[
            "verified",
            "indeterminate",
            "invalid",
            "absent",
            "unconfigured",
        ],
    );
    assert_wire(
        AttestSkippedReason::KNOWN,
        &[
            "not_offered",
            "unsupported",
            "challenge_unavailable",
            "key_error",
            "timeout",
            "backoff",
            "install_unavailable",
        ],
    );
    assert_wire(EventState::KNOWN, &["pending", "enriched", "unavailable"]);
    assert_wire(
        AnonymityNetwork::KNOWN,
        &["tor", "relay", "vpn", "proxy", "hosting"],
    );
    assert_wire(
        Environment::KNOWN,
        &["production", "staging", "development"],
    );
    assert_wire(RiskPlatform::KNOWN, &["web", "ios", "android"]);
    assert_wire(RiskSource::KNOWN, &["key", "organization", "default"]);
    assert_wire(
        WebhookEventType::KNOWN,
        &[
            "identification.completed",
            "identification.refused",
            "visitor.suspect",
            "billing.status_changed",
            "usage.daily_settled",
            "webhook.test",
        ],
    );
    assert_wire(WebhookEnvironment::KNOWN, &["live", "test"]);
    assert_wire(
        VisitorKind::KNOWN,
        &["human", "ai_bot", "automation", "search_crawler", "unknown"],
    );
    assert_wire(
        AiPurpose::KNOWN,
        &["training", "search", "user_fetch", "agent"],
    );
    assert_wire(
        AiRuntime::KNOWN,
        &["provider_cloud", "hosted_browser", "user_device"],
    );
    assert_wire(
        AiVerificationMethod::KNOWN,
        &["signature", "ip_list", "reverse_dns", "none"],
    );
    assert_wire(
        AiVerificationResult::KNOWN,
        &["pass", "fail", "not_attempted"],
    );
}

/// A value this build has no variant for decodes, keeps its exact text and
/// serializes back unchanged.
#[test]
fn unknown_values_are_kept() {
    let trigger: EventTrigger = serde_json::from_str(
        r#"{"signal":"signal_from_the_future","weight":1,"confidence":"certain"}"#,
    )
    .unwrap();
    assert_eq!(
        trigger.signal,
        Signal::Other("signal_from_the_future".into())
    );
    assert!(!trigger.signal.is_known());
    assert_eq!(trigger.signal, "signal_from_the_future");
    assert_eq!(
        trigger.confidence,
        Some(Confidence::Other("certain".into()))
    );
    let json = serde_json::to_value(&trigger).unwrap();
    assert_eq!(json["signal"], "signal_from_the_future");
    assert_eq!(json["confidence"], "certain");

    let known: EventTrigger =
        serde_json::from_str(r#"{"signal":"fingerprint_suppressed","weight":5}"#).unwrap();
    assert_eq!(known.signal, Signal::FingerprintSuppressed);
    assert!(known.signal.is_known());
    assert_eq!(known.signal.to_string(), "fingerprint_suppressed");
}

#[test]
fn webhook_envelope_decodes_into_enums() {
    let event: WebhookEvent = serde_json::from_str(
        r#"{"id":"1","type":"visitor.suspect","version":1,"environment":"test"}"#,
    )
    .unwrap();
    assert_eq!(event.event_type, WebhookEventType::VisitorSuspect);
    assert_eq!(event.environment, WebhookEnvironment::Test);

    let missing: WebhookEvent =
        serde_json::from_str(r#"{"id":"1","type":"webhook.test"}"#).unwrap();
    assert_eq!(missing.event_type, WebhookEventType::Test);
    assert_eq!(missing.environment, WebhookEnvironment::default());
    assert_eq!(missing.environment.as_str(), "");
}
