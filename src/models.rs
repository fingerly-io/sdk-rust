//! The types event reads decode into.
//!
//! They mirror the server schema with two deliberate differences:
//! [`Event::suspect_score`] is `Option<i32>` where `None` means unscored and
//! must never be read as zero, and the archived `document` stays opaque
//! rather than becoming a second public contract.

use serde::{Deserialize, Serialize};

/// Canonical v3 signal-group and detector identifiers reported on events and
/// archived risk assessments.
pub mod signals {
    /// Tor exit node network provenance.
    pub const TOR: &str = "tor";
    /// Datacenter proxy network provenance.
    pub const DATACENTER_PROXY: &str = "datacenter_proxy";
    /// Residential proxy network provenance.
    pub const RESIDENTIAL_PROXY: &str = "residential_proxy";
    /// VPN network provenance.
    pub const VPN: &str = "vpn";
    /// Public spam or attack blocklist match.
    pub const IP_BLOCKLIST: &str = "ip_blocklist";
    /// Recent IP abuse reputation match.
    pub const IP_REPUTATION: &str = "ip_reputation";
    /// Bogon or anycast network anomaly.
    pub const NETWORK_ANOMALY: &str = "network_anomaly";
    /// Device locale or timezone mismatch against network geography.
    pub const LOCATION_SPOOFING: &str = "location_spoofing";
    /// Xcode iOS simulator runtime.
    pub const IOS_SIMULATOR: &str = "ios_simulator";
    /// Android emulator runtime.
    pub const ANDROID_EMULATOR: &str = "android_emulator";
    /// Browser inside a virtual machine.
    pub const VIRTUAL_MACHINE: &str = "virtual_machine";
    /// Jailbroken iOS device.
    pub const JAILBROKEN_DEVICE: &str = "jailbroken_device";
    /// Rooted Android device.
    pub const ROOTED_DEVICE: &str = "rooted_device";
    /// App running inside a cloning framework.
    pub const CLONED_APP: &str = "cloned_app";
    /// Mass-provisioned or reset-fresh device farm indicators.
    pub const DEVICE_FARM: &str = "device_farm";
    /// Untrusted or intercepting TLS chain.
    pub const MITM_ATTACK: &str = "mitm_attack";
    /// Frida dynamic instrumentation toolkit detected.
    pub const FRIDA_DETECTED: &str = "frida_detected";
    /// Edited browser runtime or engine contradiction (group).
    pub const BROWSER_TAMPERING: &str = "browser_tampering";
    /// Edited client runtime or patched native bindings (detector).
    pub const TAMPERING: &str = "tampering";
    /// Report suppressed below minimum identifiability traits.
    pub const FINGERPRINT_SUPPRESSED: &str = "fingerprint_suppressed";
    /// Open inspector or attached debugger.
    pub const DEVELOPER_TOOLS: &str = "developer_tools";
    /// Session driven over remote desktop software.
    pub const REMOTE_CONTROL: &str = "remote_control";
    /// Automated script, headless agent, or declared bot.
    pub const BOT: &str = "bot";
    /// Abnormal request velocity from one device or network.
    pub const HIGH_ACTIVITY: &str = "high_activity";
    /// Private or incognito browsing mode.
    pub const INCOGNITO_MODE: &str = "incognito_mode";
    /// Hardened browser privacy posture.
    pub const PRIVACY_SETTINGS: &str = "privacy_settings";
    /// Page running inside an embedded in-app WebView.
    pub const EMBEDDED_WEB_VIEW: &str = "embedded_web_view";
    /// Active voice call during submission.
    pub const ACTIVE_CALL: &str = "active_call";
    /// Native device capable of hardware attestation presented none.
    pub const ATTESTATION_MISSING: &str = "attestation_missing";
    /// Hardware attestation failed cryptographic, chain, replay, or install checks.
    pub const ATTESTATION_FAILED: &str = "attestation_failed";
    /// Hardware, OS, capability, or worker-realm cross-signal contradiction.
    pub const DEVICE_INCONSISTENT: &str = "device_inconsistent";
    /// Required native security collectors omitted or selectively suppressed.
    pub const REPORT_INCOMPLETE: &str = "report_incomplete";
    /// Non-WebPKI system-trusted root CA without MITM interceptor markers.
    pub const CUSTOM_ROOT_CA: &str = "custom_root_ca";
    /// Managed Android work profile or secondary OS user profile.
    pub const SECONDARY_USER_PROFILE: &str = "secondary_user_profile";
}

/// One signal group that contributed to an event's suspect score.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct EventTrigger {
    /// The signal group, such as `vpn`, `bot`, or `attestation_failed`.
    pub signal: String,
    /// The group's combined weight in this score.
    pub weight: i32,
    /// `low`, `medium` or `high`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
}

/// Platform-neutral hardware attestation verdict inside an archived document.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Attestation {
    /// `attested`, `not_attested` or `failed`.
    pub state: String,
    /// Native platform (`ios` or `android`) when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// `verified`, `indeterminate`, `invalid`, `absent` or `unconfigured`.
    pub status: String,
    /// Short stable reason token when attestation failed or was skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Verified X.509 certificate chain length on Android registrations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_length: Option<i64>,
    /// Android attestation security level (`software`, `trusted_environment`, `strongbox`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_security_level: Option<String>,
    /// Android KeyMint security level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keymint_security_level: Option<String>,
    /// Whether the bootloader reported locked in RootOfTrust.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_locked: Option<bool>,
    /// Verified boot state (`green`, `yellow`, `orange`, `red`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_boot_state: Option<String>,
    /// Challenge nonce status when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Whether hardware revocation status was checked.
    #[serde(default)]
    pub revocation_checked: bool,
    /// Whether the app package or bundle identifier matched the key scope.
    #[serde(default)]
    pub package_bound: bool,
    /// Whether the signing certificate or Team ID matched the key scope.
    #[serde(default)]
    pub signer_bound: bool,
    /// Attestation mode (`app_attest_register`, `app_attest_assert`, `android_key_register`, `android_key_assert`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Verified Apple Team ID and bundle identifier (`<team>.<bundle>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    /// Attestation environment (`production` or `development`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// iOS App Attest receipt state (`stored`, `invalid` or `absent`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
    /// Apple App Attest 30-day key count metric when refreshed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_metric: Option<i64>,
    /// Age in hours of `risk_metric`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_metric_age_h: Option<i64>,
    /// Apple DeviceCheck token state (`held`, `unbound` or `unavailable`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_check: Option<String>,
    /// Decoded Google Play Integrity summary when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub play_integrity: Option<serde_json::Value>,
}

/// Client SDK metadata recorded in an archived event document.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct EventDocumentSdk {
    /// Client SDK platform identifier.
    #[serde(default)]
    pub platform: String,
    /// Client SDK version string.
    #[serde(default)]
    pub version: String,
}

/// One raw detector recorded inside an archived [`EventRiskReport`].
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct EventRiskTrigger {
    /// Detector identifier, such as `attestation_failed` or `device_inconsistent`.
    pub signal: String,
    /// Weight applied under the active risk profile.
    pub weight: i32,
    /// Detector confidence (`low`, `medium` or `high`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    /// Short stable explanation token for this detector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Risk scoring assessment recorded inside an archived [`EventDocument`].
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct EventRiskReport {
    /// Risk scoring platform (`web`, `ios` or `android`).
    pub platform: String,
    /// Weighted sum of triggered signals.
    pub score: i32,
    /// Banded risk level (`low`, `medium` or `high`).
    pub level: String,
    /// Suspect threshold active when scored.
    pub threshold: i32,
    /// Profile source (`key`, `organization` or `default`).
    pub source: String,
    /// Stored profile revision when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<i64>,
    /// Raw detectors that fired on this submission.
    #[serde(default)]
    pub triggers: Vec<EventRiskTrigger>,
}

/// Allow-listed view of an archived identification submission.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct EventDocument {
    /// Document schema version.
    pub schema: i32,
    /// Identification request identifier.
    pub request_id: String,
    /// RFC 3339 timestamp of the submission.
    pub occurred_at: String,
    /// Client SDK platform and version.
    #[serde(default)]
    pub sdk: EventDocumentSdk,
    /// Coarsened client IP network (`/24` IPv4 or `/40` IPv6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_network: Option<String>,
    /// City-level IP classification and detections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<serde_json::Value>,
    /// Reason token when IP lookup did not complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_error: Option<String>,
    /// Risk scoring breakdown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<EventRiskReport>,
    /// Platform-neutral hardware attestation verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Attestation>,
    /// Cross-request velocity decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub velocity: Option<serde_json::Value>,
}

/// A stored identification event.
///
/// `suspect_score` is `None` when the request was not scored. Never read that
/// as zero: an ordinary visitor about whom nothing fired scores 0, while a
/// submission that was never enriched has no score at all. [`Event::score`]
/// states the distinction at the call site.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Event {
    /// The id identification returned, and the key event reads use.
    pub request_id: String,
    /// The visitor this identification resolved to, or `""` when the submission
    /// was unidentifiable (`identifiable == false`).
    pub visitor_id: String,
    /// When the identification happened, as RFC 3339.
    pub occurred_at: String,
    /// `enriched`, or `unavailable` when the network lookup could not run.
    pub state: String,
    /// Why enrichment did not happen, on an `unavailable` event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// The deployment the event was recorded in.
    pub environment: String,
    /// The Fingerly project the event belongs to, as a UUID string. `None`
    /// when the server predates projects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// The scoring profile applied. It differs from [`Event::sdk_platform`]:
    /// `react-native-ios` reports itself as such and is scored as `ios`.
    pub platform: String,
    /// What the SDK called itself.
    pub sdk_platform: String,
    /// The SDK build that submitted the identification.
    pub sdk_version: String,

    /// The page's origin, when the browser sent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// The host of the page the identification was made from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_host: Option<String>,
    /// The path of that page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_path: Option<String>,
    /// Your own reference, as the client sent it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// The network the request came from: an IPv4 /24 or an IPv6 /40, such
    /// as `203.0.113.0/24`. The API never returns the address itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_network: Option<String>,
    /// ISO 3166-1 alpha-2 country the address resolved to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    /// The country's name, as the geolocation database spells it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_name: Option<String>,
    /// The autonomous system announcing the address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<String>,
    /// That network's name, such as a carrier or a hosting provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn_name: Option<String>,
    /// `tor`, `vpn`, `proxy` or `hosting`. `None` on an ordinary consumer
    /// connection, which is most of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anonymity_network: Option<String>,

    /// The browser or app family, such as `chrome`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Its major version, as far as the agent admits to one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    /// The operating system family, such as `windows` or `ios`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// `desktop`, `mobile`, `tablet` or similar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_kind: Option<String>,
    /// What the visitor appears to be, such as `human` or `bot`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visitor_kind: Option<String>,

    /// `None` when the request was not scored. Never read `None` as 0.
    #[serde(default)]
    pub suspect_score: Option<i32>,
    /// `low`, `medium` or `high`. `None` when not scored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspect_level: Option<String>,

    /// Never `None` from the API: an event about which nothing fired carries
    /// an empty list.
    #[serde(default)]
    pub triggers: Vec<EventTrigger>,

    /// Whether the full submission was archived.
    #[serde(default)]
    pub has_document: bool,

    /// An allow-listed view of the archived submission: schema, request id,
    /// time, SDK platform and version, the IP network, the classified IP
    /// (network, city-level location, detections) or its error, the risk,
    /// attestation and velocity results. It carries no raw signals, user
    /// agent or address. Present when [`Event::has_document`] is true and the
    /// archive could be read. Its contents are deliberately opaque, not a
    /// public contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document: Option<serde_json::Value>,

    /// The response body exactly as it arrived, so a field the API adds after
    /// this SDK was released is still reachable without an upgrade.
    ///
    /// It is not serialised back out; read the typed fields for that.
    #[serde(skip)]
    pub raw: serde_json::Value,
}

impl Event {
    /// Whether this event resolved to a non-empty visitor identifier.
    pub fn is_identifiable(&self) -> bool {
        !self.visitor_id.is_empty()
    }

    /// Parses [`Event::document`] into a typed [`EventDocument`] when present.
    pub fn parse_document(&self) -> crate::Result<Option<EventDocument>> {
        match &self.document {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(value) => serde_json::from_value(value.clone())
                .map(Some)
                .map_err(|error| crate::Error::decode(format!("document is invalid: {error}"))),
        }
    }

    /// Whether the API assigned this event a suspect score.
    ///
    /// Prefer it to a `None` check: it states the question being asked.
    pub fn is_scored(&self) -> bool {
        self.suspect_score.is_some()
    }

    /// The suspect score, or `None` when the event was never scored.
    ///
    /// ```no_run
    /// # let event = fingerly::Event::default();
    /// match event.score() {
    ///     Some(score) => println!("scored {score}"),
    ///     // Unscored. Decide on something else; do not treat it as clean.
    ///     None => println!("unscored"),
    /// }
    /// ```
    pub fn score(&self) -> Option<i32> {
        self.suspect_score
    }

    /// [`Event::occurred_at`] parsed as an RFC 3339 timestamp.
    ///
    /// Requires the `time` feature. The string is kept as the source of truth,
    /// so an unparsable timestamp is an error here rather than a decode
    /// failure for the whole event.
    #[cfg(feature = "time")]
    #[cfg_attr(docsrs, doc(cfg(feature = "time")))]
    pub fn occurred_at_time(&self) -> crate::Result<time::OffsetDateTime> {
        time::OffsetDateTime::parse(
            &self.occurred_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|error| crate::Error::decode(format!("occurred_at is not RFC 3339: {error}")))
    }
}

/// One page of events, newest first.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct EventPage {
    /// The events in this page.
    #[serde(default)]
    pub rows: Vec<Event>,
    /// The 1-based page number this is.
    #[serde(default)]
    pub page: i64,
    /// How many rows a full page holds.
    #[serde(default)]
    pub page_size: i64,

    /// The response body exactly as it arrived.
    #[serde(skip)]
    pub raw: serde_json::Value,
}

/// A suspect level, for filtering a listing.
///
/// Reading an event gives back [`Event::suspect_level`] as a string, because
/// the API may name a level this build has never heard of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuspectLevel {
    /// Nothing worth acting on fired.
    Low,
    /// Enough fired to be worth a second factor.
    Medium,
    /// Treat the visitor as suspect.
    High,
}

impl SuspectLevel {
    /// The wire value the API filters on.
    pub fn as_str(self) -> &'static str {
        match self {
            SuspectLevel::Low => "low",
            SuspectLevel::Medium => "medium",
            SuspectLevel::High => "high",
        }
    }
}

impl std::fmt::Display for SuspectLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
