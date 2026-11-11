//! The types event reads decode into.
//!
//! They mirror the server schema with two deliberate differences:
//! [`Event::suspect_score`] is `Option<i32>` where `None` means unscored and
//! must never be read as zero, and the archived `document` stays opaque
//! rather than becoming a second public contract.

use serde::{Deserialize, Serialize};

/// One signal group that contributed to an event's suspect score.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct EventTrigger {
    /// The signal group, such as `vpn` or `bot`.
    pub signal: String,
    /// The group's combined weight in this score.
    pub weight: i32,
    /// `low`, `medium` or `high`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
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
    /// The visitor this identification resolved to.
    pub visitor_id: String,
    /// When the identification happened, as RFC 3339.
    pub occurred_at: String,
    /// `enriched`, or `unavailable` when the network lookup could not run.
    pub state: String,

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
