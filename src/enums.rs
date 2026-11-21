//! The closed string sets the API reports, as enums.
//!
//! Each enum has a variant per value this build knows and an `Other` variant
//! that keeps any other value exactly as it arrived, so a value the server adds
//! later still deserializes. Match on the variants, with a wildcard arm for the
//! rest:
//!
//! ```
//! use fingerly::{Signal, SuspectLevel};
//!
//! let level = SuspectLevel::from("high");
//! assert_eq!(level, SuspectLevel::High);
//!
//! let signal = Signal::from("signal_from_the_future");
//! assert_eq!(signal, Signal::Other("signal_from_the_future".into()));
//! assert_eq!(signal.as_str(), "signal_from_the_future");
//! ```
//!
//! Build a value from a string with `From`, which maps a known value to its
//! variant. `Other` holding a known value, such as `Signal::Other("vpn".into())`,
//! is not equal to `Signal::Vpn`; only a hand-built value can be like that.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident = $wire:literal, )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
            /// A value this build has no variant for, kept exactly as it
            /// arrived.
            Other(String),
        }

        impl $name {
            /// Every value this build has a variant for, in declaration order.
            pub const KNOWN: &'static [$name] = &[$($name::$variant),+];

            /// The wire value, such as the string the API sent.
            pub fn as_str(&self) -> &str {
                match self {
                    $( $name::$variant => $wire, )+
                    $name::Other(value) => value,
                }
            }

            /// Whether this build has a variant for the value, that is, it is
            /// not [`Other`](Self::Other).
            pub fn is_known(&self) -> bool {
                !matches!(self, $name::Other(_))
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                match value {
                    $( $wire => $name::$variant, )+
                    other => $name::Other(other.to_owned()),
                }
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                match value.as_str() {
                    $( $wire => $name::$variant, )+
                    _ => $name::Other(value),
                }
            }
        }

        /// An empty [`Other`](Self::Other), which is what a missing value
        /// reads as.
        impl Default for $name {
            fn default() -> Self {
                $name::Other(String::new())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.as_str() == other
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.as_str() == *other
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                String::deserialize(deserializer).map($name::from)
            }
        }
    };
}

wire_enum! {
    /// A signal group or raw detector identifier.
    ///
    /// [`EventTrigger::signal`](crate::EventTrigger::signal) carries signal
    /// groups, the names a console shows, such as [`Signal::Vpn`].
    /// [`EventRiskTrigger::signal`](crate::EventRiskTrigger::signal) in an
    /// archived risk report carries the raw detectors behind them, such as
    /// [`Signal::VpnPublic`]. Some names, such as [`Signal::DeviceFarm`], are
    /// both.
    pub enum Signal {
        /// Group and detector: a published Tor exit node.
        Tor = "tor",
        /// Group: a datacenter proxy.
        DatacenterProxy = "datacenter_proxy",
        /// Group and detector: a proxy on a consumer connection.
        ResidentialProxy = "residential_proxy",
        /// Group: a VPN, by any detection method.
        Vpn = "vpn",
        /// Group: an address on a spam or attack blocklist.
        IpBlocklist = "ip_blocklist",
        /// Group: an address with a history of abuse.
        IpReputation = "ip_reputation",
        /// Group: a bogon or anycast address.
        NetworkAnomaly = "network_anomaly",
        /// Group: a device timezone or locale that disagrees with the address.
        LocationSpoofing = "location_spoofing",
        /// Group: the iOS simulator.
        IosSimulator = "ios_simulator",
        /// Group: an Android emulator.
        AndroidEmulator = "android_emulator",
        /// Group and detector: a browser inside a virtual machine.
        VirtualMachine = "virtual_machine",
        /// Group: a jailbroken iOS device.
        JailbrokenDevice = "jailbroken_device",
        /// Group: a rooted Android device.
        RootedDevice = "rooted_device",
        /// Group: an app running under a cloning framework.
        ClonedApp = "cloned_app",
        /// Group and detector: a mass-provisioned or reset-fresh device.
        DeviceFarm = "device_farm",
        /// Group and detector: a proxy intercepting the app's own TLS.
        MitmAttack = "mitm_attack",
        /// Group: an instrumentation framework attached to the process.
        FridaDetected = "frida_detected",
        /// Group: an edited browser runtime or engine contradiction.
        BrowserTampering = "browser_tampering",
        /// Group and detector: a report too thin to identify anyone.
        FingerprintSuppressed = "fingerprint_suppressed",
        /// Group and detector: a browser in a non-default, opt-in
        /// anti-fingerprinting mode that replaces audio, graphics, text metrics
        /// and locale readings with synthetic noise or empty answers.
        IdentityObfuscated = "identity_obfuscated",
        /// Group and detector: an open inspector or attached debugger.
        DeveloperTools = "developer_tools",
        /// Group and detector: a session driven over remote desktop software.
        RemoteControl = "remote_control",
        /// Group: an automated or self-declared bot client.
        Bot = "bot",
        /// Group and detector: a device seen far more often than an ordinary one.
        HighActivity = "high_activity",
        /// Group: a private browsing window.
        IncognitoMode = "incognito_mode",
        /// Group and detector: hardened privacy settings.
        PrivacySettings = "privacy_settings",
        /// Group and detector: a page inside an embedded in-app WebView.
        EmbeddedWebView = "embedded_web_view",
        /// Group and detector: a voice call during the submission.
        ActiveCall = "active_call",
        /// Group and detector: a native report offering no provable hardware
        /// attestation.
        AttestationMissing = "attestation_missing",
        /// Group and detector: hardware attestation that failed verification.
        AttestationFailed = "attestation_failed",
        /// Group and detector: a hardware, OS, capability or runtime
        /// contradiction.
        DeviceInconsistent = "device_inconsistent",
        /// Group and detector: a report missing evidence it always carries.
        ReportIncomplete = "report_incomplete",
        /// Group and detector: a non-system or user-added root CA without
        /// interceptor markers.
        CustomRootCa = "custom_root_ca",
        /// Group and detector: an Android work profile or secondary user.
        SecondaryUserProfile = "secondary_user_profile",

        /// Detector: a datacenter proxy.
        Proxy = "proxy",
        /// Detector: an address where servers live, with no proxy or VPN claim.
        DatacenterIp = "datacenter_ip",
        /// Detector: a residential proxy, low confidence.
        ResidentialProxyLowConfidence = "residential_proxy_low_confidence",
        /// Detector: a residential proxy, medium confidence.
        ResidentialProxyMediumConfidence = "residential_proxy_medium_confidence",
        /// Detector: a residential proxy, high confidence.
        ResidentialProxyHighConfidence = "residential_proxy_high_confidence",
        /// Detector: a commercial VPN endpoint.
        VpnPublic = "vpn_public",
        /// Detector: a privacy relay.
        VpnRelay = "vpn_relay",
        /// Detector: a VPN on a mobile carrier network.
        VpnMobile = "vpn_mobile",
        /// Detector: a claimed OS that disagrees with the connection's own.
        VpnOsMismatch = "vpn_os_mismatch",
        /// Detector: a VPN, low confidence.
        VpnLowConfidence = "vpn_low_confidence",
        /// Detector: a VPN, medium confidence.
        VpnMediumConfidence = "vpn_medium_confidence",
        /// Detector: a VPN, high confidence.
        VpnHighConfidence = "vpn_high_confidence",
        /// Detector: an address on a mail-abuse blocklist.
        IpBlocklistEmailSpam = "ip_blocklist_email_spam",
        /// Detector: an address on an attack-source blocklist.
        IpBlocklistAttackSource = "ip_blocklist_attack_source",
        /// Detector: an address with a history of abuse.
        IpAbuser = "ip_abuser",
        /// Detector: an address that cannot appear on the public internet.
        BogonIp = "bogon_ip",
        /// Detector: an address announced from many places at once.
        AnycastIp = "anycast_ip",
        /// Detector: a device timezone or locale that disagrees with the address.
        GeoMismatch = "geo_mismatch",
        /// Detector: the iOS simulator.
        Simulator = "simulator",
        /// Detector: an Android emulator.
        Emulator = "emulator",
        /// Detector: a jailbroken iOS device.
        Jailbreak = "jailbreak",
        /// Detector: a rooted Android device.
        RootApps = "root_apps",
        /// Detector: a device meeting no Play Integrity device verdict.
        PlayDeviceIntegrityFailed = "play_device_integrity_failed",
        /// Detector: an app running under a cloning framework.
        AppCloner = "app_cloner",
        /// Detector: an app Play does not recognise.
        PlayAppUnrecognized = "play_app_unrecognized",
        /// Detector: an iOS app reinstalled or a device reset over and over.
        RepeatedReinstall = "repeated_reinstall",
        /// Detector: high recent Play Integrity device activity.
        DeviceActivityHigh = "device_activity_high",
        /// Detector: the highest recent Play Integrity device activity.
        DeviceActivityVeryHigh = "device_activity_very_high",
        /// Detector: an instrumentation framework attached to the process.
        Frida = "frida",
        /// Detector: an edited client runtime or patched natives.
        Tampering = "tampering",
        /// Detector: a browser built to defeat fingerprinting.
        AntidetectBrowser = "antidetect_browser",
        /// Detector: a browser driven by something other than a person.
        Automation = "automation",
        /// Detector: a client that says it is not a browser, or a known bad
        /// crawler.
        BadBot = "bad_bot",
        /// Detector: a client that names a known AI agent and arrives from
        /// outside the addresses that agent's operator publishes.
        AiSpoofed = "ai_spoofed",
        /// Detector: a browser report with no `Sec-Fetch-*` headers.
        FetchMetadataMissing = "fetch_metadata_missing",
        /// Detector: a browser report with no freshness ticket.
        WebTicketMissing = "web_ticket_missing",
        /// Detector: a browser report whose freshness ticket did not verify.
        WebTicketInvalid = "web_ticket_invalid",
        /// Detector: a private browsing window.
        Incognito = "incognito",
        /// Detector: an unproven native report naming an install an attested
        /// key owns.
        AttestationDowngrade = "attestation_downgrade",
        /// Detector: a native security source whose probes threw, were denied
        /// or timed out.
        ProbeErrors = "probe_errors",
    }
}

wire_enum! {
    /// The band a suspect score falls into.
    pub enum SuspectLevel {
        /// Nothing worth acting on fired.
        Low = "low",
        /// Enough fired to be worth a second factor.
        Medium = "medium",
        /// Treat the visitor as suspect.
        High = "high",
    }
}

wire_enum! {
    /// How sure one detection is.
    pub enum Confidence {
        /// Low confidence.
        Low = "low",
        /// Medium confidence.
        Medium = "medium",
        /// High confidence.
        High = "high",
    }
}

wire_enum! {
    /// The server's single verdict on a native event's hardware evidence.
    pub enum AttestationState {
        /// The evidence was proven.
        Attested = "attested",
        /// No evidence could be proven.
        NotAttested = "not_attested",
        /// The evidence was rejected.
        Failed = "failed",
    }
}

wire_enum! {
    /// The detail behind an [`AttestationState`].
    pub enum AttestationStatus {
        /// The evidence verified.
        Verified = "verified",
        /// The evidence could not be checked either way.
        Indeterminate = "indeterminate",
        /// The evidence did not verify.
        Invalid = "invalid",
        /// There was no evidence.
        Absent = "absent",
        /// The key has nothing to verify the app against.
        Unconfigured = "unconfigured",
    }
}

wire_enum! {
    /// The app's own reason for sending no hardware attestation. Diagnostic
    /// only: it never lowers the score.
    pub enum AttestSkippedReason {
        /// `not_offered`: the challenge offered no attestation: on iOS the SDK
        /// key has no Apple app ID for App Attest, on Android the app's
        /// transport returned no challenge offer.
        NotOffered = "not_offered",
        /// `unsupported`: the device cannot make an attested key: App Attest
        /// is not supported on the iOS device, or Android is older than 7.0
        /// (API 24).
        Unsupported = "unsupported",
        /// `challenge_unavailable`: no usable challenge ticket: the challenge
        /// request failed, or on Android the ticket it returned was malformed.
        ChallengeUnavailable = "challenge_unavailable",
        /// `key_error`: the platform key store failed to create, attest or
        /// sign with the key, or on Android the stored key record could not
        /// be read.
        KeyError = "key_error",
        /// `timeout`: attestation did not finish in time: a key store call
        /// ran past its budget, or another identification held the
        /// attestation step too long.
        Timeout = "timeout",
        /// `backoff`: the server rejected a new key from this install (on
        /// iOS, also when it asked for a replacement), and the SDK is waiting
        /// out a backoff before it registers another.
        Backoff = "backoff",
        /// `install_unavailable`: the report has no usable install ID, or on
        /// iOS the stored key record could not be read or saved.
        InstallUnavailable = "install_unavailable",
    }
}

wire_enum! {
    /// Whether an event was enriched.
    pub enum EventState {
        /// Accepted and not written yet. An event read answers this as
        /// an error rather than an event, so a read event is never in it.
        Pending = "pending",
        /// The network lookup ran.
        Enriched = "enriched",
        /// The network lookup could not run; [`Event::reason`](crate::Event::reason)
        /// says why.
        Unavailable = "unavailable",
    }
}

wire_enum! {
    /// The kind of network that hid the visitor's address.
    pub enum AnonymityNetwork {
        /// A Tor exit node.
        Tor = "tor",
        /// A privacy relay.
        Relay = "relay",
        /// A VPN.
        Vpn = "vpn",
        /// A proxy.
        Proxy = "proxy",
        /// A hosting provider.
        Hosting = "hosting",
    }
}

wire_enum! {
    /// What sort of client made the request.
    pub enum VisitorKind {
        /// A person in an ordinary browser or app.
        Human = "human",
        /// An AI agent; [`Event::ai`](crate::Event::ai) names it.
        AiBot = "ai_bot",
        /// A browser driven by automation software.
        Automation = "automation",
        /// A search engine crawler.
        SearchCrawler = "search_crawler",
    }
}

wire_enum! {
    /// What an AI agent's operator says its traffic is for.
    pub enum AiPurpose {
        /// Collecting content to train models.
        Training = "training",
        /// Indexing for an AI answer or search product.
        Search = "search",
        /// Reading a page a person asked an assistant to read.
        UserFetch = "user_fetch",
        /// Driving a browser on a person's behalf.
        Agent = "agent",
    }
}

wire_enum! {
    /// Where an AI agent runs.
    pub enum AiRuntime {
        /// The operator's own infrastructure.
        ProviderCloud = "provider_cloud",
        /// A third party's cloud browser.
        HostedBrowser = "hosted_browser",
        /// A person's own browser.
        UserDevice = "user_device",
    }
}

wire_enum! {
    /// How an AI agent's claimed identity was checked.
    pub enum AiVerificationMethod {
        /// A signed request.
        Signature = "signature",
        /// The operator's published address ranges.
        IpList = "ip_list",
        /// A reverse lookup confirmed forward.
        ReverseDns = "reverse_dns",
        /// Not checked.
        None = "none",
    }
}

wire_enum! {
    /// What checking an AI agent's claimed identity found.
    pub enum AiVerificationResult {
        /// The claim held.
        Pass = "pass",
        /// It was checked and did not hold.
        Fail = "fail",
        /// No check was made.
        NotAttempted = "not_attempted",
    }
}

wire_enum! {
    /// The deployment an event was recorded in, set by the key that submitted
    /// it.
    pub enum Environment {
        /// Real traffic.
        Production = "production",
        /// A pre-production deployment.
        Staging = "staging",
        /// A laptop, a CI run or an integration test.
        Development = "development",
    }
}

wire_enum! {
    /// The scoring profile an event was scored under. It is coarser than the
    /// SDK platform: a React Native app on iOS is scored as
    /// [`RiskPlatform::Ios`].
    pub enum RiskPlatform {
        /// A browser.
        Web = "web",
        /// An iOS app.
        Ios = "ios",
        /// An Android app.
        Android = "android",
    }
}

wire_enum! {
    /// Which risk profile scored an event.
    pub enum RiskSource {
        /// The SDK key's own profile.
        Key = "key",
        /// The organization's profile.
        Organization = "organization",
        /// The weights the platform ships with.
        Default = "default",
    }
}

wire_enum! {
    /// The type of a webhook delivery.
    pub enum WebhookEventType {
        /// `identification.completed`.
        IdentificationCompleted = "identification.completed",
        /// `identification.refused`.
        IdentificationRefused = "identification.refused",
        /// `visitor.suspect`.
        VisitorSuspect = "visitor.suspect",
        /// `billing.status_changed`.
        BillingStatusChanged = "billing.status_changed",
        /// `usage.daily_settled`.
        UsageDailySettled = "usage.daily_settled",
        /// `webhook.test`, sent when a test delivery is requested for one
        /// endpoint. Nobody subscribes to it.
        Test = "webhook.test",
    }
}

wire_enum! {
    /// The environment of a webhook delivery: live for production keys, test
    /// for every other environment.
    pub enum WebhookEnvironment {
        /// Production traffic.
        Live = "live",
        /// Every other environment.
        Test = "test",
    }
}
