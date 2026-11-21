//! Server-side Fingerly SDK: event reads, webhook verification and a
//! same-origin proxy for the browser SDK.
//!
//! ```no_run
//! # async fn run() -> fingerly::Result<()> {
//! use fingerly::Fingerly;
//!
//! let fingerly = Fingerly::new(std::env::var("FINGERLY_SECRET_KEY").unwrap())?;
//! let event = fingerly.events().get("req_…").await?;
//! # Ok(())
//! # }
//! ```
//!
//! Secret keys and webhook secrets belong in server-side code only. A browser
//! must never see either.
//!
//! # Deadlines and cancellation
//!
//! Every request carries a deadline that covers reading the response body, so
//! a stalled stream times out like a stalled connection. Cancellation is
//! ordinary Rust cancellation: drop the future and the request stops.
//!
//! # Features
//!
//! | Feature | Default | What it adds |
//! | --- | --- | --- |
//! | `client` | yes | [`Fingerly`], event reads and DeviceCheck bits, over reqwest and Tokio. |
//! | `proxy` | yes | [`FingerlyProxy`], a [`tower_service::Service`]. Implies `client`. |
//! | `rustls` | yes | TLS through rustls. |
//! | `native-tls` | no | TLS through the platform's own stack instead. |
//! | `time` | no | [`OffsetDateTime`](time::OffsetDateTime) accessors for timestamps. |
//!
//! [`verify_webhook`] needs neither an HTTP stack nor an async runtime, so
//! `default-features = false` leaves a webhook-only build that pulls in
//! neither.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations, rust_2018_idioms)]

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "client")]
mod config;
#[cfg(feature = "client")]
mod device_check;
mod enums;
mod errors;
#[cfg(feature = "client")]
mod events;
mod models;
#[cfg(feature = "client")]
mod pool;
#[cfg(feature = "proxy")]
mod proxy;
#[cfg(feature = "client")]
mod transport;
mod webhooks;

#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub use crate::client::{Fingerly, FingerlyBuilder};
#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub use crate::device_check::{
    DeviceCheckBits, DeviceCheckClient, DeviceCheckWrite, DeviceCheckWriteResult,
};
#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub use crate::events::{
    ConsumedEvent, EventListParams, EventsClient, Verification, VerifyOptions, VerifyReason,
    DEFAULT_MAX_AGE_SECONDS,
};
#[cfg(feature = "proxy")]
#[cfg_attr(docsrs, doc(cfg(feature = "proxy")))]
pub use crate::proxy::{
    ClientIpFn, FingerlyProxy, FingerlyProxyBuilder, ProxyError, ProxyErrorHook, ProxyErrorKind,
};

pub use crate::enums::{
    AiPurpose, AiRuntime, AiVerificationMethod, AiVerificationResult, AnonymityNetwork,
    AttestSkippedReason, AttestationState, AttestationStatus, Confidence, Environment, EventState,
    RiskPlatform, RiskSource, Signal, SuspectLevel, VisitorKind, WebhookEnvironment,
    WebhookEventType,
};
pub use crate::errors::{ApiError, Error, Result};
pub use crate::models::{
    AiAgent, AiVerification, Attestation, Event, EventDocument, EventDocumentSdk, EventPage,
    EventRiskReport, EventRiskTrigger, EventTrigger,
};
pub use crate::webhooks::{
    verify_webhook, WebhookEvent, WebhookVerifier, DEFAULT_WEBHOOK_TOLERANCE,
};

/// The SDK version, reported to the API on every request.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
