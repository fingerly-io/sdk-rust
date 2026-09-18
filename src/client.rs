//! The client callers construct, and its builder.

use std::sync::Arc;
use std::time::Duration;

use crate::errors::Result;
use crate::events::EventsClient;
use crate::transport::Transport;

/// The Fingerly server SDK.
///
/// Construct it once and reuse it: it holds a pooled HTTP connection, and
/// cloning is cheap. Secret keys and webhook secrets belong in server-side
/// code only; a browser must never see either.
///
/// ```no_run
/// # async fn run() -> fingerly::Result<()> {
/// use fingerly::{EventListParams, Fingerly, SuspectLevel};
///
/// let fingerly = Fingerly::new(std::env::var("FINGERLY_SECRET_KEY").unwrap())?;
/// let page = fingerly
///     .events()
///     .list(EventListParams::new().level(SuspectLevel::High).limit(50))
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Fingerly {
    events: EventsClient,
}

impl Fingerly {
    /// Builds a client for a server-only secret key,
    /// `fly_sk_{eu|us}_{environment}_…`, whose prefix selects the regional API
    /// and the environment read.
    ///
    /// Every option is validated here, so an invalid key or endpoint fails at
    /// construction and nothing is sent.
    pub fn new(secret_key: impl Into<String>) -> Result<Self> {
        Self::builder(secret_key).build()
    }

    /// Starts a builder for the optional settings: a different endpoint, API
    /// version, deadline or HTTP stack.
    pub fn builder(secret_key: impl Into<String>) -> FingerlyBuilder {
        FingerlyBuilder {
            secret_key: secret_key.into(),
            endpoint: None,
            api_version: None,
            timeout: None,
            http_client_builder: None,
        }
    }

    /// Event reads under this client's secret key.
    pub fn events(&self) -> &EventsClient {
        &self.events
    }
}

/// Configures a [`Fingerly`] client. Start one with [`Fingerly::builder`].
#[derive(Debug)]
pub struct FingerlyBuilder {
    secret_key: String,
    endpoint: Option<String>,
    api_version: Option<String>,
    timeout: Option<Duration>,
    http_client_builder: Option<reqwest::ClientBuilder>,
}

impl FingerlyBuilder {
    /// Overrides the regional origin implied by the key, for a local or
    /// self-hosted API. The key still decides which kind of key is accepted.
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Selects a route version, such as `v2`. The default is `v1`, and the
    /// server must support whichever is chosen.
    pub fn api_version(mut self, version: impl Into<String>) -> Self {
        self.api_version = Some(version.into());
        self
    }

    /// Sets the deadline for each request, covering reading the response body.
    /// The default is 5 seconds.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Supplies the HTTP stack, for a corporate proxy, a custom TLS
    /// configuration or a connection pool of your own.
    ///
    /// It takes a [`reqwest::ClientBuilder`] rather than a finished
    /// [`reqwest::Client`] because reqwest fixes its redirect policy at build
    /// time: the SDK sets [`Policy::none`] on whatever it is given, so an
    /// authenticated request can never be replayed to another host.
    ///
    /// [`Policy::none`]: reqwest::redirect::Policy::none
    pub fn http_client_builder(mut self, builder: reqwest::ClientBuilder) -> Self {
        self.http_client_builder = Some(builder);
        self
    }

    /// Validates every option and builds the client.
    pub fn build(self) -> Result<Fingerly> {
        let transport = Transport::new(
            self.secret_key,
            self.endpoint,
            self.api_version,
            self.timeout,
            self.http_client_builder,
        )?;
        Ok(Fingerly {
            events: EventsClient::new(Arc::new(transport)),
        })
    }
}
