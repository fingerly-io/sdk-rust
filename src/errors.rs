//! The one error type every fallible call in this crate returns.

use std::fmt;

/// A [`Result`](std::result::Result) whose error is always [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Structured detail the API returns alongside an error response.
///
/// The message carries only the HTTP status: response bodies are never echoed,
/// and any occurrence of the secret key in these fields is redacted.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ApiError {
    /// The HTTP status code.
    pub status: u16,
    /// Stable machine-readable code, such as `event_not_found`.
    pub code: Option<String>,
    /// Additional context; its shape depends on the code.
    pub details: Option<serde_json::Value>,
    /// Server-side trace id to quote in support requests.
    pub request_id: Option<String>,
    /// How many seconds the API asked the caller to wait, from its
    /// `Retry-After` header, or `None` when it sent none. The SDK never
    /// retries a read itself.
    pub retry_after: Option<u64>,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.code {
            Some(code) => write!(f, "Fingerly API returned HTTP {} ({code})", self.status),
            None => write!(f, "Fingerly API returned HTTP {}", self.status),
        }
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    /// True for `404 event_pending`: the request id was accepted but its event
    /// is not recorded yet. This is not a verdict; try again after
    /// [`retry_after`](Self::retry_after) seconds, or verify asynchronously.
    /// The SDK never retries on its own.
    pub fn is_pending(&self) -> bool {
        self.status == 404 && self.code.as_deref() == Some("event_pending")
    }

    /// True for `404 event_not_found`: the request id was never issued for
    /// this key's environment, or the event is past retention.
    pub fn is_not_found(&self) -> bool {
        self.status == 404 && self.code.as_deref() == Some("event_not_found")
    }
}

/// Every failure this crate reports.
///
/// [`Error::Config`] is a programming mistake rather than something to handle
/// around a call: a key that was never valid will not become valid on a retry,
/// and nothing has been sent when it is raised.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A caller-supplied option was rejected. No request was made.
    Config {
        /// What was wrong with the option.
        message: String,
    },
    /// The API answered with a non-2xx status.
    Api(ApiError),
    /// An SDK deadline elapsed.
    Timeout,
    /// The API could not be reached, or the connection failed mid-response.
    Connection {
        /// A description with the secret key stripped out.
        message: String,
    },
    /// The response was not the JSON this SDK expects.
    Decode {
        /// A description of the mismatch. It never contains the body.
        message: String,
    },
}

// A build with fewer features has no use for some of these constructors; that
// is the point of the features, not an oversight.
#[allow(dead_code)]
impl Error {
    pub(crate) fn config(message: impl Into<String>) -> Self {
        Error::Config {
            message: message.into(),
        }
    }

    pub(crate) fn connection(message: impl Into<String>) -> Self {
        Error::Connection {
            message: message.into(),
        }
    }

    pub(crate) fn decode(message: impl Into<String>) -> Self {
        Error::Decode {
            message: message.into(),
        }
    }

    /// The HTTP status, when this is an API error.
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Api(api) => Some(api.status),
            _ => None,
        }
    }

    /// The machine-readable code, when the API sent one.
    pub fn code(&self) -> Option<&str> {
        match self {
            Error::Api(api) => api.code.as_deref(),
            _ => None,
        }
    }

    /// The seconds from the API's `Retry-After` header, for an API error that
    /// carried one.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Error::Api(api) => api.retry_after,
            _ => None,
        }
    }

    /// True when there is no such event (`404 event_not_found`): the request
    /// id was never issued for this key's environment, or the event is past
    /// retention. A pending event is not "not found"; see
    /// [`is_event_pending`](Self::is_event_pending).
    pub fn is_event_not_found(&self) -> bool {
        matches!(self, Error::Api(api) if api.is_not_found())
    }

    /// True when the event is not recorded yet (`404 event_pending`); see
    /// [`ApiError::is_pending`]. [`retry_after`](Self::retry_after) says when
    /// to try again.
    pub fn is_event_pending(&self) -> bool {
        matches!(self, Error::Api(api) if api.is_pending())
    }

    /// True when an SDK deadline elapsed.
    pub fn is_timeout(&self) -> bool {
        matches!(self, Error::Timeout)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config { message } => write!(f, "fingerly: {message}"),
            Error::Api(api) => write!(f, "fingerly: {api}"),
            Error::Timeout => f.write_str("fingerly: request timed out"),
            Error::Connection { message } => write!(f, "fingerly: request failed: {message}"),
            Error::Decode { message } => write!(f, "fingerly: decode response: {message}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Api(api) => Some(api),
            _ => None,
        }
    }
}

impl From<ApiError> for Error {
    fn from(error: ApiError) -> Self {
        Error::Api(error)
    }
}
