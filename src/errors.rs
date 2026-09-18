//! The one error type every fallible call in this crate returns.

use std::fmt;

/// A [`Result`](std::result::Result) whose error is always [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// What a deadline protected; carried by [`Error::Timeout`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// A single HTTP request, including reading its body.
    Request,
    /// The whole polling loop in [`EventsClient::wait_for`].
    ///
    /// [`EventsClient::wait_for`]: crate::EventsClient::wait_for
    EventWait,
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Operation::Request => "request",
            Operation::EventWait => "event_wait",
        })
    }
}

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
    Timeout {
        /// Which deadline it was.
        operation: Operation,
    },
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

    /// True for the one retryable read failure: the event has not been
    /// archived yet.
    ///
    /// [`EventsClient::wait_for`] polls on exactly this and nothing else.
    ///
    /// [`EventsClient::wait_for`]: crate::EventsClient::wait_for
    pub fn is_event_not_found(&self) -> bool {
        matches!(self, Error::Api(api) if api.status == 404 && api.code.as_deref() == Some("event_not_found"))
    }

    /// True when an SDK deadline elapsed.
    pub fn is_timeout(&self) -> bool {
        matches!(self, Error::Timeout { .. })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config { message } => write!(f, "fingerly: {message}"),
            Error::Api(api) => write!(f, "fingerly: {api}"),
            Error::Timeout {
                operation: Operation::EventWait,
            } => f.write_str("fingerly: timed out waiting for the event"),
            Error::Timeout { .. } => f.write_str("fingerly: request timed out"),
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
