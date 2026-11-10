//! Event reads and the list filters.

use std::sync::Arc;

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::Deserialize;

use crate::errors::{Error, Result};
use crate::models::{Event, EventPage, SuspectLevel};
use crate::transport::Transport;

/// Everything outside the unreserved set is escaped, so a request id can never
/// add a path segment, a query or a fragment of its own.
const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'=')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'|')
    .add(b'+')
    .add(b'&');

/// Filters for [`EventsClient::list`]. An unset filter is not sent, so the
/// server applies its own default.
#[derive(Clone, Debug, Default)]
pub struct EventListParams {
    from: Option<String>,
    to: Option<String>,
    page: Option<u32>,
    limit: Option<u32>,
    visitor: Option<String>,
    level: Option<SuspectLevel>,
}

impl EventListParams {
    /// An empty filter set: the server's own defaults apply.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start of the window, as RFC 3339.
    ///
    /// The default window is the last 24 hours; it may be at most 30 days wide
    /// and start at most 30 days ago.
    pub fn from(mut self, value: impl Into<String>) -> Self {
        self.from = Some(value.into());
        self
    }

    /// End of the window, as RFC 3339.
    pub fn to(mut self, value: impl Into<String>) -> Self {
        self.to = Some(value.into());
        self
    }

    /// Start of the window, rendered from an [`OffsetDateTime`].
    ///
    /// [`OffsetDateTime`]: time::OffsetDateTime
    #[cfg(feature = "time")]
    #[cfg_attr(docsrs, doc(cfg(feature = "time")))]
    pub fn from_time(self, value: time::OffsetDateTime) -> Result<Self> {
        Ok(self.from(rfc3339(value, "from")?))
    }

    /// End of the window, rendered from an [`OffsetDateTime`].
    ///
    /// [`OffsetDateTime`]: time::OffsetDateTime
    #[cfg(feature = "time")]
    #[cfg_attr(docsrs, doc(cfg(feature = "time")))]
    pub fn to_time(self, value: time::OffsetDateTime) -> Result<Self> {
        Ok(self.to(rfc3339(value, "to")?))
    }

    /// 1-based page number.
    pub fn page(mut self, value: u32) -> Self {
        self.page = Some(value);
        self
    }

    /// Rows per page; the server clamps it to its own maximum.
    pub fn limit(mut self, value: u32) -> Self {
        self.limit = Some(value);
        self
    }

    /// Restrict the listing to one exact visitor id.
    pub fn visitor(mut self, value: impl Into<String>) -> Self {
        self.visitor = Some(value.into());
        self
    }

    /// Restrict the listing to one suspect level.
    pub fn level(mut self, value: SuspectLevel) -> Self {
        self.level = Some(value);
        self
    }

    /// Renders the filters as a query string, omitting every unset one.
    fn query(&self) -> Result<String> {
        let mut pairs = url::form_urlencoded::Serializer::new(String::new());
        if let Some(from) = &self.from {
            pairs.append_pair("from", from);
        }
        if let Some(to) = &self.to {
            pairs.append_pair("to", to);
        }
        if let Some(page) = self.page {
            pairs.append_pair("page", &positive(page, "page")?.to_string());
        }
        if let Some(limit) = self.limit {
            pairs.append_pair("limit", &positive(limit, "limit")?.to_string());
        }
        if let Some(visitor) = &self.visitor {
            pairs.append_pair("visitor", visitor);
        }
        if let Some(level) = self.level {
            pairs.append_pair("level", level.as_str());
        }
        let query = pairs.finish();
        Ok(if query.is_empty() {
            String::new()
        } else {
            format!("?{query}")
        })
    }
}

/// Reads events stored for the organisation and environment of the secret key.
///
/// Reached as [`Fingerly::events`]; it is never constructed directly.
///
/// [`Fingerly::events`]: crate::Fingerly::events
#[derive(Clone, Debug)]
pub struct EventsClient {
    transport: Arc<Transport>,
}

impl EventsClient {
    pub(crate) fn new(transport: Arc<Transport>) -> Self {
        EventsClient { transport }
    }

    /// Fetches one event by request id.
    ///
    /// An error for which [`Error::is_event_pending`] is true means the request
    /// id was accepted but the event is not recorded yet; its
    /// [`retry_after`](Error::retry_after) says when to try again. One for
    /// which [`Error::is_event_not_found`] is true means it was never issued
    /// or is past retention. Neither is retried.
    pub async fn get(&self, request_id: &str) -> Result<Event> {
        // URL parsers resolve a dot segment even when it is percent-encoded,
        // so escaping cannot keep these in the path: `.` and the empty id
        // would name the list route, and `..` a route above it, key attached.
        if matches!(request_id, "" | "." | "..") {
            return Err(Error::config("request_id is not a Fingerly request id"));
        }
        let path = format!("/events/{}", utf8_percent_encode(request_id, PATH_SEGMENT));
        let body = self.transport.get_json(&path).await?;
        decode(body, "event")
    }

    /// Lists events within the retention window, newest first.
    ///
    /// ```no_run
    /// # async fn run(fingerly: fingerly::Fingerly) -> fingerly::Result<()> {
    /// use fingerly::{EventListParams, SuspectLevel};
    ///
    /// let page = fingerly
    ///     .events()
    ///     .list(EventListParams::new().level(SuspectLevel::High).limit(50))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list(&self, params: EventListParams) -> Result<EventPage> {
        let body = self
            .transport
            .get_json(&format!("/events{}", params.query()?))
            .await?;
        decode(body, "events")
    }
}

/// Decodes a response body, keeping the original alongside the typed value.
fn decode<T>(body: serde_json::Value, what: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de> + WithRaw,
{
    let mut value =
        T::deserialize(&body).map_err(|error| Error::decode(format!("{what}: {error}")))?;
    value.set_raw(body);
    Ok(value)
}

/// Lets [`decode`] hand the untouched body back to the type it just built.
trait WithRaw {
    fn set_raw(&mut self, raw: serde_json::Value);
}

impl WithRaw for Event {
    fn set_raw(&mut self, raw: serde_json::Value) {
        self.raw = raw;
    }
}

impl WithRaw for EventPage {
    fn set_raw(&mut self, raw: serde_json::Value) {
        self.raw = raw;
    }
}

/// Validates a page or limit before it is sent as a filter.
fn positive(value: u32, name: &str) -> Result<u32> {
    if value == 0 {
        return Err(Error::config(format!("{name} must be a positive integer")));
    }
    Ok(value)
}

/// Renders a window bound in the RFC 3339 form the API expects.
#[cfg(feature = "time")]
fn rfc3339(value: time::OffsetDateTime, name: &str) -> Result<String> {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| Error::config(format!("{name} could not be formatted: {error}")))
}
