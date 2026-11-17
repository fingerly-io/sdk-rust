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
        let path = event_path(request_id)?;
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

    /// Marks an event as used, once.
    ///
    /// The first call answers with [`ConsumedEvent::first`] set. Every later
    /// call fails with an error for which [`Error::is_event_already_consumed`]
    /// is true, and [`Error::consumed_at`] says when the first call landed.
    /// It is never retried.
    pub async fn consume(&self, request_id: &str) -> Result<ConsumedEvent> {
        let path = format!("{}/consume", event_path(request_id)?);
        let body = self.transport.post_json(&path).await?;
        ConsumedEvent::deserialize(&body)
            .map_err(|error| Error::decode(format!("consumed event: {error}")))
    }

    /// Reads an event and checks it can back one backend decision, consuming
    /// it last.
    ///
    /// The checks run in this order and stop at the first that fails, which
    /// becomes [`Verification::reason`]:
    ///
    /// 1. [`VerifyReason::NotFound`]: there is no such event.
    /// 2. [`VerifyReason::TooOld`]: it happened more than
    ///    [`max_age_seconds`](VerifyOptions::max_age_seconds) ago, or its time
    ///    cannot be read.
    /// 3. [`VerifyReason::TagMismatch`]: a [`tag`](VerifyOptions::tag) was
    ///    given and the event's tag is not exactly that.
    /// 4. [`VerifyReason::Unidentifiable`]: it has no visitor id.
    /// 5. [`VerifyReason::Unscored`]: it has no suspect score.
    /// 6. [`VerifyReason::AlreadyConsumed`]: it was consumed before. Only
    ///    checked, by consuming it, when every check above passed and
    ///    [`consume`](VerifyOptions::consume) is on.
    ///
    /// The score, level and triggers are never judged here: that policy is
    /// the caller's, on the returned [`Verification::event`]. Any other
    /// failure, a pending event included, is returned as an error.
    ///
    /// ```no_run
    /// # async fn run(fingerly: fingerly::Fingerly) -> fingerly::Result<()> {
    /// use fingerly::VerifyOptions;
    ///
    /// let verification = fingerly
    ///     .events()
    ///     .verify("req_…", VerifyOptions::new().tag("checkout"))
    ///     .await?;
    /// if !verification.ok {
    ///     /* refuse: verification.reason_str() says why */
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn verify(&self, request_id: &str, options: VerifyOptions) -> Result<Verification> {
        if options.max_age_seconds == 0 {
            return Err(Error::config("max_age_seconds must be a positive integer"));
        }
        if options.tag.as_deref() == Some("") {
            return Err(Error::config("tag must not be empty"));
        }

        let event = match self.get(request_id).await {
            Ok(event) => event,
            Err(error) if error.is_event_not_found() => {
                return Ok(Verification::failed(VerifyReason::NotFound, None));
            }
            Err(error) => return Err(error),
        };

        if is_too_old(&event.occurred_at, options.max_age_seconds, now_nanos()) {
            return Ok(Verification::failed(VerifyReason::TooOld, Some(event)));
        }
        if let Some(tag) = &options.tag {
            if event.tag.as_deref().unwrap_or_default() != tag {
                return Ok(Verification::failed(VerifyReason::TagMismatch, Some(event)));
            }
        }
        if event.visitor_id.is_empty() {
            return Ok(Verification::failed(
                VerifyReason::Unidentifiable,
                Some(event),
            ));
        }
        if event.suspect_score.is_none() {
            return Ok(Verification::failed(VerifyReason::Unscored, Some(event)));
        }

        if options.consume {
            match self.consume(request_id).await {
                Ok(_) => {}
                Err(error) if error.is_event_already_consumed() => {
                    return Ok(Verification::failed(
                        VerifyReason::AlreadyConsumed,
                        Some(event),
                    ));
                }
                Err(error) if error.is_event_not_found() => {
                    return Ok(Verification::failed(VerifyReason::NotFound, None));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(Verification {
            ok: true,
            reason: None,
            event: Some(event),
        })
    }
}

/// The answer to the first [`EventsClient::consume`] of an event.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct ConsumedEvent {
    /// The event that was consumed.
    pub request_id: String,
    /// When it was consumed, as RFC 3339, exactly as the API sent it.
    pub consumed_at: String,
    /// `true` on the call that consumed it.
    pub first: bool,
}

/// Options for [`EventsClient::verify`].
#[derive(Clone, Debug)]
pub struct VerifyOptions {
    max_age_seconds: u64,
    tag: Option<String>,
    consume: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        VerifyOptions {
            max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            tag: None,
            consume: true,
        }
    }
}

/// How old an event [`EventsClient::verify`] accepts unless told otherwise.
pub const DEFAULT_MAX_AGE_SECONDS: u64 = 300;

impl VerifyOptions {
    /// The defaults: at most [`DEFAULT_MAX_AGE_SECONDS`] old, any tag, and
    /// consumed when every check passes.
    pub fn new() -> Self {
        Self::default()
    }

    /// The oldest event to accept, in seconds. It must be positive; `0` is
    /// refused with [`Error::Config`] before anything is sent.
    pub fn max_age_seconds(mut self, value: u64) -> Self {
        self.max_age_seconds = value;
        self
    }

    /// The exact tag the event must carry. Without one the tag is not
    /// checked. An empty tag is refused with [`Error::Config`], since it would
    /// match every untagged event.
    pub fn tag(mut self, value: impl Into<String>) -> Self {
        self.tag = Some(value.into());
        self
    }

    /// Whether to consume the event once every other check passes; on by
    /// default. Off, the same event can pass again.
    pub fn consume(mut self, value: bool) -> Self {
        self.consume = value;
        self
    }
}

/// Why [`EventsClient::verify`] refused an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VerifyReason {
    /// There is no such event: never issued, or past retention.
    NotFound,
    /// It happened longer ago than the maximum age, or its time is unreadable.
    TooOld,
    /// It does not carry the expected tag.
    TagMismatch,
    /// It has no visitor id.
    Unidentifiable,
    /// It has no suspect score.
    Unscored,
    /// It was consumed before.
    AlreadyConsumed,
}

impl VerifyReason {
    /// The wire value, such as `too_old`.
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyReason::NotFound => "not_found",
            VerifyReason::TooOld => "too_old",
            VerifyReason::TagMismatch => "tag_mismatch",
            VerifyReason::Unidentifiable => "unidentifiable",
            VerifyReason::Unscored => "unscored",
            VerifyReason::AlreadyConsumed => "already_consumed",
        }
    }
}

impl std::fmt::Display for VerifyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What [`EventsClient::verify`] decided.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Verification {
    /// `true` when every check passed (and the event was consumed, unless
    /// consuming was turned off).
    pub ok: bool,
    /// The first check that failed; `None` when [`ok`](Self::ok).
    pub reason: Option<VerifyReason>,
    /// The event read. `None` only for [`VerifyReason::NotFound`].
    pub event: Option<Event>,
}

impl Verification {
    fn failed(reason: VerifyReason, event: Option<Event>) -> Self {
        Verification {
            ok: false,
            reason: Some(reason),
            event,
        }
    }

    /// The reason's wire value, or `""` when [`ok`](Self::ok).
    pub fn reason_str(&self) -> &'static str {
        self.reason.map_or("", VerifyReason::as_str)
    }
}

/// The current time in nanoseconds since the Unix epoch.
fn now_nanos() -> i128 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(since) => since.as_nanos() as i128,
        Err(before) => -(before.duration().as_nanos() as i128),
    }
}

/// True when `occurred_at` is more than `max_age` seconds before `now`, or
/// cannot be read. A time in the future is not too old.
fn is_too_old(occurred_at: &str, max_age: u64, now: i128) -> bool {
    match parse_rfc3339_nanos(occurred_at) {
        Some(at) => now - at > i128::from(max_age) * 1_000_000_000,
        None => true,
    }
}

/// Parses an RFC 3339 date-time into nanoseconds since the Unix epoch.
fn parse_rfc3339_nanos(value: &str) -> Option<i128> {
    let b = value.as_bytes();
    if b.len() < 20 || !b.is_ascii() {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = &value[range];
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    if b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't') || b[13] != b':' {
        return None;
    }
    if b[16] != b':' {
        return None;
    }
    let (year, month, day) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    let (hour, minute, second) = (digits(11..13)?, digits(14..16)?, digits(17..19)?);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day < 1 || day > month_days || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let mut rest = &value[19..];
    let mut nanos: i128 = 0;
    if let Some(fraction) = rest.strip_prefix('.') {
        let len = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if len == 0 {
            return None;
        }
        for (i, c) in fraction[..len].bytes().take(9).enumerate() {
            nanos += i128::from(c - b'0') * 10i128.pow(8 - i as u32);
        }
        rest = &fraction[len..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let o = rest.as_bytes();
            if o.len() != 6 || !matches!(o[0], b'+' | b'-') || o[3] != b':' {
                return None;
            }
            let parse = |part: &str| -> Option<i64> {
                if part.bytes().all(|c| c.is_ascii_digit()) {
                    part.parse().ok()
                } else {
                    None
                }
            };
            let (hours, minutes) = (parse(&rest[1..3])?, parse(&rest[4..6])?);
            if hours > 23 || minutes > 59 {
                return None;
            }
            let sign = if o[0] == b'-' { -1 } else { 1 };
            sign * (hours * 3600 + minutes * 60)
        }
    };

    let days = crate::transport::days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset;
    Some(i128::from(seconds) * 1_000_000_000 + nanos)
}

/// The escaped path of one event, `/events/{request_id}`.
pub(crate) fn event_path(request_id: &str) -> Result<String> {
    // URL parsers resolve a dot segment even when it is percent-encoded, so
    // escaping cannot keep these in the path: `.` and the empty id would name
    // the list route, and `..` a route above it, key attached.
    if matches!(request_id, "" | "." | "..") {
        return Err(Error::config("request_id is not a Fingerly request id"));
    }
    Ok(format!(
        "/events/{}",
        utf8_percent_encode(request_id, PATH_SEGMENT)
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: i128 = 1_000_000_000;

    #[test]
    fn parses_rfc3339() {
        assert_eq!(parse_rfc3339_nanos("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_nanos("2016-02-29T12:00:00Z"),
            Some(1_456_747_200 * SECOND)
        );
        assert_eq!(
            parse_rfc3339_nanos("2016-02-29T14:30:00+02:30"),
            Some(1_456_747_200 * SECOND)
        );
        assert_eq!(
            parse_rfc3339_nanos("2016-02-29t09:00:00.5-03:00"),
            Some(1_456_747_200 * SECOND + SECOND / 2)
        );
        assert_eq!(
            parse_rfc3339_nanos("1970-01-01T00:00:00.1234567891Z"),
            Some(123_456_789)
        );
        for invalid in [
            "",
            "soon",
            "2026-11-17",
            "2026-11-17 10:00:00Z",
            "2026-11-17T10:00:00",
            "2026-02-29T10:00:00Z",
            "2026-13-01T10:00:00Z",
            "2026-11-17T24:00:00Z",
            "2026-11-17T10:00:00.Z",
            "2026-11-17T10:00:00+0200",
            "2026-11-17T10:00:00+24:00",
            "+026-11-17T10:00:00Z",
            "2026-11-17T10:00:00Zjunk",
        ] {
            assert_eq!(parse_rfc3339_nanos(invalid), None, "{invalid:?}");
        }
    }

    #[test]
    fn measures_age_against_now() {
        let now = parse_rfc3339_nanos("2026-11-17T10:05:00Z").unwrap();
        assert!(!is_too_old("2026-11-17T10:00:00Z", 300, now));
        assert!(is_too_old("2026-11-17T09:59:59.9Z", 300, now));
        assert!(!is_too_old("2026-11-17T11:00:00Z", 300, now));
        assert!(is_too_old("not a time", 300, now));
        assert!(is_too_old("", 300, now));
    }
}
