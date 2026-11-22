//! Authenticated JSON reads against the Fingerly API.

use std::time::Duration;

use crate::config::{
    normalize_api_origin, normalize_api_version, parse_key, positive_duration, KeyKind,
    DEFAULT_ENDPOINT,
};
use crate::errors::{ApiError, Error, Result};

/// The SDK build that made the request, sent on every call.
pub(crate) const USER_AGENT: &str = concat!("fingerly-rust/", env!("CARGO_PKG_VERSION"));

pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Caps how much of a failed response is parsed for metadata. An error body is
/// small; anything larger is not one worth reading.
const MAX_ERROR_BODY: usize = 1 << 20;

/// Caps a successful answer. An event is a few kilobytes and a page of them
/// well under a megabyte.
const MAX_RESPONSE_BODY: usize = 4 << 20;

/// Retries after the first attempt to spend a DeviceCheck token.
const SPEND_RETRIES: u32 = 2;

/// The wait before a spend retry, times the retry's number, unless the API
/// sent `Retry-After`.
const SPEND_BACKOFF: Duration = Duration::from_millis(250);

/// The longest a spend retry waits, whatever `Retry-After` asks for.
const MAX_SPEND_WAIT: Duration = Duration::from_secs(2);

/// Every request carries a deadline that covers receiving the body, refuses
/// redirects so the key is never replayed to another host, and reports
/// failures as [`Error::Api`] without echoing the response body.
pub(crate) struct Transport {
    /// Versioned base URL, e.g. `https://api.fingerly.io/api/v1`.
    base_url: String,
    /// Deadline covering both the request and reading its JSON body.
    timeout: Duration,
    /// HTTP implementation; redirects are disabled on it at build time.
    http: reqwest::Client,
    /// Server-only read key, sent as `x-api-key` and redacted from errors.
    secret_key: String,
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key is deliberately absent: a client is easy to end up inside
        // the debug output of whatever is holding it.
        f.debug_struct("Transport")
            .field("secret_key", &"[redacted]")
            .field("base_url", &self.base_url)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl Transport {
    /// Validates every option, so a misconfigured client never reaches the
    /// network.
    ///
    /// The key is validated even when an endpoint is given, so a public, proxy
    /// or management key can never reach an API that would accept it.
    pub(crate) fn new(
        secret_key: String,
        endpoint: Option<String>,
        allow_insecure_loopback: bool,
        api_version: Option<String>,
        timeout: Option<Duration>,
        builder: Option<reqwest::ClientBuilder>,
    ) -> Result<Self> {
        parse_key(&secret_key, KeyKind::Secret)?;
        let origin = normalize_api_origin(
            endpoint.as_deref().unwrap_or(DEFAULT_ENDPOINT),
            allow_insecure_loopback,
            "endpoint",
        )?;
        let api_version = normalize_api_version(api_version.as_deref().unwrap_or("v1"))?;
        let timeout = positive_duration(timeout.unwrap_or(DEFAULT_TIMEOUT), "timeout")?;

        // Redirects are refused here rather than per request, because reqwest
        // fixes the policy when the client is built. A caller's builder is
        // accepted; a caller's finished Client is not, for exactly this reason.
        let http = crate::pool::client_from(Some(
            builder
                .unwrap_or_else(reqwest::Client::builder)
                .user_agent(USER_AGENT),
        ))
        .map_err(|error| Error::config(format!("could not build the HTTP client: {error}")))?;

        Ok(Transport {
            base_url: format!("{origin}/api/{api_version}"),
            timeout,
            http,
            secret_key,
        })
    }

    /// Performs one GET and parses its JSON body. Never retries.
    ///
    /// Dropping the returned future cancels the request, which is how a caller
    /// cancels one.
    pub(crate) async fn get_json(&self, path: &str) -> Result<serde_json::Value> {
        let request = self.http.get(format!("{}{path}", self.base_url));
        match tokio::time::timeout(self.timeout, self.send(request)).await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout),
        }
    }

    /// Performs one POST without a body and parses its JSON answer. Never
    /// retries, under the same deadline as a read.
    pub(crate) async fn post_json(&self, path: &str) -> Result<serde_json::Value> {
        let request = self.http.post(format!("{}{path}", self.base_url));
        match tokio::time::timeout(self.timeout, self.send(request)).await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout),
        }
    }

    /// Performs one POST with a JSON body and parses its JSON answer. Never
    /// retries. `timeout` replaces the client's deadline when given.
    pub(crate) async fn post_json_body(
        &self,
        path: &str,
        body: Vec<u8>,
        timeout: Option<Duration>,
    ) -> Result<serde_json::Value> {
        let request = self
            .http
            .post(format!("{}{path}", self.base_url))
            .header("content-type", "application/json")
            .body(body);
        match tokio::time::timeout(timeout.unwrap_or(self.timeout), self.send(request)).await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout),
        }
    }

    /// Spends a held DeviceCheck token: one POST or PUT with an optional JSON
    /// body, each attempt under its own deadline.
    ///
    /// It retries only an answer that leaves the token held (`503`) or no
    /// answer at all (a timeout or a connection failure), and every retry is
    /// the identical request: the API accepts a retry of a held token only
    /// when it repeats the first request. Nothing else is retried.
    pub(crate) async fn spend_json(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        let mut attempt = 0;
        loop {
            let mut request = self.http.request(method.clone(), &url);
            if let Some(body) = &body {
                request = request
                    .header("content-type", "application/json")
                    .body(body.clone());
            }
            let result = match tokio::time::timeout(self.timeout, self.send(request)).await {
                Ok(result) => result,
                Err(_) => Err(Error::Timeout),
            };
            let retryable = match &result {
                Err(Error::Api(api)) => api.status == 503,
                Err(Error::Timeout | Error::Connection { .. }) => true,
                _ => false,
            };
            if !retryable || attempt >= SPEND_RETRIES {
                return result;
            }
            let wait = match &result {
                Err(Error::Api(api)) => api.retry_after.map(Duration::from_secs),
                _ => None,
            }
            .unwrap_or(SPEND_BACKOFF * (attempt + 1))
            .min(MAX_SPEND_WAIT);
            attempt += 1;
            tokio::time::sleep(wait).await;
        }
    }

    /// Sends one request and reads its whole body inside the caller's deadline.
    async fn send(&self, request: reqwest::RequestBuilder) -> Result<serde_json::Value> {
        let response = request
            .header("x-api-key", &self.secret_key)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|error| Error::connection(failure_kind(&error)))?;

        let status = response.status();
        let request_id = header_text(&response, "x-request-id");
        let retry_after = header_text(&response, "retry-after")
            .and_then(|value| parse_retry_after(&value, std::time::SystemTime::now()));
        let rate_limit_scope = header_text(&response, "fingerly-ratelimit-scope");
        let body = self.read_capped(response).await;

        if !status.is_success() {
            // The status line is the answer. An error page too large to read,
            // or one that breaks off, must not turn it into a decode or
            // connection failure and lose the status and Retry-After.
            let mut error = self.api_error(status.as_u16(), body.as_deref().unwrap_or_default());
            error.request_id = error.request_id.or(request_id.map(|id| self.redact(&id)));
            error.retry_after = retry_after;
            if let Some(scope) = rate_limit_scope {
                error.extras_mut().rate_limit_scope = Some(self.redact(&scope));
            }
            return Err(Error::Api(error));
        }
        serde_json::from_slice(&body?)
            .map_err(|error| Error::decode(self.redact(&error.to_string())))
    }

    /// Reads the whole body, refusing one over [`MAX_RESPONSE_BODY`] without
    /// reading past the limit.
    async fn read_capped(&self, mut response: reqwest::Response) -> Result<Vec<u8>> {
        let too_large = || Error::decode("response body exceeds 4 MiB");
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BODY as u64)
        {
            return Err(too_large());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| Error::connection(failure_kind(&error)))?
        {
            if body.len() + chunk.len() > MAX_RESPONSE_BODY {
                return Err(too_large());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Maps an error response to a redacted [`ApiError`].
    ///
    /// Only the status and the structured fields the API documents are
    /// surfaced. The raw body is deliberately dropped rather than echoed.
    fn api_error(&self, status: u16, body: &[u8]) -> ApiError {
        let mut error = ApiError {
            status,
            code: None,
            details: None,
            request_id: None,
            retry_after: None,
            extras: None,
        };

        let envelope: serde_json::Value =
            match serde_json::from_slice(&body[..body.len().min(MAX_ERROR_BODY)]) {
                Ok(value) => value,
                // A non-JSON or truncated body still reports its HTTP status, and
                // its contents are deliberately dropped rather than surfaced.
                Err(_) => return error,
            };

        // The standard envelope nests the code; a bare `{"code": …}` body is
        // read too.
        if let Some(code) = envelope
            .pointer("/error/code")
            .or_else(|| envelope.get("code"))
            .and_then(|v| v.as_str())
        {
            error.code = Some(self.redact(code));
        }
        if let Some(details) = envelope.pointer("/error/details") {
            // A JSON round-trip redacts nested values without walking the tree.
            error.details = serde_json::from_str(&self.redact(&details.to_string())).ok();
        }
        if let Some(request_id) = envelope.get("request_id").and_then(|v| v.as_str()) {
            error.request_id = Some(self.redact(request_id));
        }
        if error.is_already_consumed() {
            if let Some(at) = consumed_at(&envelope) {
                error.extras_mut().consumed_at = Some(self.redact(at));
            }
        }
        error
    }

    /// Strips the secret key from anything an error may carry to logs.
    fn redact(&self, value: &str) -> String {
        value.replace(&self.secret_key, "[redacted]")
    }
}

/// The time an `event_already_consumed` answer names: a top-level
/// `consumed_at`, one inside `error`, or a `details` entry for that field.
fn consumed_at(envelope: &serde_json::Value) -> Option<&str> {
    envelope
        .get("consumed_at")
        .or_else(|| envelope.pointer("/error/consumed_at"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            envelope
                .pointer("/error/details")?
                .as_array()?
                .iter()
                .find(|detail| detail.get("field").and_then(|v| v.as_str()) == Some("consumed_at"))?
                .get("issue")?
                .as_str()
        })
}

/// Names the kind of a connection failure, never the URL, host or port: the
/// message ends up in logs that the API address is not for.
fn failure_kind(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "the request timed out"
    } else if error.is_connect() {
        "could not connect to the API"
    } else if error.is_body() || error.is_decode() {
        ANSWER_BROKE_OFF
    } else if hung_up_after_sending(error) {
        HUNG_UP_AFTER_SENDING
    } else {
        "the request failed"
    }
}

/// The connection failure that happens only once an answer has started, so
/// the API has seen the request.
pub(crate) const ANSWER_BROKE_OFF: &str = "the answer broke off";

/// The connection failure that happens only once the whole request was
/// written, so the API may have seen it.
pub(crate) const HUNG_UP_AFTER_SENDING: &str = "the connection closed before the answer";

/// Whether the connection was closed or reset while the answer was awaited.
///
/// The HTTP/1 stack buffers the whole request before it writes any of it, and
/// tells the two sides apart only by wording: a failed write is "error writing
/// a body to connection", a failed read "connection closed before message
/// completed" or "connection error" over a reset. Only the read side counts.
/// Any other failure, HTTP/2's included, leaves no telling whether the request
/// was written, and counts as before sending.
fn hung_up_after_sending(error: &reqwest::Error) -> bool {
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        match cause.to_string().as_str() {
            "connection closed before message completed" => return true,
            "connection error" => {
                return cause
                    .source()
                    .and_then(|io| io.downcast_ref::<std::io::Error>())
                    .is_some_and(|io| {
                        matches!(
                            io.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::UnexpectedEof
                        )
                    });
            }
            _ => source = cause.source(),
        }
    }
    false
}

/// A header as text, when it is present and printable.
fn header_text(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// Reads a `Retry-After` header as whole seconds: a number of seconds, or an
/// HTTP date (IMF-fixdate, as RFC 9110 requires senders to use), counted from
/// `now`. Anything else is `None`.
fn parse_retry_after(value: &str, now: std::time::SystemTime) -> Option<u64> {
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        return value.parse().ok();
    }
    let at = parse_imf_fixdate(value)?;
    let now = now.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    Some(at.saturating_sub(now))
}

/// Parses `Sun, 06 Nov 1994 08:49:37 GMT` into Unix seconds.
fn parse_imf_fixdate(value: &str) -> Option<u64> {
    let mut parts = value.split(' ');
    let (_weekday, day, month, year, clock, zone) = (
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
    );
    if parts.next().is_some() || zone != "GMT" || day.len() != 2 || year.len() != 4 {
        return None;
    }
    let month = match month {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let day: u64 = day.parse().ok()?;
    let year: i64 = year.parse().ok()?;
    let mut clock = clock.split(':').map(|part| part.parse::<u64>().ok());
    let (hour, minute, second) = (clock.next()??, clock.next()??, clock.next()??);
    if clock.next().is_some() || hour > 23 || minute > 59 || second > 60 || !(1..=31).contains(&day)
    {
        return None;
    }
    let days = days_from_civil(year, month, day as i64);
    let seconds = days * 86_400 + (hour * 3600 + minute * 60 + second) as i64;
    u64::try_from(seconds).ok()
}

/// Days since the Unix epoch of a proleptic Gregorian date, after Howard
/// Hinnant's algorithm. `month` is 1 to 12.
pub(crate) fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn reads_retry_after_as_seconds_or_a_date() {
        let now = UNIX_EPOCH + Duration::from_secs(784_111_717); // Sun, 06 Nov 1994 08:48:37 GMT
        assert_eq!(parse_retry_after("7", now), Some(7));
        assert_eq!(parse_retry_after(" 0 ", now), Some(0));
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", now),
            Some(60)
        );
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:47:37 GMT", now),
            Some(0)
        );
        assert_eq!(parse_imf_fixdate("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_imf_fixdate("Mon, 29 Feb 2016 12:00:00 GMT"),
            Some(1_456_747_200)
        );
        for invalid in [
            "",
            "-3",
            "soon",
            "1.5",
            "Sun, 06 Nov 1994 08:49:37 PST",
            "Sunday, 06-Nov-94 08:49:37 GMT",
        ] {
            assert_eq!(parse_retry_after(invalid, now), None, "{invalid:?}");
        }
    }
}
