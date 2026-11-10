//! Authenticated JSON reads against the Fingerly API.

use std::time::Duration;

use crate::config::{
    normalize_api_version, normalize_origin, parse_key, positive_duration, KeyKind,
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
        api_version: Option<String>,
        timeout: Option<Duration>,
        builder: Option<reqwest::ClientBuilder>,
    ) -> Result<Self> {
        parse_key(&secret_key, KeyKind::Secret)?;
        let origin = normalize_origin(&endpoint.unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned()))?;
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

    /// Sends one request and reads its whole body inside the caller's deadline.
    async fn send(&self, request: reqwest::RequestBuilder) -> Result<serde_json::Value> {
        let response = request
            .header("x-api-key", &self.secret_key)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|error| Error::connection(self.redact(&error.to_string())))?;

        let status = response.status();
        let request_id = header_text(&response, "x-request-id");
        let retry_after = header_text(&response, "retry-after")
            .and_then(|value| parse_retry_after(&value, std::time::SystemTime::now()));
        let body = self.read_capped(response).await;

        if !status.is_success() {
            // The status line is the answer. An error page too large to read,
            // or one that breaks off, must not turn it into a decode or
            // connection failure and lose the status and Retry-After.
            let mut error = self.api_error(status.as_u16(), body.as_deref().unwrap_or_default());
            error.request_id = error.request_id.or(request_id.map(|id| self.redact(&id)));
            error.retry_after = retry_after;
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
            .map_err(|error| Error::connection(self.redact(&error.to_string())))?
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
        };

        let envelope: serde_json::Value =
            match serde_json::from_slice(&body[..body.len().min(MAX_ERROR_BODY)]) {
                Ok(value) => value,
                // A non-JSON or truncated body still reports its HTTP status, and
                // its contents are deliberately dropped rather than surfaced.
                Err(_) => return error,
            };

        if let Some(code) = envelope.pointer("/error/code").and_then(|v| v.as_str()) {
            error.code = Some(self.redact(code));
        }
        if let Some(details) = envelope.pointer("/error/details") {
            // A JSON round-trip redacts nested values without walking the tree.
            error.details = serde_json::from_str(&self.redact(&details.to_string())).ok();
        }
        if let Some(request_id) = envelope.get("request_id").and_then(|v| v.as_str()) {
            error.request_id = Some(self.redact(request_id));
        }
        error
    }

    /// Strips the secret key from anything an error may carry to logs.
    fn redact(&self, value: &str) -> String {
        value.replace(&self.secret_key, "[redacted]")
    }
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
    // Days from the civil date, after Howard Hinnant's algorithm.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = month as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let seconds = days * 86_400 + (hour * 3600 + minute * 60 + second) as i64;
    u64::try_from(seconds).ok()
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
