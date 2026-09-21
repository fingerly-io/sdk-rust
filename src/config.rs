//! Validation and normalisation of caller-supplied configuration.
//!
//! Everything here runs before any network access, so a misconfigured client
//! fails at construction, never mid-request and never against the wrong host.

use std::time::Duration;

use crate::errors::{Error, Result};

/// Kinds of key Fingerly issues: browser public, server secret, proxy.
///
/// A build without the proxy never parses the first and third, but the parser
/// still has to know them so it can refuse them by name.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyKind {
    Public,
    Secret,
    Proxy,
}

impl KeyKind {
    /// The `pk`/`sk`/`px` segment a key of this kind carries.
    fn segment(self) -> &'static str {
        match self {
            KeyKind::Public => "pk",
            KeyKind::Secret => "sk",
            KeyKind::Proxy => "px",
        }
    }

    /// The word used in the error message, so it names the key the caller
    /// should have passed rather than the one they did.
    fn label(self) -> &'static str {
        match self {
            KeyKind::Public => "public",
            KeyKind::Secret => "secret",
            KeyKind::Proxy => "proxy",
        }
    }
}

/// The environment a key is scoped to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeyScope {
    /// The deployment the key belongs to. Keys never cross environments.
    pub environment: Environment,
}

/// The one Fingerly API origin.
pub(crate) const DEFAULT_ENDPOINT: &str = "https://api.fingerly.io";

/// Deployment a key belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Environment {
    Production,
    Staging,
    Development,
}

impl Environment {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "production" => Some(Environment::Production),
            "staging" => Some(Environment::Staging),
            "development" => Some(Environment::Development),
            _ => None,
        }
    }
}

/// Parses a Fingerly key and asserts it is of the expected kind.
///
/// The shape is `fly_{pk|sk|px}_{environment}_{secret}`, where the secret is
/// one or more of `A-Za-z0-9_-`. Splitting into exactly four parts leaves the
/// secret's own underscores in the secret, where they belong.
pub(crate) fn parse_key(key: &str, expected: KeyKind) -> Result<KeyScope> {
    let refuse = || {
        Error::config(format!(
            "a valid Fingerly {} key is required",
            expected.label()
        ))
    };

    let mut parts = key.splitn(4, '_');
    let (Some("fly"), Some(kind), Some(environment), Some(secret)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(refuse());
    };

    if kind != expected.segment() || secret.is_empty() {
        return Err(refuse());
    }
    // The secret is the only free-form part, and it may not smuggle in a path
    // separator, whitespace or a newline: it is spliced into a header.
    if !secret
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(refuse());
    }

    let Some(environment) = Environment::parse(environment) else {
        return Err(refuse());
    };
    Ok(KeyScope { environment })
}

/// Normalises a caller-supplied API origin.
///
/// Credentials, queries and fragments are refused: they would be attached to
/// every authenticated request, and embedded credentials would leak on a
/// redirect. The result has no trailing slash.
pub(crate) fn normalize_origin(value: &str) -> Result<String> {
    let refuse =
        || Error::config("endpoint must be an HTTP(S) URL without credentials, query, or fragment");

    let url = url::Url::parse(value).map_err(|_| Error::config("endpoint is not a URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(refuse());
    }
    Ok(value.trim_end_matches('/').to_owned())
}

/// Validates an API route version before it is spliced into a URL.
///
/// The shape is `v` followed by a positive integer with no leading zero.
pub(crate) fn normalize_api_version(version: &str) -> Result<String> {
    let refuse = || Error::config(r#"api_version must be a version such as "v1" or "v2""#);

    let Some(digits) = version.strip_prefix('v') else {
        return Err(refuse());
    };
    if !digits.starts_with(['1', '2', '3', '4', '5', '6', '7', '8', '9'])
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(refuse());
    }
    Ok(version.to_owned())
}

/// Validates a duration option. Zero is a deadline that has already passed.
pub(crate) fn positive_duration(value: Duration, name: &str) -> Result<Duration> {
    if value.is_zero() {
        return Err(Error::config(format!("{name} must be a positive duration")));
    }
    Ok(value)
}

/// Validates the local mount path and drops trailing slashes.
#[cfg(feature = "proxy")]
pub(crate) fn normalize_prefix(value: &str) -> Result<String> {
    let prefix = value.trim_end_matches('/');
    if !prefix.starts_with('/') || prefix.contains(['?', '#']) {
        return Err(Error::config("prefix must be an absolute URL path"));
    }
    Ok(prefix.to_owned())
}
