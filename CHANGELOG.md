# Changelog

## 0.4.1

- Each `AttestSkippedReason` variant documents when the iOS and Android SDKs
  send it.
- The vendored OpenAPI contract declares the enum values of every closed set
  the API reports, matching the SDK's enums.

## 0.4.0

- Breaking: every closed set the API reports is an enum with an
  `Other(String)` variant that keeps a value this build does not know, so a
  value the server adds later still deserializes: `Signal` (every signal group
  and raw detector, including `VpnPublic`, `Proxy`, `RepeatedReinstall`,
  `DeviceActivityHigh` and the rest), `SuspectLevel`, `Confidence`,
  `AttestationState`, `AttestationStatus`, `AttestSkippedReason`,
  `EventState`, `AnonymityNetwork` (including `Relay`), `Environment`,
  `RiskPlatform`, `RiskSource`, `WebhookEventType` and `WebhookEnvironment`.
  Each has `as_str()`, `is_known()`, `KNOWN`, `From<&str>`, `From<String>`,
  `Display` and equality with `str`. The matching fields on `Event`,
  `EventTrigger`, `EventRiskTrigger`, `EventRiskReport`, `Attestation` and
  `WebhookEvent` now have those types, and the `signals` module of string
  constants is removed in favour of `Signal`.
- Breaking: `SuspectLevel` is no longer `Copy`, and `as_str()` borrows.
- Breaking: `Verification::reason` is a `VerifyReason` rather than an
  `Option`, with `VerifyReason::Ok` (wire value `""`) when every check passed.
- `Signal` matches the server's signal list, including `repeated_reinstall`,
  `device_activity_high` and `device_activity_very_high`, and
  `AnonymityNetwork` documents `relay`.

## 0.3.0

- Added `events().verify(request_id, VerifyOptions)`, which reads an event and
  checks it exists, is recent (`max_age_seconds`, 300 by default), carries the
  expected `tag`, is identifiable and scored, then consumes it once, returning
  a `Verification` with a `VerifyReason`; and `events().consume(request_id)`,
  returning `ConsumedEvent`, with `Error::is_event_already_consumed()` and
  `Error::consumed_at()` for `409 event_already_consumed`.
- `Fingerly::device_check()` reads and writes the DeviceCheck bits of the
  device behind an iOS event: `query(request_id)` returns `DeviceCheckBits`,
  `write(request_id, DeviceCheckWrite)` returns `DeviceCheckWriteResult`. A
  `503`, a timeout or a connection failure is retried twice with the identical
  request, and `Error` has a predicate for each DeviceCheck code, with
  `apple_status()` for `apple_rejected`.
- Refreshed the vendored v3 OpenAPI and contract fixtures, removing retired
  deferred supplement schemas and routes, and added `Event::reason`,
  `Event::is_identifiable()`, `Event::parse_document()`, `EventDocument`,
  `Attestation`, and the `signals` module covering all v3 signal identifiers
  (`ATTESTATION_FAILED`, `ATTESTATION_DOWNGRADE`, `DEVICE_INCONSISTENT`,
  `REPORT_INCOMPLETE`, `PROBE_ERRORS`, `FETCH_METADATA_MISSING`,
  `WEB_TICKET_MISSING`, `WEB_TICKET_INVALID`, `TAMPERING`, `CUSTOM_ROOT_CA`,
  `SECONDARY_USER_PROFILE`), with `attest_skipped` and
  `downgrade` on `Attestation`.
- Updated `FingerlyProxy` to enforce the single-path `proxy.md` relay contract:
  sanitize-and-restore validation of `x-fingerly-sdk-platform`, rejection with
  HTTP `400` (`missing_origin`) when both `Origin` and a valid
  `x-fingerly-sdk-platform` are absent (never synthesising `x-fingerly-origin`),
  forwarding of `Sec-Fetch-*` and `Sec-CH-UA-*` client metadata headers,
  optional cross-origin `allowed_origins` CORS handling, and verbatim raw-byte
  forwarding.
- `FingerlyProxy` takes only a `proxy_key` and always checks the caller's
  public key; a secret key is never sent upstream.

## 0.2.0

- `Event::project_id` exposes the Fingerly project an event belongs to, on
  single reads and listing rows. It is `None` when the server does not send it.
  Webhooks carry it as `data.project_id`.
- `Event::ip_address` is gone; the API no longer returns the address. The new
  `Event::ip_network` (`Option<String>`) holds the network the request came
  from: an IPv4 /24 or an IPv6 /40, such as `203.0.113.0/24`.
- `Event::deferred_signals` is gone; the single-event read no longer returns
  the deferred report.
- `Event::document` is now an allow-listed view of the archived submission
  (no raw signals, user agent or address). It stays opaque JSON.
- The vendored contract snapshot is refreshed.

## 0.1.0

First release: event reads, webhook verification and the same-origin proxy.
Changes made during pre-release testing:

- Every client and proxy resolves names through one shared cache: one system
  lookup per host at a time, reused for 30 seconds. With reqwest's default
  resolver, a burst of 200 requests in flight against a hostname opened about
  seven connections per request in flight and started 512 blocking threads.
- The proxy reads the upstream answer in chunks up to 4 MiB; anything larger is
  a `502` instead of being buffered without a bound.
- The proxy answers `504` when its deadline passes during the upstream call,
  `502` for any other upstream failure and `408` for a browser too slow to send
  its body. Each upstream failure goes to the new `on_error` hook as a
  `ProxyError`, or is logged as one `tracing` warning under `fingerly::proxy`.
- `client_ip` must return exactly one IPv4 or IPv6 address; anything else is
  answered `500` without calling upstream and reported once.
- The proxy path is matched exactly: no trailing slash, dot segment, encoded
  character or case difference.
- `Debug` output of `FingerlyBuilder`, `WebhookVerifier`, the client, the proxy
  and the proxy builder shows credentials as `[redacted]`.
- `ApiError::retry_after` and `Error::retry_after()` carry the `Retry-After`
  seconds; the request id falls back to the `X-Request-Id` header. Read answers
  over 4 MiB are refused as `Error::Decode`.
- Webhook verification checks at most 32 signature candidates.
- `Error::is_event_pending()` and `ApiError::is_pending()` recognise
  `404 event_pending` (the request id was accepted, the event is not recorded
  yet; `retry_after` is set). `is_event_not_found()`, with the new
  `ApiError::is_not_found()`, still matches only `event_not_found` (never
  issued, or past retention). Neither is retried.
- `events().get` refuses an empty, `.` or `..` request id as `Error::Config`.
  Dot segments are resolved even when percent-encoded, so these would have
  sent the secret key to another route.
- A non-2xx read answer is always `Error::Api` with its status and
  `retry_after`, even when its body is over 4 MiB or breaks off.
- A panic in `client_ip` is answered `500` and reported once, like an invalid
  return value, and a panic in `on_error` no longer loses the browser's answer.
- The package no longer ships `.cargo/config.toml` or `.gitignore`, and the
  lockfile no longer pins a yanked crate.
