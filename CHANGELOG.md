# Changelog

## 0.5.0

- Added `AgentSightings`, which reports the pages your server served to
  Fingerly in the background, so AI crawlers and fetchers that never run a
  page's JavaScript are seen, and remembers what the API answered about each.
  `layer()` is a `tower::Layer` that axum mounts directly: it reports each
  in-scope response after it is produced, never delays it, and puts an
  `AgentLookup` in the request's extensions. `lookup(&request)` and
  `lookup_parts(&parts)` answer from memory only, with `AgentLookup::Known`
  or `AgentLookup::Unknown` ("serve as usual"). The builder takes the same
  `client_ip` callback as the proxy, plus `cache_capacity`, `content_types`,
  `include_paths`, `exclude_paths` and `on_error`; `report(&parts, headers)`
  serves frameworks that do not speak tower, `flush()` serverless handlers and
  `close()` shutdown, and `dropped()` counts the requests not buffered. It
  fails open on every API failure, holds at most 1000 pending requests, and
  `AgentSightingsErrorKind` names each failure it handled.
- Added `Fingerly::agents()` with `AgentsClient::sightings(&items)`, the single
  call underneath, and the `AgentSighting`, `AgentAnswer` and `AgentAnswers`
  models. `ApiError::rate_limit_scope()` and `Error::rate_limit_scope()` read
  `Fingerly-RateLimit-Scope` on a `429`.
- Breaking: `Event::visitor_kind` is a `VisitorKind` (`Human`, `AiBot`,
  `Automation`, `SearchCrawler`) rather than a string, and `Event::ai` is the
  `AiAgent` behind an AI agent event: its `name`, `provider`, `purpose`
  (`AiPurpose`), `runtime` (`AiRuntime`), whether it `declared` itself, and
  its `verification` (`AiVerificationMethod` and `AiVerificationResult`).
- `EventListParams` filters by `kind`, `ai_provider` and `ai_purpose`.
- `Signal` adds `AiSpoofed` and `IdentityObfuscated`. Breaking: `VpnTimezone`
  is removed.
- `FingerlyProxy` forwards the Web Bot Auth `Signature`, `Signature-Input` and
  `Signature-Agent` headers, each dropped when over 4096 bytes.
- Agent sightings never stop reporting because a `flush()` or `close()` was
  cancelled (for example under a `tokio::time::timeout`): the cancelled batch
  is dropped and its place in the buffer freed, instead of filling the buffer
  for good.
- On a Tokio runtime built without timers, the sightings background task is
  started again at most once a minute and reported as
  `AgentSightingsErrorKind::FlusherStopped`, instead of panicking on every
  request.
- A `429` pauses agent sightings for at most a day, whatever its
  `Retry-After` asks for, so a huge value can no longer stop reporting for
  the life of the process.
- A Web Bot Auth header that passes 4096 bytes once each byte that is not
  UTF-8 is replaced with U+FFFD is left out of a sighting, as a longer one
  is, so a single visitor's request can no longer make the API refuse the
  whole batch it was sent in.
- A `Host` over 4096 bytes as sent is left out of a sighting, as a longer
  Web Bot Auth header is, and a request whose method is over 4096 bytes is
  not reported, as one with a longer user agent is not, so every batch fits
  the API's request size limit and none is refused for one visitor's
  request.
- An answer item `AgentAnswers` cannot read keeps its place as
  `AgentAnswer::default()` (a `ttl` of 0, never remembered), so one
  malformed item leaves only its own request unknown instead of dropping
  the whole batch.
- `VisitorKind::Unknown` names the answer for a reported request the server
  could not use. It comes with a `ttl` of 0, so it is never remembered and
  that request's lookup stays `AgentLookup::Unknown`; the rest of the batch
  is answered as usual. A `422` now means no item in the batch was usable.
- `flush()` and `close()` send their own batches after the one in flight on
  a slow API, instead of waiting out the background task's run of every due
  batch and returning with nothing sent.
- The README example closes `AgentSightings` behind axum's
  `with_graceful_shutdown` on SIGTERM and Ctrl-C, so buffered sightings are
  sent when the process is stopped.
- The README and `DeviceCheckClient` describe one read and one write token
  per identification: a check-then-mark flow reads and writes on the same
  request ID.

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
