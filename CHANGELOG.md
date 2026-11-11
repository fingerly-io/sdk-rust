# Changelog

## Unreleased

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
