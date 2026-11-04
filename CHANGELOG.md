# Changelog

## 0.1.0 (unreleased)

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
- The package no longer ships `.cargo/config.toml` or `.gitignore`, and the
  lockfile no longer pins a yanked crate.
