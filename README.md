# fingerly

Server-side event reads, webhook verification and a same-origin proxy for Rust.
Rust 1.88 or newer, async on Tokio.

```sh
cargo add fingerly@0.3.0
```

```rust
use fingerly::{EventListParams, Fingerly, SuspectLevel};

let fingerly = Fingerly::new(std::env::var("FINGERLY_SECRET_KEY")?)?;

let event = fingerly.events().get(&request_id).await?;
let page = fingerly
    .events()
    .list(EventListParams::new().level(SuspectLevel::High).limit(50))
    .await?;
```

Event reads require `fly_sk_{production|staging|development}_…` keys. Requests
go to `https://api.fingerly.io`; `endpoint` on the builder overrides that for a
local API. Public, proxy, management, malformed and unsupported keys are
rejected before network access. Requests do not follow redirects. `get` and
`list` each perform one request and never retry.

`endpoint` is a bare origin only: `https://host` or `https://host:port`, with
no path, query, fragment, credentials, whitespace or control byte. Plain HTTP
is refused, except for `127.0.0.1`, `localhost` or `[::1]` with
`allow_insecure_loopback(true)`. Neither a construction error nor a connection
error repeats the endpoint or the key:

```rust
let fingerly = Fingerly::builder(std::env::var("FINGERLY_SECRET_KEY")?)
    .endpoint("http://127.0.0.1:8080")
    .allow_insecure_loopback(true)
    .build()?;
```

`Fingerly::new` returns a `Result`, so an invalid key or option fails at
construction and nothing is sent. The client holds a connection pool; build
one and clone it, and every clone shares the pool. Every client and proxy in
the process resolves names through one shared cache that performs a single
system lookup per host at a time and reuses it for 30 seconds, so a burst of
hundreds of requests reuses connections instead of opening one per request.
There is nothing to tune for a busy server. `Debug` output of every SDK value
shows keys and secrets as `[redacted]`.

## Deadlines and cancellation

Every request carries a deadline that covers reading the response body, so a
server that answers and then stalls times out like one that never answered. It
defaults to 5 seconds and is set with `.timeout(…)` on the builder.

Cancellation is ordinary Rust cancellation: drop the future and the request
stops. There is no separate cancellation token to thread through.

## Errors

Every call returns `fingerly::Result<T>`, whose error is one `Error` enum:

| Variant | When |
| --- | --- |
| `Config` | An option was rejected. Nothing was sent, and a retry will not help. |
| `Api` | The API answered with a status outside 2xx, redirects included. |
| `Timeout` | The request deadline elapsed. |
| `Connection` | The API could not be reached, or the connection failed mid-response. |
| `Decode` | The body was not the JSON this SDK expects, or was over 4 MiB. |

`Error::Api` carries `status`, and optional `code`, `details`, `request_id`
and `retry_after`. The secret key is stripped from all of them, and the
response body is never echoed into a message. `retry_after` is the number of
seconds from the `Retry-After` header, also reachable as
`error.retry_after()`; the SDK never retries a read itself. Only a
DeviceCheck spend is retried, as [DeviceCheck bits on iOS](#devicecheck-bits-on-ios)
describes.

```rust
match fingerly.events().get(&request_id).await {
    Ok(event) => { /* … */ }
    Err(error) if error.is_event_pending() => {
        let wait = error.retry_after().unwrap_or(2); // seconds
        /* not recorded yet: try again after `wait`, or verify asynchronously */
    }
    Err(error) if error.is_event_not_found() => { /* never issued, or past retention */ }
    Err(error) if error.status() == Some(429) => {
        let wait = error.retry_after().unwrap_or(1); // seconds
        /* back off for at least `wait` */
    }
    Err(error) => return Err(error),
}
```

A `404` from `get` carries one of two codes, each with a predicate, so
neither needs a status-and-code check:

- `error.is_event_pending()` (`ApiError::is_pending()`): the request id was
  accepted but its event is not recorded yet. It is not a verdict. Try again
  after `error.retry_after()` seconds, or verify asynchronously, for example
  from a webhook. The SDK never retries on its own.
- `error.is_event_not_found()` (`ApiError::is_not_found()`): the request id was
  never issued for this key's environment, or the event is past the 30-day
  retention.

## Unscored events

`Event::suspect_score` is an `Option<i32>` because `None` means unscored, which
must never be read as zero: a visitor about whom nothing fired scores 0, while
a submission that was never enriched has no score at all. `score()` and
`is_scored()` state that distinction at the call site.

```rust
let Some(score) = event.score() else {
    // Unscored. Decide on something else; do not treat it as clean.
    return Ok(Decision::Review);
};
```

`Event::raw` and `EventPage::raw` keep the response body exactly as it arrived,
so a field the API adds later is reachable without an SDK upgrade.

## Read an event you just identified

```rust
let event = fingerly.events().get(&request_id).await?;
```

If the event is not recorded yet, the error has `is_event_pending()` and a
`retry_after()`: try again after that many seconds, or verify asynchronously.
`is_event_not_found()` means the request id was never issued or the event is
past retention.

The archived `document` arrives moments after the event itself, so check
`has_document` rather than assuming it is there, and call
`event.parse_document()?` to decode it into `Option<EventDocument>` (including
`Attestation` and `EventRiskReport`). When a submission is unidentifiable
(`!event.is_identifiable()`, such as insufficient entropy, a genuine embedded
WebView, or an unmatched high-risk Web payload), `event.visitor_id` is `""`;
there are no `deferred_token`, `deferred_signals` or `supplements` fields in
`v: 3`.

The `fingerly::signals` module defines constants for every `v: 3` signal,
including `signals::ATTESTATION_FAILED` (`"attestation_failed"`),
`signals::ATTESTATION_DOWNGRADE` (`"attestation_downgrade"`),
`signals::DEVICE_INCONSISTENT` (`"device_inconsistent"`),
`signals::REPORT_INCOMPLETE` (`"report_incomplete"`),
`signals::PROBE_ERRORS` (`"probe_errors"`),
`signals::FETCH_METADATA_MISSING` (`"fetch_metadata_missing"`),
`signals::TAMPERING` (`"tampering"`),
`signals::CUSTOM_ROOT_CA` (`"custom_root_ca"`) and
`signals::SECONDARY_USER_PROFILE` (`"secondary_user_profile"`). A native
`Attestation` also carries `attest_skipped` (the app's reason for sending no
proof) and `downgrade` (the report named an install an attested device owns).

`Event::project_id` names the Fingerly project the event belongs to, as a UUID
string. It is `None` when the server is older than projects.

## Verify a backend action

Read the event with a server-only key. Check that its tag matches your action,
that it is recent, that its environment is correct, and that it was scored.
Apply your own policy to the server's verdict. Do not authorize an action using
scores or visitor identifiers supplied by the browser. Tags correlate events;
they do not replace your application's authentication or replay protection.
Never put a personal identifier (user ID, email, install ID, advertising ID) in
a tag: the server keeps tags in long-lived rollups.

```rust
use fingerly::{signals, Error, Event, Fingerly};

enum Verdict {
    Allow,
    Refuse,
    /// Not decided yet: ask the caller to come back after this many seconds.
    Pending(u64),
}

async fn verify(fingerly: &Fingerly, request_id: &str, tag: &str) -> Result<Verdict, Error> {
    let event: Event = match fingerly.events().get(request_id).await {
        Ok(event) => event,
        // Not decided yet, not fraud.
        Err(error) if error.is_event_pending() => {
            return Ok(Verdict::Pending(error.retry_after().unwrap_or(2)));
        }
        Err(error) if error.is_event_not_found() => return Ok(Verdict::Refuse),
        Err(error) => return Err(error),
    };
    if event.tag.as_deref() != Some(tag) || !event.is_scored() || !event.is_identifiable() {
        return Ok(Verdict::Refuse);
    }
    if event.triggers.iter().any(|t| t.signal == signals::ATTESTATION_FAILED) {
        return Ok(Verdict::Refuse);
    }
    if let Some(doc) = event.parse_document()? {
        let _ = doc.attestation;
    }
    Ok(Verdict::Allow)
}
```

## DeviceCheck bits on iOS

When DeviceCheck is turned on for your project's Apple key, Fingerly holds the
DeviceCheck token of an iOS identification for one hour. Your backend spends
it once, with this client, to read or to set the device's two bits. Apple
keeps the bits per device for your developer team, and they survive a
reinstall. They mean what you decide; Fingerly never reads or keeps them.

Apple treats a DeviceCheck token as single-use, so each held token pays for
one call: a read or a write, never both. To check a device and then mark it,
such as for a once-per-device free trial, use two identifications:

1. Query on the identification that asks for the trial. If the bit says the
   device already had one, refuse it.
2. Otherwise record the grant in your own data, have the app identify again,
   and write the bit with that second request ID. Until the write lands, your
   own record of the grant is what stops a second trial.

```rust
use fingerly::{DeviceCheckWrite, Error, Fingerly};

/// bit0 means "this device has had a free trial". The meaning is yours.
async fn trial_used_on_device(fingerly: &Fingerly, request_id: &str) -> Result<bool, Error> {
    match fingerly.device_check().query(request_id).await {
        Ok(bits) => Ok(bits.found && bits.bit0),
        // No token for this event: decide without the bits, not a verdict.
        Err(error) if error.is_device_check_not_held() || error.is_device_check_spent() => Ok(false),
        Err(error) => Err(error),
    }
}

/// Called with the request ID of the identification after the grant.
async fn mark_trial_used(fingerly: &Fingerly, request_id: &str) -> Result<bool, Error> {
    match fingerly
        .device_check()
        .write(request_id, DeviceCheckWrite::new().bit0(true))
        .await
    {
        Ok(_) => Ok(true),
        // Keep your record unmarked and write at the next identification.
        Err(error) if error.is_device_check_not_held() || error.is_device_check_spent() => Ok(false),
        Err(error) => Err(error),
    }
}
```

`query` returns `DeviceCheckBits` (`found`, `bit0`, `bit1`, and
`last_update` as `YYYY-MM` when Apple holds bits). `write` takes the bits to
set and returns `DeviceCheckWriteResult` with each bit it set; a bit left out
keeps its value, and a write that names neither bit is refused with
`Error::Config` before anything is sent.

A `503 device_check_unavailable`, a timeout or a connection failure leaves the
token held. The client retries those twice, with the identical request,
because the API accepts a retry of a held token only when it repeats the first
request: another operation or other bits answer `409 device_check_spent`. If
it still fails, retry the same call yourself within the hour. Nothing else is
retried. Each answer has a predicate on `Error`:

| Status | Code | Predicate |
| --- | --- | --- |
| 404 | `device_check_not_held` | `is_device_check_not_held()` |
| 409 | `device_check_spent` | `is_device_check_spent()` |
| 409 | `device_check_busy` | `is_device_check_busy()` |
| 409 | `credential_unavailable` | `is_credential_unavailable()` |
| 422 | `bits_required` | `is_bits_required()` |
| 422 | `apple_rejected` | `is_apple_rejected()`, with Apple's status in `apple_status()` |
| 503 | `device_check_unavailable` | `is_device_check_unavailable()` |

Never rely on the bits as the only fraud check, and give customers a way to
have them reset, which is a write of `false` at their next identification.

## Webhooks

```rust
let ok = fingerly::verify_webhook(
    &std::env::var("FINGERLY_WEBHOOK_SECRET")?,
    &body,
    headers.get("x-fingerly-timestamp").and_then(|v| v.to_str().ok()),
    headers.get("x-fingerly-signature").and_then(|v| v.to_str().ok()),
);
```

Verify the exact raw bytes before decoding them: re-serialising them changes
the digest. Signatures cover the timestamp and body. The default replay
tolerance is five minutes, changed with `WebhookVerifier::new(secret)
.tolerance(…)`. During a signing-secret rotation, any matching signature
among the first 32 in the comma-separated header is accepted. Malformed or missing input is a `false`
result, never a panic.

Verification proves authenticity and freshness. It does not deduplicate, so
persist processed `WebhookEvent::id` values as well. `WebhookEvent` decodes the
envelope every delivery shares and leaves `data` raw, so a new event type needs
no SDK upgrade.
`identification.completed` and `visitor.suspect` carry `data.project_id`;
`identification.refused` carries it only when the refused request named a known
key.

Webhook verification needs neither an HTTP stack nor an async runtime, so
`default-features = false` leaves a build that pulls in neither:

```toml
fingerly = { version = "0.3.0", default-features = false }
```

## Same-origin proxy

Content blockers refuse browser requests to third-party APIs, and a refused
identification is a visitor never identified. Mount the proxy on a path of your
own site and those requests become first-party. The proxy key is what lets that
hop declare the visitor's real address, origin and user agent; a public key
alone never can, so nobody can spoof them.

Create a proxy in the dashboard (**Integration > Proxy keys**), then mount the
service at the path it issued, here `/k7x2qm4a`. `FingerlyProxy` implements
`tower::Service` over `http::Request`, which axum mounts directly and hyper
serves through `hyper_util`:

```toml
[dependencies]
fingerly = "0.3.0"
axum = "0.8"
tokio = { version = "1", features = ["full"] }
```

```rust
use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use fingerly::FingerlyProxy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proxy = FingerlyProxy::builder()
        .proxy_key(std::env::var("FINGERLY_PROXY_KEY")?)
        .client_ip(|parts| {
            // The header your load balancer or CDN sets, else the TCP peer.
            if let Some(address) = parts.headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
                return address.to_owned();
            }
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(peer)| peer.ip().to_string())
                .unwrap_or_default()
        })
        .path("/k7x2qm4a")
        .build()?;

    // The proxy is the fallback too, so near misses such as `/k7x2qm4a/` get
    // the proxy's own uncacheable 404 instead of the router's.
    let app = axum::Router::new()
        .route_service("/k7x2qm4a", proxy.clone())
        .fallback_service(proxy);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    // ConnectInfo is only there when the app is served with it.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
```

Trust that header only when traffic can reach the server through that load
balancer or CDN alone; otherwise a visitor can set it.

Then point the browser SDK at the same path:

```ts
const fingerly = await load({ apiKey: 'fly_pk_…', endpoints: '/k7x2qm4a' })
```

For a framework that does not speak `tower`, such as actix-web, warp or Rocket,
`proxy.handle(request).await` takes an `http::Request` and returns an
`http::Response` directly. Those frameworks hand you the body already read, so
rebuild the request around it, keep the raw request target as its URI, and set
`.path(…)`: those routers can also match percent-encoded, trailing-slash or
doubled-slash forms of the path, and the proxy compares the raw target exactly.
Give the framework's own body limit room for
`max_body_bytes` (actix-web's `PayloadConfig` defaults to 256 KiB), and bound
its body read yourself, because `timeout` only starts once `handle` is called.

### What the proxy does

Browser and proxied native client SDKs post a single `v: 3` identification
envelope to that one path, and the proxy forwards its raw request body bytes
verbatim as a `POST` to Fingerly's one ingest URL,
`https://api.fingerly.io/api/v1/ingest` (`api_version` changes the `v1`). Any
method other than `POST` (plus `OPTIONS` when `allowed_origins` is configured)
gets `405`, and any subpath (including retired `/supplement` paths) gets `404`.
Event reads need a secret key and stay unreachable from a browser by
construction.

The proxy takes only a proxy key,
`fly_px_{production|staging|development}_…`; `build()` returns a configuration
error when it is missing or malformed. The caller's `x-api-key` must be a public
key, `fly_pk_…`, from the same environment as the proxy key. A missing header, a
public key of another environment, a secret `fly_sk_` key or any other value is
answered `401` (`text/plain; charset=utf-8`, `Cache-Control: no-store`) with
nothing forwarded. Upstream, every request carries the proxy key as
`x-fingerly-proxy-key` and the browser's public key as `x-api-key`; a secret key
is never sent. Incoming headers follow the sanitize-and-restore
sequence: all incoming `x-fingerly-*`, `cookie` and `authorization` headers are
stripped, restoring `x-fingerly-sdk-platform` only when it matches an exact
lowercase native or bridge platform (`ios`, `android`, `react-native`,
`react-native-ios`, `react-native-android`, `flutter`, `flutter-ios`,
`flutter-android`, `lynx-ios`, `lynx-android`, `capacitor`,
`kotlin-multiplatform`). A request carries one channel upstream: when `Origin`
is present it is sent as `x-fingerly-origin` and the platform header is not
sent, as on a direct call to the API. When both `Origin` and a validated
`x-fingerly-sdk-platform` are absent, the request is rejected locally with `400`
(`missing_origin`), and `x-fingerly-origin` is never synthesized from `Host`,
`Referer` or the request URL. Bodies over 1 MiB get `413`. Alongside verified
proxy metadata (`x-fingerly-host` included), only `content-type`, `x-api-key`,
`user-agent`, `idempotency-key`, `sec-fetch-*` and `sec-ch-ua-*` are forwarded;
customer cookies and authorization headers never are. The proxy reports itself
upstream as `rust/0.3.0`, which the dashboard shows per proxy.

Only `Content-Type`, `X-Request-Id`, `RateLimit-Limit`, `RateLimit-Remaining`
and `Retry-After` are relayed back, plus `Cache-Control: no-store`, so nothing
on the response names Fingerly.

One deadline, `timeout` (5 seconds by default), covers reading the browser's
body and the whole upstream exchange, so a trickling answer cannot stretch it.
When it passes during the upstream call the browser gets `504`; any other
upstream failure (refused, reset, DNS, a truncated or malformed answer, an
answer over 4 MiB, a redirect, a status outside 200 to 599) gets `502`.
Redirects are never followed, also with a caller-supplied
`http_client_builder`. A browser too slow to send its body gets `408`.
Each carries a short `text/plain` body and `Cache-Control: no-store`. The
answer is read in full before anything is relayed, so a broken upstream never
reaches the browser as a `200`. A visitor who disconnects drops the service
future, which cancels the upstream call.

Each upstream failure is reported once: to `on_error` if you set one,
otherwise as one `tracing` warning under the `fingerly::proxy` target. The line
names the kind of failure only, never the key or the upstream address.

```rust
let proxy = FingerlyProxy::builder()
    .proxy_key(std::env::var("FINGERLY_PROXY_KEY")?)
    .client_ip(|_parts| "203.0.113.7".to_owned())
    .on_error(|failure| eprintln!("identification proxy: {failure}"))
    .build()?;
```

Set `path` wherever the service sees the original path. The proxy then answers
only that path, exactly: a trailing or doubled slash, a dot segment, an encoded
character, a different case or a path under it all get `404` with
`Cache-Control: no-store`, and only an exact uppercase `POST` is forwarded.
Mounted as the fallback as well, as above, the proxy gives that answer for
every near miss. An application with a fallback of its own keeps it, mounts
only the route, and the router answers paths next to it. Without `path`, the
proxy answers whatever the router sends it.

Do not set it under `nest_service` or any other router that strips the mount
before the service sees it: the path would never match.

`upstream` is for a test harness and is a bare origin only: `https://host` or
`https://host:port`, with no path, query, fragment, credentials, whitespace or
control byte. Plain HTTP is refused, except for `127.0.0.1`, `localhost` or
`[::1]` with `allow_insecure_loopback(true)`:

```rust
let proxy = FingerlyProxy::builder()
    .proxy_key(std::env::var("FINGERLY_PROXY_KEY")?)
    .upstream("http://127.0.0.1:8080")
    .allow_insecure_loopback(true)
    // ...
    .build()?;
```

> **`client_ip` is the one thing you must get right.** Resolve it from a header
> your own infrastructure sets, such as your load balancer's or CDN's, and fall
> back to the TCP peer. Never read the left-most `X-Forwarded-For` value: the
> visitor writes it. The callback receives the request's `Parts`, so a
> framework extension such as axum's `ConnectInfo` is reachable from inside
> it. It must return exactly one IPv4 or IPv6 address. Anything else (empty, a
> list, a port) is a configuration error: the proxy answers `500` with "The
> client IP callback returned no valid address", calls nothing upstream, and
> reports it once.

## Features

| Feature | Default | What it adds |
| --- | --- | --- |
| `client` | yes | `Fingerly`, event reads and DeviceCheck bits, over reqwest and Tokio. |
| `proxy` | yes | `FingerlyProxy`, a `tower::Service`. Implies `client`. |
| `rustls` | yes | TLS through rustls. |
| `native-tls` | no | TLS through the platform's own stack instead. |
| `time` | no | `OffsetDateTime` accessors for event timestamps and list windows. |

Turn `rustls` off and `native-tls` on together; picking neither leaves the
client unable to reach an HTTPS endpoint.

## Development and release preparation

```sh
cargo fmt --all --check
cargo clippy --all-features --all-targets -- -D warnings
cargo test --all-features
cargo run --example sync_contract     # refresh the vendored contract snapshot
```

The vendored synthetic contract snapshot in `contract/` makes tests independent
of sibling repositories. To update it from the integration workspace, set
`FINGERLY_CONTRACT_DIR` to its `contract` directory. The snapshot's hashes are
checked by `cargo test`, so there is no separate check step. Never put
production secrets in fixtures.

`Cargo.lock` is committed and CI builds `--locked`, so the 1.88 floor is a
verified fact rather than a claim. `.cargo/config.toml` turns on the
MSRV-aware resolver for this repository, which is what keeps a dependency
bump from silently raising it.

## Source structure

`client.rs` holds `Fingerly` and its builder. `transport.rs` performs
authenticated requests and maps failures to `Error::Api`. `events.rs` owns the
event reads and the list filters; `models.rs` owns the types
they decode into. `webhooks.rs` verifies signatures and needs nothing else in
the crate. `proxy.rs` is the same-origin service. `config.rs` validates every
caller-supplied option: keys, origins, API versions, proxy paths and durations,
all before any network access. `errors.rs` holds the error type.
