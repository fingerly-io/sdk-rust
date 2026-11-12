<p align="center">
  <a href="https://fingerly.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/fingerly-io/.github/main/assets/logo-dark.svg">
      <img src="https://raw.githubusercontent.com/fingerly-io/.github/main/assets/logo-light.svg" alt="Fingerly" height="44">
    </picture>
  </a>
</p>

<p align="center"><b>Fingerly for Rust</b><br>Read device intelligence events, verify webhooks and serve the browser SDK from your own domain.</p>

<p align="center">
  <a href="https://crates.io/crates/fingerly"><img src="https://img.shields.io/crates/v/fingerly?style=flat-square" alt="crates.io version"></a>
  <a href="https://github.com/fingerly-io/sdk-rust/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/fingerly-io/sdk-rust/ci.yml?style=flat-square&label=ci" alt="CI status"></a>
  <a href="https://github.com/fingerly-io/sdk-rust/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/rust-1.88%2B-orange?style=flat-square" alt="Rust 1.88 or newer">
  <a href="https://docs.fingerly.io/docs/sdks/rust"><img src="https://img.shields.io/badge/docs-docs.fingerly.io-111827?style=flat-square" alt="Documentation"></a>
</p>

<p align="center"><img src="https://raw.githubusercontent.com/fingerly-io/.github/main/assets/banner.webp" alt="Fingerly" width="100%"></p>

## What is this

The `fingerly` crate is the server-side SDK for Rust, async on Tokio. It reads
Fingerly events with a secret key, verifies webhook signatures and relays the
browser SDK's traffic through your own domain with a same-origin proxy. It is
for backends that protect signups, logins and payments from fraud and abuse.
[Fingerly](https://fingerly.io) identifies the device behind each session and
scores how suspicious it is.

## Getting started

1. **Prerequisites.** A Fingerly account and a secret key (`fly_sk_...`). See
   [API keys and environments](https://docs.fingerly.io/docs/api-keys). Rust
   1.88 or newer.
2. **Install.**

   ```sh
   cargo add fingerly
   ```

3. **Read an event.**

   ```rust
   use fingerly::{EventListParams, Fingerly, SuspectLevel};

   let fingerly = Fingerly::new(std::env::var("FINGERLY_SECRET_KEY")?)?;

   let event = fingerly.events().get(&request_id).await?;
   let page = fingerly
       .events()
       .list(EventListParams::new().level(SuspectLevel::High).limit(50))
       .await?;
   ```

4. **Verify a webhook.**

   ```rust
   let ok = fingerly::verify_webhook(
       &std::env::var("FINGERLY_WEBHOOK_SECRET")?,
       &body,
       headers.get("x-fingerly-timestamp").and_then(|v| v.to_str().ok()),
       headers.get("x-fingerly-signature").and_then(|v| v.to_str().ok()),
   );
   ```

Full guide: [docs.fingerly.io/docs/sdks/rust](https://docs.fingerly.io/docs/sdks/rust).

## Choose what you need

| I want to | Use | Read |
| --- | --- | --- |
| Read an event after the browser identified a visitor | `Fingerly` and `events().get` / `list` | [Read events](#read-events) |
| Check a webhook delivery is genuine | `verify_webhook` and `WebhookVerifier` | [Verify webhooks](#verify-webhooks) |
| Keep the browser SDK first-party, away from content blockers | `FingerlyProxy`, a `tower::Service` | [First-party proxy](#first-party-proxy-same-origin) |

On this page: [Read events](#read-events) · [Verify webhooks](#verify-webhooks) · [First-party proxy](#first-party-proxy-same-origin) · [Features](#features) · [Requirements](#requirements) · [Development](#development-and-release-preparation) · [Documentation](#documentation) · [Help](#help) · [Licence](#licence)

## Read events

Event reads require `fly_sk_{production|staging|development}_…` keys. Requests
go to `https://api.fingerly.io`; `endpoint` on the builder overrides that for a
local API. Public, proxy, management, malformed and unsupported keys are
rejected before network access. Requests do not follow redirects. `get` and
`list` each perform one request and never retry.

`Fingerly::new` returns a `Result`, so an invalid key or option fails at
construction and nothing is sent. The client holds a connection pool; build
one and clone it, and every clone shares the pool. Every client and proxy in
the process resolves names through one shared cache that performs a single
system lookup per host at a time and reuses it for 30 seconds, so a burst of
hundreds of requests reuses connections instead of opening one per request.
There is nothing to tune for a busy server. `Debug` output of every SDK value
shows keys and secrets as `[redacted]`.

### Deadlines and cancellation

Every request carries a deadline that covers reading the response body, so a
server that answers and then stalls times out like one that never answered. It
defaults to 5 seconds and is set with `.timeout(…)` on the builder.

Cancellation is ordinary Rust cancellation: drop the future and the request
stops. There is no separate cancellation token to thread through.

### Errors

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
`error.retry_after()`; the SDK never retries a read itself.

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

| Predicate | Meaning |
| --- | --- |
| `error.is_event_pending()` (`ApiError::is_pending()`) | The request id was accepted but its event is not recorded yet. It is not a verdict. Try again after `error.retry_after()` seconds, or verify asynchronously, for example from a webhook. The SDK never retries on its own. |
| `error.is_event_not_found()` (`ApiError::is_not_found()`) | The request id was never issued for this key's environment, or the event is past the 30-day retention. |

### Unscored events

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

### Read an event you just identified

```rust
let event = fingerly.events().get(&request_id).await?;
```

If the event is not recorded yet, the error has `is_event_pending()` and a
`retry_after()`: try again after that many seconds, or verify asynchronously.
`is_event_not_found()` means the request id was never issued or the event is
past retention.

The archived `document` arrives moments after the event itself, so check
`has_document` rather than assuming it is there.

`Event::project_id` names the Fingerly project the event belongs to, as a UUID
string. It is `None` when the server is older than projects.

### Verify a backend action

Read the event with a server-only key. Check that its tag matches your action,
that it is recent, that its environment is correct, and that it was scored.
Apply your own policy to the server's verdict. Do not authorize an action using
scores or visitor identifiers supplied by the browser. Tags correlate events;
they do not replace your application's authentication or replay protection.
Never put a personal identifier (user ID, email, install ID, advertising ID) in
a tag: the server keeps tags in long-lived rollups.

```rust
use fingerly::{Error, Event, Fingerly};

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
    if event.tag.as_deref() != Some(tag) || !event.is_scored() {
        return Ok(Verdict::Refuse);
    }
    Ok(Verdict::Allow)
}
```

## Verify webhooks

The call is in [Getting started](#getting-started). Verify the exact raw bytes
before decoding them: re-serialising them changes the digest.

| Behaviour | Detail |
| --- | --- |
| What a signature covers | the timestamp and the body |
| Replay tolerance | five minutes by default, changed with `WebhookVerifier::new(secret).tolerance(…)` |
| Secret rotation | any matching signature among the first 32 in the comma-separated header is accepted |
| Malformed or missing input | a `false` result, never a panic |
| Deduplication | verification proves authenticity and freshness only; persist processed `WebhookEvent::id` values as well |

`WebhookEvent` decodes the envelope every delivery shares and leaves `data`
raw, so a new event type needs no SDK upgrade. `identification.completed` and
`visitor.suspect` carry `data.project_id`; `identification.refused` carries it
only when the refused request named a known key.

Webhook verification needs neither an HTTP stack nor an async runtime, so
`default-features = false` leaves a build that pulls in neither:

```toml
fingerly = { version = "0.2", default-features = false }
```

## First-party proxy (same-origin)

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
fingerly = "0.2"
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
        .build()?;

    let app = axum::Router::new().route_service("/k7x2qm4a", proxy);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    // ConnectInfo is only there when the app is served with it.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
```

Trust that header only when traffic can reach the server through that load
balancer or CDN alone; otherwise a visitor can set it.

> **`client_ip` is the one thing you must get right.** Resolve it from a header
> your own infrastructure sets, such as your load balancer's or CDN's, and fall
> back to the TCP peer. Never read the left-most `X-Forwarded-For` value: the
> visitor writes it. The callback receives the request's `Parts`, so a
> framework extension such as axum's `ConnectInfo` is reachable from inside
> it. It must return exactly one IPv4 or IPv6 address. Anything else (empty, a
> list, a port) is a configuration error: the proxy answers `500` with "The
> client IP callback returned no valid address", calls nothing upstream, and
> reports it once.

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

| Rule | Behaviour |
| --- | --- |
| Upstream | The browser SDK posts both of its calls to the one path, and the proxy forwards each, as a `POST`, to Fingerly's one ingest URL, `https://api.fingerly.io/api/v1/ingest` (`api_version` changes the `v1`). |
| Other methods | `405` |
| Event reads | Need a secret key and stay unreachable from a browser by construction. |
| Public key | The browser must present a public key from the same environment as the proxy key, or the request gets `401`. |
| Body size | Bodies over 1 MiB get `413`. |
| Forwarded upstream | Only the content type, the visitor metadata Fingerly needs, and an `Idempotency-Key`. Customer cookies and authorization headers never are. |
| Proxy identity | The proxy reports itself upstream as `rust/0.2.0`, which the dashboard shows per proxy. |
| Relayed back | Only `Content-Type`, `X-Request-Id`, `RateLimit-Limit`, `RateLimit-Remaining` and `Retry-After`, plus `Cache-Control: no-store`, so nothing on the response names Fingerly. |
| Deadline | One deadline, `timeout` (5 seconds by default), covers reading the browser's body and the whole upstream exchange, so a trickling answer cannot stretch it. |
| Deadline passes during the upstream call | `504` |
| Any other upstream failure | `502`: refused, reset, DNS, a truncated or malformed answer, an answer over 4 MiB. |
| Browser too slow to send its body | `408` |
| Error responses | Each carries a short `text/plain` body and `Cache-Control: no-store`. |
| Broken upstream | The answer is read in full before anything is relayed, so a broken upstream never reaches the browser as a `200`. |
| Visitor disconnects | Dropping the service future cancels the upstream call. |

Each upstream failure is reported once: to `on_error` if you set one,
otherwise as one `tracing` warning under the `fingerly::proxy` target.

```rust
let proxy = FingerlyProxy::builder()
    .proxy_key(std::env::var("FINGERLY_PROXY_KEY")?)
    .client_ip(|_parts| "203.0.113.7".to_owned())
    .on_error(|failure| eprintln!("identification proxy: {failure}"))
    .build()?;
```

`path` is optional. Leave it unset when the router already sends only the
issued path to the service, as `route_service` does. Set it when the service
sees more than that, as a fallback does, and the proxy answers only that path,
exactly: a trailing or doubled slash, a dot segment, an encoded character, a
different case or a path under it all get `404`:

```rust
let proxy = FingerlyProxy::builder()
    .proxy_key(std::env::var("FINGERLY_PROXY_KEY")?)
    .path("/k7x2qm4a")
    // ...
    .build()?;

let app = axum::Router::new().fallback_service(proxy);
```

Do not set it under `nest_service` or any other router that strips the mount
before the service sees it: the path would never match.

## Features

| Feature | Default | What it adds |
| --- | --- | --- |
| `client` | yes | `Fingerly` and event reads, over reqwest and Tokio. |
| `proxy` | yes | `FingerlyProxy`, a `tower::Service`. Implies `client`. |
| `rustls` | yes | TLS through rustls. |
| `native-tls` | no | TLS through the platform's own stack instead. |
| `time` | no | `OffsetDateTime` accessors for event timestamps and list windows. |

Turn `rustls` off and `native-tls` on together; picking neither leaves the
client unable to reach an HTTPS endpoint.

## Requirements

Rust 1.88 or newer (`rust-version` in `Cargo.toml`), async on Tokio. CI builds
on 1.88 and on stable.

## Development and release preparation

<details>
<summary>Checks, contract snapshot, MSRV, source structure</summary>

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

### Source structure

`client.rs` holds `Fingerly` and its builder. `transport.rs` performs
authenticated requests and maps failures to `Error::Api`. `events.rs` owns the
event reads and the list filters; `models.rs` owns the types
they decode into. `webhooks.rs` verifies signatures and needs nothing else in
the crate. `proxy.rs` is the same-origin service. `config.rs` validates every
caller-supplied option: keys, origins, API versions, proxy paths and durations,
all before any network access. `errors.rs` holds the error type.

</details>

## Documentation

- [Rust SDK guide](https://docs.fingerly.io/docs/sdks/rust)
- [Webhooks](https://docs.fingerly.io/docs/webhooks)
- [Proxy integrations](https://docs.fingerly.io/docs/proxy-integrations)
- [API reference](https://docs.fingerly.io/reference/overview)
- [API documentation on docs.rs](https://docs.rs/fingerly)

## Help

Open an issue on [this repository](https://github.com/fingerly-io/sdk-rust/issues), or write to
[support@fingerly.io](mailto:support@fingerly.io). Report security issues to
[security@fingerly.io](mailto:security@fingerly.io).

## Licence

Apache-2.0. See [LICENSE](https://github.com/fingerly-io/sdk-rust/blob/main/LICENSE).
