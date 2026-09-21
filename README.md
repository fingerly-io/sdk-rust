# fingerly

Server-side event reads, webhook verification and a same-origin proxy for Rust.
Rust 1.88 or newer, async on Tokio. Version 0.1.0 is prepared for release; the
repository is private and the crate has not been published.

```sh
cargo add fingerly
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

`Fingerly::new` returns a `Result`, so an invalid key or option fails at
construction and nothing is sent. The client holds a pooled connection; build
one and clone it.

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
| `Api` | The API answered with a non-2xx status. |
| `Timeout` | The request deadline elapsed. |
| `Connection` | The API could not be reached, or the connection failed mid-response. |
| `Decode` | The body was not the JSON this SDK expects. |

`Error::Api` carries `status`, and optional `code`, `details` and `request_id`.
The secret key is stripped from all three, and the response body is never
echoed into a message.

```rust
match fingerly.events().get(&request_id).await {
    Ok(event) => { /* … */ }
    Err(error) if error.is_event_not_found() => { /* no such request id */ }
    Err(error) if error.status() == Some(429) => { /* back off */ }
    Err(error) => return Err(error),
}
```

A missing event has a predicate, so it needs no status-and-code check:
`error.is_event_not_found()`.

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

An event is readable as soon as identification answers, so this needs nothing
special:

```rust
let event = fingerly.events().get(&request_id).await?;
```

Earlier versions had a `wait_for` that polled through the gap between
identification and the event becoming queryable. There is no gap, so
`is_event_not_found()` now means a request id that was never issued.

The archived `document` arrives moments after the event itself, so check
`has_document` rather than assuming it is there.

## Verify a backend action

Read the event with a server-only key. Check that its tag matches your action,
that it is recent, that its environment is correct, and that it was scored.
Apply your own policy to the server's verdict. Do not authorize an action using
scores or visitor identifiers supplied by the browser. Tags correlate events;
they do not replace your application's authentication or replay protection.

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
.tolerance(…)`. During a signing-secret rotation, any matching signature in
the comma-separated header is accepted. Malformed or missing input is a `false`
result, never a panic.

Verification proves authenticity and freshness. It does not deduplicate, so
persist processed `WebhookEvent::id` values as well. `WebhookEvent` decodes the
envelope every delivery shares and leaves `data` raw, so a new event type needs
no SDK upgrade.

Webhook verification needs neither an HTTP stack nor an async runtime, so
`default-features = false` leaves a build that pulls in neither:

```toml
fingerly = { version = "0.1", default-features = false }
```

## Same-origin proxy

Content blockers refuse browser requests to third-party APIs, and a refused
identification is a visitor never identified. Mount the proxy on a path of your
own site and those requests become first-party. The proxy key is what lets that
hop declare the visitor's real address, origin and user agent; a public key
alone never can, so nobody can spoof them.

`FingerlyProxy` implements `tower::Service` over `http::Request`, which is what
axum, hyper, warp and tonic all take:

```rust
use fingerly::FingerlyProxy;

let proxy = FingerlyProxy::builder()
    .proxy_key(std::env::var("FINGERLY_PROXY_KEY")?)
    .prefix("/metrics")
    .client_ip(|parts| {
        parts.headers
            .get("cf-connecting-ip")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    })
    .build()?;

let app = axum::Router::new().nest_service("/metrics", proxy);
```

Then point the browser SDK at the same path:

```ts
const fingerly = await load({ apiKey: 'fly_pk_…', endpoints: '/metrics' })
```

For a framework that does not speak `tower`, `proxy.handle(request).await`
takes an `http::Request` and returns an `http::Response` directly.

### What the proxy does

It forwards only `POST` to `{prefix}/api/v1/identify` and
`{prefix}/api/v1/events/{request_id}/supplement`. Anything else gets `404`, and
any other method gets `405`. Event reads need a secret key and stay unreachable
from a browser by construction.

The browser must present a public key from the same environment as the proxy
key, or the request gets `401`. Bodies over 1 MiB get `413`. A
Fingerly that stalls or cannot be reached gets `502` after 5 seconds rather
than holding the browser's connection open. Responses are marked `no-store`.
Only the content type, the visitor metadata Fingerly needs, and an
`Idempotency-Key` are forwarded; customer cookies and authorization headers
never are.

`prefix` must match where you mount the service. Mounting under
`nest_service`, `ServiceBuilder`'s path layers or any other router that strips
the mount also works: the prefix is accepted as either present or already
stripped, because none of them give a way to detect which happened. Choose a
neutral path. Blockers look for words such as `fingerprint`, `tracking` and
`fingerly`.

> **`client_ip` is the one thing you must get right.** Resolve it from a header
> your own infrastructure sets, such as your load balancer's or CDN's. Never
> read the left-most `X-Forwarded-For` value: the visitor writes it. The
> callback receives the request's `Parts`, so a framework extension such as
> axum's `ConnectInfo` is reachable from inside it.

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
caller-supplied option: keys, origins, API versions, mount paths and durations,
all before any network access. `errors.rs` holds the error type.
