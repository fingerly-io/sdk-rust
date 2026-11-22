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
| Read or set an iOS device's two DeviceCheck bits | `device_check().query` / `write` | [DeviceCheck bits on iOS](#devicecheck-bits-on-ios) |
| Keep the browser SDK first-party, away from content blockers | `FingerlyProxy`, a `tower::Service` | [First-party proxy](#first-party-proxy-same-origin) |
| See AI crawlers that never run the page's JavaScript | `AgentSightings`, a `tower::Layer` | [AI crawlers on your server](#ai-crawlers-on-your-server) |

On this page: [Read events](#read-events) · [DeviceCheck bits on iOS](#devicecheck-bits-on-ios) · [Verify webhooks](#verify-webhooks) · [First-party proxy](#first-party-proxy-same-origin) · [AI crawlers on your server](#ai-crawlers-on-your-server) · [Features](#features) · [Requirements](#requirements) · [Development](#development-and-release-preparation) · [Documentation](#documentation) · [Help](#help) · [Licence](#licence)

## Read events

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
`has_document` rather than assuming it is there, and call
`event.parse_document()?` to decode it into `Option<EventDocument>` (including
`Attestation` and `EventRiskReport`). When a submission is unidentifiable
(`!event.is_identifiable()`, such as insufficient entropy, a genuine embedded
WebView, or an unmatched high-risk Web payload), `event.visitor_id` is `""`;
there are no `deferred_token`, `deferred_signals` or `supplements` fields in
`v: 3`.

Every closed set the API reports is an enum with a variant per value and an
`Other(String)` variant that keeps a value this build does not know, so one
the server adds later still deserializes. Match or compare on the variants,
not on strings; `From<&str>` builds one, `as_str()` gives the wire value back,
and every enum is `#[non_exhaustive]`:

| Enum | Fields | Variants |
| --- | --- | --- |
| `Signal` | `EventTrigger::signal` (groups), `EventRiskTrigger::signal` (raw detectors) | `Vpn`, `Bot`, `FingerprintSuppressed`, `AttestationFailed`, `VpnPublic`, ... (every group and detector) |
| `SuspectLevel` | `Event::suspect_level`, `EventRiskReport::level`, `EventListParams::level` | `Low`, `Medium`, `High` |
| `Confidence` | `EventTrigger::confidence`, `EventRiskTrigger::confidence` | `Low`, `Medium`, `High` |
| `AttestationState` | `Attestation::state` | `Attested`, `NotAttested`, `Failed` |
| `AttestationStatus` | `Attestation::status` | `Verified`, `Indeterminate`, `Invalid`, `Absent`, `Unconfigured` |
| `AttestSkippedReason` | `Attestation::attest_skipped` | `NotOffered`, `Unsupported`, `ChallengeUnavailable`, `KeyError`, `Timeout`, `Backoff`, `InstallUnavailable` |
| `EventState` | `Event::state` | `Pending`, `Enriched`, `Unavailable` |
| `AnonymityNetwork` | `Event::anonymity_network` | `Tor`, `Relay`, `Vpn`, `Proxy`, `Hosting` |
| `VisitorKind` | `Event::visitor_kind`, `EventListParams::kind` | `Human`, `AiBot`, `Automation`, `SearchCrawler` |
| `AiPurpose` | `AiAgent::purpose`, `EventListParams::ai_purpose` | `Training`, `Search`, `UserFetch`, `Agent` |
| `AiRuntime` | `AiAgent::runtime` | `ProviderCloud`, `HostedBrowser`, `UserDevice` |
| `AiVerificationMethod` | `AiVerification::method` | `Signature`, `IpList`, `ReverseDns`, `None` |
| `AiVerificationResult` | `AiVerification::result` | `Pass`, `Fail`, `NotAttempted` |
| `Environment` | `Event::environment` | `Production`, `Staging`, `Development` |
| `RiskPlatform` | `Event::platform`, `EventRiskReport::platform` | `Web`, `Ios`, `Android` |
| `RiskSource` | `EventRiskReport::source` | `Key`, `Organization`, `Default` |
| `VerifyReason` | `Verification::reason` | `Ok`, `NotFound`, `TooOld`, `TagMismatch`, `Unidentifiable`, `Unscored`, `AlreadyConsumed` |
| `WebhookEventType` | `WebhookEvent::event_type` | `IdentificationCompleted`, `IdentificationRefused`, `VisitorSuspect`, `BillingStatusChanged`, `UsageDailySettled`, `Test` |
| `WebhookEnvironment` | `WebhookEvent::environment` | `Live`, `Test` |

A native `Attestation` also carries `attest_skipped` (the app's reason for
sending no proof) and `downgrade` (the report named an install an attested
device owns).

`Event::project_id` names the Fingerly project the event belongs to, as a UUID
string. It is `None` when the server is older than projects.

`Event::visitor_kind` says what sort of client made the request. When it is
`VisitorKind::AiBot`, `Event::ai` is an `AiAgent` naming the agent: `name` and
`provider` (open strings, such as `ChatGPT-User` and `OpenAI`), `purpose`,
`runtime`, `declared`, and `verification` with its `method` and `result`. On
every other event `ai` is `None`. The agent is named by a Web Bot Auth
signature when the request carried one, otherwise by its user agent.
`verification` says how far that was checked:
`AiVerificationMethod::Signature` (the operator's published key signed the
request) or `AiVerificationMethod::IpList` (the address is inside the
operator's published ranges), with result `AiVerificationResult::Pass`,
`AiVerificationResult::Fail` (the name was borrowed), or
`AiVerificationResult::NotAttempted` with method `AiVerificationMethod::None`
(the operator publishes nothing to check against, or it could not be checked;
the name is then only the client's claim). Only clients that run the browser
SDK produce events, so a crawler that does not run JavaScript never appears. `EventListParams` narrows a listing by `kind`,
`ai_provider` (exact and case sensitive, as events name it) and `ai_purpose`,
next to `visitor` and `level`:

```rust
use fingerly::{AiPurpose, EventListParams, VisitorKind};

let page = fingerly
    .events()
    .list(
        EventListParams::new()
            .kind(VisitorKind::AiBot)
            .ai_purpose(AiPurpose::UserFetch),
    )
    .await?;
for event in &page.rows {
    if let Some(ai) = &event.ai {
        println!("{} {}", ai.provider, ai.name);
    }
}
```

### Verify a backend action

Verify the event with a server-only key, then apply your own policy to the
server's verdict. Do not authorize an action using scores or visitor
identifiers supplied by the browser. Tags correlate events; they do not
replace your application's authentication. Never put a personal identifier
(user ID, email, install ID, advertising ID) in a tag: the server keeps tags
in long-lived rollups.

`fingerly.events().verify(request_id, options)` reads the event and runs these
checks in order, stopping at the first that fails. It returns a
`Verification` whose `ok` is `false` and whose `reason` names that check, as a
`VerifyReason` with the wire value from `as_str()`:

1. `not_found`: there is no such event (never issued, or past retention).
2. `too_old`: it happened more than `max_age_seconds` ago (300 by default),
   or its `occurred_at` cannot be read. A time in the future passes.
3. `tag_mismatch`: a `tag` was given and the event's tag is not exactly that.
   Without a `tag` this check is skipped; an empty `tag` is refused with
   `Error::Config`.
4. `unidentifiable`: the event has no visitor ID.
5. `unscored`: the event has no suspect score.
6. `already_consumed`: the event was consumed before.

Consuming comes last and happens only when every other check passes, so one
event backs one decision: the first `verify` consumes it, and any later one
answers `already_consumed`. Pass `.consume(false)` to check without consuming.
When everything passes, `ok` is `true`, `reason` is `VerifyReason::Ok` and
`reason_str()` is `""`. `event` holds the event read, and is `None` only for
`not_found`.

`verify` never judges the score, the level or the triggers: that policy stays
with you, on the event it returns. Any other failure is returned as an error,
including `event_pending`, which is not a verdict.

```rust
use fingerly::{Error, Fingerly, Signal, SuspectLevel, VerifyOptions};

enum Verdict {
    Allow,
    Refuse,
    /// Not decided yet: ask the caller to come back after this many seconds.
    Pending(u64),
}

async fn verify(fingerly: &Fingerly, request_id: &str, tag: &str) -> Result<Verdict, Error> {
    let verification = match fingerly
        .events()
        .verify(request_id, VerifyOptions::new().tag(tag))
        .await
    {
        Ok(verification) => verification,
        // Not decided yet, not fraud.
        Err(error) if error.is_event_pending() => {
            return Ok(Verdict::Pending(error.retry_after().unwrap_or(2)));
        }
        Err(error) => return Err(error),
    };
    if !verification.ok {
        // verification.reason_str() says which check failed.
        return Ok(Verdict::Refuse);
    }
    let Some(event) = verification.event else {
        return Ok(Verdict::Refuse);
    };
    // Your score policy.
    if event.suspect_level == Some(SuspectLevel::High) {
        return Ok(Verdict::Refuse);
    }
    if event.triggers.iter().any(|t| t.signal == Signal::AttestationFailed) {
        return Ok(Verdict::Refuse);
    }
    Ok(Verdict::Allow)
}
```

`fingerly.events().consume(request_id)` consumes an event on its own. The
first call returns a `ConsumedEvent` (`request_id`, `consumed_at` as RFC 3339,
`first`); every later one fails with an error for which
`error.is_event_already_consumed()` is true and `error.consumed_at()` says
when the first call landed. Like a read, it is never retried.

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
raw, so a new event type needs no SDK upgrade. Match `event_type` on the
`WebhookEventType` variants, such as `WebhookEventType::IdentificationCompleted`.
`identification.completed` and
`visitor.suspect` carry `data.project_id`; `identification.refused` carries it
only when the refused request named a known key.

Webhook verification needs neither an HTTP stack nor an async runtime, so
`default-features = false` leaves a build that pulls in neither:

```toml
fingerly = { version = "0.3", default-features = false }
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
fingerly = "0.3"
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
| Upstream | Browser and proxied native client SDKs post a single `v: 3` identification envelope to the one path, and the proxy forwards its raw request body bytes verbatim, as a `POST`, to Fingerly's one ingest URL, `https://api.fingerly.io/api/v1/ingest` (`api_version` changes the `v1`). |
| Other methods | `405` for anything other than `POST` (plus `OPTIONS` when `allowed_origins` is configured). |
| Subpaths | `404` |
| Event reads | Need a secret key and stay unreachable from a browser by construction. |
| Proxy key | Only a proxy key, `fly_px_{production\|staging\|development}_…`; `build()` returns a configuration error when it is missing or malformed. |
| Public key | The caller's `x-api-key` must be a public key, `fly_pk_…`, from the same environment as the proxy key. A missing header, a public key of another environment, a secret `fly_sk_` key or any other value gets `401` (`text/plain; charset=utf-8`, `Cache-Control: no-store`) with nothing forwarded. |
| Keys sent upstream | Every request carries the proxy key as `x-fingerly-proxy-key` and the browser's public key as `x-api-key`; a secret key is never sent. |
| Sanitize and restore | All incoming `x-fingerly-*`, `cookie` and `authorization` headers are stripped, restoring `x-fingerly-sdk-platform` only when it matches an exact lowercase native or bridge platform (`ios`, `android`, `react-native`, `react-native-ios`, `react-native-android`, `flutter`, `flutter-ios`, `flutter-android`, `lynx-ios`, `lynx-android`, `capacitor`, `kotlin-multiplatform`). |
| One channel | When `Origin` is present it is sent as `x-fingerly-origin` and the platform header is not sent, as on a direct call to the API. |
| No origin and no platform | `400` (`missing_origin`), rejected locally. `x-fingerly-origin` is never synthesized from `Host`, `Referer` or the request URL. |
| Body size | Bodies over 1 MiB get `413`. |
| Forwarded upstream | Alongside verified proxy metadata (`x-fingerly-host` included), only `content-type`, `x-api-key`, `user-agent`, `idempotency-key`, `sec-fetch-*`, `sec-ch-ua-*` and the Web Bot Auth `signature`, `signature-input` and `signature-agent` (each dropped when over 4096 bytes). Customer cookies and authorization headers never are. |
| Proxy identity | The proxy reports itself upstream as `rust/0.4.1`, which the dashboard shows per proxy. |
| Relayed back | Only `Content-Type`, `X-Request-Id`, `RateLimit-Limit`, `RateLimit-Remaining` and `Retry-After`, plus `Cache-Control: no-store`, so nothing on the response names Fingerly. |
| Deadline | One deadline, `timeout` (5 seconds by default), covers reading the browser's body and the whole upstream exchange, so a trickling answer cannot stretch it. |
| Deadline passes during the upstream call | `504` |
| Any other upstream failure | `502`: refused, reset, DNS, a truncated or malformed answer, an answer over 4 MiB, a redirect, a status outside 200 to 599. |
| Redirects | Never followed, also with a caller-supplied `http_client_builder`. |
| Browser too slow to send its body | `408` |
| Error responses | Each carries a short `text/plain` body and `Cache-Control: no-store`. |
| Broken upstream | The answer is read in full before anything is relayed, so a broken upstream never reaches the browser as a `200`. |
| Visitor disconnects | Dropping the service future cancels the upstream call. |

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

## AI crawlers on your server

Most AI crawler and fetcher requests (GPTBot, ClaudeBot and the like) load a
page without running its JavaScript, so they never reach the browser SDK and
leave no event. `AgentSightings` reports the pages your server served to
Fingerly, in the background, and remembers what Fingerly answered about each
one. The console's AI traffic view then counts them, and your handlers can ask
what sent a request.

It runs under your secret key, on the `Fingerly` client's connection pool, and
mounts as a `tower::Layer`, which axum takes directly:

```rust
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Extension};
use axum::response::Html;
use axum::routing::get;
use fingerly::{AgentLookup, AgentSightings, AiVerificationResult, Fingerly, VisitorKind};
use tokio::signal::unix::{signal, SignalKind};

async fn home(Extension(lookup): Extension<AgentLookup>) -> Html<&'static str> {
    if let Some(ai) = lookup.ai() {
        if ai.verification.result == AiVerificationResult::Fail {
            // An AI agent's name, sent from an address its operator does not
            // publish. Decide what that means for your site.
        }
    }
    if lookup.visitor_kind() == Some(&VisitorKind::SearchCrawler) {
        // A search engine's crawler, as the server classified it.
    }
    // AgentLookup::Unknown: serve as usual.
    Html("<h1>Welcome</h1>")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fingerly = Fingerly::new(std::env::var("FINGERLY_SECRET_KEY")?)?;
    let sightings = AgentSightings::builder(&fingerly)
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

    let app = axum::Router::new()
        .route("/", get(home))
        .layer(sightings.layer());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    // Docker, Kubernetes and systemd stop a service with SIGTERM; Ctrl-C sends
    // SIGINT. Without graceful shutdown `serve` never returns and the
    // sightings still buffered are lost.
    let mut terminate = signal(SignalKind::terminate())?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
        })
        .await?;

    // Send what is still buffered before the process exits.
    sightings.close().await;
    Ok(())
}
```

`client_ip` is the same callback, with the same rules, as the proxy's: one
IPv4 or IPv6 address from a header your own infrastructure sets, else the TCP
peer, and never the left-most `X-Forwarded-For` value. A request it returns no
address for is not reported, and that is reported once a minute.

### Asking what sent a request

The layer puts an `AgentLookup` in every request's extensions. Elsewhere,
`sightings.lookup(&request)` or `sightings.lookup_parts(&parts)` answers the
same. A lookup reads memory only: it never waits on the network and never
fails. It returns `AgentLookup::Known` with the server's answer
(`visitor_kind`, `agent`, and for an AI agent the `ai` object with how its
claim was checked) when the server has answered for this exact user agent,
address and `Signature-Agent` and the answer has not expired, and
`AgentLookup::Unknown` otherwise. Treat `Unknown` as "serve as usual".

The first request from a client is always `Unknown`: it is reported after its
response, and the answer arrives with the next flush. A request signed with
Web Bot Auth is checked every time, so it is never remembered and its lookup
is always `Unknown`; its answer still reaches the console.

### Which responses are reported

| Rule | Behaviour |
| --- | --- |
| By default | Responses with a `Content-Type` of `text/html` or `application/xhtml+xml`, and every request for `/robots.txt`, `/llms.txt` and `/llms-full.txt`, whatever the status. |
| `content_types([...])` | Replaces the default content types. Compared with the media type, without parameters and ignoring case. |
| `include_paths([...])` | Path prefixes reported whatever their content type. |
| `exclude_paths([...])` | Path prefixes never reported. They win over everything else. |
| Never | Static assets, API routes and health checks unless you include them. Nothing is ever chosen by user agent, address or any request header. |

The report is made once your service has produced the response, and never
delays it.

### What is sent

| Sent | Never sent |
| --- | --- |
| The `User-Agent` as received (a request with one over 4096 bytes is not reported), the client address from `client_ip`, the `Host`, the method, the Web Bot Auth `Signature`, `Signature-Input` and `Signature-Agent` headers (each left out over 4096 bytes), and how many times the same request was served since the last report. | The path, the query string, cookies, `Authorization`, any other header, the request body and the response. None of the reported fields is logged. |

### Memory, batching and failures

- Answers are kept in a least-recently-used cache, per process: 4096 entries by
  default (about 1.5 MB), up to 65536 with `cache_capacity` (about 25 MB). Each
  answer is kept for the `ttl` the server gave it, and all of them are dropped
  when the server's `rules_version` changes.
- Repeats of the same request are folded into one pending report with a count,
  so a crawler fetching a thousand pages is a handful of items. At most 1000
  requests are pending; past that a new request is not buffered (it stays
  `Unknown`) and `sightings.dropped()` counts it.
- A Tokio task sends up to 200 requests at a time, two seconds after the oldest
  pending one or as soon as 200 requests or 64 KiB are pending, one call at a
  time, each under a 5 second deadline. It never runs on a request you are
  serving.
- It fails open. A rate-limited call (`429`) keeps the batch and waits for
  `Retry-After`; an unavailable API (`503`) or a failed connection keeps it and
  retries after 1 second, doubling up to a minute; a refused key (`401`/`403`)
  drops it and pauses for a minute; an invalid batch (`422`) or a deadline
  passed after the request went out drops it. Requests keep being served
  throughout, and lookups keep answering from the cache or `Unknown`.
- Failures the component handled go to `on_error` if you set one, otherwise
  to one `tracing` warning under the `fingerly::agents` target, each kind at
  most once a minute.

On a serverless or edge runtime, where nothing runs between invocations, call
`sightings.flush().await` before the invocation ends. On shutdown,
`sightings.close().await` sends what is left and stops the task, as in the
example above (on Windows, wait for `ctrl_c` alone). Neither ever returns an
error. Each waits at most 6 seconds for a flush in flight, then sends the
remaining batches one at a time, each under the 5 second deadline, and stops
at the first that fails, so a hung API holds `close()` for 11 seconds at
most. A `flush()` or `close()` you cancel, for example under a
`tokio::time::timeout` of your own, drops the batch it was sending, as a
passed deadline does. Build the Tokio runtime with timers (`#[tokio::main]`
or `enable_all()`): on a runtime without them the background task cannot run,
which is reported once a minute.

For a framework that does not speak `tower`, call
`sightings.report(&parts, response.headers())` once the response is produced;
it applies the same rules and never waits on the network. The single call
underneath is `fingerly.agents().sightings(&items)`, for a server that batches
on its own.

## Features

| Feature | Default | What it adds |
| --- | --- | --- |
| `client` | yes | `Fingerly`, event reads and DeviceCheck bits, over reqwest and Tokio. |
| `proxy` | yes | `FingerlyProxy`, a `tower::Service`, and `AgentSightings`, a `tower::Layer`. Implies `client`. |
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
event reads, the list filters, consuming and verifying; `models.rs` owns the types
they decode into. `webhooks.rs` verifies signatures and needs nothing else in
the crate. `proxy.rs` is the same-origin service. `agents.rs` is the agent sightings
call and `sightings.rs` the component and layer built on it: the cache key,
the answer cache, the buffer and the background flusher. `config.rs` validates every
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
