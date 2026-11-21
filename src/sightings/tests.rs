//! The agent sightings component against its contract: the key vectors, the
//! cache, the buffer, the flush triggers and every row of the failure table.
//!
//! These live inside the crate so the clock can be faked and the buffer
//! inspected; the API is still a real server on a real socket.

#[path = "../../tests/common/mod.rs"]
mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{Canned, TestServer, SECRET_KEY};
use http::request::Parts;
use http::{HeaderMap, HeaderValue, Request};
use serde::Deserialize;

use super::*;
use crate::{AiVerificationResult, Fingerly};

/// A clock the test moves by hand.
#[derive(Clone)]
struct FakeClock(Arc<Mutex<Instant>>);

impl FakeClock {
    fn new() -> Self {
        FakeClock(Arc::new(Mutex::new(Instant::now())))
    }

    fn advance(&self, by: Duration) {
        *self.0.lock().unwrap() += by;
    }

    fn clock(&self) -> Clock {
        let now = self.0.clone();
        Arc::new(move || *now.lock().unwrap())
    }
}

fn fingerly(base_url: &str) -> Fingerly {
    Fingerly::builder(SECRET_KEY)
        .endpoint(base_url)
        .allow_insecure_loopback(true)
        .build()
        .unwrap()
}

/// The test's trusted client-IP source: a header only the test writes.
fn from_test_header(parts: &Parts) -> String {
    parts
        .headers
        .get("x-test-ip")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

fn builder(base_url: &str, clock: &FakeClock) -> AgentSightingsBuilder {
    let mut builder = AgentSightings::builder(&fingerly(base_url)).client_ip(from_test_header);
    builder.clock = Some(clock.clock());
    builder.background = false;
    builder.deadline = Duration::from_millis(300);
    builder
}

/// A component with a fake clock and no background flusher, plus the
/// failures it reported.
fn component(
    base_url: &str,
    clock: &FakeClock,
) -> (AgentSightings, Arc<Mutex<Vec<AgentSightingsError>>>) {
    let failures = Arc::new(Mutex::new(Vec::new()));
    let seen = failures.clone();
    let sightings = builder(base_url, clock)
        .on_error(move |failure| seen.lock().unwrap().push(failure.clone()))
        .build()
        .unwrap();
    (sightings, failures)
}

fn parts(user_agent: &str, ip: &str) -> Parts {
    request(user_agent, ip).into_parts().0
}

fn request(user_agent: &str, ip: &str) -> Request<()> {
    Request::builder()
        .uri("https://shop.example/products?id=7")
        .header("host", "shop.example")
        .header("user-agent", user_agent)
        .header("x-test-ip", ip)
        .header("cookie", "session=secret")
        .header("authorization", "Bearer secret")
        .body(())
        .unwrap()
}

fn signed(user_agent: &str, ip: &str) -> Parts {
    let mut parts = parts(user_agent, ip);
    parts
        .headers
        .insert("signature", HeaderValue::from_static("sig1=:abc:"));
    parts.headers.insert(
        "signature-input",
        HeaderValue::from_static(r#"sig1=("@authority");created=1"#),
    );
    parts.headers.insert(
        "signature-agent",
        HeaderValue::from_static(r#""https://chatgpt.com""#),
    );
    parts
}

fn html() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers
}

fn answers(rules: &str, ttls: &[i64]) -> String {
    let items: Vec<serde_json::Value> = ttls
        .iter()
        .map(|ttl| serde_json::json!({"ttl": ttl, "visitor_kind": "human"}))
        .collect();
    serde_json::json!({"rules_version": rules, "items": items}).to_string()
}

fn ok(rules: &str, ttls: &[i64]) -> Canned {
    Canned::json(200, answers(rules, ttls))
}

fn error(status: u16, code: &str) -> Canned {
    Canned::json(
        status,
        format!(r#"{{"error":{{"code":"{code}","message":"no","status":{status}}}}}"#),
    )
}

/// The items a recorded request carried.
fn sent_items(body: &[u8]) -> Vec<serde_json::Value> {
    let body: serde_json::Value = serde_json::from_slice(body).unwrap();
    body["items"].as_array().unwrap().clone()
}

fn pending_counts(sightings: &AgentSightings) -> Vec<u64> {
    let state = sightings.inner().state();
    state
        .pending
        .values()
        .map(|pending| pending.count)
        .collect()
}

fn hex(key: &Key) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Deserialize)]
struct Vectors {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    user_agent: String,
    client_ip: String,
    canonical_ip: String,
    signature_agent: String,
    signed: bool,
    key: String,
}

#[tokio::test]
async fn reproduces_every_contract_vector() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("contract/agent-sightings-vectors.json");
    let vectors: Vectors = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(!vectors.vectors.is_empty());
    let clock = FakeClock::new();
    let (sightings, _) = component("http://127.0.0.1:9", &clock);

    for vector in vectors.vectors {
        let address: IpAddr = vector.client_ip.parse().unwrap();
        assert_eq!(
            canonical_ip(address),
            vector.canonical_ip,
            "{}",
            vector.name
        );
        let key = sighting_key(
            &vector.user_agent,
            &vector.canonical_ip,
            &vector.signature_agent,
            vector.signed,
        );
        assert_eq!(hex(&key), vector.key, "{}", vector.name);

        // The same key from the request itself, as the layer computes it.
        let mut parts = parts("", &vector.client_ip);
        parts.headers.insert(
            "user-agent",
            HeaderValue::from_bytes(vector.user_agent.as_bytes()).unwrap(),
        );
        if !vector.signature_agent.is_empty() {
            parts.headers.insert(
                "signature-agent",
                HeaderValue::from_str(&vector.signature_agent).unwrap(),
            );
        }
        if vector.signed {
            parts
                .headers
                .insert("signature", HeaderValue::from_static("sig1=:abc:"));
            parts
                .headers
                .insert("signature-input", HeaderValue::from_static("sig1=()"));
        }
        let observed = sightings.inner().observe(&parts).unwrap();
        assert_eq!(hex(&observed.key), vector.key, "{}", vector.name);
        assert_eq!(
            observed.item.client_ip, vector.canonical_ip,
            "{}",
            vector.name
        );
    }
}

#[test]
fn the_cache_is_bounded_and_evicts_the_least_recently_used() {
    let now = Instant::now();
    let later = now + Duration::from_secs(60);
    let answer = Arc::new(AgentAnswer::default());
    let mut cache = Lru::new(2);
    cache.insert([1; 16], answer.clone(), later);
    cache.insert([2; 16], answer.clone(), later);
    // Using the first makes the second the least recently used.
    assert!(cache.get(&[1; 16], now).is_some());
    cache.insert([3; 16], answer.clone(), later);
    assert_eq!(cache.len(), 2);
    assert!(
        cache.get(&[2; 16], now).is_none(),
        "the least recently used stayed"
    );
    assert!(cache.get(&[1; 16], now).is_some());
    assert!(cache.get(&[3; 16], now).is_some());
    // Replacing an entry does not evict another.
    cache.insert([3; 16], answer, later);
    assert_eq!(cache.len(), 2);
}

#[test]
fn the_capacity_defaults_is_capped_and_must_be_positive() {
    let clock = FakeClock::new();
    let base = "http://127.0.0.1:9";
    let capacity = |sightings: AgentSightings| sightings.inner().state().cache.capacity;
    assert_eq!(capacity(builder(base, &clock).build().unwrap()), 4096);
    assert_eq!(
        capacity(
            builder(base, &clock)
                .cache_capacity(1_000_000)
                .build()
                .unwrap()
        ),
        AgentSightings::MAX_CACHE_CAPACITY
    );
    assert_eq!(
        capacity(builder(base, &clock).cache_capacity(7).build().unwrap()),
        7
    );
    let error = builder(base, &clock).cache_capacity(0).build().unwrap_err();
    assert!(matches!(error, Error::Config { .. }));
    let error = AgentSightings::builder(&fingerly(base))
        .build()
        .unwrap_err();
    assert!(error.to_string().contains("client_ip is required"));
}

#[tokio::test]
async fn answers_expire_with_their_ttl_and_ttl_zero_is_never_cached() {
    let server = TestServer::always(ok("r1", &[10, 0])).await;
    let clock = FakeClock::new();
    let (sightings, _) = component(&server.base_url, &clock);
    let first = request("GPTBot/1.4", "20.171.206.9");
    let second = request("curl/8.7.1", "198.51.100.1");
    sightings.report(&parts("GPTBot/1.4", "20.171.206.9"), &html());
    sightings.report(&parts("curl/8.7.1", "198.51.100.1"), &html());
    assert_eq!(sightings.lookup(&first), AgentLookup::Unknown);

    sightings.flush().await;
    assert_eq!(server.request_count(), 1);
    assert!(
        pending_counts(&sightings).is_empty(),
        "the sent items stayed"
    );
    let known = sightings.lookup(&first);
    assert_eq!(known.visitor_kind(), Some(&VisitorKind::Human));
    assert_eq!(
        sightings.lookup(&second),
        AgentLookup::Unknown,
        "ttl 0 was cached"
    );

    clock.advance(Duration::from_secs(9));
    assert!(!sightings.lookup(&first).is_unknown());
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        sightings.lookup(&first),
        AgentLookup::Unknown,
        "an expired answer was used"
    );
}

#[tokio::test]
async fn a_new_rules_version_drops_every_answer() {
    let server = TestServer::start(vec![ok("r1", &[600]), ok("r2", &[600])]).await;
    let clock = FakeClock::new();
    let (sightings, _) = component(&server.base_url, &clock);
    sightings.report(&parts("first", "198.51.100.1"), &html());
    sightings.flush().await;
    assert!(!sightings
        .lookup(&request("first", "198.51.100.1"))
        .is_unknown());

    sightings.report(&parts("second", "198.51.100.2"), &html());
    sightings.flush().await;
    assert_eq!(server.request_count(), 2);
    assert!(sightings
        .lookup(&request("first", "198.51.100.1"))
        .is_unknown());
    assert!(!sightings
        .lookup(&request("second", "198.51.100.2"))
        .is_unknown());
    assert_eq!(
        sightings.inner().state().rules_version.as_deref(),
        Some("r2")
    );
}

#[tokio::test]
async fn repeats_fold_into_one_count_including_cache_hits() {
    let server = TestServer::always(ok("r1", &[600])).await;
    let clock = FakeClock::new();
    let (sightings, _) = component(&server.base_url, &clock);
    for _ in 0..3 {
        sightings.report(&parts("GPTBot/1.4", "20.171.206.9"), &html());
    }
    // The IPv4-mapped form is the same request.
    sightings.report(&parts("GPTBot/1.4", "::ffff:20.171.206.9"), &html());
    assert_eq!(pending_counts(&sightings), vec![4]);
    sightings.flush().await;
    let items = sent_items(&server.first().body);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["count"], 4);

    // Now the cache answers, and the repeats still count.
    assert!(!sightings
        .lookup(&request("GPTBot/1.4", "20.171.206.9"))
        .is_unknown());
    sightings.report(&parts("GPTBot/1.4", "20.171.206.9"), &html());
    sightings.report(&parts("GPTBot/1.4", "20.171.206.9"), &html());
    assert_eq!(pending_counts(&sightings), vec![2]);
    sightings.flush().await;
    let items = sent_items(&server.requests()[1].body);
    assert_eq!(items[0]["count"], 2);
}

#[tokio::test]
async fn signed_requests_are_never_folded() {
    let server = TestServer::always(ok("r1", &[0, 0])).await;
    let clock = FakeClock::new();
    let (sightings, _) = component(&server.base_url, &clock);
    sightings.report(&signed("Mozilla/5.0", "34.31.25.14"), &html());
    sightings.report(&signed("Mozilla/5.0", "34.31.25.14"), &html());
    assert_eq!(pending_counts(&sightings), vec![1, 1]);
    sightings.flush().await;
    let items = sent_items(&server.first().body);
    assert_eq!(items.len(), 2);
    for item in &items {
        assert_eq!(item["count"], 1);
        assert_eq!(item["signature"], "sig1=:abc:");
        assert_eq!(item["signature_agent"], r#""https://chatgpt.com""#);
    }
    // ttl 0: a signed request is checked every time.
    let mut again = Request::new(());
    *again.headers_mut() = signed("Mozilla/5.0", "34.31.25.14").headers;
    assert!(sightings.lookup(&again).is_unknown());
}

#[tokio::test]
async fn sends_only_the_contract_fields() {
    let server = TestServer::always(ok("r1", &[600])).await;
    let clock = FakeClock::new();
    let (sightings, _) = component(&server.base_url, &clock);
    sightings.report(&parts("GPTBot/1.4", "2001:DB8:0:0:0:0:0:1"), &html());
    sightings.flush().await;
    let recorded = server.first();
    assert_eq!(recorded.method, "POST");
    assert_eq!(recorded.path, "/api/v1/agents/sightings");
    assert_eq!(recorded.header("x-api-key"), SECRET_KEY);
    let items = sent_items(&recorded.body);
    let item = items[0].as_object().unwrap();
    let mut fields: Vec<&str> = item.keys().map(String::as_str).collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        ["client_ip", "count", "host", "method", "user_agent"]
    );
    assert_eq!(item["client_ip"], "2001:db8::1");
    assert_eq!(item["host"], "shop.example");
    assert_eq!(item["method"], "GET");
    let body = String::from_utf8_lossy(&recorded.body);
    for secret in ["products", "id=7", "session", "Bearer"] {
        assert!(!body.contains(secret), "{secret} was sent");
    }
}

#[tokio::test]
async fn flushes_on_size_bytes_and_time() {
    let clock = FakeClock::new();
    let (sightings, _) = component("http://127.0.0.1:9", &clock);
    let now = || (clock.clock())();

    // 200 items.
    for i in 0..199 {
        sightings.report(&parts(&format!("agent {i}"), "198.51.100.1"), &html());
    }
    assert!(!sightings.inner().state().due(now()));
    sightings.report(&parts("agent 199", "198.51.100.1"), &html());
    assert!(sightings.inner().state().due(now()));
    let batch = sightings.inner().state().take_batch();
    assert_eq!(batch.len(), 200);

    // 64 KiB of fields, in batches that stay under it.
    let clock = FakeClock::new();
    let (sightings, _) = component("http://127.0.0.1:9", &clock);
    let now = || (clock.clock())();
    let long = "a".repeat(4000);
    for i in 0..16 {
        sightings.report(&parts(&format!("{long}{i:02}"), "198.51.100.1"), &html());
    }
    assert!(
        !sightings.inner().state().due(now()),
        "{}",
        sightings.inner().state().bytes
    );
    sightings.report(&parts(&format!("{long}16"), "198.51.100.1"), &html());
    assert!(sightings.inner().state().due(now()));
    let batch = sightings.inner().state().take_batch();
    assert_eq!(batch.len(), 16, "a batch passed 64 KiB");

    // Two seconds after the oldest item.
    let clock = FakeClock::new();
    let (sightings, _) = component("http://127.0.0.1:9", &clock);
    let now = || (clock.clock())();
    sightings.report(&parts("one", "198.51.100.1"), &html());
    clock.advance(Duration::from_millis(1900));
    sightings.report(&parts("two", "198.51.100.1"), &html());
    assert!(!sightings.inner().state().due(now()));
    clock.advance(Duration::from_millis(100));
    assert!(sightings.inner().state().due(now()));
}

/// The background flusher on the real clock: a lone item goes after two
/// seconds, a full batch at once.
#[tokio::test]
async fn the_background_flusher_sends_on_time_and_on_size() {
    let server = TestServer::always(ok("r1", &[600])).await;
    let sightings = AgentSightings::builder(&fingerly(&server.base_url))
        .client_ip(from_test_header)
        .build()
        .unwrap();
    sightings.report(&parts("one", "198.51.100.1"), &html());
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(server.request_count(), 0, "flushed before two seconds");
    wait_for(|| server.request_count() == 1, Duration::from_secs(2)).await;

    let server = TestServer::always(Canned::json(200, answers("r1", &[600; 200]))).await;
    let sightings = AgentSightings::builder(&fingerly(&server.base_url))
        .client_ip(from_test_header)
        .build()
        .unwrap();
    let started = Instant::now();
    for i in 0..200 {
        sightings.report(&parts(&format!("agent {i}"), "198.51.100.1"), &html());
    }
    wait_for(|| server.request_count() == 1, Duration::from_secs(1)).await;
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(sent_items(&server.first().body).len(), 200);

    // close sends what is left and ignores later reports.
    sightings.report(&parts("last", "198.51.100.1"), &html());
    sightings.close().await;
    assert_eq!(server.request_count(), 2);
    sightings.report(&parts("after", "198.51.100.1"), &html());
    assert!(pending_counts(&sightings).is_empty());
}

async fn wait_for(condition: impl Fn() -> bool, within: Duration) {
    let until = Instant::now() + within;
    while !condition() {
        assert!(Instant::now() < until, "timed out waiting");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn the_buffer_is_capped_and_counts_what_it_drops() {
    let clock = FakeClock::new();
    let (sightings, _) = component("http://127.0.0.1:9", &clock);
    for i in 0..1000 {
        sightings.report(&parts(&format!("agent {i}"), "198.51.100.1"), &html());
    }
    assert_eq!(sightings.dropped(), 0);
    sightings.report(&parts("one too many", "198.51.100.1"), &html());
    sightings.report(&signed("signed", "198.51.100.1"), &html());
    assert_eq!(sightings.dropped(), 2);
    // An existing key keeps counting.
    sightings.report(&parts("agent 0", "198.51.100.1"), &html());
    assert_eq!(pending_counts(&sightings)[0], 2);
    assert_eq!(pending_counts(&sightings).len(), 1000);

    // In-flight items count against the cap too.
    let batch = sightings.inner().state().take_batch();
    assert_eq!(batch.len(), 200);
    sightings.report(&parts("while in flight", "198.51.100.1"), &html());
    assert_eq!(sightings.dropped(), 3);
}

#[tokio::test]
async fn a_422_drops_the_batch_and_is_reported_once_a_minute() {
    let server = TestServer::always(error(422, "invalid_request")).await;
    let clock = FakeClock::new();
    let (sightings, failures) = component(&server.base_url, &clock);
    sightings.report(&parts("one", "198.51.100.1"), &html());
    sightings.flush().await;
    assert!(pending_counts(&sightings).is_empty(), "the batch was kept");
    sightings.report(&parts("two", "198.51.100.1"), &html());
    sightings.flush().await;
    assert_eq!(server.request_count(), 2, "a 422 paused flushing");
    assert_eq!(failures.lock().unwrap().len(), 1);
    assert_eq!(
        failures.lock().unwrap()[0].kind,
        AgentSightingsErrorKind::InvalidRequest
    );

    clock.advance(Duration::from_secs(60));
    sightings.report(&parts("three", "198.51.100.1"), &html());
    sightings.flush().await;
    assert_eq!(failures.lock().unwrap().len(), 2);
    for failure in failures.lock().unwrap().iter() {
        assert!(!failure.message.contains("198.51.100.1"));
    }
}

#[tokio::test]
async fn a_429_keeps_the_batch_and_waits_for_retry_after() {
    let server = TestServer::start(vec![
        error(429, "rate_limited").header("retry-after", "30"),
        ok("r1", &[600, 600]),
    ])
    .await;
    let clock = FakeClock::new();
    let (sightings, failures) = component(&server.base_url, &clock);
    sightings.report(&parts("one", "198.51.100.1"), &html());
    sightings.flush().await;
    assert_eq!(pending_counts(&sightings), vec![1], "the batch was dropped");

    // Counting goes on while flushing waits.
    sightings.report(&parts("one", "198.51.100.1"), &html());
    sightings.report(&parts("two", "198.51.100.1"), &html());
    clock.advance(Duration::from_secs(29));
    sightings.flush().await;
    assert_eq!(server.request_count(), 1, "flushed before Retry-After");
    assert_eq!(pending_counts(&sightings), vec![2, 1]);

    clock.advance(Duration::from_secs(1));
    sightings.flush().await;
    assert_eq!(server.request_count(), 2);
    let items = sent_items(&server.requests()[1].body);
    assert_eq!(items[0]["user_agent"], "one");
    assert_eq!(items[0]["count"], 2);
    assert!(failures.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_429_mid_flight_folds_into_the_newer_entry() {
    let server = TestServer::always(error(429, "rate_limited").header("retry-after", "5")).await;
    let clock = FakeClock::new();
    let (sightings, _) = component(&server.base_url, &clock);
    sightings.report(&parts("one", "198.51.100.1"), &html());
    let taken = sightings.inner().state().take_batch();
    // The same request arrives while its batch is out.
    sightings.report(&parts("one", "198.51.100.1"), &html());
    sightings.report(&parts("one", "198.51.100.1"), &html());
    let mut state = sightings.inner().state();
    state.in_flight -= taken.len();
    state.keep(taken);
    assert_eq!(state.pending.len(), 1);
    assert_eq!(state.pending.values().next().unwrap().count, 3);
    assert_eq!(state.by_key.len(), 1);
}

#[tokio::test]
async fn a_daily_429_without_retry_after_waits_for_the_next_utc_day() {
    let server =
        TestServer::always(error(429, "rate_limited").header("fingerly-ratelimit-scope", "daily"))
            .await;
    let clock = FakeClock::new();
    let (sightings, _) = component(&server.base_url, &clock);
    sightings.report(&parts("one", "198.51.100.1"), &html());
    let expected = until_next_utc_day(SystemTime::now());
    sightings.flush().await;
    let now = (clock.clock())();
    let paused = sightings.inner().state().paused_until.unwrap() - now;
    assert!(
        paused.abs_diff(expected) < Duration::from_secs(5),
        "{paused:?} vs {expected:?}"
    );
    assert_eq!(pending_counts(&sightings), vec![1]);
}

#[tokio::test]
async fn a_401_or_403_drops_the_batch_and_pauses_for_a_minute() {
    for status in [401, 403] {
        let server = TestServer::start(vec![error(status, "unauthorized"), ok("r1", &[600])]).await;
        let clock = FakeClock::new();
        let (sightings, failures) = component(&server.base_url, &clock);
        sightings.report(&parts("one", "198.51.100.1"), &html());
        sightings.flush().await;
        assert!(
            pending_counts(&sightings).is_empty(),
            "{status}: the batch was kept"
        );
        sightings.report(&parts("two", "198.51.100.1"), &html());
        clock.advance(Duration::from_secs(59));
        sightings.flush().await;
        assert_eq!(
            server.request_count(),
            1,
            "{status}: flushed during the pause"
        );
        clock.advance(Duration::from_secs(1));
        sightings.flush().await;
        assert_eq!(server.request_count(), 2);
        let failures = failures.lock().unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].kind, AgentSightingsErrorKind::Unauthorized);
        assert_eq!(failures[0].status, Some(status));
    }
}

#[tokio::test]
async fn a_503_keeps_the_batch_and_backs_off_up_to_a_minute() {
    let server = TestServer::always(error(503, "unavailable")).await;
    let clock = FakeClock::new();
    let (sightings, failures) = component(&server.base_url, &clock);
    sightings.report(&parts("one", "198.51.100.1"), &html());
    let mut expected = Vec::new();
    for _ in 0..8 {
        let now = (clock.clock())();
        sightings.flush().await;
        let wait = sightings.inner().state().paused_until.unwrap() - now;
        expected.push(wait.as_secs());
        clock.advance(wait);
    }
    assert_eq!(expected, [1, 2, 4, 8, 16, 32, 60, 60]);
    assert_eq!(pending_counts(&sightings), vec![1]);
    assert!(failures.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_200_resets_the_backoff() {
    let server = TestServer::start(vec![
        error(503, "unavailable"),
        error(503, "unavailable"),
        ok("r1", &[600]),
        error(503, "unavailable"),
    ])
    .await;
    let clock = FakeClock::new();
    let (sightings, _) = component(&server.base_url, &clock);
    for _ in 0..3 {
        sightings.report(&parts("one", "198.51.100.1"), &html());
        sightings.flush().await;
        clock.advance(Duration::from_secs(10));
    }
    sightings.report(&parts("two", "198.51.100.1"), &html());
    let now = (clock.clock())();
    sightings.flush().await;
    let wait = sightings.inner().state().paused_until.unwrap() - now;
    assert_eq!(wait, Duration::from_secs(1));
}

#[tokio::test]
async fn a_failed_connection_keeps_the_batch_and_backs_off() {
    // A port nothing listens on: refused before any request goes out.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let clock = FakeClock::new();
    let (sightings, _) = component(&format!("http://{address}"), &clock);
    sightings.report(&parts("one", "198.51.100.1"), &html());
    let now = (clock.clock())();
    sightings.flush().await;
    assert_eq!(pending_counts(&sightings), vec![1]);
    let wait = sightings.inner().state().paused_until.unwrap() - now;
    assert_eq!(wait, Duration::from_secs(1));
}

#[tokio::test]
async fn a_timeout_after_sending_drops_the_batch() {
    let server = TestServer::always(ok("r1", &[600]).delay(Duration::from_secs(2))).await;
    let clock = FakeClock::new();
    let (sightings, _) = component(&server.base_url, &clock);
    sightings.report(&parts("one", "198.51.100.1"), &html());
    sightings.flush().await;
    assert_eq!(server.request_count(), 1);
    assert!(
        pending_counts(&sightings).is_empty(),
        "a sent batch was kept"
    );
    assert!(sightings.inner().state().paused_until.is_none());
    assert_eq!(sightings.inner().state().in_flight, 0);
}

#[tokio::test]
async fn any_other_answer_drops_the_batch_and_is_reported() {
    for canned in [
        error(500, "internal"),
        error(404, "not_found"),
        Canned::json(200, answers("r1", &[600, 600])),
        Canned::json(200, "not json"),
    ] {
        let server = TestServer::always(canned).await;
        let clock = FakeClock::new();
        let (sightings, failures) = component(&server.base_url, &clock);
        sightings.report(&parts("one", "198.51.100.1"), &html());
        sightings.flush().await;
        assert!(pending_counts(&sightings).is_empty());
        assert!(sightings.inner().state().paused_until.is_none());
        let failures = failures.lock().unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].kind, AgentSightingsErrorKind::UnexpectedAnswer);
    }
}

#[tokio::test]
async fn oversized_headers_are_not_reported_or_left_out() {
    let server = TestServer::always(ok("r1", &[600])).await;
    let clock = FakeClock::new();
    let (sightings, _) = component(&server.base_url, &clock);

    // A user agent over 4096 bytes: not reported, and unknown.
    let long = "a".repeat(4097);
    sightings.report(&parts(&long, "198.51.100.1"), &html());
    assert!(pending_counts(&sightings).is_empty());
    assert!(sightings
        .lookup(&request(&long, "198.51.100.1"))
        .is_unknown());
    sightings.report(&parts(&"a".repeat(4096), "198.51.100.1"), &html());
    assert_eq!(pending_counts(&sightings).len(), 1);

    // An oversized Web Bot Auth header is left out, and the request is then
    // keyed and sent as unsigned.
    let mut parts = signed("Mozilla/5.0", "34.31.25.14");
    parts.headers.insert(
        "signature",
        HeaderValue::from_str(&"s".repeat(4097)).unwrap(),
    );
    parts.headers.insert(
        "signature-agent",
        HeaderValue::from_str(&"g".repeat(4097)).unwrap(),
    );
    let observed = sightings.inner().observe(&parts).unwrap();
    assert!(!observed.signed);
    assert!(observed.item.signature.is_none());
    assert!(observed.item.signature_agent.is_none());
    assert!(observed.item.signature_input.is_some());
    assert_eq!(
        observed.key,
        sighting_key("Mozilla/5.0", "34.31.25.14", "", false)
    );
}

#[tokio::test]
async fn a_request_without_a_valid_address_is_not_reported() {
    let clock = FakeClock::new();
    let (sightings, failures) = component("http://127.0.0.1:9", &clock);
    for bad in [
        "",
        "203.0.113.7, 10.0.0.1",
        "203.0.113.7:443",
        " 203.0.113.7",
    ] {
        sightings.report(&parts("GPTBot/1.4", bad), &html());
        assert!(sightings.lookup(&request("GPTBot/1.4", bad)).is_unknown());
    }
    assert!(pending_counts(&sightings).is_empty());
    let failures = failures.lock().unwrap();
    assert_eq!(failures.len(), 1, "reported more than once a minute");
    assert_eq!(failures[0].kind, AgentSightingsErrorKind::InvalidClientIp);

    // A panicking callback is the same integration bug.
    let panicking = AgentSightings::builder(&fingerly("http://127.0.0.1:9"))
        .client_ip(|_| panic!("no address"))
        .build()
        .unwrap();
    panicking.report(&parts("GPTBot/1.4", "198.51.100.1"), &html());
    assert!(pending_counts(&panicking).is_empty());
}

#[test]
fn the_scope_follows_content_type_and_paths_never_the_visitor() {
    let scope = |builder: AgentSightingsBuilder| builder.build().unwrap();
    let clock = FakeClock::new();
    let base = "http://127.0.0.1:9";
    let headers = |content_type: &str| {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_str(content_type).unwrap());
        headers
    };
    let none = HeaderMap::new();

    let default = scope(builder(base, &clock));
    let reports = |path: &str, response: &HeaderMap| default.inner().scope.reports(path, response);
    assert!(reports("/", &headers("text/html")));
    assert!(reports("/a", &headers("Text/HTML ; charset=utf-8")));
    assert!(reports("/a", &headers("application/xhtml+xml")));
    assert!(!reports("/api", &headers("application/json")));
    assert!(!reports("/app.js", &headers("text/javascript")));
    assert!(!reports("/health", &none));
    for fixed in ["/robots.txt", "/llms.txt", "/llms-full.txt"] {
        assert!(reports(fixed, &headers("text/plain")));
        assert!(reports(fixed, &none));
    }
    assert!(!reports("/robots.txt.bak", &headers("text/plain")));
    assert!(!reports("/ROBOTS.TXT", &headers("text/plain")));

    let custom = scope(
        builder(base, &clock)
            .content_types(["application/json"])
            .include_paths(["/feed"])
            .exclude_paths(["/admin", "/robots.txt"]),
    );
    let reports = |path: &str, response: &HeaderMap| custom.inner().scope.reports(path, response);
    assert!(reports("/api", &headers("application/json")));
    assert!(
        !reports("/", &headers("text/html")),
        "the list replaces the default"
    );
    assert!(reports("/feed/rss", &headers("application/rss+xml")));
    assert!(!reports("/admin", &headers("application/json")));
    assert!(
        !reports("/robots.txt", &headers("text/plain")),
        "exclude lost to a fixed path"
    );
    assert!(reports("/llms.txt", &none));
}

mod layer {
    use super::*;

    use axum::extract::Extension;
    use axum::response::{Html, IntoResponse};
    use axum::routing::get;
    use axum::Router;
    use tower_service::Service;

    async fn page(Extension(lookup): Extension<AgentLookup>) -> Html<String> {
        Html(format!("known: {}", !lookup.is_unknown()))
    }

    fn app(sightings: &AgentSightings) -> Router {
        Router::new()
            .route("/", get(page))
            .route("/admin", get(page))
            .route(
                "/api",
                get(|| async { axum::Json(serde_json::json!({"ok": true})) }),
            )
            .route("/robots.txt", get(|| async { "User-agent: *" }))
            .route(
                "/missing",
                get(|| async { (http::StatusCode::NOT_FOUND, Html("gone")).into_response() }),
            )
            .layer(sightings.layer())
    }

    async fn call(app: &mut Router, path: &str, user_agent: &str) -> (http::StatusCode, String) {
        let request = Request::builder()
            .uri(path)
            .header("user-agent", user_agent)
            .header("x-test-ip", "20.171.206.9")
            .body(axum::body::Body::empty())
            .unwrap();
        std::future::poll_fn(|cx| {
            <Router as Service<Request<axum::body::Body>>>::poll_ready(app, cx)
        })
        .await
        .unwrap();
        let response = app.call(request).await.unwrap();
        let status = response.status();
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn reported(sightings: &AgentSightings) -> Vec<String> {
        let state = sightings.inner().state();
        state
            .pending
            .values()
            .map(|pending| pending.item.user_agent.clone())
            .collect()
    }

    #[tokio::test]
    async fn reports_only_in_scope_responses() {
        let clock = FakeClock::new();
        let sightings = builder("http://127.0.0.1:9", &clock)
            .exclude_paths(["/admin"])
            .build()
            .unwrap();
        let mut app = app(&sightings);
        assert_eq!(call(&mut app, "/", "page").await.1, "known: false");
        call(&mut app, "/admin", "admin").await;
        call(&mut app, "/api", "api").await;
        call(&mut app, "/robots.txt", "robots").await;
        assert_eq!(call(&mut app, "/missing", "missing").await.0, 404);
        call(&mut app, "/nowhere", "nowhere").await;
        assert_eq!(reported(&sightings), ["page", "robots", "missing"]);
    }

    #[tokio::test]
    async fn hands_the_lookup_to_the_handler() {
        let server = TestServer::always(ok("r1", &[600])).await;
        let clock = FakeClock::new();
        let (sightings, _) = component(&server.base_url, &clock);
        let mut app = app(&sightings);
        call(&mut app, "/", "GPTBot/1.4").await;
        sightings.flush().await;
        assert_eq!(call(&mut app, "/", "GPTBot/1.4").await.1, "known: true");
    }

    #[tokio::test]
    async fn never_delays_the_response() {
        // The API stalls; flushes are in flight the whole time.
        let server = TestServer::always(ok("r1", &[600]).delay(Duration::from_secs(3))).await;
        let sightings = AgentSightings::builder(&fingerly(&server.base_url))
            .client_ip(from_test_header)
            .build()
            .unwrap();
        let mut app = app(&sightings);
        for i in 0..200 {
            call(&mut app, "/", &format!("agent {i}")).await;
        }
        let flushing = sightings.clone();
        let explicit = tokio::spawn(async move { flushing.flush().await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = Instant::now();
        for i in 0..50 {
            call(&mut app, "/", &format!("later {i}")).await;
        }
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "{:?}",
            started.elapsed()
        );
        explicit.abort();
    }
}

#[tokio::test]
async fn decodes_the_agent_sightings_fixture() {
    #[derive(Deserialize)]
    struct Fixtures {
        responses: Vec<Fixture>,
    }
    #[derive(Deserialize)]
    struct Fixture {
        name: String,
        body: serde_json::Value,
    }
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("contract/fixtures.json");
    let fixtures: Fixtures = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let fixture = fixtures
        .responses
        .into_iter()
        .find(|fixture| fixture.name == "agent_sightings")
        .unwrap();
    let server = TestServer::always(Canned::json(200, fixture.body.to_string())).await;
    let clock = FakeClock::new();
    let (sightings, _) = component(&server.base_url, &clock);
    let agents = [
        "a browser",
        "GPTBot",
        "ChatGPT-User",
        "ChatGPT agent",
        "Googlebot",
    ];
    for agent in agents {
        sightings.report(&parts(agent, "198.51.100.1"), &html());
    }
    sightings.flush().await;
    let lookup = |agent: &str| sightings.lookup(&request(agent, "198.51.100.1"));
    assert_eq!(
        lookup("a browser").visitor_kind(),
        Some(&VisitorKind::Human)
    );
    assert_eq!(
        lookup("GPTBot").ai().unwrap().verification.result,
        AiVerificationResult::Pass
    );
    assert_eq!(
        lookup("ChatGPT-User").ai().unwrap().verification.result,
        AiVerificationResult::Fail
    );
    assert_eq!(
        lookup("ChatGPT agent"),
        AgentLookup::Unknown,
        "ttl 0 was cached"
    );
    let googlebot = lookup("Googlebot");
    assert_eq!(googlebot.visitor_kind(), Some(&VisitorKind::SearchCrawler));
    assert_eq!(
        googlebot.answer().unwrap().agent.as_deref(),
        Some("Googlebot")
    );
    assert!(googlebot.ai().is_none());
}
