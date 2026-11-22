//! Agent sightings: reports of the pages a server served, so that AI crawlers
//! and fetchers that never run a page's JavaScript are seen, and answers from
//! what the server said about them.
//!
//! The server decides. This module forwards raw input, folds repeats into
//! counts and remembers the server's answers; it never classifies a user
//! agent, never checks an address against a list and never filters by what
//! the visitor claims to be. What it decides is which of your own responses
//! are worth reporting, which is a fact about your resource.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http::header::{HeaderValue, CONTENT_TYPE, HOST, USER_AGENT};
use http::request::Parts;
use http::{HeaderMap, Request, Response};
use sha2::{Digest, Sha256};

use crate::agents::AgentsClient;
use crate::client::Fingerly;
use crate::enums::VisitorKind;
use crate::errors::{Error, Result};
use crate::models::{AgentAnswer, AgentAnswers, AgentSighting, AiAgent};
use crate::proxy::{resolve_client_ip, signature_header, ClientIpFn};
use crate::transport::{ANSWER_BROKE_OFF, HUNG_UP_AFTER_SENDING};

/// The longest user agent or method reported, in bytes as sent: a request
/// with a longer one is not reported. A longer `Host` or Web Bot Auth header
/// is left out.
const MAX_HEADER_BYTES: usize = 4096;
/// A flush sends at most this many items.
const BATCH_ITEMS: usize = 200;
/// A flush runs once the pending fields reach this many bytes, and sends at
/// most this many.
const BATCH_BYTES: usize = 64 * 1024;
/// A flush runs this long after its oldest pending item.
const FLUSH_AFTER: Duration = Duration::from_secs(2);
/// The deadline for one flush, the whole exchange included.
const FLUSH_DEADLINE: Duration = Duration::from_secs(5);
/// How much longer than a flush's deadline `flush()` waits for one already
/// in flight: six seconds in all.
const FLUSH_WAIT_MARGIN: Duration = Duration::from_secs(1);
/// The longest an answer is kept, whatever `ttl` the server gave.
const MAX_TTL_SECONDS: u64 = 86_400;
/// Pending and in-flight items together never pass this.
const MAX_PENDING: usize = 1000;
/// The largest count the server accepts for one item.
const MAX_COUNT: u64 = 1_000_000;
/// How long a refused key pauses flushing.
const AUTH_PAUSE: Duration = Duration::from_secs(60);
/// How long a `429` without `Retry-After` pauses flushing.
const RATE_LIMIT_PAUSE: Duration = Duration::from_secs(60);
/// The shortest pause a `429` causes, even with a `Retry-After` of `0` or a
/// date already past.
const MIN_RATE_LIMIT_PAUSE: Duration = Duration::from_secs(1);
/// The longest pause a `429` causes, whatever its `Retry-After` asks for: a
/// day, the longest any allowance takes to reset.
const MAX_RATE_LIMIT_PAUSE: Duration = Duration::from_secs(86_400);
/// The first and the longest wait after a `503` or a failed connection.
const BACKOFF_START: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// Each kind of failure is reported at most once per this long.
const REPORT_EVERY: Duration = Duration::from_secs(60);
/// How long the background flusher sleeps with nothing pending before it
/// checks whether its component is still alive.
const IDLE_WAIT: Duration = Duration::from_secs(30);
/// The shortest the background flusher sleeps, so it can never spin.
const MIN_WAIT: Duration = Duration::from_millis(100);
/// How long after a panic the background flusher is started again.
const FLUSHER_RESTART: Duration = Duration::from_secs(60);

/// The response content types reported by default.
const DEFAULT_CONTENT_TYPES: [&str; 2] = ["text/html", "application/xhtml+xml"];
/// Paths reported whatever their status or content type.
const FIXED_PATHS: [&str; 3] = ["/robots.txt", "/llms.txt", "/llms-full.txt"];

/// The cache key of section 4.1 of the contract: the first 16 bytes of
/// SHA-256 over the user agent, the canonical address, the `Signature-Agent`
/// and whether the request was signed, each separated by a zero byte.
pub(crate) type Key = [u8; 16];

pub(crate) fn sighting_key(
    user_agent: &str,
    canonical_ip: &str,
    signature_agent: &str,
    signed: bool,
) -> Key {
    let mut hash = Sha256::new();
    hash.update(user_agent.as_bytes());
    hash.update([0]);
    hash.update(canonical_ip.as_bytes());
    hash.update([0]);
    hash.update(signature_agent.as_bytes());
    hash.update([0]);
    hash.update(if signed { b"1" } else { b"0" });
    let digest = hash.finalize();
    let mut key = [0; 16];
    key.copy_from_slice(&digest[..16]);
    key
}

/// An address in its canonical text form: an IPv4-mapped IPv6 address as the
/// IPv4 address, IPv6 as RFC 5952 writes it.
pub(crate) fn canonical_ip(address: IpAddr) -> String {
    match address {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
    }
}

/// What [`AgentSightings::lookup`] knows about a request.
///
/// [`AgentLookup::Unknown`] means the server has not answered for this exact
/// request yet, its answer expired, or the request could not be reported.
/// Serve it as usual: the component fails open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentLookup {
    /// The server's remembered answer for this exact request, shared with
    /// the cache.
    Known(Arc<AgentAnswer>),
    /// No answer is remembered. Serve the request as usual.
    Unknown,
}

impl AgentLookup {
    /// The server's answer, unless this is [`AgentLookup::Unknown`].
    pub fn answer(&self) -> Option<&AgentAnswer> {
        match self {
            AgentLookup::Known(answer) => Some(answer.as_ref()),
            AgentLookup::Unknown => None,
        }
    }

    /// Whether this is [`AgentLookup::Unknown`].
    pub fn is_unknown(&self) -> bool {
        matches!(self, AgentLookup::Unknown)
    }

    /// What sort of client sent the request, when the answer is known.
    pub fn visitor_kind(&self) -> Option<&VisitorKind> {
        self.answer().map(|answer| &answer.visitor_kind)
    }

    /// The AI agent, when the answer is known and names one.
    pub fn ai(&self) -> Option<&AiAgent> {
        self.answer()?.ai.as_ref()
    }
}

/// What went wrong, for an [`AgentSightingsError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AgentSightingsErrorKind {
    /// The API refused a batch as invalid (`422`): no item in the batch was
    /// usable. The batch was dropped.
    InvalidRequest,
    /// The API refused the secret key (`401` or `403`). The batch was
    /// dropped and flushing paused for 60 seconds.
    Unauthorized,
    /// The API answered with something this build does not expect. The batch
    /// was dropped.
    UnexpectedAnswer,
    /// The `client_ip` callback returned something other than one address,
    /// so the request was not reported.
    InvalidClientIp,
    /// The background flusher stopped on a panic, as it does on a Tokio
    /// runtime built without timers (use `enable_all()`). It is started again
    /// 60 seconds later; sightings wait in the buffer meanwhile.
    FlusherStopped,
}

/// A failure the component handled on its own. Requests keep being served
/// either way. It never carries a user agent, an address or any other field
/// of a request.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct AgentSightingsError {
    /// What went wrong.
    pub kind: AgentSightingsErrorKind,
    /// The HTTP status the API answered, when it answered.
    pub status: Option<u16>,
    /// A one-line description of the cause.
    pub message: String,
}

impl fmt::Display for AgentSightingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fingerly agent sightings: {}", self.message)
    }
}

impl std::error::Error for AgentSightingsError {}

/// Receives the failures the component handled; see
/// [`AgentSightingsBuilder::on_error`].
pub type AgentSightingsErrorHook = dyn Fn(&AgentSightingsError) + Send + Sync + 'static;

/// The time source; a test supplies its own.
pub(crate) type Clock = Arc<dyn Fn() -> Instant + Send + Sync + 'static>;

/// Reports the requests your server served to Fingerly in the background, and
/// answers what sent each one from what the server said.
///
/// AI crawlers and fetchers that never run a page's JavaScript never reach
/// the browser SDK, so they are seen only this way. Mount
/// [`layer`](Self::layer) on your router; it reports each in-scope response
/// after it is produced, and never delays it. Ask
/// [`lookup`](Self::lookup) what sent a request: it answers from memory, never
/// waits on the network, and returns [`AgentLookup::Unknown`] when it does not
/// know, which means "serve as usual".
///
/// Construct it once per process and clone it freely: clones share one
/// cache, one buffer and one background flusher. Call
/// [`close`](Self::close) on shutdown to send what is still buffered.
///
/// ```no_run
/// # async fn run() -> fingerly::Result<()> {
/// use fingerly::{AgentSightings, Fingerly};
///
/// let fingerly = Fingerly::new(std::env::var("FINGERLY_SECRET_KEY").unwrap())?;
/// let sightings = AgentSightings::builder(&fingerly)
///     .client_ip(|parts| {
///         // The header your load balancer or CDN sets, else the TCP peer.
///         if let Some(address) = parts.headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
///             return address.to_owned();
///         }
///         parts
///             .extensions
///             .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
///             .map(|info| info.0.ip().to_string())
///             .unwrap_or_default()
///     })
///     .build()?;
///
/// let app: axum::Router = axum::Router::new()
///     .route("/", axum::routing::get(|| async { axum::response::Html("<h1>Hello</h1>") }))
///     .layer(sightings.layer());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AgentSightings {
    inner: Arc<Inner>,
}

pub(crate) struct Inner {
    agents: AgentsClient,
    client_ip: Arc<ClientIpFn>,
    scope: Scope,
    state: Mutex<State>,
    /// Held for the whole of a flush, so at most one is in flight.
    flight: tokio::sync::Mutex<()>,
    /// Wakes the background flusher early.
    wake: Arc<tokio::sync::Notify>,
    flusher: Mutex<Flusher>,
    background: bool,
    closed: AtomicBool,
    dropped: AtomicU64,
    on_error: Option<Arc<AgentSightingsErrorHook>>,
    clock: Clock,
    deadline: Duration,
}

/// The background flusher's task.
#[derive(Default)]
struct Flusher {
    task: Option<tokio::task::JoinHandle<()>>,
    /// After the task panicked: when it may be started again.
    restart_at: Option<Instant>,
}

impl fmt::Debug for AgentSightings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentSightings")
            .field("cache_capacity", &self.inner.lock().cache.capacity)
            .field("dropped", &self.dropped())
            .finish_non_exhaustive()
    }
}

/// One request seen, as it would be reported.
#[derive(Clone, Debug)]
pub(crate) struct Observed {
    pub(crate) key: Key,
    pub(crate) signed: bool,
    pub(crate) item: AgentSighting,
    pub(crate) bytes: usize,
}

/// One pending item: the first sighting's raw fields and a running count.
#[derive(Debug)]
pub(crate) struct Pending {
    pub(crate) key: Key,
    pub(crate) signed: bool,
    pub(crate) item: AgentSighting,
    pub(crate) count: u64,
    pub(crate) bytes: usize,
    pub(crate) first_seen: Instant,
}

pub(crate) struct State {
    pub(crate) cache: Lru,
    pub(crate) rules_version: Option<String>,
    /// Pending items, oldest first, by the order they were first seen.
    pub(crate) pending: BTreeMap<u64, Pending>,
    /// The pending item of each unsigned key.
    pub(crate) by_key: HashMap<Key, u64>,
    pub(crate) next_seq: u64,
    pub(crate) in_flight: usize,
    pub(crate) bytes: usize,
    pub(crate) paused_until: Option<Instant>,
    pub(crate) backoff: Duration,
    reported: HashMap<AgentSightingsErrorKind, Instant>,
}

impl State {
    fn paused(&self, now: Instant) -> bool {
        self.paused_until.is_some_and(|until| now < until)
    }

    /// Whether a flush is due: enough items, enough bytes, or an old enough
    /// item, and no pause.
    pub(crate) fn due(&self, now: Instant) -> bool {
        let Some(oldest) = self.pending.values().next() else {
            return false;
        };
        !self.paused(now)
            && (self.pending.len() >= BATCH_ITEMS
                || self.bytes >= BATCH_BYTES
                || now.saturating_duration_since(oldest.first_seen) >= FLUSH_AFTER)
    }

    /// How long the background flusher may sleep.
    fn wait(&self, now: Instant) -> Duration {
        let Some(oldest) = self.pending.values().next() else {
            return IDLE_WAIT;
        };
        let at = match self.paused_until {
            Some(until) if now < until => until,
            _ => oldest.first_seen + FLUSH_AFTER,
        };
        at.saturating_duration_since(now).max(MIN_WAIT)
    }

    /// Takes the oldest items for one flush: up to 200, and no more than
    /// 64 KiB of fields past the first.
    pub(crate) fn take_batch(&mut self) -> Vec<(u64, Pending)> {
        let mut taken: Vec<(u64, Pending)> = Vec::new();
        let mut bytes = 0;
        while let Some(entry) = self.pending.first_entry() {
            if taken.len() >= BATCH_ITEMS
                || (!taken.is_empty() && bytes + entry.get().bytes > BATCH_BYTES)
            {
                break;
            }
            let (seq, item) = entry.remove_entry();
            if !item.signed {
                self.by_key.remove(&item.key);
            }
            self.bytes -= item.bytes;
            bytes += item.bytes;
            taken.push((seq, item));
        }
        self.in_flight += taken.len();
        taken
    }

    /// Puts a kept batch back as the oldest items, folding each unsigned key
    /// into the entry it gained meanwhile.
    pub(crate) fn keep(&mut self, taken: Vec<(u64, Pending)>) {
        for (seq, mut item) in taken {
            if !item.signed {
                if let Some(newer) = self
                    .by_key
                    .remove(&item.key)
                    .and_then(|newer| self.pending.remove(&newer))
                {
                    item.count = (item.count + newer.count).min(MAX_COUNT);
                    self.bytes -= newer.bytes;
                }
                self.by_key.insert(item.key, seq);
            }
            self.bytes += item.bytes;
            self.pending.insert(seq, item);
        }
    }

    /// Stores the server's answers, after dropping every remembered answer
    /// when its rules changed.
    fn store(&mut self, taken: &[(u64, Pending)], answers: AgentAnswers, now: Instant) {
        if self.rules_version.as_deref() != Some(answers.rules_version.as_str()) {
            self.cache.clear();
            self.rules_version = Some(answers.rules_version);
        }
        for ((_, item), answer) in taken.iter().zip(answers.items) {
            let Ok(ttl) = u64::try_from(answer.ttl) else {
                continue;
            };
            if ttl == 0 {
                continue;
            }
            if let Some(expires) = now.checked_add(Duration::from_secs(ttl.min(MAX_TTL_SECONDS))) {
                self.cache.insert(item.key, Arc::new(answer), expires);
            }
        }
    }

    /// Whether a failure of this kind may be reported now, at most once a
    /// minute.
    fn may_report(&mut self, kind: AgentSightingsErrorKind, now: Instant) -> bool {
        match self.reported.get(&kind) {
            Some(last) if now.saturating_duration_since(*last) < REPORT_EVERY => false,
            _ => {
                self.reported.insert(kind, now);
                true
            }
        }
    }
}

/// A bounded least-recently-used map of answers and their expiry.
pub(crate) struct Lru {
    pub(crate) capacity: usize,
    entries: HashMap<Key, CacheEntry>,
    /// Keys by last use, least recent first.
    order: BTreeMap<u64, Key>,
    tick: u64,
}

struct CacheEntry {
    answer: Arc<AgentAnswer>,
    expires: Instant,
    tick: u64,
}

impl Lru {
    pub(crate) fn new(capacity: usize) -> Self {
        Lru {
            capacity,
            entries: HashMap::new(),
            order: BTreeMap::new(),
            tick: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn get(&mut self, key: &Key, now: Instant) -> Option<Arc<AgentAnswer>> {
        let entry = self.entries.get_mut(key)?;
        if now >= entry.expires {
            self.order.remove(&entry.tick);
            self.entries.remove(key);
            return None;
        }
        self.order.remove(&entry.tick);
        self.tick += 1;
        entry.tick = self.tick;
        self.order.insert(self.tick, *key);
        Some(entry.answer.clone())
    }

    pub(crate) fn insert(&mut self, key: Key, answer: Arc<AgentAnswer>, expires: Instant) {
        if let Some(old) = self.entries.remove(&key) {
            self.order.remove(&old.tick);
        }
        while self.entries.len() >= self.capacity {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        self.tick += 1;
        self.order.insert(self.tick, key);
        self.entries.insert(
            key,
            CacheEntry {
                answer,
                expires,
                tick: self.tick,
            },
        );
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }
}

/// Which responses are reported.
#[derive(Debug)]
pub(crate) struct Scope {
    content_types: Vec<String>,
    include: Vec<String>,
    exclude: Vec<String>,
}

impl Scope {
    /// Whether the response to a request for `path` is reported: never under
    /// an excluded prefix; always for the fixed paths and the included
    /// prefixes; otherwise when its media type is one of the configured ones.
    /// Whatever the status, and never by anything the visitor sent.
    pub(crate) fn reports(&self, path: &str, response: &HeaderMap) -> bool {
        if self
            .exclude
            .iter()
            .any(|prefix| path.starts_with(prefix.as_str()))
        {
            return false;
        }
        if FIXED_PATHS.contains(&path)
            || self
                .include
                .iter()
                .any(|prefix| path.starts_with(prefix.as_str()))
        {
            return true;
        }
        media_type(response).is_some_and(|media| self.content_types.contains(&media))
    }
}

/// The response's media type: the `Content-Type` before any parameter,
/// trimmed and lowercased.
fn media_type(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(CONTENT_TYPE)?.to_str().ok()?;
    let media = value.split(';').next()?.trim();
    (!media.is_empty()).then(|| media.to_ascii_lowercase())
}

/// A header value as text; bytes that are not UTF-8 become U+FFFD, so the
/// key is computed over exactly what is sent.
fn text(value: &HeaderValue) -> String {
    String::from_utf8_lossy(value.as_bytes()).into_owned()
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic elsewhere while holding the lock leaves the state usable:
        // every change to it is complete before anything can panic.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn now(&self) -> Instant {
        (self.clock)()
    }

    /// Reads a request as it would be reported, or `None` when it cannot be:
    /// a user agent or method over 4096 bytes as sent, or no valid client
    /// address.
    pub(crate) fn observe(&self, parts: &Parts) -> Option<Observed> {
        let user_agent = parts.headers.get(USER_AGENT).map(text).unwrap_or_default();
        if user_agent.len() > MAX_HEADER_BYTES {
            return None;
        }
        // No real host name or method comes near 4096 bytes. Bounding them
        // bounds every item, so a batch always fits the API's 1 MiB body
        // limit: one item past it would be refused with its whole batch. The
        // `Host` serves only to check a signature, so a longer one is left
        // out, as a longer Web Bot Auth header is.
        let method = parts.method.as_str().to_owned();
        if method.len() > MAX_HEADER_BYTES {
            return None;
        }
        let host = parts
            .headers
            .get(HOST)
            .map(text)
            .or_else(|| parts.uri.authority().map(|authority| authority.to_string()))
            .filter(|host| host.len() <= MAX_HEADER_BYTES);
        let Some(address) = resolve_client_ip(&*self.client_ip, parts) else {
            self.report_failure(
                AgentSightingsErrorKind::InvalidClientIp,
                None,
                "the client IP callback returned no valid address; the request was not reported"
                    .to_owned(),
            );
            return None;
        };
        let client_ip = canonical_ip(address);
        // A Web Bot Auth header over 4096 bytes is left out, and then counts
        // as absent for the key too, so the key matches what is sent. The
        // limit applies to the text sent, after U+FFFD replaces each byte that
        // is not UTF-8: up to three times the bytes received, which the API
        // would refuse with the whole batch.
        let header = |name| {
            signature_header(&parts.headers, name)
                .map(|value| text(&value))
                .filter(|value| value.len() <= MAX_HEADER_BYTES)
        };
        let signature = header("signature");
        let signature_input = header("signature-input");
        let signature_agent = header("signature-agent");
        let signed = signature.is_some() && signature_input.is_some();
        let key = sighting_key(
            &user_agent,
            &client_ip,
            signature_agent.as_deref().unwrap_or(""),
            signed,
        );

        let field = |value: &Option<String>| value.as_ref().map_or(0, String::len);
        let bytes = user_agent.len()
            + client_ip.len()
            + method.len()
            + field(&host)
            + field(&signature)
            + field(&signature_input)
            + field(&signature_agent);
        Some(Observed {
            key,
            signed,
            bytes,
            item: AgentSighting {
                user_agent,
                client_ip,
                host,
                method: Some(method),
                signature,
                signature_input,
                signature_agent,
                count: None,
            },
        })
    }

    pub(crate) fn lookup_key(&self, key: &Key) -> AgentLookup {
        let now = self.now();
        match self.lock().cache.get(key, now) {
            Some(answer) => AgentLookup::Known(answer),
            None => AgentLookup::Unknown,
        }
    }

    /// Adds one sighting to the pending buffer. Never waits on the network.
    pub(crate) fn record(self: &Arc<Self>, observed: Observed) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let now = self.now();
        let wake = {
            let mut state = self.lock();
            if !observed.signed {
                if let Some(seq) = state.by_key.get(&observed.key).copied() {
                    if let Some(pending) = state.pending.get_mut(&seq) {
                        pending.count = (pending.count + 1).min(MAX_COUNT);
                        return;
                    }
                }
            }
            if state.pending.len() + state.in_flight >= MAX_PENDING {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let seq = state.next_seq;
            state.next_seq += 1;
            if !observed.signed {
                state.by_key.insert(observed.key, seq);
            }
            state.bytes += observed.bytes;
            state.pending.insert(
                seq,
                Pending {
                    key: observed.key,
                    signed: observed.signed,
                    item: observed.item,
                    count: 1,
                    bytes: observed.bytes,
                    first_seen: now,
                },
            );
            state.pending.len() == 1
                || state.pending.len() >= BATCH_ITEMS
                || state.bytes >= BATCH_BYTES
        };
        self.ensure_flusher();
        if wake {
            self.wake.notify_one();
        }
    }

    /// Starts the background flusher on the current Tokio runtime, or again
    /// when the runtime it ran on has gone. Without a runtime nothing starts,
    /// and [`AgentSightings::flush`] sends what is buffered.
    ///
    /// A flusher that panicked, as one does on a runtime built without
    /// timers, is started again at most once a minute rather than on every
    /// request, and that is reported.
    fn ensure_flusher(self: &Arc<Self>) {
        if !self.background {
            return;
        }
        let now = self.now();
        let mut panicked = false;
        {
            let mut flusher = self.flusher.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(task) = flusher.task.as_mut() {
                if !task.is_finished() {
                    return;
                }
                // A finished task is ready, so this poll never registers the
                // waker; the handle is dropped right after, never polled again.
                let mut cx = Context::from_waker(std::task::Waker::noop());
                panicked = matches!(
                    Pin::new(task).poll(&mut cx),
                    Poll::Ready(Err(error)) if error.is_panic()
                );
                flusher.task = None;
                if panicked {
                    flusher.restart_at = now.checked_add(FLUSHER_RESTART);
                }
            }
            let waiting = flusher.restart_at.is_some_and(|at| now < at);
            if !waiting {
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    let weak = Arc::downgrade(self);
                    let wake = self.wake.clone();
                    flusher.task = Some(runtime.spawn(run_flusher(weak, wake)));
                    flusher.restart_at = None;
                }
            }
        }
        if panicked {
            self.report_failure(
                AgentSightingsErrorKind::FlusherStopped,
                None,
                "the background flusher stopped on a panic, such as on a Tokio runtime built \
                 without timers; it is started again in 60 seconds"
                    .to_owned(),
            );
        }
    }

    /// Hands a failure to the hook, or logs one line, at most once a minute
    /// per kind.
    fn report_failure(&self, kind: AgentSightingsErrorKind, status: Option<u16>, message: String) {
        let now = self.now();
        if !self.lock().may_report(kind, now) {
            return;
        }
        let failure = AgentSightingsError {
            kind,
            status,
            message,
        };
        match &self.on_error {
            Some(hook) => drop(catch_unwind(AssertUnwindSafe(|| hook(&failure)))),
            None => tracing::warn!(
                target: "fingerly::agents",
                status = failure.status,
                "{}",
                failure.message
            ),
        }
    }

    /// Flushes while a flush is due, unless one is already in flight.
    ///
    /// The flight lock is taken for each batch rather than for them all, so
    /// a `flush()` or `close()` waiting for it gets it after the batch in
    /// flight, however many more are due.
    async fn flush_due(&self) {
        while self.lock().due(self.now()) {
            let Ok(_flight) = self.flight.try_lock() else {
                return;
            };
            if self.send_batch().await != Sent::Yes {
                break;
            }
        }
    }

    /// Sends every pending batch, after any flush in flight, until the buffer
    /// is empty, a pause begins or a batch fails. It waits at most a second
    /// past one flush's deadline for the flush in flight, and returns with
    /// nothing sent when that one is still out.
    async fn flush_all(&self) {
        let wait = self.deadline + FLUSH_WAIT_MARGIN;
        let Ok(_flight) = tokio::time::timeout(wait, self.flight.lock()).await else {
            return;
        };
        while self.send_batch().await == Sent::Yes {}
    }

    /// Sends one batch and applies the answer as section 6 of the contract
    /// says. The caller holds the flight lock.
    async fn send_batch(&self) -> Sent {
        let (taken, items) = {
            let mut state = self.lock();
            let now = self.now();
            if state.paused(now) {
                return Sent::No;
            }
            state.paused_until = None;
            let taken = state.take_batch();
            if taken.is_empty() {
                return Sent::No;
            }
            let items: Vec<AgentSighting> = taken
                .iter()
                .map(|(_, pending)| {
                    let mut item = pending.item.clone();
                    item.count = Some(pending.count);
                    item
                })
                .collect();
            (taken, items)
        };

        // A caller that drops this future, such as `flush()` under a deadline
        // of its own or a runtime shutting down, must not leave the batch
        // counted as in flight forever: that would fill the buffer for good.
        // The request may have gone out, so the batch is dropped, as when the
        // deadline passes.
        let mut flight = InFlight {
            inner: self,
            items: taken.len(),
        };
        let result = self
            .agents
            .sightings_within(&items, Some(self.deadline))
            .await;

        let now = self.now();
        let mut state = self.lock();
        state.in_flight -= taken.len();
        flight.items = 0;
        let failure = match result {
            Ok(answers) if answers.items.len() == taken.len() => {
                state.store(&taken, answers, now);
                state.backoff = BACKOFF_START;
                return Sent::Yes;
            }
            Ok(_) => Some((
                AgentSightingsErrorKind::UnexpectedAnswer,
                Some(200),
                "the API answered a different number of sightings than were sent; the batch \
                 was dropped"
                    .to_owned(),
            )),
            Err(Error::Api(api)) => match api.status {
                422 => Some((
                    AgentSightingsErrorKind::InvalidRequest,
                    Some(422),
                    "the API refused a batch of sightings as invalid; it was dropped".to_owned(),
                )),
                401 | 403 => {
                    state.paused_until = Some(now + AUTH_PAUSE);
                    Some((
                        AgentSightingsErrorKind::Unauthorized,
                        Some(api.status),
                        "the API refused the secret key; sightings are paused for 60 seconds"
                            .to_owned(),
                    ))
                }
                429 => {
                    let wait = match (api.retry_after, api.rate_limit_scope()) {
                        (Some(seconds), _) => Duration::from_secs(seconds)
                            .clamp(MIN_RATE_LIMIT_PAUSE, MAX_RATE_LIMIT_PAUSE),
                        (None, Some("daily")) => until_next_utc_day(SystemTime::now()),
                        (None, _) => RATE_LIMIT_PAUSE,
                    };
                    state.paused_until = now.checked_add(wait).or(Some(now + RATE_LIMIT_PAUSE));
                    state.keep(taken);
                    return Sent::No;
                }
                503 => {
                    state.back_off(now);
                    state.keep(taken);
                    return Sent::No;
                }
                status => Some((
                    AgentSightingsErrorKind::UnexpectedAnswer,
                    Some(status),
                    format!("the API answered sightings with HTTP {status}; the batch was dropped"),
                )),
            },
            // The deadline passed once the request was out: the server may
            // have counted it, and a retry would count it twice.
            Err(Error::Timeout) => None,
            // The answer started and broke off, or the connection was closed
            // or reset once the request was out: the server saw the request.
            Err(Error::Connection { message })
                if message == ANSWER_BROKE_OFF || message == HUNG_UP_AFTER_SENDING =>
            {
                None
            }
            // No connection, a request that could not be written in full, or
            // no telling whether it was (HTTP/2): nothing known to be counted.
            Err(Error::Connection { .. }) => {
                state.back_off(now);
                state.keep(taken);
                return Sent::No;
            }
            Err(_) => Some((
                AgentSightingsErrorKind::UnexpectedAnswer,
                None,
                "the API's answer to sightings could not be read; the batch was dropped".to_owned(),
            )),
        };
        drop(state);
        if let Some((kind, status, message)) = failure {
            self.report_failure(kind, status, message);
        }
        Sent::No
    }
}

impl State {
    /// Pauses for the current backoff and doubles it, up to a minute.
    fn back_off(&mut self, now: Instant) {
        self.paused_until = Some(now + self.backoff);
        self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
    }
}

/// Releases a batch's place in the buffer when its send is cancelled.
struct InFlight<'a> {
    inner: &'a Inner,
    items: usize,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if self.items > 0 {
            self.inner.lock().in_flight -= self.items;
        }
    }
}

/// Whether a batch was sent and answered, so the next may follow at once.
#[derive(Debug, PartialEq, Eq)]
enum Sent {
    Yes,
    No,
}

/// The time from `now` to the next midnight UTC, when a daily allowance
/// resets.
fn until_next_utc_day(now: SystemTime) -> Duration {
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    Duration::from_secs(86_400 - seconds % 86_400)
}

/// The background flusher: sleeps until a flush can be due, flushes, and
/// ends with the last handle to its component or with [`AgentSightings::close`].
async fn run_flusher(inner: Weak<Inner>, wake: Arc<tokio::sync::Notify>) {
    loop {
        let wait = {
            let Some(inner) = inner.upgrade() else {
                return;
            };
            if inner.closed.load(Ordering::Acquire) {
                return;
            }
            inner.flush_due().await;
            let now = inner.now();
            let wait = inner.lock().wait(now);
            wait
        };
        let _ = tokio::time::timeout(wait, wake.notified()).await;
    }
}

impl AgentSightings {
    /// The cache capacity when none is configured, in entries: about 1.5 MB.
    pub const DEFAULT_CACHE_CAPACITY: usize = 4096;
    /// The largest cache capacity accepted, in entries: about 25 MB. A larger
    /// one is reduced to this.
    pub const MAX_CACHE_CAPACITY: usize = 65_536;

    /// Starts a builder that reports under `fingerly`'s secret key and shares
    /// its connection pool. A `client_ip` callback is required.
    pub fn builder(fingerly: &Fingerly) -> AgentSightingsBuilder {
        AgentSightingsBuilder {
            agents: fingerly.agents().clone(),
            client_ip: None,
            cache_capacity: None,
            content_types: None,
            include_paths: Vec::new(),
            exclude_paths: Vec::new(),
            on_error: None,
            clock: None,
            deadline: FLUSH_DEADLINE,
            background: true,
        }
    }

    /// A [`tower_layer::Layer`] that reports each in-scope response once it
    /// is produced, without delaying it, and puts this request's
    /// [`AgentLookup`] in the request's extensions for the handler.
    pub fn layer(&self) -> AgentSightingsLayer {
        AgentSightingsLayer {
            sightings: self.clone(),
        }
    }

    /// What the server said about this exact request (its user agent,
    /// address and `Signature-Agent`), or [`AgentLookup::Unknown`].
    ///
    /// It answers from memory and never waits on the network. A signed
    /// request is checked every time, so it is always unknown here.
    ///
    /// It copies the request's head to hand `client_ip` its parts. Behind
    /// [`layer`](Self::layer), read the [`AgentLookup`] from the request's
    /// extensions instead, which the layer has already computed.
    pub fn lookup<B>(&self, request: &Request<B>) -> AgentLookup {
        let (mut parts, ()) = Request::new(()).into_parts();
        parts.method = request.method().clone();
        parts.uri = request.uri().clone();
        parts.version = request.version();
        parts.headers = request.headers().clone();
        parts.extensions = request.extensions().clone();
        self.lookup_parts(&parts)
    }

    /// [`lookup`](Self::lookup) for the parts of a request.
    pub fn lookup_parts(&self, parts: &Parts) -> AgentLookup {
        match self.inner.observe(parts) {
            Some(observed) => self.inner.lookup_key(&observed.key),
            None => AgentLookup::Unknown,
        }
    }

    /// Reports a request your server answered with `response_headers`, when
    /// it is in scope, for a framework that does not speak tower. Call it
    /// after the response is produced. It never waits on the network.
    pub fn report(&self, parts: &Parts, response_headers: &HeaderMap) {
        if !self.inner.scope.reports(parts.uri.path(), response_headers) {
            return;
        }
        if let Some(observed) = self.inner.observe(parts) {
            self.inner.record(observed);
        }
    }

    /// Sends everything buffered now, after any flush already in flight,
    /// until the buffer is empty, a pause begins or a batch fails. It waits
    /// at most 6 seconds for a flush in flight, and never returns an error.
    /// Serverless and edge handlers call it before the
    /// invocation ends.
    ///
    /// Cancelling it, by dropping the future, drops the batch it was
    /// sending, as a passed deadline does: the API may already have counted
    /// it.
    pub async fn flush(&self) {
        self.inner.flush_all().await;
    }

    /// Stops the background flusher, sends what is buffered, and ignores
    /// every later report. Call it on shutdown, after your server has
    /// stopped serving (with axum, behind `with_graceful_shutdown`). Calling
    /// it again, or from several tasks at once, is harmless.
    pub async fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        self.inner.wake.notify_one();
        self.inner.flush_all().await;
    }

    /// How many sightings were not buffered because the buffer was full,
    /// since the process started. Their requests stay unknown.
    pub fn dropped(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn inner(&self) -> &Arc<Inner> {
        &self.inner
    }
}

#[cfg(test)]
impl Inner {
    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        self.lock()
    }
}

/// Configures an [`AgentSightings`]. Start one with
/// [`AgentSightings::builder`].
pub struct AgentSightingsBuilder {
    agents: AgentsClient,
    client_ip: Option<Arc<ClientIpFn>>,
    cache_capacity: Option<usize>,
    content_types: Option<Vec<String>>,
    include_paths: Vec<String>,
    exclude_paths: Vec<String>,
    on_error: Option<Arc<AgentSightingsErrorHook>>,
    pub(crate) clock: Option<Clock>,
    pub(crate) deadline: Duration,
    pub(crate) background: bool,
}

impl fmt::Debug for AgentSightingsBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentSightingsBuilder")
            .field("cache_capacity", &self.cache_capacity)
            .field("content_types", &self.content_types)
            .field("include_paths", &self.include_paths)
            .field("exclude_paths", &self.exclude_paths)
            .finish_non_exhaustive()
    }
}

impl AgentSightingsBuilder {
    /// Resolves the visitor's address. Required, and the same callback as
    /// [`FingerlyProxyBuilder::client_ip`](crate::FingerlyProxyBuilder::client_ip).
    ///
    /// It must return exactly one IPv4 or IPv6 address, read from a header
    /// your own infrastructure sets, else the TCP peer. Never the left-most
    /// `X-Forwarded-For` value: the visitor writes it. A request it returns
    /// no address for is not reported, and that is reported once a minute.
    pub fn client_ip<F>(mut self, resolve: F) -> Self
    where
        F: Fn(&Parts) -> String + Send + Sync + 'static,
    {
        self.client_ip = Some(Arc::new(resolve));
        self
    }

    /// How many answers are remembered, per process. Defaults to
    /// [`AgentSightings::DEFAULT_CACHE_CAPACITY`]; a larger value than
    /// [`AgentSightings::MAX_CACHE_CAPACITY`] is reduced to it.
    pub fn cache_capacity(mut self, entries: usize) -> Self {
        self.cache_capacity = Some(entries);
        self
    }

    /// The response content types reported, replacing the default
    /// `text/html` and `application/xhtml+xml`. Compared with the response's
    /// media type, without parameters and ignoring case.
    pub fn content_types<I, S>(mut self, types: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.content_types = Some(
            types
                .into_iter()
                .map(|value| value.into().trim().to_ascii_lowercase())
                .collect(),
        );
        self
    }

    /// Path prefixes reported whatever their content type, such as `/feed`.
    /// `/robots.txt`, `/llms.txt` and `/llms-full.txt` always are.
    pub fn include_paths<I, S>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.include_paths = prefixes.into_iter().map(Into::into).collect();
        self
    }

    /// Path prefixes never reported, such as `/admin`. They win over
    /// everything else, the fixed paths included.
    pub fn exclude_paths<I, S>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exclude_paths = prefixes.into_iter().map(Into::into).collect();
        self
    }

    /// Receives the failures the component handled on its own, each kind at
    /// most once a minute. Without it, each is logged as one `tracing`
    /// warning under `fingerly::agents`.
    pub fn on_error<F>(mut self, hook: F) -> Self
    where
        F: Fn(&AgentSightingsError) + Send + Sync + 'static,
    {
        self.on_error = Some(Arc::new(hook));
        self
    }

    /// Validates every option and builds the component.
    pub fn build(self) -> Result<AgentSightings> {
        let Some(client_ip) = self.client_ip else {
            return Err(Error::config("client_ip is required"));
        };
        let capacity = match self.cache_capacity {
            Some(0) => return Err(Error::config("cache_capacity must be a positive integer")),
            Some(entries) => entries.min(AgentSightings::MAX_CACHE_CAPACITY),
            None => AgentSightings::DEFAULT_CACHE_CAPACITY,
        };
        let content_types = self.content_types.unwrap_or_else(|| {
            DEFAULT_CONTENT_TYPES
                .iter()
                .map(|value| (*value).to_owned())
                .collect()
        });
        let clock = self.clock.unwrap_or_else(|| Arc::new(Instant::now));
        Ok(AgentSightings {
            inner: Arc::new(Inner {
                agents: self.agents,
                client_ip,
                scope: Scope {
                    content_types,
                    include: self.include_paths,
                    exclude: self.exclude_paths,
                },
                state: Mutex::new(State {
                    cache: Lru::new(capacity),
                    rules_version: None,
                    pending: BTreeMap::new(),
                    by_key: HashMap::new(),
                    next_seq: 0,
                    in_flight: 0,
                    bytes: 0,
                    paused_until: None,
                    backoff: BACKOFF_START,
                    reported: HashMap::new(),
                }),
                flight: tokio::sync::Mutex::new(()),
                wake: Arc::new(tokio::sync::Notify::new()),
                flusher: Mutex::new(Flusher::default()),
                background: self.background,
                closed: AtomicBool::new(false),
                dropped: AtomicU64::new(0),
                on_error: self.on_error,
                clock,
                deadline: self.deadline,
            }),
        })
    }
}

/// Reports each in-scope response after it is produced. Made by
/// [`AgentSightings::layer`].
#[derive(Clone, Debug)]
pub struct AgentSightingsLayer {
    sightings: AgentSightings,
}

impl<S> tower_layer::Layer<S> for AgentSightingsLayer {
    type Service = AgentSightingsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AgentSightingsService {
            inner,
            sightings: self.sightings.clone(),
        }
    }
}

/// The service an [`AgentSightingsLayer`] wraps around yours.
#[derive(Clone, Debug)]
pub struct AgentSightingsService<S> {
    inner: S,
    sightings: AgentSightings,
}

impl<S, ReqBody, ResBody> tower_service::Service<Request<ReqBody>> for AgentSightingsService<S>
where
    S: tower_service::Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: 'static,
    ResBody: 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Response<ResBody>, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let (mut parts, body) = request.into_parts();
        let inner = self.sightings.inner.clone();
        let observed = inner.observe(&parts);
        let lookup = match &observed {
            Some(observed) => inner.lookup_key(&observed.key),
            None => AgentLookup::Unknown,
        };
        let path = parts.uri.path().to_owned();
        parts.extensions.insert(lookup);
        let future = self.inner.call(Request::from_parts(parts, body));
        Box::pin(async move {
            let response = future.await?;
            if let Some(observed) = observed {
                if inner.scope.reports(&path, response.headers()) {
                    inner.record(observed);
                }
            }
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests;
