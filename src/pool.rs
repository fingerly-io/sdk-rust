//! How the SDK builds its HTTP clients, and the DNS cache they share.
//!
//! reqwest's default resolver runs every lookup on Tokio's blocking pool. Under
//! a burst against a hostname, each request without an idle connection starts
//! its own lookup; the lookups queue behind each other, the connects they feed
//! race the pool, and every connect that finishes late is kept anyway. In the
//! field test, 10,000 proxied requests at 200 in flight opened about 1,200
//! connections per burst, held 2,900 sockets and started 512 threads. Sharing
//! one lookup per host among concurrent callers, and caching it briefly,
//! removes the queue and with it the race.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::sync::OnceCell;

/// How long a successful lookup is reused before the name is resolved again,
/// so a DNS change reaches new connections within this window. Failures are
/// not cached.
const DNS_TTL: Duration = Duration::from_secs(30);

type Lookup = Arc<OnceCell<Result<Arc<[SocketAddr]>, String>>>;

/// A system resolver that performs one lookup per host at a time, shared by
/// every caller waiting on it, and reuses the answer for [`DNS_TTL`].
#[derive(Debug, Default)]
pub(crate) struct SharedResolver {
    entries: Mutex<HashMap<String, (Instant, Lookup)>>,
}

impl SharedResolver {
    /// The lookup to wait on for `host`: the live one, or a fresh one when
    /// there is none, it expired, or it failed.
    fn lookup_for(&self, host: &str) -> Lookup {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((started, lookup)) = entries.get(host) {
            let failed = matches!(lookup.get(), Some(Err(_)));
            if started.elapsed() < DNS_TTL && !failed {
                return lookup.clone();
            }
        }
        let lookup = Lookup::default();
        entries.insert(host.to_owned(), (Instant::now(), lookup.clone()));
        lookup
    }
}

impl Resolve for SharedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let lookup = self.lookup_for(&host);
        Box::pin(async move {
            let result = lookup
                .get_or_init(|| async {
                    tokio::net::lookup_host((host.as_str(), 0))
                        .await
                        .map(|addresses| addresses.collect::<Vec<_>>().into())
                        .map_err(|error| error.to_string())
                })
                .await;
            match result {
                Ok(addresses) => {
                    let addresses = Arc::clone(addresses);
                    let each = (0..addresses.len()).map(move |index| addresses[index]);
                    Ok(Box::new(each) as Addrs)
                }
                Err(message) => Err(message.clone().into()),
            }
        })
    }
}

/// The resolver every SDK client in the process shares.
pub(crate) fn shared_resolver() -> Arc<SharedResolver> {
    static RESOLVER: OnceLock<Arc<SharedResolver>> = OnceLock::new();
    RESOLVER.get_or_init(Arc::default).clone()
}

/// Applies the SDK's fixed policy to a builder: no redirects, ever, and the
/// shared resolver.
pub(crate) fn configure(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(shared_resolver())
}

/// Builds the HTTP client, and with it the connection pool, for one SDK value:
/// the caller's builder or a default one, with the SDK's policy applied.
///
/// The pool belongs to the value and is shared by its clones. It is not a
/// process-wide static: a pooled connection is driven by a task on the Tokio
/// runtime that opened it, so a static client breaks in any process that runs
/// more than one runtime, a test suite among them.
pub(crate) fn client_from(
    builder: Option<reqwest::ClientBuilder>,
) -> std::result::Result<reqwest::Client, String> {
    configure(builder.unwrap_or_default())
        .build()
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_callers_share_one_lookup_until_it_expires_or_fails() {
        let resolver = SharedResolver::default();
        let first = resolver.lookup_for("api.example.test");
        assert!(Arc::ptr_eq(
            &first,
            &resolver.lookup_for("api.example.test")
        ));
        assert!(!Arc::ptr_eq(
            &first,
            &resolver.lookup_for("other.example.test")
        ));

        first.set(Err("no such host".into())).unwrap();
        assert!(
            !Arc::ptr_eq(&first, &resolver.lookup_for("api.example.test")),
            "a failed lookup was reused"
        );

        let fresh = resolver.lookup_for("api.example.test");
        resolver
            .entries
            .lock()
            .unwrap()
            .get_mut("api.example.test")
            .unwrap()
            .0 -= DNS_TTL;
        assert!(
            !Arc::ptr_eq(&fresh, &resolver.lookup_for("api.example.test")),
            "an expired lookup was reused"
        );
    }
}
