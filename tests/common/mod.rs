//! A recording HTTP server the tests point the SDK at.
//!
//! It is a real axum server on a real socket, so the tests exercise the
//! transport rather than a stub of it: headers, status codes, redirects and
//! stalled responses all behave as they would against the API.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Router;
use http_body_util::BodyExt;

/// A secret key of the right shape. It is not a credential for anything.
pub const SECRET_KEY: &str = "fly_sk_production_testonlysecret";
pub const PUBLIC_KEY: &str = "fly_pk_production_testonlypublic";
pub const PROXY_KEY: &str = "fly_px_production_testonlyproxy";
pub const WEBHOOK_SECRET: &str = "whsec_testonly";

/// One request the server saw.
#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Recorded {
    /// One header as a string, or `""` when it was not sent.
    pub fn header(&self, name: &str) -> String {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    }
}

/// One canned answer. Queue as many as the test has requests.
#[derive(Clone, Debug)]
pub struct Canned {
    pub status: u16,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
    pub delay: Option<Duration>,
}

impl Canned {
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self::bytes(status, body.into().into_bytes())
    }

    /// An answer whose body is not text, such as a compressed one.
    pub fn bytes(status: u16, body: Vec<u8>) -> Self {
        Canned {
            status,
            body,
            headers: vec![("content-type".into(), "application/json".into())],
            delay: None,
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }
}

/// The event body the happy-path tests read back.
pub fn event_body(request_id: &str) -> String {
    format!(
        r#"{{"request_id":"{request_id}","visitor_id":"vis_1","occurred_at":"2026-09-18T08:00:00Z",
            "state":"enriched","environment":"production","platform":"web","sdk_platform":"web",
            "sdk_version":"1.0.0","ip_network":"203.0.113.0/24","suspect_score":12,
            "suspect_level":"low","triggers":[],"has_document":false}}"#
    )
}

/// The `404 event_not_found` envelope, which is the only retryable failure.
pub fn pending_body() -> String {
    r#"{"error":{"code":"event_pending","message":"Still recording","status":404},
        "request_id":"req_trace"}"#
        .to_owned()
}

pub fn not_found_body() -> String {
    r#"{"error":{"code":"event_not_found","message":"No such event","status":404},
        "request_id":"req_trace"}"#
        .to_owned()
}

#[derive(Clone, Default)]
struct Shared {
    requests: Arc<Mutex<Vec<Recorded>>>,
    responses: Arc<Mutex<VecDeque<Canned>>>,
}

/// A running server, shut down when it is dropped.
pub struct TestServer {
    pub base_url: String,
    shared: Shared,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestServer {
    /// Starts a server that answers with `responses` in order, repeating the
    /// last one once the queue runs dry.
    pub async fn start(responses: Vec<Canned>) -> Self {
        let shared = Shared {
            requests: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(responses.into())),
        };
        let app = Router::new().fallback(handle).with_state(shared.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        TestServer {
            base_url: format!("http://{address}"),
            shared,
            task,
        }
    }

    /// Starts a server that answers every request the same way.
    pub async fn always(response: Canned) -> Self {
        Self::start(vec![response]).await
    }

    /// Every request the server has seen, in order.
    pub fn requests(&self) -> Vec<Recorded> {
        self.shared.requests.lock().unwrap().clone()
    }

    /// The first request, which is all most tests need.
    pub fn first(&self) -> Recorded {
        self.requests()
            .first()
            .cloned()
            .expect("no request arrived")
    }

    pub fn request_count(&self) -> usize {
        self.shared.requests.lock().unwrap().len()
    }
}

async fn handle(State(shared): State<Shared>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    shared.requests.lock().unwrap().push(Recorded {
        method: parts.method.to_string(),
        path: parts.uri.path().to_owned(),
        query: parts.uri.query().unwrap_or_default().to_owned(),
        headers: parts.headers.clone(),
        body,
    });

    let canned = {
        let mut queue = shared.responses.lock().unwrap();
        // Keep the last answer in place, so a test that makes several
        // requests can stop queueing once it has said what it wants to say.
        if queue.len() > 1 {
            queue.pop_front()
        } else {
            queue.front().cloned()
        }
    };
    let Some(canned) = canned else {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(axum::body::Body::from("no canned response"))
            .unwrap();
    };

    if let Some(delay) = canned.delay {
        tokio::time::sleep(delay).await;
    }
    let mut builder = Response::builder().status(canned.status);
    for (name, value) in &canned.headers {
        builder = builder.header(name, value);
    }
    builder.body(axum::body::Body::from(canned.body)).unwrap()
}
