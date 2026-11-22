//! Reports of the requests a server served, and the server's answers.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::errors::{Error, Result};
use crate::models::{AgentAnswers, AgentSighting};
use crate::transport::Transport;

/// The route sightings are posted to, under the versioned base URL.
const SIGHTINGS_PATH: &str = "/agents/sightings";

/// Reports the requests your server served, under this client's secret key.
///
/// Most servers want [`AgentSightings`](crate::AgentSightings) instead, which
/// batches, folds repeats into counts and remembers the answers. This is the
/// single call it makes.
#[derive(Clone, Debug)]
pub struct AgentsClient {
    pub(crate) transport: Arc<Transport>,
}

#[derive(Serialize)]
struct SightingsBody<'a> {
    items: &'a [AgentSighting],
}

impl AgentsClient {
    pub(crate) fn new(transport: Arc<Transport>) -> Self {
        AgentsClient { transport }
    }

    /// Reports up to 200 served requests, as raw input, and returns what sent
    /// each one, in the same order.
    ///
    /// An item the server could not use is answered
    /// [`VisitorKind::Unknown`](crate::VisitorKind::Unknown) with a `ttl` of 0
    /// in its own position, and is neither classified nor counted; the others
    /// are answered as usual.
    ///
    /// Never retried. A refusal is [`Error::Api`]: `422 invalid_request` for
    /// an empty or oversized batch, or when no item in the batch was usable,
    /// `401`/`403` for a key that is wrong or
    /// revoked, and `429 rate_limited` with
    /// [`retry_after`](crate::ApiError::retry_after) and
    /// [`rate_limit_scope`](crate::ApiError::rate_limit_scope) (`daily` for
    /// the organization's daily allowance).
    pub async fn sightings(&self, items: &[AgentSighting]) -> Result<AgentAnswers> {
        self.sightings_within(items, None).await
    }

    /// [`sightings`](Self::sightings) under a deadline of its own.
    pub(crate) async fn sightings_within(
        &self,
        items: &[AgentSighting],
        timeout: Option<Duration>,
    ) -> Result<AgentAnswers> {
        let body = serde_json::to_vec(&SightingsBody { items })
            .map_err(|error| Error::config(format!("could not encode the sightings: {error}")))?;
        let value = self
            .transport
            .post_json_body(SIGHTINGS_PATH, body, timeout)
            .await?;
        serde_json::from_value(value)
            .map_err(|error| Error::decode(format!("agent sightings answer: {error}")))
    }
}
