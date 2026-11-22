//! Apple DeviceCheck bits of the device behind an iOS event.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::errors::{Error, Result};
use crate::events::event_path;
use crate::transport::Transport;

/// The device's two bits, as Apple holds them for your developer team.
///
/// The bits mean what you decide; Fingerly never reads or keeps them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct DeviceCheckBits {
    /// `false` when Apple holds no bits for the device yet; both bits are then
    /// `false`.
    pub found: bool,
    /// The first bit.
    pub bit0: bool,
    /// The second bit.
    pub bit1: bool,
    /// When the bits last changed, as `YYYY-MM`. `None` when Apple holds no
    /// bits.
    #[serde(default)]
    pub last_update: Option<String>,
}

/// The bits to set with [`DeviceCheckClient::write`]. A bit left unset keeps
/// its value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DeviceCheckWrite {
    #[serde(skip_serializing_if = "Option::is_none")]
    bit0: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bit1: Option<bool>,
}

impl DeviceCheckWrite {
    /// A write that sets nothing yet. Name at least one bit before sending it.
    pub fn new() -> Self {
        Self::default()
    }

    /// The value to set for the first bit.
    pub fn bit0(mut self, value: bool) -> Self {
        self.bit0 = Some(value);
        self
    }

    /// The value to set for the second bit.
    pub fn bit1(mut self, value: bool) -> Self {
        self.bit1 = Some(value);
        self
    }
}

/// What Apple accepted for a write. A bit the write left out is `None`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct DeviceCheckWriteResult {
    /// The value set for the first bit.
    #[serde(default)]
    pub bit0: Option<bool>,
    /// The value set for the second bit.
    #[serde(default)]
    pub bit1: Option<bool>,
}

/// Reads and writes the DeviceCheck bits of the device behind an iOS event.
///
/// Fingerly holds two DeviceCheck tokens of an iOS identification for one
/// hour, a read token and a write token, and each pays for one Apple call: a
/// read spends the read token, a write the write token. To check a device and
/// then mark it, read and write with the same request ID.
///
/// A `503` or a lost answer leaves the token held. The client then retries
/// the identical request, which is the only retry the API accepts for a held
/// token: a second read, or a write with other bits, answers
/// `409 device_check_spent`.
///
/// Reached as [`Fingerly::device_check`]; it is never constructed directly.
///
/// [`Fingerly::device_check`]: crate::Fingerly::device_check
#[derive(Clone, Debug)]
pub struct DeviceCheckClient {
    transport: Arc<Transport>,
}

impl DeviceCheckClient {
    pub(crate) fn new(transport: Arc<Transport>) -> Self {
        DeviceCheckClient { transport }
    }

    /// Spends the event's held read token to read the device's two bits.
    ///
    /// ```no_run
    /// # async fn run(fingerly: fingerly::Fingerly) -> fingerly::Result<()> {
    /// match fingerly.device_check().query("req_…").await {
    ///     Ok(bits) if bits.found && bits.bit0 => { /* this device had its trial */ }
    ///     Ok(_) => { /* no trial recorded for this device */ }
    ///     Err(error) if error.is_device_check_not_held() => { /* decide without the bits */ }
    ///     Err(error) => return Err(error),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query(&self, request_id: &str) -> Result<DeviceCheckBits> {
        let path = format!("{}/device-check/query", event_path(request_id)?);
        let body = self
            .transport
            .spend_json(reqwest::Method::POST, &path, None)
            .await?;
        DeviceCheckBits::deserialize(&body)
            .map_err(|error| Error::decode(format!("device check bits: {error}")))
    }

    /// Spends the event's held write token to set `bit0`, `bit1` or both.
    ///
    /// A write that names neither bit is refused with [`Error::Config`] and
    /// nothing is sent.
    ///
    /// ```no_run
    /// # async fn run(fingerly: fingerly::Fingerly) -> fingerly::Result<()> {
    /// use fingerly::DeviceCheckWrite;
    ///
    /// fingerly
    ///     .device_check()
    ///     .write("req_…", DeviceCheckWrite::new().bit0(true))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn write(
        &self,
        request_id: &str,
        bits: DeviceCheckWrite,
    ) -> Result<DeviceCheckWriteResult> {
        if bits.bit0.is_none() && bits.bit1.is_none() {
            return Err(Error::config("name bit0, bit1 or both"));
        }
        let path = format!("{}/device-check", event_path(request_id)?);
        let body = serde_json::to_vec(&bits)
            .map_err(|error| Error::config(format!("could not encode the bits: {error}")))?;
        let answer = self
            .transport
            .spend_json(reqwest::Method::PUT, &path, Some(body))
            .await?;
        DeviceCheckWriteResult::deserialize(&answer)
            .map_err(|error| Error::decode(format!("device check write: {error}")))
    }
}
