//! Persist [`DeliveryAttempt`] rows (`SYSTEM_ONLY`; schema TTL 7d).

use chrono::Utc;
use lepton_host_adapter::generated::{
    DeliveryAttempt, DeliveryAttemptChannel, DeliveryAttemptOutcome,
};
use thiserror::Error;
use uuid::Uuid;
use valence::{Model, Valence};

/// Input for [`record_delivery_attempt`]. Never includes recipient or message body.
#[derive(Clone, Debug)]
pub struct DeliveryAttemptInput {
    /// `email` or `sms`.
    pub channel: DeliveryAttemptChannel,
    /// Auth flow label (e.g. `signup_verify`, `password_reset`, `sms_otp`).
    pub intent_kind: String,
    /// Soft correlation id (usually the token / challenge id).
    pub intent_id: String,
    /// Provider/driver name when known.
    pub provider: Option<String>,
    /// Provider-assigned message id when the send succeeded.
    pub message_id: Option<String>,
    /// Terminal classification for this attempt.
    pub outcome: DeliveryAttemptOutcome,
    /// Ops `reason_class` from the delivery error, when any.
    pub reason_class: Option<String>,
    /// Boson job id when enqueued via durable delivery.
    pub boson_job_id: Option<String>,
}

/// Errors writing a delivery attempt row.
#[derive(Debug, Error)]
pub enum DeliveryAttemptWriteError {
    /// Valence create / policy failure.
    #[error("reason_class=store: delivery attempt persist failed")]
    Store,
}

/// Create a [`DeliveryAttempt`] row under the system actor Valence.
///
/// # Errors
///
/// [`DeliveryAttemptWriteError::Store`] when build or create fails.
pub async fn record_delivery_attempt(
    valence: &Valence,
    input: DeliveryAttemptInput,
) -> Result<DeliveryAttempt, DeliveryAttemptWriteError> {
    let id = Uuid::new_v4().to_string();
    let row = DeliveryAttempt::new(
        input.channel,
        input.intent_kind,
        input.intent_id,
        input.provider,
        input.message_id,
        input.outcome,
        input.reason_class,
        input.boson_job_id,
        Utc::now(),
    )
    .map_err(|_| DeliveryAttemptWriteError::Store)?;
    DeliveryAttempt::upsert_used(&id, row, valence, valence::use_!("upsert DeliveryAttempt in src/delivery/attempt.rs; Valence persistence for this feature path; typed store; visible to session actor / service path."))
        .await
        .map_err(|_| DeliveryAttemptWriteError::Store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_attempt_schema_ttl_happy() {
        let schema = DeliveryAttempt::get_schema();
        let ttl = schema.ttl.as_ref().expect("ttl declared");
        assert_eq!(ttl.seconds, 604_800);
        assert_eq!(ttl.mode, "backend_capability");
    }
}
