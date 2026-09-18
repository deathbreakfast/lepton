//! Email OTP issue / verify (`email` feature).

use lepton_host_adapter::generated::AccountEmail;
use lepton_smtp::VerificationEmailFlow;
use valence::{RecordId, StringPredicate, Valence};

use super::{FactorChallengeError, FactorChallengeService};
use crate::contacts::{account_for_user, add_account_email, ContactError};
use crate::token_helpers::{issue_email_verification_token, try_consume_email_verification_token};

fn bare_id(record: &RecordId) -> String {
    valence::extract_id_from_record(record).unwrap_or_else(|_| record.id().to_string())
}

pub(super) async fn issue(
    svc: &FactorChallengeService,
    valence: &Valence,
    user: RecordId,
    target: &str,
    email_flow: VerificationEmailFlow,
) -> Result<String, FactorChallengeError> {
    let address = target.trim().to_string();
    let email = if let Some(existing) = AccountEmail::query_used(valence, valence::use_!(r"In **factor**, we **list Account Email** so the product can show or process the matching set for this workflow. Callers allowed for **factor** use the list; it is not a public dump of every field to anonymous visitors."))
        .where_address(StringPredicate::Equals(address.clone()))
        .first()
        .await
        .map_err(|_| FactorChallengeError::Token)?
    {
        // Email belongs to an account; caller must be a member (checked via add path /
        // later verify). Reject addresses already registered to another account.
        let memberships = lepton_host_adapter::generated::AccountMembership::query_used(valence, valence::use_!(r"In **factor**, we **list Account Membership** so the product can show or process the matching set for this workflow. Callers allowed for **factor** use the list; it is not a public dump of every field to anonymous visitors."))
            .where_user(valence::RecordPredicate::Equals(user.clone()))
            .await
            .map_err(|_| FactorChallengeError::Token)?;
        let account_ok = memberships
            .iter()
            .any(|m| bare_id(m.account()) == bare_id(existing.account()));
        if account_ok {
            existing
        } else {
            return Err(FactorChallengeError::Token);
        }
    } else {
        let account = account_for_user(valence, &user)
            .await
            .map_err(|_: ContactError| FactorChallengeError::Token)?;
        add_account_email(valence, &account, &address)
            .await
            .map_err(|_: ContactError| FactorChallengeError::Token)?
    };
    let email_id = email.id().cloned().ok_or(FactorChallengeError::Token)?;
    let token_id = issue_email_verification_token(valence, user, email_id)
        .await
        .map_err(|_| FactorChallengeError::Token)?;
    let envelope = lepton_smtp::verification_email_envelope(&address, &token_id, email_flow);
    #[cfg(feature = "boson-delivery")]
    {
        use crate::delivery::{enqueue_email, EmailDeliveryIntent};
        enqueue_email(EmailDeliveryIntent {
            intent_kind: "email_otp".into(),
            intent_id: token_id.clone(),
            envelope,
        })
        .await
        .map_err(|e| FactorChallengeError::Delivery(e.to_string()))?;
    }
    #[cfg(not(feature = "boson-delivery"))]
    {
        svc.services
            .email
            .send(&envelope)
            .await
            .map_err(|e| FactorChallengeError::Delivery(e.to_string()))?;
    }
    #[cfg(feature = "boson-delivery")]
    {
        let _ = svc;
    }
    Ok(token_id)
}

pub(super) async fn verify(
    token_id: &str,
    valence: &Valence,
) -> Result<bool, FactorChallengeError> {
    try_consume_email_verification_token(token_id, valence)
        .await
        .map_err(|_| FactorChallengeError::Token)
}
