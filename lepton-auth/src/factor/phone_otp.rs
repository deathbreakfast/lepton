//! SMS OTP issue / verify (`phone` feature).

use lepton_host_adapter::generated::AccountPhone;
use lepton_sms::SmsEnvelope;
use valence::{Model, RecordId, Valence};

use super::{FactorChallengeError, FactorChallengeService};
use crate::contacts::{
    account_for_user, add_account_phone, mark_account_phone_verified, normalize_phone_to_e164,
    ContactError,
};
use crate::events::{publish_verification_completed, VerificationKind};
use crate::token_helpers::{issue_phone_verification_token, try_consume_phone_verification_token};

fn bare_id(record: &RecordId) -> String {
    valence::extract_id_from_record(record).unwrap_or_else(|_| record.id().to_string())
}

pub(super) async fn issue(
    svc: &FactorChallengeService,
    valence: &Valence,
    user: RecordId,
    target: &str,
) -> Result<String, FactorChallengeError> {
    let e164 = normalize_phone_to_e164(target).map_err(|_| FactorChallengeError::InvalidPhone)?;
    let phone = if let Some(existing) = AccountPhone::query_used(valence, valence::use_!(r"In **factor**, we **list Account Phone** so the product can show or process the matching set for this workflow. Callers allowed for **factor** use the list; it is not a public dump of every field to anonymous visitors."))
        .where_e164(valence::StringPredicate::Equals(e164.clone()))
        .first()
        .await
        .map_err(|_| FactorChallengeError::Token)?
    {
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
        add_account_phone(valence, &account, &e164)
            .await
            .map_err(|_: ContactError| FactorChallengeError::Token)?
    };
    let phone_id = phone.id().cloned().ok_or(FactorChallengeError::Token)?;
    let issued = issue_phone_verification_token(valence, user, phone_id)
        .await
        .map_err(|_| FactorChallengeError::Token)?;
    let body = format!("Your verification code is: {}", issued.otp_code);
    let envelope = SmsEnvelope {
        to_e164: e164,
        body,
        otp_code: Some(issued.otp_code.clone()),
    };
    #[cfg(feature = "boson-delivery")]
    {
        use crate::delivery::{enqueue_sms, SmsDeliveryIntent};
        enqueue_sms(SmsDeliveryIntent {
            intent_kind: "sms_otp".into(),
            intent_id: issued.challenge_id.clone(),
            envelope,
        })
        .await
        .map_err(|e| FactorChallengeError::Delivery(e.to_string()))?;
    }
    #[cfg(not(feature = "boson-delivery"))]
    {
        svc.services
            .sms
            .send(&envelope)
            .await
            .map_err(|e| FactorChallengeError::Delivery(e.to_string()))?;
    }
    #[cfg(feature = "boson-delivery")]
    {
        let _ = svc;
    }
    Ok(issued.challenge_id)
}

pub(super) async fn verify(
    challenge_id: &str,
    otp_code: &str,
    valence: &Valence,
) -> Result<bool, FactorChallengeError> {
    let Some(token) = try_consume_phone_verification_token(challenge_id, otp_code, valence)
        .await
        .map_err(|_| FactorChallengeError::Token)?
    else {
        return Ok(false);
    };

    let phone_bare = bare_id(token.user_phone());
    let phone = AccountPhone::get_used(&phone_bare, valence, valence::use_!(r"In **factor**, we **load Account Phone** so the application can decide what to do next in this workflow. The result is used by **factor** logic—not necessarily displayed on a page unless that feature’s UI shows it."))
        .await
        .map_err(|_| FactorChallengeError::Token)?
        .ok_or(FactorChallengeError::UserMissing)?;

    mark_account_phone_verified(valence, &phone)
        .await
        .map_err(|_| FactorChallengeError::Token)?;

    publish_verification_completed(challenge_id.to_string(), VerificationKind::Phone).await;
    Ok(true)
}
