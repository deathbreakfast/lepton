//! Shared Twilio HTTP helpers for Messages + Verify (status mapping; no PII in errors).

use crate::error::SmsDeliveryError;

#[derive(Debug, serde::Deserialize)]
struct TwilioErrBody {
    code: Option<i64>,
    message: Option<String>,
}

/// Map a Twilio error response into a typed delivery error.
///
/// Uses `message` only for stable reason classification (compliance / Trust Hub); never
/// forwards the raw message (may echo phone numbers).
#[must_use]
pub(super) fn map_twilio_http_error(
    status: u16,
    twilio_code: Option<i64>,
    message: Option<&str>,
) -> SmsDeliveryError {
    let code_suffix = twilio_code.map_or_else(String::new, |c| format!(", code {c}"));
    let msg_l = message.unwrap_or("").to_ascii_lowercase();
    if msg_l.contains("compliance") || msg_l.contains("trust hub") || msg_l.contains("kyc") {
        return SmsDeliveryError::rejected(
            "compliance_blocked",
            format!(
                "Twilio blocked send pending Trust Hub / KYC compliance approval (HTTP {status}{code_suffix})"
            ),
        );
    }
    // Verify: CustomCode without Console "Enable Custom Verification Code" → 403 / 60204.
    if twilio_code == Some(60204) {
        return SmsDeliveryError::rejected(
            "feature_not_enabled",
            format!(
                "Twilio Verify Service does not allow CustomCode; enable Custom Verification Code in Console (HTTP {status}{code_suffix})"
            ),
        );
    }
    // Messages: A2P 10DLC registration required.
    if twilio_code == Some(30034) {
        return SmsDeliveryError::rejected(
            "compliance_blocked",
            format!(
                "Twilio blocked send pending A2P 10DLC registration (HTTP {status}{code_suffix})"
            ),
        );
    }
    match status {
        401 | 403 => SmsDeliveryError::rejected(
            "auth_failed",
            format!("Twilio rejected credentials (HTTP {status}{code_suffix})"),
        ),
        429 => SmsDeliveryError::transient(
            "rate_limited",
            format!("Twilio rate limited the request (HTTP {status}{code_suffix})"),
        ),
        400 | 404 | 422 => SmsDeliveryError::rejected(
            "provider_rejected",
            format!("Twilio rejected the message (HTTP {status}{code_suffix})"),
        ),
        s if (500..600).contains(&s) => SmsDeliveryError::transient(
            "provider_unavailable",
            format!("Twilio unavailable (HTTP {status}{code_suffix})"),
        ),
        _ => SmsDeliveryError::transport(
            "transport_error",
            format!("Twilio returned unexpected HTTP {status}{code_suffix}"),
        ),
    }
}

/// Parse Twilio REST error `code` and `message` from a JSON body when present.
#[must_use]
pub(super) fn parse_twilio_err_body(body: &[u8]) -> (Option<i64>, Option<String>) {
    let Ok(parsed) = serde_json::from_slice::<TwilioErrBody>(body) else {
        return (None, None);
    };
    (parsed.code, parsed.message)
}

/// Build the Messages create URL for an account.
#[must_use]
pub(super) fn messages_url(api_base_url: &str, account_sid: &str) -> String {
    format!(
        "{}/2010-04-01/Accounts/{}/Messages.json",
        api_base_url.trim_end_matches('/'),
        account_sid
    )
}

/// Build the Verify Verifications create URL for a service.
#[must_use]
pub(super) fn verifications_url(api_base_url: &str, service_sid: &str) -> String {
    format!(
        "{}/v2/Services/{}/Verifications",
        api_base_url.trim_end_matches('/'),
        service_sid
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_http_status_auth_failed_sad() {
        let err = map_twilio_http_error(401, None, None);
        assert!(matches!(err, SmsDeliveryError::Rejected(_)));
        assert!(err.to_string().contains("reason_class=auth_failed"));
    }

    #[test]
    fn map_http_status_compliance_not_auth_sad() {
        let err = map_twilio_http_error(
            401,
            Some(20003),
            Some("Primary compliance profile is not approved. Complete KYC in Trust Hub."),
        );
        assert!(err.to_string().contains("reason_class=compliance_blocked"));
        assert!(!err.to_string().contains("rejected credentials"));
    }

    #[test]
    fn map_http_status_rate_limited_sad() {
        let err = map_twilio_http_error(429, Some(20429), None);
        assert!(matches!(err, SmsDeliveryError::Transient(_)));
        assert!(err.to_string().contains("reason_class=rate_limited"));
        assert!(err.to_string().contains("code 20429"));
    }

    #[test]
    fn map_http_status_verify_custom_code_disabled_sad() {
        let err = map_twilio_http_error(403, Some(60204), Some("Custom code not allowed"));
        assert!(err.to_string().contains("reason_class=feature_not_enabled"));
        assert!(!err.to_string().contains("rejected credentials"));
        assert!(err.to_string().contains("code 60204"));
    }

    #[test]
    fn map_http_status_a2p_10dlc_sad() {
        let err = map_twilio_http_error(400, Some(30034), None);
        assert!(err.to_string().contains("reason_class=compliance_blocked"));
        assert!(err.to_string().contains("code 30034"));
    }

    #[test]
    fn parse_twilio_err_body_code_happy() {
        let (code, msg) = parse_twilio_err_body(br#"{"code":21608,"message":"unverified"}"#);
        assert_eq!(code, Some(21608));
        assert_eq!(msg.as_deref(), Some("unverified"));
        assert_eq!(parse_twilio_err_body(b"not-json"), (None, None));
    }
}
