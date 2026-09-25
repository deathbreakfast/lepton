//! MX resolution and recipient-domain helpers for direct delivery.

use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;

use crate::error::EmailDeliveryError;

/// Extract the domain portion of a recipient mailbox.
pub fn extract_recipient_domain(recipient_email: &str) -> Result<String, EmailDeliveryError> {
    let (_, domain) = recipient_email.rsplit_once('@').ok_or_else(|| {
        EmailDeliveryError::config("invalid_mailbox", "Invalid recipient email: missing domain")
    })?;
    let normalized = domain.trim().trim_end_matches('.');
    if normalized.is_empty() {
        return Err(EmailDeliveryError::config(
            "invalid_mailbox",
            "Invalid recipient email: empty domain",
        ));
    }
    Ok(normalized.to_ascii_lowercase())
}

/// Resolve MX hosts for `domain`, falling back to the apex host when none exist.
pub async fn resolve_mx_hosts(domain: &str) -> Result<Vec<String>, EmailDeliveryError> {
    tracing::debug!(
        driver = "direct_mx",
        operation = "mx_resolve",
        outcome = "start",
        "mx resolve"
    );
    let resolver = TokioResolver::builder_tokio()
        .and_then(hickory_resolver::ResolverBuilder::build)
        .map_err(|e| {
            EmailDeliveryError::transport(
                "dns_resolver_init",
                format!("Failed to initialize DNS resolver: {e}"),
            )
        })?;
    let response = resolver.mx_lookup(domain).await.map_err(|e| {
        EmailDeliveryError::transport("mx_lookup_failed", format!("MX lookup failed: {e}"))
    })?;

    let mut records: Vec<_> = response
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::MX(mx) => Some((mx.preference, mx.exchange.to_utf8())),
            _ => None,
        })
        .collect();
    records.sort_by_key(|(preference, _)| *preference);
    let hosts: Vec<String> = records
        .into_iter()
        .map(|(_, exchange)| exchange.trim_end_matches('.').to_string())
        .filter(|exchange| !exchange.is_empty())
        .collect();

    if hosts.is_empty() {
        tracing::debug!(
            driver = "direct_mx",
            operation = "mx_resolve",
            outcome = "fallback_apex",
            reason_class = "no_mx_records",
            "mx resolve"
        );
        return Ok(vec![domain.to_string()]);
    }

    tracing::debug!(
        driver = "direct_mx",
        operation = "mx_resolve",
        outcome = "success",
        host_count = hosts.len(),
        "mx resolve"
    );
    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_recipient_domain() {
        assert!(matches!(
            extract_recipient_domain("user@example.com"),
            Ok(ref d) if d == "example.com"
        ));
    }
}
