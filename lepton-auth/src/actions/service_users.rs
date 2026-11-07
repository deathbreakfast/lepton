//! Server function for the all-service-users admin page.

use leptos::prelude::*;
use serde::{Deserialize, Serialize};

/// One row of the all-service-users admin list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceUserAdminView {
    /// Bare service user id.
    pub id: String,
    /// Handle such as `spectra-agent`.
    pub handle: String,
    /// Display name.
    pub display_name: String,
    /// `active` or `suspended`.
    pub status: String,
    /// Bare id of the owning user; empty when the row has no owner.
    pub owner_id: String,
}

/// Keep the rows whose handle contains `query`, ignoring case and dashes (the same
/// folding the handle-clash rule uses). A blank query keeps every row.
#[must_use]
pub fn filter_by_handle(rows: &[ServiceUserAdminView], query: &str) -> Vec<ServiceUserAdminView> {
    let fold = |text: &str| {
        text.chars()
            .filter(|c| *c != '-')
            .flat_map(char::to_lowercase)
            .collect::<String>()
    };
    let needle = fold(query.trim());
    rows.iter()
        .filter(|row| fold(&row.handle).contains(&needle))
        .cloned()
        .collect()
}

/// List every service user, whoever owns it. Only callers the host's service user gate
/// grants manage-any may call this; everyone else gets an error.
#[server(ListAllServiceUsersAdmin)]
pub async fn list_all_service_users_admin() -> Result<Vec<ServiceUserAdminView>, ServerFnError> {
    use crate::service_users::{list_all_service_users, ServiceUserError};
    let (ctx, _auth_user) = crate::ssr_support::require_auth_user().await?;
    let valence = crate::ssr_support::user_valence(&ctx)?;
    tracing::info!(
        operation = "service_user_list_all",
        outcome = "start",
        "lepton_auth.service_users.list_all"
    );
    let rows = list_all_service_users(&valence).await.map_err(|e| {
        tracing::warn!(
            operation = "service_user_list_all",
            outcome = "error",
            reason_class = e.reason_class(),
            "lepton_auth.service_users.list_all"
        );
        match e {
            ServiceUserError::Forbidden | ServiceUserError::NotAUser => {
                ServerFnError::new("You are not allowed to list every service user")
            }
            other => ServerFnError::new(other.to_string()),
        }
    })?;
    tracing::info!(
        operation = "service_user_list_all",
        outcome = "ok",
        "lepton_auth.service_users.list_all"
    );
    Ok(rows.iter().map(admin_view).collect())
}

#[cfg(feature = "ssr")]
fn admin_view(row: &lepton_host_adapter::generated::ServiceUserAccount) -> ServiceUserAdminView {
    use lepton_host_adapter::generated::ServiceUserAccountStatus;

    let bare = |rid: &valence::RecordId| {
        valence::extract_id_from_record(rid).unwrap_or_else(|_| rid.id().to_string())
    };
    ServiceUserAdminView {
        id: row.id().map_or_else(String::new, bare),
        handle: row.handle().clone(),
        display_name: row.display_name().clone(),
        status: match row.status() {
            ServiceUserAccountStatus::Active => "active",
            ServiceUserAccountStatus::Suspended => "suspended",
        }
        .to_string(),
        owner_id: row.user().map_or_else(String::new, bare),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(handle: &str) -> ServiceUserAdminView {
        ServiceUserAdminView {
            id: handle.into(),
            handle: handle.into(),
            display_name: handle.into(),
            status: "active".into(),
            owner_id: "o".into(),
        }
    }

    #[test]
    fn filter_ignores_case_and_dashes_happy() {
        let rows = [row("spectra-agent"), row("mail-bot")];
        let hit = filter_by_handle(&rows, "  SPECTRAA ");
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].handle, "spectra-agent");
        assert_eq!(filter_by_handle(&rows, "").len(), 2);
    }

    #[test]
    fn filter_no_match_sad() {
        assert!(filter_by_handle(&[row("mail-bot")], "zzz").is_empty());
    }
}
