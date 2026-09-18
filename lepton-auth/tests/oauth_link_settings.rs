//! OAuth Link bind, account-taken, unlink IDOR, last-method guard (TM coverage).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_auth::actions::oauth_settings::{
    linked_identity_to_view, user_has_password, would_remove_last_sign_in_method,
    LinkedIdentityView,
};
use lepton_auth::oauth::{
    begin_oauth, begin_oauth_for_user, complete_oauth, list_linked_identities,
    unlink_oauth_identity, OAuthClientConfig, OAuthCompletion, OAuthError, OAuthIntent,
    OAuthProvider,
};
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{User, UserStatus, UserUserType};
use support::system_valence;
use valence::{Model, RecordId};

fn mock_cfg() -> OAuthClientConfig {
    OAuthClientConfig {
        public_base_url: "http://localhost:3000".into(),
        redirect_path: "/auth/oauth/callback".into(),
        google_client_id: None,
        google_client_secret: None,
        github_client_id: None,
        github_client_secret: None,
        use_mock_provider: true,
        mock_oidc_issuer_url: None,
        google_token_url: None,
        google_userinfo_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    }
}

async fn seed_password_user(valence: &valence::Valence) -> RecordId {
    let now = Utc::now();
    let user = User::new(
        Some(UserUserType::Person),
        Some(hash_password("CorrectHorseBattery1!").expect("hash")),
        Some(UserStatus::Active),
        None,
        None,
        None,
        None,
        None,
        now,
        now,
    )
    .expect("user");
    let created = User::create_used(user, valence, valence::use_!(r"**Test:** Fixture **User** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await.expect("create user");
    created.id().cloned().expect("user id")
}

#[tokio::test]
async fn oauth_link_bind_happy() {
    let valence = system_valence("oauth_link_bind").await;
    let user = seed_password_user(&valence).await;
    let cfg = mock_cfg();

    let start = begin_oauth_for_user(
        &cfg,
        &valence,
        OAuthProvider::Google,
        OAuthIntent::Link,
        Some(&user),
        None,
    )
    .await
    .expect("begin link");
    let result = complete_oauth(
        &cfg,
        &valence,
        OAuthProvider::Google,
        &start.state,
        "link-google-1",
    )
    .await
    .expect("complete");

    match result.completion {
        OAuthCompletion::Linked { user_id } => assert_eq!(user_id, user),
        other => panic!("expected Linked, got {other:?}"),
    }

    let links = list_linked_identities(&valence, &user).await.expect("list");
    assert_eq!(links.len(), 1);
    let view = linked_identity_to_view(&links[0]).expect("view");
    assert_eq!(view.provider, "google");
    assert_eq!(
        view.email_hint.as_deref(),
        Some("link-google-1@oauth.mock.test")
    );
    let json = serde_json::to_value(&view).expect("json");
    assert!(json.get("provider_subject").is_none());
}

#[tokio::test]
async fn oauth_link_account_taken_sad() {
    let valence = system_valence("oauth_link_taken").await;
    let cfg = mock_cfg();

    let start = begin_oauth(&cfg, &valence, OAuthProvider::GitHub, OAuthIntent::Signup)
        .await
        .expect("begin signup");
    let owner = match complete_oauth(
        &cfg,
        &valence,
        OAuthProvider::GitHub,
        &start.state,
        "taken-subject",
    )
    .await
    .expect("signup")
    .completion
    {
        OAuthCompletion::SignedUp { user_id } => user_id,
        other => panic!("expected SignedUp, got {other:?}"),
    };
    let _ = owner;

    let other = seed_password_user(&valence).await;
    let start = begin_oauth_for_user(
        &cfg,
        &valence,
        OAuthProvider::GitHub,
        OAuthIntent::Link,
        Some(&other),
        None,
    )
    .await
    .expect("begin link");
    let err = complete_oauth(
        &cfg,
        &valence,
        OAuthProvider::GitHub,
        &start.state,
        "taken-subject",
    )
    .await
    .expect_err("account taken");
    assert_eq!(err.reason_class(), "oauth_account_taken");
    assert!(!err.to_string().contains("taken-subject"));
}

#[tokio::test]
async fn oauth_unlink_wrong_owner_sad() {
    let valence = system_valence("oauth_unlink_idor").await;
    let cfg = mock_cfg();

    let start = begin_oauth(&cfg, &valence, OAuthProvider::Google, OAuthIntent::Signup)
        .await
        .expect("begin");
    let owner = match complete_oauth(
        &cfg,
        &valence,
        OAuthProvider::Google,
        &start.state,
        "idor-owner",
    )
    .await
    .expect("signup")
    .completion
    {
        OAuthCompletion::SignedUp { user_id } => user_id,
        other => panic!("expected SignedUp, got {other:?}"),
    };

    let links = list_linked_identities(&valence, &owner)
        .await
        .expect("list");
    let linked_id = links[0].id().cloned().expect("linked id");

    let attacker = seed_password_user(&valence).await;
    let err = unlink_oauth_identity(&valence, &attacker, &linked_id)
        .await
        .expect_err("wrong owner");
    assert_eq!(err.reason_class(), "link");

    let still = list_linked_identities(&valence, &owner)
        .await
        .expect("list");
    assert_eq!(still.len(), 1);
}

#[tokio::test]
async fn oauth_last_sign_in_method_refuse_sad() {
    let valence = system_valence("oauth_last_method").await;
    let cfg = mock_cfg();

    let start = begin_oauth(&cfg, &valence, OAuthProvider::Google, OAuthIntent::Signup)
        .await
        .expect("begin");
    let user = match complete_oauth(
        &cfg,
        &valence,
        OAuthProvider::Google,
        &start.state,
        "oauth-only-user",
    )
    .await
    .expect("signup")
    .completion
    {
        OAuthCompletion::SignedUp { user_id } => user_id,
        other => panic!("expected SignedUp, got {other:?}"),
    };

    assert!(!user_has_password(&valence, &user).await.expect("pw check"));
    let links = list_linked_identities(&valence, &user).await.expect("list");
    assert_eq!(links.len(), 1);
    let linked_id = links[0].id().cloned().expect("linked id");

    assert!(
        would_remove_last_sign_in_method(&valence, &user, &linked_id)
            .await
            .expect("guard")
    );
}

#[tokio::test]
async fn oauth_last_sign_in_method_allows_with_password_happy() {
    let valence = system_valence("oauth_last_with_pw").await;
    let user = seed_password_user(&valence).await;
    let cfg = mock_cfg();

    let start = begin_oauth_for_user(
        &cfg,
        &valence,
        OAuthProvider::Google,
        OAuthIntent::Link,
        Some(&user),
        None,
    )
    .await
    .expect("begin");
    complete_oauth(
        &cfg,
        &valence,
        OAuthProvider::Google,
        &start.state,
        "pw-user-link",
    )
    .await
    .expect("link");

    assert!(user_has_password(&valence, &user).await.expect("pw"));
    let links = list_linked_identities(&valence, &user).await.expect("list");
    let linked_id = links[0].id().cloned().expect("id");
    assert!(
        !would_remove_last_sign_in_method(&valence, &user, &linked_id)
            .await
            .expect("guard")
    );

    unlink_oauth_identity(&valence, &user, &linked_id)
        .await
        .expect("unlink");
    assert!(list_linked_identities(&valence, &user)
        .await
        .expect("list")
        .is_empty());
}

#[test]
fn linked_identity_view_serde_omits_subject() {
    let view = LinkedIdentityView {
        id: "x1".into(),
        provider: "github".into(),
        email_hint: None,
        linked_at: Utc::now(),
    };
    let s = serde_json::to_string(&view).expect("ser");
    assert!(!s.contains("provider_subject"));
    let _: LinkedIdentityView = serde_json::from_str(&s).expect("de");
}

#[test]
fn oauth_account_taken_display_has_no_subject() {
    let err = OAuthError::AccountTaken;
    assert_eq!(err.reason_class(), "oauth_account_taken");
    assert!(!err.to_string().contains("secret"));
}
