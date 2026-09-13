//! OAuth Signup collision → `NeedsLink`; free / no-hint provision (TM-O1–O3, TM-S5–S6).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_auth::oauth::{
    begin_oauth, complete_oauth, OAuthClientConfig, OAuthCompletion, OAuthIntent, OAuthProvider,
};
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{
    Account, AccountEmail, AccountMembership, AccountMembershipRole, AccountPlan, AccountStatus,
    User, UserStatus, UserUserType,
};
use lepton_identity::ownership::bare_id_from_record;
use support::system_valence;
use valence::{Model, RecordPredicate, StringPredicate};

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

async fn count_users(valence: &valence::Valence) -> usize {
    User::query_used(valence, valence::use_!("query User in lepton-auth/tests/oauth_signup_collision.rs; Valence persistence for this feature path; typed store; visible to test harness.")).await.expect("users").len()
}

async fn count_accounts(valence: &valence::Valence) -> usize {
    Account::query_used(valence, valence::use_!("query Account in lepton-auth/tests/oauth_signup_collision.rs; Valence persistence for this feature path; typed store; visible to test harness.")).await.expect("accounts").len()
}

async fn seed_taken_email(valence: &valence::Valence, address: &str) {
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
    let created = User::create_used(user, valence, valence::use_!("create User in lepton-auth/tests/oauth_signup_collision.rs; Valence persistence for this feature path; typed store; visible to test harness.")).await.expect("create user");
    let user_id = created.id().cloned().expect("user id");

    let account = Account::new(
        address.to_string(),
        user_id.clone(),
        Some(AccountPlan::Free),
        Some(AccountStatus::Active),
        None,
        None,
        now,
        now,
    )
    .expect("account");
    let account = Account::create_used(account, valence, valence::use_!("create Account in lepton-auth/tests/oauth_signup_collision.rs; Valence persistence for this feature path; typed store; visible to test harness."))
        .await
        .expect("create account");
    let account_id = account.id().cloned().expect("account id");

    let membership = AccountMembership::new(
        account_id.clone(),
        user_id,
        AccountMembershipRole::Owner,
        now,
        now,
    )
    .expect("membership");
    AccountMembership::create_used(membership, valence, valence::use_!("create AccountMembership in lepton-auth/tests/oauth_signup_collision.rs; Valence persistence for this feature path; typed store; visible to test harness."))
        .await
        .expect("membership");

    let email = AccountEmail::new(account_id, address.into(), Some(now), now, now).expect("email");
    AccountEmail::create_used(email, valence, valence::use_!("create AccountEmail in lepton-auth/tests/oauth_signup_collision.rs; Valence persistence for this feature path; typed store; visible to test harness.")).await.expect("email");
}

#[tokio::test]
async fn oauth_signup_email_taken_needs_link_sad() {
    let valence = system_valence("oauth_collision").await;
    let code = "taken-user";
    let address = format!("{code}@oauth.mock.test");
    seed_taken_email(&valence, &address).await;

    let users_before = count_users(&valence).await;
    let accounts_before = count_accounts(&valence).await;

    let cfg = mock_cfg();
    let start = begin_oauth(&cfg, &valence, OAuthProvider::GitHub, OAuthIntent::Signup)
        .await
        .expect("begin");
    let result = complete_oauth(&cfg, &valence, OAuthProvider::GitHub, &start.state, code)
        .await
        .expect("complete");

    match result.completion {
        OAuthCompletion::NeedsLink { pending } => {
            assert_eq!(pending.email_hint.as_deref(), Some(address.as_str()));
        }
        other => panic!("expected NeedsLink, got {other:?}"),
    }
    assert_eq!(count_users(&valence).await, users_before);
    assert_eq!(count_accounts(&valence).await, accounts_before);
}

#[tokio::test]
async fn oauth_signup_free_email_happy() {
    let valence = system_valence("oauth_free").await;
    let cfg = mock_cfg();
    let code = "free-user-xyz";
    let start = begin_oauth(&cfg, &valence, OAuthProvider::GitHub, OAuthIntent::Signup)
        .await
        .expect("begin");
    let result = complete_oauth(&cfg, &valence, OAuthProvider::GitHub, &start.state, code)
        .await
        .expect("complete");

    let user_id = match result.completion {
        OAuthCompletion::SignedUp { user_id } => user_id,
        other => panic!("expected SignedUp, got {other:?}"),
    };

    let account = Account::query_used(&valence, valence::use_!("query Account in lepton-auth/tests/oauth_signup_collision.rs; Valence persistence for this feature path; typed store; visible to test harness."))
        .where_user(RecordPredicate::Equals(user_id.clone()))
        .first()
        .await
        .expect("query")
        .expect("account");
    assert_eq!(
        bare_id_from_record(account.user()),
        bare_id_from_record(&user_id)
    );
    assert!(account.primary_email().is_some());

    let user = User::get_used(&bare_id_from_record(&user_id), &valence, valence::use_!("get User in lepton-auth/tests/oauth_signup_collision.rs; Valence persistence for this feature path; typed store; visible to test harness."))
        .await
        .expect("get")
        .expect("user");
    assert!(user.primary_email().is_some());

    let address = format!("{code}@oauth.mock.test");
    assert!(AccountEmail::query_used(&valence, valence::use_!("query AccountEmail in lepton-auth/tests/oauth_signup_collision.rs; Valence persistence for this feature path; typed store; visible to test harness."))
        .where_address(StringPredicate::Equals(address))
        .first()
        .await
        .expect("email")
        .is_some());
}

#[tokio::test]
async fn oauth_signup_no_hint_happy() {
    let valence = system_valence("oauth_no_hint").await;
    let cfg = mock_cfg();
    let start = begin_oauth(&cfg, &valence, OAuthProvider::GitHub, OAuthIntent::Signup)
        .await
        .expect("begin");
    let result = complete_oauth(
        &cfg,
        &valence,
        OAuthProvider::GitHub,
        &start.state,
        "no-email",
    )
    .await
    .expect("complete");

    let user_id = match result.completion {
        OAuthCompletion::SignedUp { user_id } => user_id,
        other => panic!("expected SignedUp, got {other:?}"),
    };

    let account = Account::query_used(&valence, valence::use_!("query Account in lepton-auth/tests/oauth_signup_collision.rs; Valence persistence for this feature path; typed store; visible to test harness."))
        .where_user(RecordPredicate::Equals(user_id.clone()))
        .first()
        .await
        .expect("query")
        .expect("account");
    assert_eq!(
        bare_id_from_record(account.user()),
        bare_id_from_record(&user_id)
    );
    assert!(account.primary_email().is_none());

    let user = User::get_used(&bare_id_from_record(&user_id), &valence, valence::use_!("get User in lepton-auth/tests/oauth_signup_collision.rs; Valence persistence for this feature path; typed store; visible to test harness."))
        .await
        .expect("get")
        .expect("user");
    assert!(user.primary_email().is_none());
}

#[tokio::test]
async fn oauth_provision_sets_account_user_happy() {
    let valence = system_valence("oauth_s5").await;
    let cfg = mock_cfg();
    let code = "s5-user";
    let start = begin_oauth(&cfg, &valence, OAuthProvider::GitHub, OAuthIntent::Signup)
        .await
        .expect("begin");
    let result = complete_oauth(&cfg, &valence, OAuthProvider::GitHub, &start.state, code)
        .await
        .expect("complete");
    let user_id = match result.completion {
        OAuthCompletion::SignedUp { user_id } => user_id,
        other => panic!("expected SignedUp, got {other:?}"),
    };
    let account = Account::query_used(&valence, valence::use_!("query Account in lepton-auth/tests/oauth_signup_collision.rs; Valence persistence for this feature path; typed store; visible to test harness."))
        .where_user(RecordPredicate::Equals(user_id.clone()))
        .first()
        .await
        .expect("query")
        .expect("account");
    assert_eq!(
        bare_id_from_record(account.user()),
        bare_id_from_record(&user_id)
    );
    assert!(account.primary_email().is_some());
}

#[tokio::test]
async fn oauth_provision_no_email_hint_happy() {
    let valence = system_valence("oauth_s6").await;
    let cfg = mock_cfg();
    let start = begin_oauth(&cfg, &valence, OAuthProvider::GitHub, OAuthIntent::Signup)
        .await
        .expect("begin");
    let result = complete_oauth(
        &cfg,
        &valence,
        OAuthProvider::GitHub,
        &start.state,
        "noemail:s6",
    )
    .await
    .expect("complete");
    let user_id = match result.completion {
        OAuthCompletion::SignedUp { user_id } => user_id,
        other => panic!("expected SignedUp, got {other:?}"),
    };
    let account = Account::query_used(&valence, valence::use_!("query Account in lepton-auth/tests/oauth_signup_collision.rs; Valence persistence for this feature path; typed store; visible to test harness."))
        .where_user(RecordPredicate::Equals(user_id.clone()))
        .first()
        .await
        .expect("query")
        .expect("account");
    assert_eq!(
        bare_id_from_record(account.user()),
        bare_id_from_record(&user_id)
    );
    assert!(account.primary_email().is_none());
}
