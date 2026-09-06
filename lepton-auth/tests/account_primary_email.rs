//! Account-owned emails: primary FK, contacts, deletion guards, erase, login lookup.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_auth::contacts::{
    add_account_email, mark_account_email_verified, set_account_primary_email, set_primary_email,
    ContactError,
};
use lepton_auth::identity_delete::{
    delete_account_email, delete_membership, delete_user, erase_account, IdentityDeleteError,
};
use lepton_auth::security::random_token_part;
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{
    Account, AccountEmail, AccountMembership, AccountMembershipRole, AccountPlan, AccountStatus,
    TotpFactor, User, UserStatus, UserUserType,
};
use lepton_identity::generated::User as GeneratedUser;
use lepton_identity::ownership::bare_id_from_record;
use support::system_valence;
use valence::{Model, RecordId, RecordPredicate, StringPredicate};

async fn seed_user(valence: &valence::Valence) -> RecordId {
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
    let created = User::create(user, valence).await.expect("create user");
    created.id().cloned().expect("user id")
}

async fn seed_account(valence: &valence::Valence, name: &str, user: &RecordId) -> RecordId {
    let now = Utc::now();
    let account = Account::new(
        name.to_string(),
        user.clone(),
        Some(AccountPlan::Free),
        Some(AccountStatus::Active),
        None,
        None,
        now,
        now,
    )
    .expect("account");
    let created = Account::create(account, valence)
        .await
        .expect("create account");
    created.id().cloned().expect("account id")
}

async fn seed_membership(
    valence: &valence::Valence,
    account: &RecordId,
    user: &RecordId,
) -> RecordId {
    seed_membership_with_role(valence, account, user, AccountMembershipRole::Owner).await
}

async fn seed_membership_with_role(
    valence: &valence::Valence,
    account: &RecordId,
    user: &RecordId,
    role: AccountMembershipRole,
) -> RecordId {
    let now = Utc::now();
    let membership =
        AccountMembership::new(account.clone(), user.clone(), role, now, now).expect("membership");
    let created = AccountMembership::create(membership, valence)
        .await
        .expect("create membership");
    created.id().cloned().expect("membership id")
}

async fn seed_enabled_totp(valence: &valence::Valence, user: &RecordId) -> String {
    let now = Utc::now();
    let factor_id = random_token_part(12);
    let factor = TotpFactor::new(
        user.clone(),
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
        None,
        None,
        None,
        Some(now),
        Some(now),
        now,
        now,
    )
    .expect("totp factor");
    TotpFactor::upsert(&factor_id, factor, valence)
        .await
        .expect("upsert totp");
    factor_id
}

async fn seed_account_email(
    valence: &valence::Valence,
    account: &RecordId,
    address: &str,
    verified: bool,
) -> RecordId {
    let now = Utc::now();
    let verified_at = verified.then_some(now);
    let email_row =
        AccountEmail::new(account.clone(), address.into(), verified_at, now, now).expect("email");
    let email = AccountEmail::create(email_row, valence)
        .await
        .expect("create email");
    email.id().cloned().expect("email id")
}

#[tokio::test]
async fn account_primary_email_optional_none_and_record_fk() {
    let valence = system_valence("account_primary_fk").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "acct@example.test", &user).await;
    seed_membership(&valence, &account, &user).await;

    let account_bare = bare_id_from_record(&account);
    let loaded = Account::get(&account_bare, &valence)
        .await
        .expect("get")
        .expect("account");
    assert!(loaded.primary_email().is_none());

    let email_id = seed_account_email(&valence, &account, "acct@example.test", false).await;
    let now = Utc::now();

    User::get(&bare_id_from_record(&user), &valence)
        .await
        .expect("get user")
        .expect("user")
        .get_mutable(&valence)
        .set_primary_email(email_id.clone())
        .expect("user primary")
        .set_updated_at(now)
        .expect("user updated")
        .commit()
        .await
        .expect("commit user");

    Account::get(&account_bare, &valence)
        .await
        .expect("get account")
        .expect("account")
        .get_mutable(&valence)
        .set_primary_email(email_id.clone())
        .expect("account primary")
        .set_updated_at(now)
        .expect("account updated")
        .commit()
        .await
        .expect("commit account");

    let user_row = User::get(&bare_id_from_record(&user), &valence)
        .await
        .expect("reload user")
        .expect("user");
    let account_row = Account::get(&account_bare, &valence)
        .await
        .expect("reload account")
        .expect("account");
    assert_eq!(user_row.primary_email(), Some(&email_id));
    assert_eq!(account_row.primary_email(), Some(&email_id));
}

#[tokio::test]
async fn set_account_primary_email_happy() {
    let valence = system_valence("set_account_primary_happy").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "billing-acct", &user).await;
    seed_membership(&valence, &account, &user).await;

    let email = add_account_email(&valence, &account, "billing@example.test")
        .await
        .expect("add");
    mark_account_email_verified(&valence, &email)
        .await
        .expect("verify");
    let email_id = email.id().cloned().expect("email id");

    set_account_primary_email(&valence, &account, &email_id)
        .await
        .expect("set account primary");

    let account_row = Account::get(&bare_id_from_record(&account), &valence)
        .await
        .expect("get")
        .expect("account");
    assert_eq!(account_row.primary_email(), Some(&email_id));
}

#[tokio::test]
async fn set_account_primary_email_unverified_sad() {
    let valence = system_valence("set_account_primary_unverified").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "unverified-acct", &user).await;
    seed_membership(&valence, &account, &user).await;

    let email = add_account_email(&valence, &account, "unverified@example.test")
        .await
        .expect("add");
    let email_id = email.id().cloned().expect("email id");

    let err = set_account_primary_email(&valence, &account, &email_id)
        .await
        .expect_err("unverified");
    assert!(matches!(err, ContactError::Unverified));

    let account_row = Account::get(&bare_id_from_record(&account), &valence)
        .await
        .expect("get")
        .expect("account");
    assert!(account_row.primary_email().is_none());
}

#[tokio::test]
async fn set_account_primary_email_wrong_account_sad() {
    let valence = system_valence("set_account_primary_wrong_acct").await;
    let user = seed_user(&valence).await;
    let outsider = seed_user(&valence).await;
    let account = seed_account(&valence, "owner-acct", &user).await;
    let other = seed_account(&valence, "other-acct", &outsider).await;
    seed_membership(&valence, &account, &user).await;
    seed_membership(&valence, &other, &outsider).await;

    let email = add_account_email(&valence, &other, "outsider@example.test")
        .await
        .expect("add");
    mark_account_email_verified(&valence, &email)
        .await
        .expect("verify");
    let email_id = email.id().cloned().expect("email id");

    let err = set_account_primary_email(&valence, &account, &email_id)
        .await
        .expect_err("wrong account");
    assert!(matches!(err, ContactError::NotMember));
}

#[tokio::test]
async fn login_resolves_user_via_primary_email_fk() {
    let valence = system_valence("login_lookup").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "login@example.test", &user).await;
    seed_membership(&valence, &account, &user).await;
    let email_id = seed_account_email(&valence, &account, "login@example.test", true).await;
    let now = Utc::now();

    User::get(&bare_id_from_record(&user), &valence)
        .await
        .expect("get")
        .expect("user")
        .get_mutable(&valence)
        .set_primary_email(email_id.clone())
        .expect("set")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("commit");

    let email_row = AccountEmail::query(&valence)
        .where_address(StringPredicate::Equals("login@example.test".into()))
        .first()
        .await
        .expect("query")
        .expect("email");
    let found = GeneratedUser::query(&valence)
        .where_primary_email(RecordPredicate::Equals(
            email_row.id().cloned().expect("id"),
        ))
        .first()
        .await
        .expect("user query")
        .expect("user");
    assert_eq!(found.id(), Some(&user));
}

#[tokio::test]
async fn delete_primary_email_restricted() {
    let valence = system_valence("restrict_primary").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "restrict@example.test", &user).await;
    seed_membership(&valence, &account, &user).await;
    let email_id = seed_account_email(&valence, &account, "restrict@example.test", true).await;
    let now = Utc::now();

    Account::get(&bare_id_from_record(&account), &valence)
        .await
        .expect("get")
        .expect("account")
        .get_mutable(&valence)
        .set_primary_email(email_id.clone())
        .expect("primary")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("commit");

    let err = delete_account_email(&valence, &email_id)
        .await
        .expect_err("restrict");
    assert!(matches!(err, IdentityDeleteError::RestrictPrimary));
    assert!(AccountEmail::get(&bare_id_from_record(&email_id), &valence)
        .await
        .expect("get")
        .is_some());
}

#[tokio::test]
async fn sole_member_user_delete_denied() {
    let valence = system_valence("sole_member").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "sole@example.test", &user).await;
    seed_membership(&valence, &account, &user).await;

    let err = delete_user(&valence, &user).await.expect_err("sole");
    assert!(matches!(err, IdentityDeleteError::SoleMember));
    assert!(User::get(&bare_id_from_record(&user), &valence)
        .await
        .expect("get")
        .is_some());
}

#[tokio::test]
async fn last_membership_delete_denied() {
    let valence = system_valence("last_membership").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "last-m", &user).await;
    let mid = seed_membership(&valence, &account, &user).await;

    let err = delete_membership(&valence, &mid).await.expect_err("last");
    assert!(matches!(err, IdentityDeleteError::LastMembership));
}

#[tokio::test]
async fn erase_account_cascades_emails_and_deletes_users() {
    let valence = system_valence("erase_account").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "erase@example.test", &user).await;
    seed_membership(&valence, &account, &user).await;
    let email_id = seed_account_email(&valence, &account, "erase@example.test", true).await;
    let backup = seed_account_email(&valence, &account, "backup-erase@example.test", true).await;
    let now = Utc::now();

    Account::get(&bare_id_from_record(&account), &valence)
        .await
        .expect("get")
        .expect("account")
        .get_mutable(&valence)
        .set_primary_email(email_id.clone())
        .expect("primary")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("commit");
    User::get(&bare_id_from_record(&user), &valence)
        .await
        .expect("get")
        .expect("user")
        .get_mutable(&valence)
        .set_primary_email(email_id.clone())
        .expect("login")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("commit");

    let totp_id = seed_enabled_totp(&valence, &user).await;

    erase_account(&valence, &account).await.expect("erase");

    assert!(Account::get(&bare_id_from_record(&account), &valence)
        .await
        .expect("get")
        .is_none());
    assert!(User::get(&bare_id_from_record(&user), &valence)
        .await
        .expect("get")
        .is_none());
    assert!(AccountEmail::get(&bare_id_from_record(&email_id), &valence)
        .await
        .expect("get")
        .is_none());
    assert!(AccountEmail::get(&bare_id_from_record(&backup), &valence)
        .await
        .expect("get")
        .is_none());
    assert!(TotpFactor::get(&totp_id, &valence)
        .await
        .expect("get totp")
        .is_none());
}

#[tokio::test]
async fn erase_account_deletes_all_member_users() {
    let valence = system_valence("erase_multi_member").await;
    let owner = seed_user(&valence).await;
    let persona = seed_user(&valence).await;
    let account = seed_account(&valence, "erase-multi@example.test", &owner).await;
    seed_membership(&valence, &account, &owner).await;
    seed_membership_with_role(&valence, &account, &persona, AccountMembershipRole::Admin).await;
    let _ = seed_account_email(&valence, &account, "erase-multi@example.test", true).await;

    erase_account(&valence, &account).await.expect("erase");

    assert!(Account::get(&bare_id_from_record(&account), &valence)
        .await
        .expect("get")
        .is_none());
    assert!(User::get(&bare_id_from_record(&owner), &valence)
        .await
        .expect("get")
        .is_none());
    assert!(User::get(&bare_id_from_record(&persona), &valence)
        .await
        .expect("get")
        .is_none());
}

#[tokio::test]
async fn persona_delete_denied_when_account_primary() {
    let valence = system_valence("persona_account_primary").await;
    let owner = seed_user(&valence).await;
    let persona = seed_user(&valence).await;
    let account = seed_account(&valence, "primary-guard@example.test", &owner).await;
    seed_membership(&valence, &account, &owner).await;
    seed_membership_with_role(&valence, &account, &persona, AccountMembershipRole::Admin).await;

    let primary = seed_account_email(&valence, &account, "primary-guard@example.test", true).await;
    let persona_login =
        seed_account_email(&valence, &account, "persona-guard@example.test", true).await;
    let now = Utc::now();

    Account::get(&bare_id_from_record(&account), &valence)
        .await
        .expect("get")
        .expect("account")
        .get_mutable(&valence)
        .set_primary_email(primary.clone())
        .expect("primary")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("commit");

    // Persona login email is also the account primary — delete_user must deny.
    User::get(&bare_id_from_record(&persona), &valence)
        .await
        .expect("get")
        .expect("user")
        .get_mutable(&valence)
        .set_primary_email(primary.clone())
        .expect("persona login = account primary")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("commit");

    User::get(&bare_id_from_record(&owner), &valence)
        .await
        .expect("get")
        .expect("user")
        .get_mutable(&valence)
        .set_primary_email(persona_login)
        .expect("owner login")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("commit");

    let err = delete_user(&valence, &persona)
        .await
        .expect_err("account primary");
    assert!(matches!(err, IdentityDeleteError::AccountPrimary));
    assert_eq!(err.reason_class(), "account_primary");
    assert!(User::get(&bare_id_from_record(&persona), &valence)
        .await
        .expect("get")
        .is_some());
}

#[tokio::test]
async fn persona_user_delete_allowed_when_sibling_exists() {
    let valence = system_valence("persona_delete").await;
    let owner = seed_user(&valence).await;
    let persona = seed_user(&valence).await;
    let account = seed_account(&valence, "multi@example.test", &owner).await;
    seed_membership(&valence, &account, &owner).await;
    seed_membership(&valence, &account, &persona).await;

    let primary = seed_account_email(&valence, &account, "multi@example.test", true).await;
    let login = seed_account_email(&valence, &account, "persona@example.test", true).await;
    let now = Utc::now();

    Account::get(&bare_id_from_record(&account), &valence)
        .await
        .expect("get")
        .expect("account")
        .get_mutable(&valence)
        .set_primary_email(primary.clone())
        .expect("primary")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("commit");

    User::get(&bare_id_from_record(&owner), &valence)
        .await
        .expect("get")
        .expect("user")
        .get_mutable(&valence)
        .set_primary_email(primary)
        .expect("owner login")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("commit");

    User::get(&bare_id_from_record(&persona), &valence)
        .await
        .expect("get")
        .expect("user")
        .get_mutable(&valence)
        .set_primary_email(login.clone())
        .expect("persona login")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("commit");

    delete_user(&valence, &persona)
        .await
        .expect("delete persona");
    assert!(User::get(&bare_id_from_record(&persona), &valence)
        .await
        .expect("get")
        .is_none());
    assert!(User::get(&bare_id_from_record(&owner), &valence)
        .await
        .expect("get")
        .is_some());
    assert!(AccountEmail::get(&bare_id_from_record(&login), &valence)
        .await
        .expect("get")
        .is_some());
}

#[tokio::test]
async fn set_primary_email_login_fk() {
    let valence = system_valence("set_login_fk").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "login-fk", &user).await;
    seed_membership(&valence, &account, &user).await;

    let email = add_account_email(&valence, &account, "login-fk@example.test")
        .await
        .expect("add");
    mark_account_email_verified(&valence, &email)
        .await
        .expect("verify");
    let email_id = email.id().cloned().expect("id");

    // mark_account_email_verified may already set login; ensure setter works explicitly.
    set_primary_email(&valence, &user, &email_id)
        .await
        .expect("set login");

    let user_row = User::get(&bare_id_from_record(&user), &valence)
        .await
        .expect("get")
        .expect("user");
    assert_eq!(user_row.primary_email(), Some(&email_id));
}

#[tokio::test]
async fn account_email_provision_signup_happy() {
    use lepton_auth::signup_api::ssr::{create_pending_user, SignupRequest};

    let valence = system_valence("signup_provision").await;
    let pending = create_pending_user(
        &valence,
        SignupRequest {
            legal_name: "Ada Lovelace".into(),
            display_name: "Ada".into(),
            email: "ada@example.test".into(),
            password: "CorrectHorseBattery1!".into(),
            confirm: "CorrectHorseBattery1!".into(),
        },
    )
    .await
    .expect("signup");

    let user = User::get(&bare_id_from_record(&pending.user_id), &valence)
        .await
        .expect("get")
        .expect("user");
    let account = Account::query(&valence)
        .where_user(RecordPredicate::Equals(pending.user_id.clone()))
        .first()
        .await
        .expect("query")
        .expect("account");
    let email = AccountEmail::get(&bare_id_from_record(&pending.email_id), &valence)
        .await
        .expect("get")
        .expect("email");

    assert_eq!(
        bare_id_from_record(email.account()),
        bare_id_from_record(account.id().expect("id"))
    );
    assert_eq!(
        bare_id_from_record(account.user()),
        bare_id_from_record(&pending.user_id)
    );
    assert_eq!(
        bare_id_from_record(account.primary_email().expect("acct primary")),
        bare_id_from_record(&pending.email_id)
    );
    assert_eq!(
        bare_id_from_record(user.primary_email().expect("login")),
        bare_id_from_record(&pending.email_id)
    );
}

#[tokio::test]
async fn account_email_provision_signup_invalid_sad() {
    let valence = system_valence("signup_invalid_email").await;
    let user = seed_user(&valence).await;
    let account = seed_account(&valence, "bad-email", &user).await;
    let now = Utc::now();
    let err = AccountEmail::new(account, "not-an-email".into(), None, now, now);
    assert!(err.is_err());
}
