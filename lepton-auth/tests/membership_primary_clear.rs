//! Membership delete SideEffect clears matching Account primaries (TM-SE1–SE4).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

use chrono::Utc;
use lepton_auth::contacts::{
    add_account_phone, mark_account_phone_verified, set_account_primary_phone, set_primary_phone,
};
use lepton_auth::identity_delete::delete_membership;
use lepton_host_adapter::auth::hash_password;
use lepton_host_adapter::generated::{
    Account, AccountEmail, AccountMembership, AccountMembershipRole, AccountPlan, AccountStatus,
    User, UserStatus, UserUserType,
};
use lepton_identity::ownership::bare_id_from_record;
use lepton_identity::side_effects::force_primary_clear_failure;
use support::system_valence;
use valence::{Model, RecordId};

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
    User::create(user, valence, valence::use_!(r#"**Test:** Fixture **User** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("create")
        .id()
        .cloned()
        .expect("id")
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
    Account::create(account, valence, valence::use_!(r#"**Test:** Fixture **Account** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("create")
        .id()
        .cloned()
        .expect("id")
}

async fn seed_membership(
    valence: &valence::Valence,
    account: &RecordId,
    user: &RecordId,
) -> RecordId {
    let now = Utc::now();
    let m = AccountMembership::new(
        account.clone(),
        user.clone(),
        AccountMembershipRole::Owner,
        now,
        now,
    )
    .expect("m");
    AccountMembership::create(m, valence, valence::use_!(r#"**Test:** Fixture **Account Membership** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("create")
        .id()
        .cloned()
        .expect("id")
}

#[tokio::test]
async fn membership_delete_clears_matching_email_primary_happy() {
    let valence = system_valence("se_email_clear").await;
    let owner = seed_user(&valence).await;
    let persona = seed_user(&valence).await;
    let account = seed_account(&valence, "se-email", &owner).await;
    seed_membership(&valence, &account, &owner).await;
    let persona_m = seed_membership(&valence, &account, &persona).await;

    let now = Utc::now();
    let owner_email = AccountEmail::new(
        account.clone(),
        "owner@example.test".into(),
        Some(now),
        now,
        now,
    )
    .expect("email");
    let owner_email = AccountEmail::create(owner_email, &valence, valence::use_!(r#"**Test:** Fixture **Account Email** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("create");
    let owner_email_id = owner_email.id().cloned().expect("id");

    let persona_email = AccountEmail::new(
        account.clone(),
        "persona@example.test".into(),
        Some(now),
        now,
        now,
    )
    .expect("email");
    let persona_email = AccountEmail::create(persona_email, &valence, valence::use_!(r#"**Test:** Fixture **Account Email** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("create");
    let persona_email_id = persona_email.id().cloned().expect("id");

    // Account legal primary matches persona login — removing persona clears it.
    Account::get(&bare_id_from_record(&account), &valence, valence::use_!(r#"**Test:** Fixture **Account** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("get")
        .expect("a")
        .get_mutable(&valence, valence::use_!(r#"**Test:** Fixture **this data** access in `membership_primary_clear` so the suite can arrange and assert persistence. CI and developers running the suite only."#))
        .set_primary_email(persona_email_id.clone())
        .expect("p")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("c");

    User::get(&bare_id_from_record(&persona), &valence, valence::use_!(r#"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("get")
        .expect("u")
        .get_mutable(&valence, valence::use_!(r#"**Test:** Fixture **this data** access in `membership_primary_clear` so the suite can arrange and assert persistence. CI and developers running the suite only."#))
        .set_primary_email(persona_email_id)
        .expect("p")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("c");

    User::get(&bare_id_from_record(&owner), &valence, valence::use_!(r#"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("get")
        .expect("u")
        .get_mutable(&valence, valence::use_!(r#"**Test:** Fixture **this data** access in `membership_primary_clear` so the suite can arrange and assert persistence. CI and developers running the suite only."#))
        .set_primary_email(owner_email_id)
        .expect("p")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("c");

    delete_membership(&valence, &persona_m)
        .await
        .expect("delete membership");

    let acct = Account::get(&bare_id_from_record(&account), &valence, valence::use_!(r#"**Test:** Fixture **Account** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("get")
        .expect("account");
    assert!(acct.primary_email().is_none());
}

#[tokio::test]
async fn membership_delete_unrelated_login_leaves_primary_happy() {
    let valence = system_valence("se_email_leave").await;
    let owner = seed_user(&valence).await;
    let persona = seed_user(&valence).await;
    let account = seed_account(&valence, "se-leave", &owner).await;
    seed_membership(&valence, &account, &owner).await;
    let persona_m = seed_membership(&valence, &account, &persona).await;

    let now = Utc::now();
    let owner_email = AccountEmail::new(
        account.clone(),
        "owner-keep@example.test".into(),
        Some(now),
        now,
        now,
    )
    .expect("email");
    let owner_email = AccountEmail::create(owner_email, &valence, valence::use_!(r#"**Test:** Fixture **Account Email** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("create");
    let owner_email_id = owner_email.id().cloned().expect("id");

    let persona_email = AccountEmail::new(
        account.clone(),
        "persona-other@example.test".into(),
        Some(now),
        now,
        now,
    )
    .expect("email");
    let persona_email = AccountEmail::create(persona_email, &valence, valence::use_!(r#"**Test:** Fixture **Account Email** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("create");
    let persona_email_id = persona_email.id().cloned().expect("id");

    Account::get(&bare_id_from_record(&account), &valence, valence::use_!(r#"**Test:** Fixture **Account** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("get")
        .expect("a")
        .get_mutable(&valence, valence::use_!(r#"**Test:** Fixture **this data** access in `membership_primary_clear` so the suite can arrange and assert persistence. CI and developers running the suite only."#))
        .set_primary_email(owner_email_id.clone())
        .expect("p")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("c");

    User::get(&bare_id_from_record(&owner), &valence, valence::use_!(r#"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("get")
        .expect("u")
        .get_mutable(&valence, valence::use_!(r#"**Test:** Fixture **this data** access in `membership_primary_clear` so the suite can arrange and assert persistence. CI and developers running the suite only."#))
        .set_primary_email(owner_email_id.clone())
        .expect("p")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("c");

    User::get(&bare_id_from_record(&persona), &valence, valence::use_!(r#"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("get")
        .expect("u")
        .get_mutable(&valence, valence::use_!(r#"**Test:** Fixture **this data** access in `membership_primary_clear` so the suite can arrange and assert persistence. CI and developers running the suite only."#))
        .set_primary_email(persona_email_id)
        .expect("p")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("c");

    delete_membership(&valence, &persona_m)
        .await
        .expect("delete");

    let acct = Account::get(&bare_id_from_record(&account), &valence, valence::use_!(r#"**Test:** Fixture **Account** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("get")
        .expect("account");
    assert_eq!(
        bare_id_from_record(acct.primary_email().expect("kept")),
        bare_id_from_record(&owner_email_id)
    );
}

#[tokio::test]
async fn membership_delete_phone_primary_clears_when_match_happy() {
    let valence = system_valence("se_phone_clear").await;
    let owner = seed_user(&valence).await;
    let persona = seed_user(&valence).await;
    let account = seed_account(&valence, "se-phone", &owner).await;
    seed_membership(&valence, &account, &owner).await;
    let persona_m = seed_membership(&valence, &account, &persona).await;

    let phone = add_account_phone(&valence, &account, "+15555550201")
        .await
        .expect("add");
    mark_account_phone_verified(&valence, &phone)
        .await
        .expect("verify");
    let phone_id = phone.id().cloned().expect("id");
    set_account_primary_phone(&valence, &account, &phone_id)
        .await
        .expect("acct");
    set_primary_phone(&valence, &persona, &phone_id)
        .await
        .expect("login");

    delete_membership(&valence, &persona_m)
        .await
        .expect("delete");

    let acct = Account::get(&bare_id_from_record(&account), &valence, valence::use_!(r#"**Test:** Fixture **Account** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("get")
        .expect("account");
    assert!(acct.primary_phone().is_none());
}

#[tokio::test]
async fn membership_delete_phone_primary_leaves_when_no_match_happy() {
    let valence = system_valence("se_phone_leave").await;
    let owner = seed_user(&valence).await;
    let persona = seed_user(&valence).await;
    let account = seed_account(&valence, "se-phone-leave", &owner).await;
    seed_membership(&valence, &account, &owner).await;
    let persona_m = seed_membership(&valence, &account, &persona).await;

    let owner_phone = add_account_phone(&valence, &account, "+15555550202")
        .await
        .expect("add");
    mark_account_phone_verified(&valence, &owner_phone)
        .await
        .expect("verify");
    let owner_phone_id = owner_phone.id().cloned().expect("id");
    set_account_primary_phone(&valence, &account, &owner_phone_id)
        .await
        .expect("acct");
    set_primary_phone(&valence, &owner, &owner_phone_id)
        .await
        .expect("owner login");

    let persona_phone = add_account_phone(&valence, &account, "+15555550203")
        .await
        .expect("add");
    mark_account_phone_verified(&valence, &persona_phone)
        .await
        .expect("verify");
    let persona_phone_id = persona_phone.id().cloned().expect("id");
    set_primary_phone(&valence, &persona, &persona_phone_id)
        .await
        .expect("persona login");

    delete_membership(&valence, &persona_m)
        .await
        .expect("delete");

    let acct = Account::get(&bare_id_from_record(&account), &valence, valence::use_!(r#"**Test:** Fixture **Account** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("get")
        .expect("account");
    assert_eq!(
        bare_id_from_record(acct.primary_phone().expect("kept")),
        bare_id_from_record(&owner_phone_id)
    );
}

#[tokio::test]
async fn membership_delete_se_failure_still_deletes() {
    let valence = system_valence("se_fail_still_deletes").await;
    let owner = seed_user(&valence).await;
    let persona = seed_user(&valence).await;
    let account = seed_account(&valence, "se-fail", &owner).await;
    seed_membership(&valence, &account, &owner).await;
    let persona_m = seed_membership(&valence, &account, &persona).await;

    let now = Utc::now();
    let persona_email = AccountEmail::new(
        account.clone(),
        "persona-fail@example.test".into(),
        Some(now),
        now,
        now,
    )
    .expect("email");
    let persona_email = AccountEmail::create(persona_email, &valence, valence::use_!(r#"**Test:** Fixture **Account Email** save for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("create");
    let persona_email_id = persona_email.id().cloned().expect("id");

    Account::get(&bare_id_from_record(&account), &valence, valence::use_!(r#"**Test:** Fixture **Account** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("get")
        .expect("a")
        .get_mutable(&valence, valence::use_!(r#"**Test:** Fixture **this data** access in `membership_primary_clear` so the suite can arrange and assert persistence. CI and developers running the suite only."#))
        .set_primary_email(persona_email_id.clone())
        .expect("p")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("c");

    User::get(&bare_id_from_record(&persona), &valence, valence::use_!(r#"**Test:** Fixture **User** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("get")
        .expect("u")
        .get_mutable(&valence, valence::use_!(r#"**Test:** Fixture **this data** access in `membership_primary_clear` so the suite can arrange and assert persistence. CI and developers running the suite only."#))
        .set_primary_email(persona_email_id.clone())
        .expect("p")
        .set_updated_at(now)
        .expect("ts")
        .commit()
        .await
        .expect("c");

    force_primary_clear_failure(true);
    let result = delete_membership(&valence, &persona_m).await;
    force_primary_clear_failure(false);
    result.expect("membership delete must succeed even if clear fails");

    assert!(
        AccountMembership::get(&bare_id_from_record(&persona_m), &valence, valence::use_!(r#"**Test:** Fixture **Account Membership** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
            .await
            .expect("get")
            .is_none()
    );
    // Clear failed → primary still set (log-only SE contract).
    let acct = Account::get(&bare_id_from_record(&account), &valence, valence::use_!(r#"**Test:** Fixture **Account** load for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."#))
        .await
        .expect("get")
        .expect("account");
    assert_eq!(
        bare_id_from_record(acct.primary_email().expect("uncleared")),
        bare_id_from_record(&persona_email_id)
    );
}
