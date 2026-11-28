//! Device sign-in: start, approve as a service user the approver owns, poll a token, move, sign
//! out, and every refusal.
//!
//! Approvals and moves go through the `*_without_step_up` twins (`test-utils`): the step-up
//! check needs an HTTP session these suites don't have.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/service_users.rs"]
mod service_users_support;

use std::time::Duration;

use chrono::Utc;
use lepton_auth::device_signin::{
    approve_device_without_step_up as approve_device, deny_device, list_my_devices,
    list_service_user_devices, lookup_device_request, move_device_without_step_up as move_device,
    rename_device, sign_out_device, ActAs, ApproveDevice, DeviceSigninError, LeptonDeviceFlow,
    Unavailable,
};
use lepton_auth::service_users::{
    create_service_user_token_without_step_up as create_service_user_token, delete_service_user,
    suspend_service_user, NewServiceUser, NewServiceUserToken, MAX_TOKENS_PER_SERVICE_USER,
};
use lepton_host_adapter::device_signin::{
    DevicePollError, DeviceStartError, DeviceStartGrant, DeviceStartRequest, DeviceTokenGrant,
};
use lepton_host_adapter::generated::{
    DeviceAuthorization, ServiceUserToken as TokenRow, ServiceUserTokenKind, SignedInDevice,
    SignedInDeviceStatus,
};
use lepton_identity::service_users::ServiceUserId;
use lepton_identity::tokens::{
    scopes_to_json, verify_bearer_token, LeptonToken, TokenLifetime, TokenPrincipal,
};
use service_users_support::{
    install_test_gate, install_test_scopes, scope, seed_service_user, seed_user, MAGNON_READ,
    TEST_SCOPES,
};
use support::{system_valence, user_valence};
use valence::{Model, RecordId, Valence};

fn setup() {
    install_test_gate();
    install_test_scopes();
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
}

/// A flow that never answers `slow_down`, so tests can poll back to back.
fn flow() -> LeptonDeviceFlow {
    LeptonDeviceFlow::with_poll_interval(Duration::ZERO)
}

async fn start(flow: &LeptonDeviceFlow, sys: &Valence) -> DeviceStartGrant {
    flow.start(
        sys,
        DeviceStartRequest {
            client: "uf CLI 0.4".into(),
            device_name: "mei-laptop".into(),
            scopes: vec!["magnon:read".into()],
            asked_from: Some("203.0.113.24".into()),
            user_agent: Some("uf/0.4 (Linux)".into()),
        },
    )
    .await
    .expect("start")
}

fn approve_as<'a>(user_code: &'a str, act_as: ActAs<'a>) -> ApproveDevice<'a> {
    ApproveDevice {
        user_code,
        act_as,
        scopes: &MAGNON_READ,
        lifetime: TokenLifetime::Days30,
    }
}

async fn poll(
    flow: &LeptonDeviceFlow,
    sys: &Valence,
    grant: &DeviceStartGrant,
) -> Result<DeviceTokenGrant, DevicePollError> {
    flow.poll(sys, &grant.device_code).await
}

/// The service user a token acts as, or `None` when it doesn't verify.
async fn acts_as(sys: &Valence, token: &str) -> Option<ServiceUserId> {
    match verify_bearer_token(token, sys).await?.principal {
        TokenPrincipal::ServiceUser { service_user, .. } => Some(service_user),
        TokenPrincipal::Person(_) => None,
    }
}

fn device_id(grant: &DeviceStartGrant) -> String {
    let rest = grant.device_code.strip_prefix("lpdc_").expect("prefix");
    rest.split_once('_').expect("id").0.to_string()
}

#[tokio::test]
async fn approve_as_owned_service_user_then_poll_once_happy() {
    setup();
    let sys = system_valence("device_owned").await;
    let (mei, id, _) = seed_service_user(&sys, "maker-dev-a", "dev-ci").await;
    let flow = flow();
    let grant = start(&flow, &sys).await;
    assert_eq!(grant.user_code.len(), 9);
    assert_eq!(grant.expires_in, 600);
    assert_eq!(
        poll(&flow, &sys, &grant).await.unwrap_err(),
        DevicePollError::AuthorizationPending
    );

    let request = lookup_device_request(&mei, &grant.user_code.to_lowercase())
        .await
        .expect("lookup");
    assert_eq!(request.device_name, "mei-laptop");
    assert_eq!(request.client, "uf CLI 0.4");
    assert_eq!(request.asked_from.as_deref(), Some("203.0.113.24"));
    assert_eq!(request.requested_scopes, *MAGNON_READ);
    assert_eq!(request.choices.len(), 1);
    assert_eq!(request.choices[0].id, id);
    assert_eq!(request.choices[0].unavailable, None);

    let device = approve_device(&mei, approve_as(&grant.user_code, ActAs::Existing(&id)))
        .await
        .expect("approve");
    assert!(matches!(
        device.status(),
        SignedInDeviceStatus::IssuePending
    ));

    let token = poll(&flow, &sys, &grant).await.expect("token");
    assert_eq!(token.scopes, *MAGNON_READ);
    assert!((29 * 86_400..=30 * 86_400).contains(&token.expires_in));
    let verified = verify_bearer_token(&token.access_token, &sys)
        .await
        .expect("verifies");
    assert!(matches!(
        &verified.principal,
        TokenPrincipal::ServiceUser { service_user, kind: ServiceUserTokenKind::Device, device_id: Some(d), .. }
            if *service_user == id && *d == device_id(&grant)
    ));

    // Works once: the request is gone and the device has its token.
    assert_eq!(
        poll(&flow, &sys, &grant).await.unwrap_err(),
        DevicePollError::InvalidGrant
    );
    let request_row = DeviceAuthorization::get(&device_id(&grant), &sys, valence::use_!(r"**Test:** Fixture read of a **device sign-in request** to assert it was deleted once used. CI and developers running the suite only."))
        .await
        .expect("read");
    assert!(request_row.is_none());
    let listed = list_service_user_devices(&mei, &id).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert!(matches!(
        listed[0].device.status(),
        SignedInDeviceStatus::SignedIn
    ));
    assert_eq!(
        listed[0].device.token().map(String::as_str),
        Some(verified.token_id.as_str())
    );
    assert!(listed[0].device.signed_in_until().is_some());
    assert!(listed[0].last_seen_at.is_some());
    assert_eq!(list_my_devices(&mei).await.expect("mine").len(), 1);
}

#[tokio::test]
async fn approve_creating_a_service_user_happy() {
    setup();
    let sys = system_valence("device_new_su").await;
    seed_user(&sys, "maker-dev-b").await;
    let mei = user_valence(&sys, "maker-dev-b");
    let flow = flow();
    let grant = start(&flow, &sys).await;
    let lookup = lookup_device_request(&mei, &grant.user_code)
        .await
        .expect("lookup");
    assert!(lookup.choices.is_empty(), "no service users yet");

    let device = approve_device(
        &mei,
        approve_as(
            &grant.user_code,
            ActAs::New(NewServiceUser {
                handle: "mei-laptop",
                display_name: "Mei's laptop",
                description: None,
            }),
        ),
    )
    .await
    .expect("approve with a new service user");
    let new_id =
        ServiceUserId::parse(device.service_user().expect("service user").id()).expect("id");
    let token = poll(&flow, &sys, &grant).await.expect("token");
    assert_eq!(acts_as(&sys, &token.access_token).await, Some(new_id));

    // The handle is checked like the create flow.
    let second = start(&flow, &sys).await;
    let err = approve_device(
        &mei,
        approve_as(
            &second.user_code,
            ActAs::New(NewServiceUser {
                handle: "mei-laptop",
                display_name: "Again",
                description: None,
            }),
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(err.reason_class(), "handle_taken");
    // A refused approval leaves the request open.
    lookup_device_request(&mei, &second.user_code)
        .await
        .expect("still pending");
}

#[tokio::test]
async fn someone_elses_service_user_refused_even_for_manage_any_sad() {
    setup();
    let sys = system_valence("device_foreign").await;
    let (_mei, meis, _) = seed_service_user(&sys, "maker-dev-c", "dev-meis").await;
    seed_user(&sys, "maker-dev-c2").await;
    seed_user(&sys, "super-dev-c").await;
    let other = user_valence(&sys, "maker-dev-c2");
    let admin = user_valence(&sys, "super-dev-c");
    let flow = flow();
    let grant = start(&flow, &sys).await;

    let err = approve_device(&other, approve_as(&grant.user_code, ActAs::Existing(&meis)))
        .await
        .unwrap_err();
    assert!(matches!(err, DeviceSigninError::NotFound), "{err}");
    let err = approve_device(&admin, approve_as(&grant.user_code, ActAs::Existing(&meis)))
        .await
        .unwrap_err();
    assert!(matches!(err, DeviceSigninError::Forbidden), "{err}");
    assert!(
        lookup_device_request(&admin, &grant.user_code)
            .await
            .expect("lookup")
            .choices
            .is_empty(),
        "an admin only sees their own service users"
    );
    assert_eq!(
        poll(&flow, &sys, &grant).await.unwrap_err(),
        DevicePollError::AuthorizationPending
    );

    // Nor can anyone write a device record for someone else's service user directly.
    let forged = SignedInDevice::new(
        Some(RecordId::new("user", "maker-dev-c2")),
        Some(RecordId::new("service_user_account", meis.as_str())),
        "forged".into(),
        "uf".into(),
        None,
        None,
        "0".repeat(64),
        Some(scopes_to_json(&MAGNON_READ)),
        30,
        SignedInDeviceStatus::IssuePending,
        None,
        Utc::now(),
        None,
        None,
    )
    .expect("row");
    SignedInDevice::upsert("forged-device", forged, &other, valence::use_!(r"**Test:** Attempted forged **device** row for another person's service user; the create rule must refuse it. CI and developers running the suite only."))
        .await
        .expect_err("create rule refuses a foreign service user");
}

#[tokio::test]
async fn paused_or_full_service_user_refused_with_reason_sad() {
    setup();
    let sys = system_valence("device_unavailable").await;
    let (mei, paused, _) = seed_service_user(&sys, "maker-dev-d", "dev-paused").await;
    let full = lepton_auth::service_users::create_service_user(
        &mei,
        NewServiceUser {
            handle: "dev-full",
            display_name: "Full",
            description: None,
        },
    )
    .await
    .expect("second service user");
    let full = ServiceUserId::parse(full.id().expect("id").id()).expect("id");
    suspend_service_user(&mei, &paused).await.expect("pause");
    for i in 0..MAX_TOKENS_PER_SERVICE_USER {
        create_service_user_token(
            &mei,
            &full,
            NewServiceUserToken {
                label: &format!("t{i}"),
                scopes: &MAGNON_READ,
                lifetime: TokenLifetime::Days30,
                kind: ServiceUserTokenKind::Manual,
                device_id: None,
            },
        )
        .await
        .expect("token");
    }
    let flow = flow();
    let grant = start(&flow, &sys).await;
    let request = lookup_device_request(&mei, &grant.user_code)
        .await
        .expect("lookup");
    let reason = |id: &ServiceUserId| {
        request
            .choices
            .iter()
            .find(|c| &c.id == id)
            .and_then(|c| c.unavailable)
    };
    assert_eq!(reason(&paused), Some(Unavailable::Paused));
    assert_eq!(reason(&full), Some(Unavailable::TokenLimit));

    let err = approve_device(&mei, approve_as(&grant.user_code, ActAs::Existing(&paused)))
        .await
        .unwrap_err();
    assert_eq!(err.reason_class(), "paused");
    let err = approve_device(&mei, approve_as(&grant.user_code, ActAs::Existing(&full)))
        .await
        .unwrap_err();
    assert_eq!(err.reason_class(), "quota");
}

#[tokio::test]
async fn scopes_are_required_and_registered_sad() {
    setup();
    let sys = system_valence("device_scopes").await;
    let (mei, id, _) = seed_service_user(&sys, "maker-dev-e", "dev-scopes").await;
    let flow = flow();
    let grant = start(&flow, &sys).await;
    let err = approve_device(
        &mei,
        ApproveDevice {
            scopes: &[],
            ..approve_as(&grant.user_code, ActAs::Existing(&id))
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.reason_class(), "scopes");
    let unknown = [scope("billing:write")];
    let err = approve_device(
        &mei,
        ApproveDevice {
            scopes: &unknown,
            ..approve_as(&grant.user_code, ActAs::Existing(&id))
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.reason_class(), "scopes");

    let bad_start = flow
        .start(
            &sys,
            DeviceStartRequest {
                client: "uf".into(),
                device_name: "x".into(),
                scopes: vec!["billing:write".into()],
                asked_from: None,
                user_agent: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(bad_start, DeviceStartError::InvalidScope);
    let no_name = flow
        .start(
            &sys,
            DeviceStartRequest {
                client: " ".into(),
                device_name: "x".into(),
                scopes: vec![],
                asked_from: None,
                user_agent: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(no_name, DeviceStartError::InvalidRequest);
}

#[tokio::test]
async fn expired_request_refused_sad() {
    setup();
    let sys = system_valence("device_expired").await;
    let (mei, id, _) = seed_service_user(&sys, "maker-dev-f", "dev-expired").await;
    let flow = flow();
    let grant = start(&flow, &sys).await;
    let row = DeviceAuthorization::get(&device_id(&grant), &sys, valence::use_!(r"**Test:** Fixture read of a **device sign-in request** so the suite can age it past its expiry. CI and developers running the suite only."))
        .await
        .expect("read")
        .expect("row");
    row.get_mutable(&sys, valence::use_!(r"**Test:** Fixture write that ages a **device sign-in request** past its expiry. CI and developers running the suite only."))
        .set_expires_at(Utc::now() - chrono::Duration::seconds(1))
        .expect("set")
        .commit()
        .await
        .expect("age the request");

    let err = approve_device(&mei, approve_as(&grant.user_code, ActAs::Existing(&id)))
        .await
        .unwrap_err();
    assert!(matches!(err, DeviceSigninError::NotFound), "{err}");
    assert_eq!(
        poll(&flow, &sys, &grant).await.unwrap_err(),
        DevicePollError::ExpiredToken
    );
    assert_eq!(
        poll(&flow, &sys, &grant).await.unwrap_err(),
        DevicePollError::InvalidGrant,
        "an expired request is deleted"
    );
}

#[tokio::test]
async fn five_wrong_codes_lock_the_approver_sad() {
    setup();
    let sys = system_valence("device_lockout").await;
    let (mei, id, _) = seed_service_user(&sys, "maker-dev-g", "dev-lockout").await;
    let flow = flow();
    let grant = start(&flow, &sys).await;
    for attempt in 1..=5 {
        let err = lookup_device_request(&mei, "BBBB-BBBB").await.unwrap_err();
        let expected = if attempt < 5 { "not_found" } else { "locked" };
        assert_eq!(err.reason_class(), expected, "attempt {attempt}");
    }
    let err = approve_device(&mei, approve_as(&grant.user_code, ActAs::Existing(&id)))
        .await
        .unwrap_err();
    assert!(matches!(err, DeviceSigninError::Locked), "{err}");
    // Another person isn't locked out.
    seed_user(&sys, "maker-dev-g2").await;
    lookup_device_request(&user_valence(&sys, "maker-dev-g2"), &grant.user_code)
        .await
        .expect("someone else can still look it up");
}

#[tokio::test]
async fn request_is_decided_once_sad() {
    setup();
    let sys = system_valence("device_once").await;
    let (mei, id, _) = seed_service_user(&sys, "maker-dev-h", "dev-once").await;
    let flow = flow();
    let grant = start(&flow, &sys).await;
    approve_device(&mei, approve_as(&grant.user_code, ActAs::Existing(&id)))
        .await
        .expect("approve");
    let err = approve_device(&mei, approve_as(&grant.user_code, ActAs::Existing(&id)))
        .await
        .unwrap_err();
    assert!(matches!(err, DeviceSigninError::NotFound), "{err}");
    let err = deny_device(&mei, &grant.user_code).await.unwrap_err();
    assert!(matches!(err, DeviceSigninError::NotFound), "{err}");
    poll(&flow, &sys, &grant).await.expect("token once");
}

#[tokio::test]
async fn denied_request_refused_sad() {
    setup();
    let sys = system_valence("device_denied").await;
    let (mei, _, _) = seed_service_user(&sys, "maker-dev-i", "dev-denied").await;
    let flow = flow();
    let grant = start(&flow, &sys).await;
    deny_device(&mei, &grant.user_code).await.expect("deny");
    assert_eq!(
        poll(&flow, &sys, &grant).await.unwrap_err(),
        DevicePollError::AccessDenied
    );
    assert_eq!(
        poll(&flow, &sys, &grant).await.unwrap_err(),
        DevicePollError::InvalidGrant
    );
}

#[tokio::test]
async fn polling_too_fast_slows_down_sad() {
    setup();
    let sys = system_valence("device_slow_down").await;
    let flow = LeptonDeviceFlow::with_poll_interval(Duration::from_secs(60));
    let grant = start(&flow, &sys).await;
    assert_eq!(grant.interval, 60);
    assert_eq!(
        poll(&flow, &sys, &grant).await.unwrap_err(),
        DevicePollError::AuthorizationPending
    );
    assert_eq!(
        poll(&flow, &sys, &grant).await.unwrap_err(),
        DevicePollError::SlowDown
    );
    assert_eq!(
        flow.poll(&sys, "lpdc_nonsense").await.unwrap_err(),
        DevicePollError::InvalidGrant
    );
    let mut wrong_secret = grant.device_code.clone();
    wrong_secret.pop();
    wrong_secret.push(if grant.device_code.ends_with('0') {
        '1'
    } else {
        '0'
    });
    assert_eq!(
        flow.poll(&sys, &wrong_secret).await.unwrap_err(),
        DevicePollError::InvalidGrant
    );
}

#[tokio::test]
async fn move_swaps_the_token_happy() {
    setup();
    let sys = system_valence("device_move").await;
    let (mei, first, _) = seed_service_user(&sys, "maker-dev-j", "dev-first").await;
    let second = lepton_auth::service_users::create_service_user(
        &mei,
        NewServiceUser {
            handle: "dev-second",
            display_name: "Second",
            description: None,
        },
    )
    .await
    .expect("second");
    let second = ServiceUserId::parse(second.id().expect("id").id()).expect("id");
    let flow = flow();
    let grant = start(&flow, &sys).await;
    approve_device(&mei, approve_as(&grant.user_code, ActAs::Existing(&first)))
        .await
        .expect("approve");
    let old = poll(&flow, &sys, &grant).await.expect("first token");
    assert_eq!(acts_as(&sys, &old.access_token).await, Some(first.clone()));

    let moved = move_device(&mei, &device_id(&grant), &second)
        .await
        .expect("move");
    assert!(matches!(moved.status(), SignedInDeviceStatus::IssuePending));
    assert_eq!(
        acts_as(&sys, &old.access_token).await,
        None,
        "old token revoked"
    );

    let new = poll(&flow, &sys, &grant).await.expect("replacement token");
    assert_eq!(acts_as(&sys, &new.access_token).await, Some(second.clone()));
    assert_eq!(new.scopes, *MAGNON_READ);
    assert_eq!(
        poll(&flow, &sys, &grant).await.unwrap_err(),
        DevicePollError::InvalidGrant,
        "the replacement is collected once too"
    );
    assert_eq!(
        list_service_user_devices(&mei, &first)
            .await
            .expect("first")
            .len(),
        0
    );
    assert_eq!(
        list_service_user_devices(&mei, &second)
            .await
            .expect("second")
            .len(),
        1
    );

    // Moving to the same service user, or to someone else's, is refused.
    let err = move_device(&mei, &device_id(&grant), &second)
        .await
        .unwrap_err();
    assert_eq!(err.reason_class(), "profile");
    let (_other, foreign, _) = seed_service_user(&sys, "maker-dev-j2", "dev-foreign").await;
    let err = move_device(&mei, &device_id(&grant), &foreign)
        .await
        .unwrap_err();
    assert!(matches!(err, DeviceSigninError::NotFound), "{err}");
    // And nobody else can move Mei's device.
    seed_user(&sys, "super-dev-j").await;
    let err = move_device(
        &user_valence(&sys, "super-dev-j"),
        &device_id(&grant),
        &first,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, DeviceSigninError::Forbidden), "{err}");
}

#[tokio::test]
async fn rename_keeps_the_device_signed_in_happy() {
    setup();
    let sys = system_valence("device_rename").await;
    let (mei, id, _) = seed_service_user(&sys, "maker-dev-k", "dev-rename").await;
    let flow = flow();
    let grant = start(&flow, &sys).await;
    approve_device(&mei, approve_as(&grant.user_code, ActAs::Existing(&id)))
        .await
        .expect("approve");
    let token = poll(&flow, &sys, &grant).await.expect("token");
    let renamed = rename_device(&mei, &device_id(&grant), "ci runner 3")
        .await
        .expect("rename");
    assert_eq!(renamed.name(), "ci runner 3");
    assert_eq!(renamed.client(), "uf CLI 0.4");
    assert!(acts_as(&sys, &token.access_token).await.is_some());
    let err = rename_device(&mei, &device_id(&grant), "  ")
        .await
        .unwrap_err();
    assert_eq!(err.reason_class(), "profile");
    seed_user(&sys, "maker-dev-k2").await;
    let err = rename_device(
        &user_valence(&sys, "maker-dev-k2"),
        &device_id(&grant),
        "mine",
    )
    .await
    .unwrap_err();
    assert!(matches!(err, DeviceSigninError::NotFound), "{err}");
}

#[tokio::test]
async fn sign_out_revokes_the_token_happy() {
    setup();
    let sys = system_valence("device_sign_out").await;
    let (mei, id, _) = seed_service_user(&sys, "maker-dev-l", "dev-sign-out").await;
    let flow = flow();
    let grant = start(&flow, &sys).await;
    approve_device(&mei, approve_as(&grant.user_code, ActAs::Existing(&id)))
        .await
        .expect("approve");
    let token = poll(&flow, &sys, &grant).await.expect("token");
    sign_out_device(&mei, &device_id(&grant))
        .await
        .expect("sign out");
    assert_eq!(acts_as(&sys, &token.access_token).await, None);
    assert_eq!(
        poll(&flow, &sys, &grant).await.unwrap_err(),
        DevicePollError::InvalidGrant
    );
    assert!(list_my_devices(&mei).await.expect("list").is_empty());
}

#[tokio::test]
async fn deleting_or_pausing_the_service_user_signs_devices_out_sad() {
    setup();
    let sys = system_valence("device_su_gone").await;
    let (mei, id, _) = seed_service_user(&sys, "maker-dev-m", "dev-gone").await;
    let flow = flow();
    let collected = start(&flow, &sys).await;
    approve_device(&mei, approve_as(&collected.user_code, ActAs::Existing(&id)))
        .await
        .expect("approve");
    let token = poll(&flow, &sys, &collected).await.expect("token");
    let waiting = start(&flow, &sys).await;
    approve_device(&mei, approve_as(&waiting.user_code, ActAs::Existing(&id)))
        .await
        .expect("approve second");

    suspend_service_user(&mei, &id).await.expect("pause");
    assert_eq!(
        poll(&flow, &sys, &waiting).await.unwrap_err(),
        DevicePollError::AccessDenied,
        "a paused service user's device can't collect a token"
    );
    lepton_auth::service_users::resume_service_user(&mei, &id)
        .await
        .expect("resume");

    delete_service_user(&mei, &id).await.expect("delete");
    assert_eq!(acts_as(&sys, &token.access_token).await, None);
    assert!(matches!(
        poll(&flow, &sys, &waiting).await.unwrap_err(),
        DevicePollError::AccessDenied | DevicePollError::InvalidGrant
    ));
}

#[tokio::test]
async fn a_service_user_cannot_approve_or_mint_extra_tokens_sad() {
    setup();
    let sys = system_valence("device_svc_actor").await;
    let (mei, id, _) = seed_service_user(&sys, "maker-dev-n", "dev-svc").await;
    let flow = flow();
    let grant = start(&flow, &sys).await;
    let as_service_user = sys.with_actor(id.actor());
    let err = approve_device(
        &as_service_user,
        approve_as(&grant.user_code, ActAs::Existing(&id)),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, DeviceSigninError::NotAUser), "{err}");

    approve_device(&mei, approve_as(&grant.user_code, ActAs::Existing(&id)))
        .await
        .expect("approve");
    poll(&flow, &sys, &grant).await.expect("token");

    // The device collected its token; the service user can't mint another for it, nor widen
    // its scopes.
    let forged = LeptonToken::generate();
    let row = TokenRow::new(
        Some(RecordId::new("user", "maker-dev-n")),
        Some(RecordId::new("service_user_account", id.as_str())),
        "extra".into(),
        forged.hash(),
        Some(scopes_to_json(&TEST_SCOPES)),
        Some(ServiceUserTokenKind::Device),
        Some(device_id(&grant)),
        Utc::now() + chrono::Duration::days(30),
        None,
        None,
        Utc::now(),
    )
    .expect("row");
    TokenRow::upsert(forged.id(), row, &as_service_user, valence::use_!(r"**Test:** Attempted extra **device token** minted by a service user for a device that already holds one; the create rule must refuse it. CI and developers running the suite only."))
        .await
        .expect_err("no second token for a signed-in device");
    assert_eq!(acts_as(&sys, &forged.expose()).await, None);
}
