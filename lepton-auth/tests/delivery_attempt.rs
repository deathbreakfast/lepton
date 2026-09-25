//! `DeliveryAttempt` persistence + durable email task drain (boson-delivery).

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::sync::Arc;

use boson_backend_mem::MemQueueBackend;
use boson_runtime::{configure, Boson};
use boson_valence_identity::{
    router_config_reject_external_system, ValenceExecutionContextFactory,
};
use lepton_auth::delivery::{
    enqueue_email, record_delivery_attempt, DeliveryAttemptInput, DeliveryRuntime,
    EmailDeliveryIntent,
};
use lepton_host_adapter::generated::{
    DeliveryAttempt, DeliveryAttemptChannel, DeliveryAttemptOutcome,
};
use lepton_smtp::{EmailEnvelope, EmailServiceBuilder};
use support::system_valence;
use valence::{
    register_backend_logical_names_slices, router_key, Actor, ActorTrust, DatabaseBackend,
    DatabaseRouter, InMemoryBackend, RegisterBackendLogicalNamesOptions, RouterValenceFactory,
    MEM_ENGINE_ID,
};

#[tokio::test]
async fn delivery_attempt_persists_message_id_happy() {
    let valence = system_valence("delivery_attempt_write").await;
    let saved = record_delivery_attempt(
        &valence,
        DeliveryAttemptInput {
            channel: DeliveryAttemptChannel::Email,
            intent_kind: "signup_verify".into(),
            intent_id: "tok-abc".into(),
            provider: Some("twilio".into()),
            message_id: Some("msg-123".into()),
            outcome: DeliveryAttemptOutcome::Success,
            reason_class: None,
            boson_job_id: Some("job-1".into()),
        },
    )
    .await
    .expect("write");
    assert_eq!(saved.message_id().map(String::as_str), Some("msg-123"));
    assert_eq!(saved.intent_id(), "tok-abc");
    assert_eq!(*saved.outcome(), DeliveryAttemptOutcome::Success);
}

#[tokio::test]
async fn delivery_attempt_omits_body_sad() {
    let valence = system_valence("delivery_attempt_fields").await;
    let saved = record_delivery_attempt(
        &valence,
        DeliveryAttemptInput {
            channel: DeliveryAttemptChannel::Sms,
            intent_kind: "sms_otp".into(),
            intent_id: "chal-1".into(),
            provider: Some("noop".into()),
            message_id: None,
            outcome: DeliveryAttemptOutcome::Permanent,
            reason_class: Some("rejected".into()),
            boson_job_id: None,
        },
    )
    .await
    .expect("write");
    assert!(saved.message_id().is_none());
    assert_eq!(saved.reason_class().map(String::as_str), Some("rejected"));
    assert_eq!(*saved.channel(), DeliveryAttemptChannel::Sms);
}

#[tokio::test]
async fn email_task_noop_success_writes_attempt_happy() {
    let email = EmailServiceBuilder::new().noop().build().expect("noop");
    DeliveryRuntime::install(DeliveryRuntime::builder().email(email).build()).expect("install");

    let backend: Arc<dyn DatabaseBackend> = Arc::new(InMemoryBackend::new());
    let mut router = DatabaseRouter::new();
    register_backend_logical_names_slices(
        &mut router,
        backend,
        &[&["default"]],
        RegisterBackendLogicalNamesOptions::default(),
    );
    let router = Arc::new(router);
    let default_key = router_key("default", MEM_ENGINE_ID);
    let mut factory_cfg = router_config_reject_external_system(&default_key);
    factory_cfg.actor_trust = ActorTrust::Internal;
    let valence_factory = RouterValenceFactory::arc(Arc::clone(&router), factory_cfg);
    let exec_factory = ValenceExecutionContextFactory::new(valence_factory);

    let (boson, manual) = Boson::builder()
        .queue_backend(Arc::new(MemQueueBackend::new()))
        .execution_context_factory(exec_factory)
        .auto_registry()
        .without_worker()
        .build_manual()
        .expect("boson");
    configure(boson);

    let job_id = enqueue_email(EmailDeliveryIntent {
        intent_kind: "signup_verify".into(),
        intent_id: "tok-drain-1".into(),
        envelope: EmailEnvelope {
            to: "user@example.test".into(),
            subject: "t".into(),
            text_body: "body".into(),
            html_body: "<p>body</p>".into(),
        },
    })
    .await
    .expect("enqueue");
    assert!(!job_id.is_empty());

    let ran = manual.try_run_next().await;
    assert!(ran, "expected job to run");

    let valence = valence::Valence::builder()
        .database_router(router)
        .default_backend_key(default_key)
        .with_actor(Actor::System {
            operation: "assert".into(),
        })
        .build()
        .expect("valence");

    let rows = DeliveryAttempt::query(&valence, valence::use_!(r"**Test:** Fixture **Delivery Attempt** list for `tests` so the suite can arrange and assert persistence behavior. CI and developers running the suite only.")).await.expect("query");
    let hit = rows
        .iter()
        .find(|r| r.intent_id() == "tok-drain-1")
        .expect("attempt row");
    assert_eq!(*hit.outcome(), DeliveryAttemptOutcome::Success);
    assert_eq!(hit.provider().map(String::as_str), Some("noop"));
}
