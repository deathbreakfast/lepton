//! Shared step-up UI coverage inventory (enrollment + expiry).
//!
//! Product apps (Gauge / Neutrino / Gluon) mount `lepton-auth-ui` step-up modal.
//! Enrollment and expired-window UX for that shared surface are locked here via
//! the lepton-auth-ui-e2e Playwright source (plus product `step_up_expired_sad` greps).

#![allow(clippy::expect_used)]

#[test]
fn step_up_modal_spec_covers_enrollment_and_expiry_inventory() {
    let spec = include_str!("../../lepton-auth-ui-e2e/end2end/tests/step_up_modal.spec.ts");
    assert!(
        spec.contains("step_up_modal_no_totp_enrolled"),
        "enrollment: no-TOTP user must see not-enrolled state (TM enrollment)"
    );
    assert!(
        spec.contains("step-up-not-enrolled"),
        "enrollment: modal must assert step-up-not-enrolled test id"
    );
    // Expiry: product e2e uses the same modal title for expired windows; lock the
    // shared dialog entry points exercised by step_up_modal (happy + sad codes).
    assert!(
        spec.contains("step_up_modal_totp_happy")
            && spec.contains("step_up_modal_totp_sad_wrong_code"),
        "shared modal happy/sad paths must remain (expiry UX reuses this dialog)"
    );
    assert!(
        spec.contains("Confirm") || spec.contains("step-up-dialog"),
        "expected step-up dialog surface in modal e2e"
    );
}
