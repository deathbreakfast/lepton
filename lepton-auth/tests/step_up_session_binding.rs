//! TM-3: logout and password-change clear the sudo window (source inventory).

#![allow(clippy::expect_used)]

#[test]
fn logout_clears_step_up_window_happy() {
    let logout = include_str!("../src/actions/logout.rs");
    assert!(
        logout.contains("clear_step_up_window"),
        "logout must drop the TOTP sudo window (TM-3)"
    );
}

#[test]
fn password_change_clears_step_up_window_happy() {
    let account = include_str!("../src/actions/account.rs");
    assert!(
        account.contains("clear_step_up_window"),
        "change_password must drop the TOTP sudo window after a credential change (TM-3)"
    );
    assert!(
        account.contains("ChangePassword") || account.contains("change_password"),
        "expected change_password action in account.rs"
    );
}
