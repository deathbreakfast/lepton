//! AccountEmail privacy contract: entity read is owner-deferred, not AUTHENTICATED.
//!
//! Address has no field-level read policy — Valence sync field filtering does not
//! honor `defer_to_edge`, so entity defer_to_edge + SYSTEM_ONLY is the owner gate.

#![allow(clippy::expect_used)]

fn account_email_schema_src() -> &'static str {
    include_str!("../schemas/account_email_valence_schema.rs")
}

#[test]
fn account_email_entity_read_defers_to_account_owner_happy() {
    let src = account_email_schema_src();
    assert!(
        src.contains("defer_to_edge: \"account\""),
        "entity read must defer to Account owner edge"
    );
    assert!(
        src.contains("SYSTEM_ONLY"),
        "System always_allow must remain for login/signup paths"
    );
    assert!(
        !src.contains("AUTHENTICATED"),
        "AccountEmail must not grant AUTHENTICATED entity/address read"
    );
}

#[test]
fn account_email_address_has_no_field_read_policy_sad() {
    let src = account_email_schema_src();
    let address_idx = src
        .find("address:")
        .expect("address field present in AccountEmail schema");
    let address_block = &src[address_idx..];
    let next_field = address_block
        .find("verified_at:")
        .expect("verified_at follows address");
    let address_only = &address_block[..next_field];
    assert!(
        !address_only.contains("policies:"),
        "address must not carry a field-level read policy (sync filter ignores defer); got: {address_only}"
    );
    assert!(
        !address_only.contains("AUTHENTICATED"),
        "address must not be AUTHENTICATED at field level"
    );
}
