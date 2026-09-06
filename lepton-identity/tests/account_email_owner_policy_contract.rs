//! AccountEmail privacy contract: address read is owner-deferred, not AUTHENTICATED-only.
//!
//! Schema source is the policy of record for codegen; this asserts the L5 remediation
//! shape (SYSTEM_ONLY always_allow + defer_to_edge account) without a full Valence host.

#![allow(clippy::expect_used)]

fn account_email_schema_src() -> &'static str {
    include_str!("../schemas/account_email_valence_schema.rs")
}

#[test]
fn account_email_entity_read_defers_to_account_owner_happy() {
    let src = account_email_schema_src();
    assert!(
        src.contains("defer_to_edge: \"account\""),
        "entity/field read must defer to Account owner edge"
    );
    assert!(
        src.contains("SYSTEM_ONLY"),
        "System always_allow must remain for login/signup paths"
    );
    assert!(
        !src.contains("AUTHENTICATED"),
        "AccountEmail must not grant AUTHENTICATED-only address/entity read"
    );
}

#[test]
fn account_email_address_field_read_is_not_authenticated_only_sad() {
    let src = account_email_schema_src();
    // Field-level address policy block must keep the same owner gate.
    let address_idx = src
        .find("address:")
        .expect("address field present in AccountEmail schema");
    let address_block = &src[address_idx..];
    let policies_idx = address_block
        .find("policies:")
        .expect("address field policies");
    let policy_snip =
        &address_block[policies_idx..policies_idx + 280.min(address_block.len() - policies_idx)];
    assert!(
        policy_snip.contains("defer_to_edge: \"account\""),
        "address read must defer_to_edge account, got: {policy_snip}"
    );
    assert!(
        policy_snip.contains("SYSTEM_ONLY"),
        "address read must keep SYSTEM_ONLY always_allow"
    );
    assert!(
        !policy_snip.contains("AUTHENTICATED"),
        "address read must not be AUTHENTICATED-only"
    );
}
