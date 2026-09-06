//! Gate: this workspace must not depend on uf-product (breaks publish order).

use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace_root().join(path)).unwrap_or_else(|e| {
        panic!("read {path}: {e}");
    })
}

#[test]
fn lepton_has_no_uf_product_dep_happy_path() {
    let root = read("Cargo.toml");
    for forbidden in ["uf-product", "uf-integrations", "uf-product-macros"] {
        assert!(
            !root.contains(forbidden),
            "workspace Cargo.toml must not mention {forbidden}"
        );
    }
    let auth = read("lepton-auth/Cargo.toml");
    for forbidden in ["uf-product", "uf-integrations", "uf-product-macros"] {
        assert!(
            !auth.contains(forbidden),
            "lepton-auth Cargo.toml must not mention {forbidden}"
        );
    }
}

#[test]
fn lepton_product_feature_absent_sad() {
    let auth = read("lepton-auth/Cargo.toml");
    assert!(
        !auth.contains("\nproduct =") && !auth.contains("product = ["),
        "lepton-auth must not expose a product feature that pulls uf-product"
    );
    assert!(
        !auth.contains("dep:uf-product"),
        "lepton-auth must not optionally depend on uf-product"
    );
}

#[test]
fn lepton_auth_has_no_orbital_dep_happy_path() {
    let auth = read("lepton-auth/Cargo.toml");
    for forbidden in [
        "orbital-primitives",
        "orbital-core-components",
        "orbital-base-components",
        "orbital-motion",
        "orbital-zone-a",
        "orbital-shell",
        "orbital-theme",
        "orbital-macros",
    ] {
        assert!(
            !auth.contains(forbidden),
            "lepton-auth Cargo.toml must not mention {forbidden} (UI lives in lepton-auth-ui)"
        );
    }
}

#[test]
fn lepton_auth_ui_declares_orbital_sad_if_missing() {
    let ui = read("lepton-auth-ui/Cargo.toml");
    assert!(
        ui.contains("orbital-core-components"),
        "lepton-auth-ui must depend on orbital-core-components"
    );
}
