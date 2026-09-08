//! Runtime trait registration for identity schemas.
//!
//! Model schemas are registered by codegen (`OUT_DIR/generated_models.rs`). Including
//! `*_valence_schema.rs` here would submit a second [`valence::SchemaMetadataInit`]
//! without merged trait fields and panic (or silently overwrite) in
//! [`valence::SchemaRegistry`].

mod file_trait {
    include!("../schemas/file_valence_trait.rs");
}
