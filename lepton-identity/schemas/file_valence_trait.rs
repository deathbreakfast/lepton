// Shared Valence File trait — metadata for uploadable objects.
// Canonical definition lives in Meson; this file is vendored for local codegen.
// Keep uploaded_by → user typed hop for lepton-identity User navigation.

use valence::prelude::*;

valence_trait_schema! {
    File {
        repository: "https://github.com/unified-field-dev/lepton",
        fields: [
            file_name: { r#type: FieldType::String, required: true },
            file_extension: { r#type: FieldType::String, required: true },
            mime_type: { r#type: FieldType::String, required: true },
            size_bytes: { r#type: FieldType::Integer, required: true },
            storage_path: { r#type: FieldType::String, required: true },
            file_status: {
                r#type: FieldType::Enum(&[
                    "available", "pending_virus_scan", "virus_scan_complete", "quarantined",
                ]),
                required: true,
            },
            uploaded_by: { r#type: FieldType::Record("user"), required: true },
            uploaded_at: { r#type: FieldType::DateTime, required: true },
        ],
        connections: [
            uploaded_by: {
                table: "user",
                cardinality: HasOne,
                required: true,
                on_delete: Cascade,
                model: "crate::generated::User",
            },
        ],
    }
}
