use valence::prelude::*;
use valence::privacy_policies::common::SYSTEM_ONLY;

valence_schema! {
    TotpFactor {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "totp_factor",
        version: "0.1.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Sealed TOTP shared secret and confirmation state for a user",

        privacy: {
            gdpr_compliant: true,
        },

        policies: {
            read: {
                always_allow: [],
                allow: [SYSTEM_ONLY],
                block: [],
                always_block: [],
            },
            create: {
                always_allow: [],
                allow: [SYSTEM_ONLY],
                block: [],
                always_block: [],
            },
            update: {
                always_allow: [],
                allow: [SYSTEM_ONLY],
                block: [],
                always_block: [],
            },
            delete: {
                always_allow: [],
                allow: [SYSTEM_ONLY],
                block: [],
                always_block: [],
            },
        },

        fields: [
            id: {
                r#type: FieldType::String,
                primary_key: true,
                required: true,
            },
            user: {
                r#type: FieldType::Record("user"),
                required: true,
            },
            secret_sealed: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty],
                policies: {
                    read: { allow: [SYSTEM_ONLY] },
                },
            },
            last_used_step: {
                r#type: FieldType::Integer,
                required: false,
            },
            failed_attempts: {
                r#type: FieldType::Integer,
                required: false,
            },
            locked_until: {
                r#type: FieldType::DateTime,
                required: false,
            },
            confirmed_at: {
                r#type: FieldType::DateTime,
                required: false,
            },
            enabled_at: {
                r#type: FieldType::DateTime,
                required: false,
            },
            created_at: {
                r#type: FieldType::DateTime,
                required: true,
            },
            updated_at: {
                r#type: FieldType::DateTime,
                required: true,
            }
        ],

        connections: [
            user: {
                table: "user",
                on_delete: Cascade,
                model: "lepton_identity::generated::User",
            },
        ],
    }
}
