use valence::prelude::*;
use valence::privacy_policies::common::SYSTEM_ONLY;

valence_schema! {
    TotpRecoveryCode {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "totp_recovery_code",
        version: "0.1.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Hashed one-time TOTP recovery codes for a user",

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
            code_hash: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty],
                policies: {
                    read: { allow: [SYSTEM_ONLY] },
                },
            },
            used_at: {
                r#type: FieldType::DateTime,
                required: false,
            },
            created_at: {
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
