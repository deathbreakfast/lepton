use valence::prelude::*;
use valence::privacy_policies::common::{AUTHENTICATED, SYSTEM_ONLY};

valence_schema! {
    AccountPhone {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "account_phone",
        version: "0.2.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "E.164 phone number belonging to an account (legal identity), with per-row verification",

        privacy: {
            gdpr_compliant: true,
        },

        policies: {
            read: {
                always_allow: [],
                allow: [AUTHENTICATED, SYSTEM_ONLY],
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
            account: {
                r#type: FieldType::Record("account"),
                required: true,
            },
            e164: {
                r#type: FieldType::String,
                required: true,
                unique: true,
                validations: [Validator::Phone],
                policies: {
                    read: { allow: [AUTHENTICATED, SYSTEM_ONLY] },
                },
            },
            verified_at: {
                r#type: FieldType::DateTime,
                required: false,
                policies: {
                    read: { allow: [AUTHENTICATED, SYSTEM_ONLY] },
                },
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
            account: {
                table: "account",
                cardinality: HasOne,
                on_delete: Cascade,
                model: "crate::generated::Account",
            },
        ],
    }
}
