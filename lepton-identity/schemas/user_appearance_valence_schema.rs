// User appearance Valence schema (1:1 with `user`).

use valence::prelude::*;
use valence::privacy_policies::common::SYSTEM_ONLY;
use valence::privacy_policies::owner::OWNER_BY_USER_FIELD;

valence_schema! {
    UserAppearance {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "user_appearance",
        version: "0.1.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Per-user UI appearance: color mode and brand color preferences",

        privacy: {
            gdpr_compliant: true,
        },

        policies: {
            read: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD],
                block: [],
                always_block: [],
            },
            create: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD],
                block: [],
                always_block: [],
            },
            update: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD],
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
            color_mode: {
                r#type: FieldType::String,
                required: true,
                default: "light",
                validations: [Validator::OneOf(vec!["light".to_string(), "dark".to_string()])],
            },
            brand_source: {
                r#type: FieldType::String,
                required: true,
                default: "product",
                validations: [Validator::OneOf(vec!["product".to_string(), "custom".to_string()])],
            },
            brand_seed_color: {
                r#type: FieldType::String,
                required: false,
                validations: [Validator::Regex(r"^#[0-9A-Fa-f]{6}$".to_string())],
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD] },
                },
            },
            updated_at: {
                r#type: FieldType::DateTime,
                required: true,
            },
        ],

        connections: [
            user: {
                table: "user",
                cardinality: HasOne,
                on_delete: Cascade,
                model: "crate::generated::User",
            },
        ],
    }
}
