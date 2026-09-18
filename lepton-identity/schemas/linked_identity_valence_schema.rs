use valence::prelude::*;
use valence::privacy_policies::common::{AUTHENTICATED, SYSTEM_ONLY};
use valence::privacy_policies::owner::OWNER_BY_USER_FIELD;

valence_schema! {
    LinkedIdentity {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "linked_identity",
        version: "0.1.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "OAuth / external identity linked to a user (provider + subject)",

        privacy: {
            gdpr_compliant: true,
        },

        policies: {
            read: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD, AUTHENTICATED],
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
            provider: {
                r#type: FieldType::Enum(&["google", "github"]),
                required: true,
            },
            provider_subject: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty],
            },
            email_hint: {
                r#type: FieldType::String,
                required: false,
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD] },
                },
            },
            linked_at: {
                r#type: FieldType::DateTime,
                required: true,
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
                cardinality: HasOne,
                on_delete: Cascade,
                model: "crate::generated::User",
            },
        ],
    }
}
