use valence::prelude::*;
use valence::privacy_policies::common::SYSTEM_ONLY;

valence_schema! {
    AccountEmail {
        table: "account_email",
        version: "0.4.1",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Email address belonging to an account (legal identity), with per-row verification",

        privacy: {
            gdpr_compliant: true,
        },

        policies: {
            // Owner-only via Account.user (OWNER_BY_USER_FIELD on Account). System
            // always_allow covers login/signup/reset that mint System Valence.
            read: {
                always_allow: [SYSTEM_ONLY],
                defer_to_edge: "account",
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
            address: {
                r#type: FieldType::String,
                required: true,
                unique: true,
                validations: [Validator::Email],
                policies: {
                    // Same owner gate as the entity (via Account.user).
                    read: {
                        always_allow: [SYSTEM_ONLY],
                        defer_to_edge: "account",
                    },
                },
            },
            verified_at: {
                r#type: FieldType::DateTime,
                required: false,
                policies: {
                    read: {
                        always_allow: [SYSTEM_ONLY],
                        defer_to_edge: "account",
                    },
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
