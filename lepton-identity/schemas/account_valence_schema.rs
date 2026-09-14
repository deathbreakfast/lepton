use valence::prelude::*;
use valence::privacy_policies::common::{PUBLIC_READ, SYSTEM_ONLY};
use valence::privacy_policies::owner::OWNER_BY_USER_FIELD;

valence_schema! {
    Account {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "account",
        version: "0.5.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Account — plan, status, and contacts for a legal identity (1:1 with founding user)",

        privacy: {
            gdpr_compliant: true,
        },

        policies: {
            // Owner-only entity read so AccountEmail (defer_to_edge: account) cannot
            // be enumerated by arbitrary authenticated users. Public display names
            // live on UserProfile, not Account.
            read: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD, SYSTEM_ONLY],
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
                allow: [OWNER_BY_USER_FIELD, SYSTEM_ONLY],
                block: [],
                always_block: [],
            },
            delete: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD, SYSTEM_ONLY],
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
            name: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(255)],
                policies: {
                    read: { allow: [PUBLIC_READ] },
                },
            },
            user: {
                r#type: FieldType::Record("user"),
                required: true,
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD, SYSTEM_ONLY] },
                },
            },
            plan: {
                r#type: FieldType::Enum(&["free", "starter", "professional", "enterprise"]),
                required: false,
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD] },
                },
            },
            status: {
                r#type: FieldType::Enum(&["active", "suspended", "cancelled"]),
                required: false,
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD] },
                },
            },
            primary_email: {
                r#type: FieldType::Record("account_email"),
                required: false,
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD] },
                },
            },
            primary_phone: {
                r#type: FieldType::Record("account_phone"),
                required: false,
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD] },
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
            user: {
                table: "user",
                cardinality: HasOne,
                required: true,
                on_delete: Restrict,
                model: "crate::generated::User",
            },
            memberships: {
                table: "account_membership",
                cardinality: HasMany,
                reverse_field: "account",
                on_delete: Cascade,
                model: "crate::generated::AccountMembership",
            },
            emails: {
                table: "account_email",
                cardinality: HasMany,
                reverse_field: "account",
                on_delete: Cascade,
                model: "crate::generated::AccountEmail",
            },
            phones: {
                table: "account_phone",
                cardinality: HasMany,
                reverse_field: "account",
                on_delete: Cascade,
                model: "crate::generated::AccountPhone",
            },
            primary_email: {
                table: "account_email",
                cardinality: HasOne,
                required: false,
                on_delete: Restrict,
                model: "crate::generated::AccountEmail",
            },
            primary_phone: {
                table: "account_phone",
                cardinality: HasOne,
                required: false,
                on_delete: Restrict,
                model: "crate::generated::AccountPhone",
            },
        ],
    }
}
