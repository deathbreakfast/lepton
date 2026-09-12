#[allow(unused_imports)]
use crate::side_effects::clear_account_primary_on_membership_delete::ClearAccountPrimaryOnMembershipDelete;
use valence::prelude::*;
use valence::privacy_policies::common::{AUTHENTICATED, SYSTEM_ONLY};
use valence::privacy_policies::owner::OWNER_BY_USER_FIELD;

valence_schema! {
    AccountMembership {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "account_membership",
        version: "0.2.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Links a user (persona) to an account with a role",

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
                // Owner may leave / cascade when their Account delete runs as OWNER_BY_USER_FIELD.
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
            account: {
                r#type: FieldType::Record("account"),
                required: true,
            },
            user: {
                r#type: FieldType::Record("user"),
                required: true,
            },
            role: {
                r#type: FieldType::Enum(&["owner", "admin", "super_admin"]),
                required: true,
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
            account: {
                table: "account",
                on_delete: Cascade,
                model: "crate::generated::Account",
            },
            user: {
                table: "user",
                on_delete: Cascade,
                model: "crate::generated::User",
            },
        ],

        side_effects: [ClearAccountPrimaryOnMembershipDelete],
    }
}
