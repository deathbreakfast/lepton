use valence::prelude::*;
use valence::privacy_policies::common::SYSTEM_ONLY;
use valence::privacy_policies::owner::OWNER_BY_USER_FIELD;

use crate::service_users::{
    SERVICE_USER_ACTIVITY_APPEND_ONLY, SERVICE_USER_ACTIVITY_WRITE, SERVICE_USER_MANAGE_ANY,
};

valence_schema! {
    ServiceUserActivity {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "service_user_activity",
        version: "0.1.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Append-only history of a service user: lifecycle changes and token events",

        privacy: {
            gdpr_compliant: true,
        },

        // Rows are written by the lifecycle calls under the caller's own Valence and never
        // change. Delete exists only so the service user's own deletion (and the owner's
        // erasure) can remove its history.
        policies: {
            read: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD, SERVICE_USER_MANAGE_ANY],
                block: [],
                always_block: [],
            },
            create: {
                always_allow: [],
                allow: [SERVICE_USER_ACTIVITY_WRITE],
                block: [],
                always_block: [],
            },
            update: {
                always_allow: [],
                allow: [],
                block: [],
                always_block: [SERVICE_USER_ACTIVITY_APPEND_ONLY],
            },
            delete: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD, SERVICE_USER_MANAGE_ANY, SYSTEM_ONLY],
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
            service_user: {
                r#type: FieldType::Record("service_user_account"),
                required: true,
            },
            // Owner of the service user when the event happened; the owner policy reads it.
            user: {
                r#type: FieldType::Record("user"),
                required: false,
            },
            kind: {
                r#type: FieldType::Enum(&[
                    "created",
                    "updated",
                    "suspended",
                    "resumed",
                    "token_created",
                    "token_revoked",
                    "token_rotated",
                ]),
                required: true,
            },
            // The user who made the change; cleared when that user is erased.
            actor: {
                r#type: FieldType::Record("user"),
                required: false,
            },
            // Short label such as a token name. Never a secret or token text.
            detail: {
                r#type: FieldType::String,
                required: false,
                validations: [Validator::MaxLength(120)],
            },
            occurred_at: {
                r#type: FieldType::DateTime,
                required: true,
            }
        ],
        connections: [
            service_user: {
                table: "service_user_account",
                cardinality: HasOne,
                required: true,
                on_delete: Cascade,
                model: "crate::generated::ServiceUserAccount",
            },
            user: {
                table: "user",
                cardinality: HasOne,
                required: false,
                on_delete: Cascade,
                model: "crate::generated::User",
            },
            actor: {
                table: "user",
                cardinality: HasOne,
                required: false,
                on_delete: SetNull,
                model: "crate::generated::User",
            },
        ],
    }
}
