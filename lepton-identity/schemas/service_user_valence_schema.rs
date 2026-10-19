use valence::prelude::*;
use valence::privacy_policies::owner::OWNER_BY_USER_FIELD;

use crate::service_users::{SERVICE_USER_CREATE_GATE, SERVICE_USER_IDENTITY_IMMUTABLE, SERVICE_USER_MANAGE_ANY};

valence_schema! {
    ServiceUserAccount {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "service_user_account",
        version: "0.1.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Service user owned by a user; acts in Valence as Actor::ServiceUser `svc:<id>`",

        privacy: {
            gdpr_compliant: true,
        },

        // Owners manage their own service users; the host's ServiceUserGate decides who may
        // create service users and who may manage any service user. Service user actors,
        // registered or built-in, match none of these rules, so a service user never manages
        // itself.
        policies: {
            read: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD, SERVICE_USER_MANAGE_ANY],
                block: [],
                always_block: [],
            },
            create: {
                always_allow: [],
                allow: [SERVICE_USER_CREATE_GATE],
                block: [],
                always_block: [],
            },
            update: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD, SERVICE_USER_MANAGE_ANY],
                block: [],
                always_block: [SERVICE_USER_IDENTITY_IMMUTABLE],
            },
            delete: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD, SERVICE_USER_MANAGE_ANY],
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
            // Owning user. Optional at the column level so a team owner can be
            // added later without a nullability change; SERVICE_USER_CREATE_GATE requires it.
            user: {
                r#type: FieldType::Record("user"),
                required: false,
            },
            owner_kind: {
                r#type: FieldType::Enum(&["user"]),
                required: true,
            },
            created_by: {
                r#type: FieldType::Record("user"),
                required: false,
            },
            handle: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(32)],
            },
            handle_key: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(32)],
            },
            display_name: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(80)],
            },
            description: {
                r#type: FieldType::String,
                required: false,
                validations: [Validator::MaxLength(500)],
            },
            status: {
                r#type: FieldType::Enum(&["active", "suspended"]),
                required: true,
            },
            suspended_at: {
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
                cardinality: HasOne,
                required: false,
                on_delete: Cascade,
                model: "crate::generated::User",
            },
            created_by: {
                table: "user",
                cardinality: HasOne,
                required: false,
                on_delete: SetNull,
                model: "crate::generated::User",
            },
        ],
    }
}
