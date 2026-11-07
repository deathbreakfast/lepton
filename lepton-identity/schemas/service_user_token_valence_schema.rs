use valence::prelude::*;
use valence::privacy_policies::owner::OWNER_BY_USER_FIELD;

use crate::service_users::{
    SERVICE_USER_MANAGE_ANY, SERVICE_USER_TOKEN_CREATE, SERVICE_USER_TOKEN_IMMUTABLE,
};

valence_schema! {
    ServiceUserToken {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "service_user_token",
        version: "0.1.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Personal access token for a service user; stores only a hash of the secret",

        privacy: {
            gdpr_compliant: true,
        },

        // The owner of the service user manages its tokens; users the host's gate grants
        // manage-any can read and revoke. Service user actors match none of these rules, so a
        // token can never mint or revoke tokens.
        policies: {
            read: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD, SERVICE_USER_MANAGE_ANY],
                block: [],
                always_block: [],
            },
            create: {
                always_allow: [],
                allow: [SERVICE_USER_TOKEN_CREATE],
                block: [],
                always_block: [],
            },
            update: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD, SERVICE_USER_MANAGE_ANY],
                block: [],
                always_block: [SERVICE_USER_TOKEN_IMMUTABLE],
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
            // Owner of the service user at creation; the `user` match for owner rules.
            user: {
                r#type: FieldType::Record("user"),
                required: false,
            },
            // The service user this token acts as.
            service_user: {
                r#type: FieldType::Record("service_user_account"),
                required: false,
            },
            label: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(80)],
            },
            // Lowercase hex SHA-256 of the secret half of the token.
            token_hash: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(64)],
            },
            expires_at: {
                r#type: FieldType::DateTime,
                required: true,
            },
            revoked_at: {
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
                cardinality: HasOne,
                required: false,
                on_delete: Cascade,
                model: "crate::generated::User",
            },
            service_user: {
                table: "service_user_account",
                cardinality: HasOne,
                required: false,
                on_delete: Cascade,
                model: "crate::generated::ServiceUserAccount",
            },
        ],
    }
}
