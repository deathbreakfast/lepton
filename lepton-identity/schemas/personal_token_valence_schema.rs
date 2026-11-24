use valence::prelude::*;
use valence::privacy_policies::owner::OWNER_BY_USER_FIELD;

use crate::tokens::PERSONAL_TOKEN_IMMUTABLE;

valence_schema! {
    PersonalToken {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "personal_token",
        version: "0.1.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Personal access token that acts as its person, with API scopes; stores only a hash of the secret",

        privacy: {
            gdpr_compliant: true,
        },

        // Only the person who owns a token sees or touches it. No manage-any rule: a person's
        // tokens act as them, so nobody else lists or revokes them. Service user actors match
        // nothing here.
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
                always_block: [PERSONAL_TOKEN_IMMUTABLE],
            },
            delete: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD],
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
            // The person the token acts as.
            user: {
                r#type: FieldType::Record("user"),
                required: true,
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
            // The APIs the token may call: a JSON array of `api:action` strings.
            scopes: {
                r#type: FieldType::Json,
                required: true,
            },
            expires_at: {
                r#type: FieldType::DateTime,
                required: true,
            },
            last_used_at: {
                r#type: FieldType::DateTime,
                required: false,
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
                on_delete: Cascade,
                model: "crate::generated::User",
            },
        ],
    }
}
