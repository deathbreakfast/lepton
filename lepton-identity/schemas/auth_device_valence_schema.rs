use valence::prelude::*;
use valence::privacy_policies::common::{AUTHENTICATED, SYSTEM_ONLY};
use valence::privacy_policies::owner::OWNER_BY_USER_FIELD;

valence_schema! {
    AuthDevice {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "auth_device",
        version: "0.3.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Trusted browser or WebAuthn device registered for a user",

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
            kind: {
                r#type: FieldType::Enum(&["trusted_browser", "webauthn"]),
                required: true,
            },
            label: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(255)],
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD] },
                },
            },
            confirm_secret_hash: {
                r#type: FieldType::String,
                required: false,
                policies: {
                    read: { allow: [SYSTEM_ONLY] },
                },
            },
            binding_secret_hash: {
                r#type: FieldType::String,
                required: false,
                policies: {
                    read: { allow: [SYSTEM_ONLY] },
                },
            },
            credential_id: {
                r#type: FieldType::String,
                required: false,
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD] },
                },
            },
            passkey_json: {
                r#type: FieldType::Json,
                required: false,
                policies: {
                    read: { allow: [SYSTEM_ONLY] },
                },
            },
            sign_count: {
                r#type: FieldType::Integer,
                required: false,
                default: 0,
            },
            transports: {
                r#type: FieldType::String,
                required: false,
            },
            trusted_at: {
                r#type: FieldType::DateTime,
                required: false,
            },
            last_seen_at: {
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
