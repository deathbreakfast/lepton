use valence::prelude::*;
use valence::privacy_policies::common::SYSTEM_ONLY;
use valence::privacy_policies::owner::OWNER_BY_USER_FIELD;

valence_schema! {
    AuthDeviceCeremony {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "auth_device_ceremony",
        version: "0.1.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Short-lived WebAuthn registration or assertion ceremony state",

        privacy: {
            gdpr_compliant: true,
        },

        policies: {
            read: {
                always_allow: [],
                allow: [SYSTEM_ONLY],
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
            phase: {
                r#type: FieldType::Enum(&["register", "assert"]),
                required: true,
            },
            label: {
                r#type: FieldType::String,
                required: false,
                validations: [Validator::MaxLength(255)],
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD] },
                },
            },
            state_json: {
                r#type: FieldType::Json,
                required: true,
                policies: {
                    read: { allow: [SYSTEM_ONLY] },
                },
            },
            expires_at: {
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
