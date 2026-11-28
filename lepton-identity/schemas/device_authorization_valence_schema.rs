use valence::prelude::*;
use valence::privacy_policies::common::SYSTEM_ONLY;
use valence::privacy_policies::owner::OWNER_BY_USER_FIELD;

use crate::device_signin::{DEVICE_AUTH_DECIDE, DEVICE_AUTH_PENDING_READ};

valence_schema! {
    DeviceAuthorization {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "device_authorization",
        version: "0.1.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "A device's pending sign-in (RFC 8628): the device code hash, the short user code, and what the device asked for. Lives at most 10 minutes",

        privacy: {
            gdpr_compliant: true,
        },

        // The device side runs before anyone signs in, so start and poll use the host's
        // System lookup handle, the same narrow exception as OAuth pending state. A signed-in
        // person may read a pending request (they hold its user code) and approve or deny it
        // once; after that only the approver reads it.
        policies: {
            read: {
                always_allow: [],
                allow: [SYSTEM_ONLY, DEVICE_AUTH_PENDING_READ, OWNER_BY_USER_FIELD],
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
                allow: [SYSTEM_ONLY, DEVICE_AUTH_DECIDE],
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
            // Also the id of the device record an approval creates.
            id: {
                r#type: FieldType::String,
                primary_key: true,
                required: true,
            },
            // Lowercase hex SHA-256 of the device code's secret half.
            device_code_hash: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(64)],
            },
            // `XXXX-XXXX`, what the person types on the approval page.
            user_code: {
                r#type: FieldType::String,
                required: true,
                unique: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(9)],
            },
            device_name: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(80)],
            },
            // The app that asked, such as `uf CLI 0.4`.
            client: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(80)],
            },
            // The address the request came from, shown on the approval page.
            asked_from: {
                r#type: FieldType::String,
                required: false,
                validations: [Validator::MaxLength(255)],
            },
            user_agent: {
                r#type: FieldType::String,
                required: false,
                validations: [Validator::MaxLength(255)],
            },
            // The API scopes the device asked for.
            scopes: {
                r#type: FieldType::Json,
                required: false,
            },
            status: {
                r#type: FieldType::Enum(&["pending", "approved", "denied"]),
                required: true,
            },
            // The person who approved or denied it.
            user: {
                r#type: FieldType::Record("user"),
                required: false,
            },
            expires_at: {
                r#type: FieldType::DateTime,
                required: true,
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
        ],
    }
}
