use valence::prelude::*;
use valence::privacy_policies::owner::OWNER_BY_USER_FIELD;

use crate::device_signin::{
    SIGNED_IN_DEVICE_CREATE, SIGNED_IN_DEVICE_IMMUTABLE, SIGNED_IN_DEVICE_SELF,
    SIGNED_IN_DEVICE_SELF_TOUCH,
};
use crate::service_users::SERVICE_USER_MANAGE_ANY;

valence_schema! {
    SignedInDevice {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "signed_in_device",
        version: "0.1.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "A device signed in as a service user its owner picked, with the service user token it was issued",

        privacy: {
            gdpr_compliant: true,
        },

        // The owner who approved the device manages it; manage-any users can see and remove
        // it. The service user the device acts as reads its own device records and records its
        // token on them when the device collects one (SIGNED_IN_DEVICE_SELF_TOUCH).
        policies: {
            read: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD, SERVICE_USER_MANAGE_ANY, SIGNED_IN_DEVICE_SELF],
                block: [],
                always_block: [],
            },
            create: {
                always_allow: [],
                allow: [SIGNED_IN_DEVICE_CREATE],
                block: [],
                always_block: [],
            },
            update: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD, SIGNED_IN_DEVICE_SELF_TOUCH],
                block: [],
                always_block: [SIGNED_IN_DEVICE_IMMUTABLE],
            },
            delete: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD, SERVICE_USER_MANAGE_ANY],
                block: [],
                always_block: [],
            },
        },

        fields: [
            // The id of the device authorization it came from.
            id: {
                r#type: FieldType::String,
                primary_key: true,
                required: true,
            },
            // The person who signed the device in and owns its service user.
            user: {
                r#type: FieldType::Record("user"),
                required: false,
            },
            // The service user the device acts as.
            service_user: {
                r#type: FieldType::Record("service_user_account"),
                required: false,
            },
            // The owner's name for the device.
            name: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(80)],
            },
            client: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(80)],
            },
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
            // Lowercase hex SHA-256 of the device code's secret half; the device presents the
            // code to collect a token.
            device_code_hash: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(64)],
            },
            // The API scopes its tokens carry.
            scopes: {
                r#type: FieldType::Json,
                required: false,
            },
            // 30 or 90.
            lifetime_days: {
                r#type: FieldType::Integer,
                required: true,
            },
            // `issue_pending` until the device collects its token.
            status: {
                r#type: FieldType::Enum(&["issue_pending", "signed_in"]),
                required: true,
            },
            // Row id of its current service user token.
            token: {
                r#type: FieldType::String,
                required: false,
                validations: [Validator::MaxLength(64)],
            },
            signed_in_at: {
                r#type: FieldType::DateTime,
                required: true,
            },
            last_seen_at: {
                r#type: FieldType::DateTime,
                required: false,
            },
            signed_in_until: {
                r#type: FieldType::DateTime,
                required: false,
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
