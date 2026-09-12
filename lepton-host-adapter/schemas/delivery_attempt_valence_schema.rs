use valence::prelude::*;
use valence::privacy_policies::common::SYSTEM_ONLY;

valence_schema! {
    DeliveryAttempt {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "delivery_attempt",
        version: "0.1.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Ops log of email/SMS delivery attempts (provider message ids, outcomes); not a token row",
        ttl: {
            seconds: 604800,
            mode: "backend_capability",
        },

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
            channel: {
                r#type: FieldType::Enum(&["email", "sms"]),
                required: true,
            },
            intent_kind: {
                r#type: FieldType::String,
                required: true,
            },
            intent_id: {
                r#type: FieldType::String,
                required: true,
            },
            provider: {
                r#type: FieldType::String,
                required: false,
            },
            message_id: {
                r#type: FieldType::String,
                required: false,
            },
            outcome: {
                r#type: FieldType::Enum(&["success", "transient", "permanent"]),
                required: true,
            },
            reason_class: {
                r#type: FieldType::String,
                required: false,
            },
            boson_job_id: {
                r#type: FieldType::String,
                required: false,
            },
            created_at: {
                r#type: FieldType::DateTime,
                required: true,
            }
        ],
    }
}
