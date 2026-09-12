use valence::prelude::*;
use valence::privacy_policies::common::SYSTEM_ONLY;

valence_schema! {
    PhoneVerificationToken {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "phone_verification_token",
        version: "0.2.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "One-time token metadata for phone / SMS OTP verification",
        traits: [OneTimeTokenLifecycle],
        ttl: {
            seconds: 1800,
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
            user: {
                r#type: FieldType::Record("user"),
                required: true,
            },
            user_phone: {
                r#type: FieldType::Record("account_phone"),
                required: true,
            }
        ],

        connections: [
            user: {
                table: "user",
                on_delete: Cascade,
                model: "lepton_identity::generated::User",
            },
            user_phone: {
                table: "account_phone",
                on_delete: Cascade,
                model: "lepton_identity::generated::AccountPhone",
            },
        ],
    }
}
