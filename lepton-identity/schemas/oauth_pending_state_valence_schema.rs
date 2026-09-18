use valence::prelude::*;
use valence::privacy_policies::common::SYSTEM_ONLY;

valence_schema! {
    OAuthPendingState {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "oauth_pending_state",
        version: "0.1.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Short-lived OAuth CSRF + PKCE pending state (begin → callback)",

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
            provider: {
                r#type: FieldType::Enum(&["google", "github"]),
                required: true,
            },
            intent: {
                r#type: FieldType::Enum(&["login", "signup", "link"]),
                required: true,
            },
            link_user: {
                r#type: FieldType::String,
                required: false,
            },
            pkce_verifier: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty],
                policies: {
                    read: { allow: [SYSTEM_ONLY] },
                },
            },
            referer: {
                r#type: FieldType::String,
                required: false,
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
    }
}
