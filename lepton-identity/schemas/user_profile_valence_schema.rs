use valence::prelude::*;
use valence::privacy_policies::common::{AUTHENTICATED, PUBLIC_READ, SYSTEM_ONLY};
use valence::privacy_policies::owner::OWNER_BY_USER_FIELD;

use crate::privacy_policies::{CHAT_HANDLE_SHARED, CONTACT_EMAIL_SHARED, CONTACT_PHONE_SHARED};

valence_schema! {
    UserProfile {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "user_profile",
        version: "0.2.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Profile names and contact details for a User login (legal_name private; display_name public; contact fields owner-only unless shared with signed-in users)",

        privacy: {
            gdpr_compliant: true,
        },

        policies: {
            read: {
                always_allow: [],
                allow: [AUTHENTICATED],
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
                allow: [OWNER_BY_USER_FIELD, SYSTEM_ONLY],
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
            legal_name: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(255)],
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD] },
                },
            },
            display_name: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(255)],
                policies: {
                    read: { allow: [PUBLIC_READ] },
                },
            },
            created_at: {
                r#type: FieldType::DateTime,
                required: true,
            },
            updated_at: {
                r#type: FieldType::DateTime,
                required: true,
            },
            active_photo: {
                r#type: FieldType::Record("profile_photo"),
                required: false,
            },
            // Opt-in contact details. Each value has its own share setting: empty or "owner"
            // keeps it owner-only, "signed_in" lets any signed-in user read it.
            contact_email: {
                r#type: FieldType::String,
                required: false,
                validations: [Validator::Email, Validator::MaxLength(254)],
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD, CONTACT_EMAIL_SHARED] },
                },
            },
            contact_email_share: {
                r#type: FieldType::Enum(&["owner", "signed_in"]),
                required: false,
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD] },
                },
            },
            contact_phone: {
                r#type: FieldType::String,
                required: false,
                validations: [Validator::Phone],
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD, CONTACT_PHONE_SHARED] },
                },
            },
            contact_phone_share: {
                r#type: FieldType::Enum(&["owner", "signed_in"]),
                required: false,
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD] },
                },
            },
            chat_handle: {
                r#type: FieldType::String,
                required: false,
                validations: [Validator::MaxLength(64)],
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD, CHAT_HANDLE_SHARED] },
                },
            },
            chat_handle_share: {
                r#type: FieldType::Enum(&["owner", "signed_in"]),
                required: false,
                policies: {
                    read: { allow: [OWNER_BY_USER_FIELD] },
                },
            }
        ],

        connections: [
            user: {
                table: "user",
                on_delete: Cascade,
                model: "crate::generated::User",
            },
            active_photo: {
                table: "profile_photo",
                cardinality: HasOne,
                required: false,
                on_delete: SetNull,
                model: "crate::generated::ProfilePhoto",
            },
            photos: {
                table: "profile_photo",
                cardinality: HasMany,
                reverse_field: "profile",
                on_delete: Cascade,
                model: "crate::generated::ProfilePhoto",
            },
        ],
    }
}
