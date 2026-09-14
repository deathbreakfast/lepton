use valence::prelude::*;
use valence::privacy_policies::common::{AUTHENTICATED, PUBLIC_READ, SYSTEM_ONLY};
use valence::privacy_policies::owner::OWNER_BY_USER_FIELD;

valence_schema! {
    UserProfile {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "user_profile",
        version: "0.1.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Profile names for a User login (legal_name private; display_name public)",

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
