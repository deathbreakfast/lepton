use valence::prelude::*;
use valence::privacy_policies::common::{AUTHENTICATED, SYSTEM_ONLY};
use valence::privacy_policies::owner::OWNER_BY_USER_FIELD;

valence_schema! {
    ProfilePhoto {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "profile_photo",
        version: "0.1.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Profile photo backed by the File trait — stores image metadata and links to a user profile",

        traits: [File],

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
                allow: [SYSTEM_ONLY],
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
                allow: [OWNER_BY_USER_FIELD, SYSTEM_ONLY],
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
            profile: {
                r#type: FieldType::Record("user_profile"),
                required: true,
            },
            width: {
                r#type: FieldType::Integer,
                required: false,
            },
            height: {
                r#type: FieldType::Integer,
                required: false,
            },
        ],

        connections: [
            profile: {
                table: "user_profile",
                cardinality: HasOne,
                required: true,
                on_delete: Cascade,
                model: "crate::generated::UserProfile",
            },
        ],
    }
}
