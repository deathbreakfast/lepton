use valence::prelude::*;
use valence::privacy_policies::common::{AUTHENTICATED, SYSTEM_ONLY};
use valence::privacy_policies::owner::OWNER_BY_ID;

valence_schema! {
    User {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "user",
        version: "0.3.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "User identity - person or service (login / persona under an Account)",

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
                allow: [OWNER_BY_ID, SYSTEM_ONLY],
                block: [],
                always_block: [],
            },
            delete: {
                always_allow: [],
                allow: [OWNER_BY_ID, SYSTEM_ONLY],
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
            user_type: {
                r#type: FieldType::Enum(&["person", "service", "test"]),
                required: false,
                policies: {
                    read: { allow: [OWNER_BY_ID] },
                },
            },
            password_hash: {
                r#type: FieldType::String,
                required: false,
                policies: {
                    // Owner: change-password / email re-auth via session user_valence.
                    // System: pre-session authenticate, get_user stamp, reset/signup.
                    read: { allow: [OWNER_BY_ID, SYSTEM_ONLY] },
                },
            },
            status: {
                r#type: FieldType::Enum(&["active", "disabled", "pending_verification"]),
                required: false,
                policies: {
                    read: { allow: [OWNER_BY_ID] },
                },
            },
            primary_email: {
                r#type: FieldType::Record("account_email"),
                required: false,
                policies: {
                    read: { allow: [OWNER_BY_ID] },
                },
            },
            primary_phone: {
                r#type: FieldType::Record("account_phone"),
                required: false,
                policies: {
                    read: { allow: [OWNER_BY_ID] },
                },
            },
            confirmed_at: {
                r#type: FieldType::DateTime,
                required: false,
                policies: {
                    read: { allow: [OWNER_BY_ID] },
                },
            },
            id_verified_at: {
                r#type: FieldType::DateTime,
                required: false,
                policies: {
                    read: { allow: [OWNER_BY_ID, SYSTEM_ONLY] },
                },
            },
            last_login_at: {
                r#type: FieldType::DateTime,
                required: false,
                policies: {
                    read: { allow: [OWNER_BY_ID] },
                },
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
            profile: {
                table: "user_profile",
                cardinality: HasMany,
                reverse_field: "user",
                on_delete: Cascade,
                model: "crate::generated::UserProfile",
            },
            memberships: {
                table: "account_membership",
                cardinality: HasMany,
                reverse_field: "user",
                on_delete: Cascade,
                model: "crate::generated::AccountMembership",
            },
            linked_identities: {
                table: "linked_identity",
                cardinality: HasMany,
                reverse_field: "user",
                on_delete: Cascade,
                model: "crate::generated::LinkedIdentity",
            },
            devices: {
                table: "auth_device",
                cardinality: HasMany,
                reverse_field: "user",
                on_delete: Cascade,
                model: "crate::generated::AuthDevice",
            },
            device_ceremonies: {
                table: "auth_device_ceremony",
                cardinality: HasMany,
                reverse_field: "user",
                on_delete: Cascade,
                model: "crate::generated::AuthDeviceCeremony",
            },
            primary_email: {
                table: "account_email",
                cardinality: HasOne,
                required: false,
                on_delete: SetNull,
                model: "crate::generated::AccountEmail",
            },
            primary_phone: {
                table: "account_phone",
                cardinality: HasOne,
                required: false,
                on_delete: SetNull,
                model: "crate::generated::AccountPhone",
            },
        ],
    }
}
