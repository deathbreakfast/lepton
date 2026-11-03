use valence::prelude::*;
use valence::privacy_policies::common::{AUTHENTICATED, SYSTEM_ONLY};
use valence::privacy_policies::owner::OWNER_BY_ID;

use crate::protected_fields::USER_PROTECTED_FIELDS;

valence_schema! {
    User {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "user",
        version: "0.4.0",
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
            // Status, user type, verification stamps, and the password hash are
            // system-only to write: System skips the block rule via always_allow, the
            // owner passes `allow` only while those fields are unchanged.
            update: {
                always_allow: [SYSTEM_ONLY],
                allow: [OWNER_BY_ID],
                block: [USER_PROTECTED_FIELDS],
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
                    // System only (also the only writer). Owner re-auth reads the hash
                    // through `protected_fields::stored_password_hash`.
                    read: { allow: [SYSTEM_ONLY] },
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
            service_users: {
                table: "service_user_account",
                cardinality: HasMany,
                reverse_field: "user",
                on_delete: Cascade,
                model: "crate::generated::ServiceUserAccount",
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
