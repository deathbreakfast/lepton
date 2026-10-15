use valence::prelude::*;
use valence::privacy_policies::owner::OWNER_BY_USER_FIELD;

use crate::bots::{BOT_CREATE_GATE, BOT_IDENTITY_IMMUTABLE, BOT_MANAGE_ANY};

valence_schema! {
    Bot {
        repository: "https://github.com/unified-field-dev/lepton",
        table: "bot",
        version: "0.1.0",
        database: crate::embedded_surreal::IDENTITY_DEFAULT_STORAGE,
        description: "Bot account owned by a user; acts in Valence as Actor::ServiceUser `bot:<id>`",

        privacy: {
            gdpr_compliant: true,
        },

        // Owners manage their own bots; the host's BotGate decides who may create
        // bots and who may manage any bot. Bot and service-user actors match none
        // of these rules, so a bot never manages itself.
        policies: {
            read: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD, BOT_MANAGE_ANY],
                block: [],
                always_block: [],
            },
            create: {
                always_allow: [],
                allow: [BOT_CREATE_GATE],
                block: [],
                always_block: [],
            },
            update: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD, BOT_MANAGE_ANY],
                block: [],
                always_block: [BOT_IDENTITY_IMMUTABLE],
            },
            delete: {
                always_allow: [],
                allow: [OWNER_BY_USER_FIELD, BOT_MANAGE_ANY],
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
            // Owning user. Optional at the column level so a team owner can be
            // added later without a nullability change; BOT_CREATE_GATE requires it.
            user: {
                r#type: FieldType::Record("user"),
                required: false,
            },
            owner_kind: {
                r#type: FieldType::Enum(&["user"]),
                required: true,
            },
            created_by: {
                r#type: FieldType::Record("user"),
                required: false,
            },
            handle: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(32)],
            },
            handle_key: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(32)],
            },
            display_name: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty, Validator::MaxLength(80)],
            },
            description: {
                r#type: FieldType::String,
                required: false,
                validations: [Validator::MaxLength(500)],
            },
            status: {
                r#type: FieldType::Enum(&["active", "suspended"]),
                required: true,
            },
            suspended_at: {
                r#type: FieldType::DateTime,
                required: false,
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
            user: {
                table: "user",
                cardinality: HasOne,
                required: false,
                on_delete: Cascade,
                model: "crate::generated::User",
            },
            created_by: {
                table: "user",
                cardinality: HasOne,
                required: false,
                on_delete: SetNull,
                model: "crate::generated::User",
            },
        ],
    }
}
