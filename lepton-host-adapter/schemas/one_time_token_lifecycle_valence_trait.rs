use valence::prelude::*;

valence_trait_schema! {
    OneTimeTokenLifecycle {
        repository: "https://github.com/unified-field-dev/lepton",
        fields: [
            user: {
                r#type: FieldType::Record("user"),
                required: true,
            },
            token_hash: {
                r#type: FieldType::String,
                required: true,
                validations: [Validator::NonEmpty],
            },
            expires_at: {
                r#type: FieldType::DateTime,
                required: true,
            },
            used_at: {
                r#type: FieldType::DateTime,
                required: false,
            },
            created_at: {
                r#type: FieldType::DateTime,
                required: true,
            }
        ],
    }
}
