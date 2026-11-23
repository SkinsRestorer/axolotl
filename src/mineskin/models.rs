#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// A note from `MineSkin`, passed through unchanged. Either field is left out
/// when `MineSkin` does not send it.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct MineSkinErrorItem {
    /// Machine-readable `MineSkin` code.
    // Serde omits a missing value instead of writing null.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false, example = "invalid_image")]
    pub code: Option<String>,
    /// Human-readable `MineSkin` text.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false, example = "Invalid skin image")]
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobDetails {
    pub id: String,
    pub status: JobStatus,
    pub result: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Waiting,
    Active,
    Processing,
    Failed,
    Completed,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobSuccessResponse {
    pub job: JobDetails,
    pub skin: Option<SkinResult>,
    pub warnings: Option<Vec<MineSkinErrorItem>>,
    pub messages: Option<Vec<MineSkinErrorItem>>,
}

impl JobSuccessResponse {
    pub fn validate(&self) -> Result<(), &'static str> {
        if matches!(self.skin, Some(SkinResult::Boolean(true))) {
            return Err("skin must be an object, false, or null");
        }

        Ok(())
    }

    pub fn into_sanitized(
        self,
        encrypted_url: Option<String>,
    ) -> Result<SanitizedResponse, &'static str> {
        self.validate()?;
        let skin = if self.skin_uuid().is_some() {
            Some(SanitizedSkin {
                url: encrypted_url.ok_or("encrypted skin URL is missing")?,
            })
        } else {
            None
        };

        Ok(SanitizedResponse {
            success: true,
            skin,
            warnings: self.warnings.unwrap_or_default(),
            messages: self.messages.unwrap_or_default(),
        })
    }

    #[must_use]
    pub fn skin_uuid(&self) -> Option<&str> {
        match self.skin.as_ref() {
            Some(SkinResult::Skin(skin)) => Some(&skin.uuid),
            Some(SkinResult::Boolean(_)) | None => {
                if self.job.status == JobStatus::Completed {
                    self.job.result.as_deref()
                } else {
                    None
                }
            }
        }
    }
}

/// `MineSkin` sends either a skin object or a boolean in the `skin` field.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum SkinResult {
    Skin(Skin),
    Boolean(bool),
}

#[derive(Debug, Deserialize)]
pub struct Skin {
    pub uuid: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MineSkinResponse {
    pub success: Option<bool>,
    pub errors: Option<Vec<MineSkinErrorItem>>,
    pub warnings: Option<Vec<MineSkinErrorItem>>,
    pub messages: Option<Vec<MineSkinErrorItem>>,
    pub job: Option<JobDetails>,
    pub skin: Option<SkinResult>,
    pub capes: Option<Vec<UpstreamCape>>,
    pub grants: Option<Grants>,
}

impl MineSkinResponse {
    #[must_use]
    pub fn into_error_message(self) -> String {
        [self.errors, self.warnings, self.messages]
            .into_iter()
            .flatten()
            .flatten()
            .find_map(|item| item.message)
            .unwrap_or_else(|| "MineSkin request failed".to_owned())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpstreamCape {
    pub uuid: String,
    pub alias: String,
    pub url: String,
    pub supported: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct Grants {
    pub capes: Option<Value>,
}

/// A `MineSkin` job result with the skin ID replaced by an encrypted URL.
#[derive(Debug, Serialize, ToSchema)]
pub struct SanitizedResponse {
    /// Always `true`. Failures return an error response instead.
    #[schema(example = true)]
    pub success: bool,
    /// The generated skin, or `null` while the job is still waiting or
    /// processing.
    // Serde writes null when there is no skin, so the key is always present.
    #[schema(required = true)]
    pub skin: Option<SanitizedSkin>,
    /// Warnings that `MineSkin` sent about the job, for example about the
    /// uploaded image. Empty when there are none.
    pub warnings: Vec<MineSkinErrorItem>,
    /// Informational messages that `MineSkin` sent about the job. Empty when
    /// there are none.
    pub messages: Vec<MineSkinErrorItem>,
}

/// The skin that a completed `MineSkin` job generated.
#[derive(Debug, Serialize, ToSchema)]
pub struct SanitizedSkin {
    /// Encrypted `skinsrestorer-axolotl://` URL that hides the `MineSkin` skin
    /// ID. `GET /mineskin/decrypt-url` turns it back into the
    /// `https://minesk.in/` URL of the skin.
    #[schema(
        example = "skinsrestorer-axolotl://v2/9IJci0UfwS33GsLnF9TQ2DjmhN_41nuUj19ziM-d2macEg6M9ddIUIMEz7nUUKVKkVyU7INPzAhOAsmr"
    )]
    pub url: String,
}

/// A `MineSkin` cape that the proxy accepts as `capeUuid` in skin uploads.
#[derive(Debug, Serialize, ToSchema)]
pub struct Cape {
    /// Cape UUID in hyphenated form.
    #[schema(format = Uuid, example = "cc0a2b5e-50ee-41d2-9e4b-cd3b39b1c5a3")]
    pub uuid: String,
    /// Short cape name from `MineSkin`.
    #[schema(example = "migrator")]
    pub alias: String,
    /// HTTPS URL of the cape texture. A `https://minesk.in/` URL is
    /// encrypted to a `skinsrestorer-axolotl://` URL instead.
    #[schema(
        example = "https://textures.minecraft.net/texture/2340c0e03dd24a11b15a8b33c2a7e9e32abb2051b2481d0ba7defd635ca7a933"
    )]
    pub url: String,
}

/// Capes that `MineSkin` marks as supported.
#[derive(Debug, Serialize, ToSchema)]
pub struct CapesResponse {
    /// Supported capes. Empty when `MineSkin` supports none.
    #[schema(value_type = Vec<Cape>)]
    pub capes: Arc<[Cape]>,
}

/// Whether the configured `MineSkin` account can apply capes.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapeSupportResponse {
    /// `true` when the `MineSkin` account has a cape grant.
    #[schema(example = true)]
    pub has_cape_grant: bool,
    /// Supported capes. Always empty when `hasCapeGrant` is `false`.
    #[schema(value_type = Vec<Cape>)]
    pub capes: Arc<[Cape]>,
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use utoipa::ToSchema;

    use super::{
        Cape, CapeSupportResponse, CapesResponse, MineSkinErrorItem, SanitizedResponse,
        SanitizedSkin,
    };
    use crate::crypto::ENCRYPTED_URL_SCHEME;

    fn schema_json<T: ToSchema>() -> Value {
        serde_json::to_value(T::schema()).unwrap_or(Value::Null)
    }

    #[test]
    fn sanitized_response_schema_requires_a_nullable_skin() {
        let schema = schema_json::<SanitizedResponse>();
        assert_eq!(
            schema.pointer("/required"),
            Some(&json!(["success", "skin", "warnings", "messages"]))
        );
        assert_eq!(
            schema.pointer("/properties/skin/oneOf/0/$ref"),
            Some(&json!("#/components/schemas/SanitizedSkin"))
        );
        assert_eq!(
            schema.pointer("/properties/skin/oneOf/1"),
            Some(&json!({ "type": "null" }))
        );

        let serialized = serde_json::to_value(SanitizedResponse {
            success: true,
            skin: None,
            warnings: Vec::new(),
            messages: Vec::new(),
        })
        .unwrap_or(Value::Null);
        assert_eq!(serialized.get("skin"), Some(&Value::Null));
    }

    #[test]
    fn error_item_schema_omits_absent_fields_instead_of_allowing_null() {
        let schema = schema_json::<MineSkinErrorItem>();
        for field in ["code", "message"] {
            assert_eq!(
                schema.pointer(&format!("/properties/{field}/type")),
                Some(&json!("string")),
                "{field}"
            );
        }
        assert!(schema.get("required").is_none());

        let serialized = serde_json::to_value(MineSkinErrorItem {
            code: None,
            message: None,
        })
        .unwrap_or(Value::Null);
        assert_eq!(serialized, json!({}));
    }

    #[test]
    fn public_schemas_describe_every_property() {
        for (name, schema) in [
            ("SanitizedResponse", schema_json::<SanitizedResponse>()),
            ("SanitizedSkin", schema_json::<SanitizedSkin>()),
            ("MineSkinErrorItem", schema_json::<MineSkinErrorItem>()),
            ("Cape", schema_json::<Cape>()),
            ("CapesResponse", schema_json::<CapesResponse>()),
            ("CapeSupportResponse", schema_json::<CapeSupportResponse>()),
        ] {
            assert!(
                schema.get("description").and_then(Value::as_str).is_some(),
                "{name} has no description"
            );
            let properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            assert!(!properties.is_empty(), "{name} has no properties");
            for (field, property) in properties {
                // A nullable reference keeps its description on the reference.
                let description = property
                    .get("description")
                    .or_else(|| property.pointer("/oneOf/0/description"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                assert!(!description.is_empty(), "{name}.{field} has no description");
            }
        }
    }

    #[test]
    fn skin_url_example_uses_the_encrypted_scheme() {
        let schema = schema_json::<SanitizedSkin>();
        let example = schema
            .pointer("/properties/url/example")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(example.starts_with(ENCRYPTED_URL_SCHEME), "{example}");

        let description = schema
            .pointer("/properties/url/description")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(description.contains(ENCRYPTED_URL_SCHEME), "{description}");
    }

    #[test]
    fn cape_schemas_match_the_serialized_json() {
        let cape = schema_json::<Cape>();
        assert_eq!(
            cape.pointer("/properties/uuid/format"),
            Some(&json!("uuid"))
        );

        let support = schema_json::<CapeSupportResponse>();
        assert_eq!(
            support.pointer("/required"),
            Some(&json!(["hasCapeGrant", "capes"]))
        );
        assert_eq!(
            support.pointer("/properties/capes/items/$ref"),
            Some(&json!("#/components/schemas/Cape"))
        );
        let serialized = serde_json::to_value(CapeSupportResponse {
            has_cape_grant: false,
            capes: std::sync::Arc::from([]),
        })
        .unwrap_or(Value::Null);
        assert_eq!(serialized, json!({ "hasCapeGrant": false, "capes": [] }));
    }
}
