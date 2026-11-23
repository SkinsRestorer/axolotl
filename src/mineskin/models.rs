#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct MineSkinErrorItem {
    // Serde omits a missing value instead of writing null.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
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

#[derive(Debug, Serialize, ToSchema)]
pub struct SanitizedResponse {
    pub success: bool,
    // Serde writes null when there is no skin, so the key is always present.
    #[schema(required = true)]
    pub skin: Option<SanitizedSkin>,
    pub warnings: Vec<MineSkinErrorItem>,
    pub messages: Vec<MineSkinErrorItem>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SanitizedSkin {
    pub url: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Cape {
    pub uuid: String,
    pub alias: String,
    pub url: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CapesResponse {
    #[schema(value_type = Vec<Cape>)]
    pub capes: Arc<[Cape]>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapeSupportResponse {
    pub has_cape_grant: bool,
    #[schema(value_type = Vec<Cape>)]
    pub capes: Arc<[Cape]>,
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use utoipa::ToSchema;

    use super::{MineSkinErrorItem, SanitizedResponse};

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
            schema.pointer("/properties/skin/oneOf"),
            Some(&json!([{ "$ref": "#/components/schemas/SanitizedSkin" }, { "type": "null" }]))
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
        assert_eq!(
            schema.pointer("/properties/code"),
            Some(&json!({ "type": "string" }))
        );
        assert_eq!(
            schema.pointer("/properties/message"),
            Some(&json!({ "type": "string" }))
        );
        assert!(schema.get("required").is_none());

        let serialized = serde_json::to_value(MineSkinErrorItem {
            code: None,
            message: None,
        })
        .unwrap_or(Value::Null);
        assert_eq!(serialized, json!({}));
    }
}
