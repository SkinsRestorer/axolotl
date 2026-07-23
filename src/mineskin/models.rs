use std::{fmt, sync::Arc};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, IgnoredAny, MapAccess, Visitor},
};
use serde_json::Value;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct MineSkinErrorItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobDetails {
    pub id: String,
    pub status: JobStatus,
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
    pub success: bool,
    pub job: JobDetails,
    pub skin: Option<SkinResult>,
    pub warnings: Option<Vec<MineSkinErrorItem>>,
    pub messages: Option<Vec<MineSkinErrorItem>>,
}

impl JobSuccessResponse {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.success {
            return Err("success must be true");
        }

        if matches!(self.skin, Some(SkinResult::Boolean(true))) {
            return Err("skin must be an object, false, or null");
        }

        Ok(())
    }

    #[must_use]
    pub fn has_skin(&self) -> bool {
        matches!(self.skin, Some(SkinResult::Skin(_)))
    }

    pub fn into_sanitized(
        self,
        encrypted_url: Option<String>,
    ) -> Result<SanitizedResponse, &'static str> {
        let skin = match self.skin {
            Some(SkinResult::Skin(_)) => Some(SanitizedSkin {
                url: encrypted_url.ok_or("encrypted skin URL is missing")?,
            }),
            Some(SkinResult::Boolean(false)) | None => None,
            Some(SkinResult::Boolean(true)) => {
                return Err("skin must be an object, false, or null");
            }
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
            Some(SkinResult::Boolean(_)) | None => None,
        }
    }
}

#[derive(Debug)]
pub enum SkinResult {
    Skin(Skin),
    Boolean(bool),
}

impl<'de> Deserialize<'de> for SkinResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(SkinResultVisitor)
    }
}

struct SkinResultVisitor;

impl<'de> Visitor<'de> for SkinResultVisitor {
    type Value = SkinResult;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a MineSkin skin object or boolean")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(SkinResult::Boolean(value))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut uuid = None;

        while let Some(field) = map.next_key()? {
            match field {
                SkinField::Uuid => {
                    if uuid.is_some() {
                        return Err(de::Error::duplicate_field("uuid"));
                    }
                    uuid = Some(map.next_value()?);
                }
                SkinField::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        let uuid = uuid.ok_or_else(|| de::Error::missing_field("uuid"))?;
        Ok(SkinResult::Skin(Skin { uuid }))
    }
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "camelCase")]
enum SkinField {
    Uuid,
    #[serde(other)]
    Other,
}

#[derive(Debug)]
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
