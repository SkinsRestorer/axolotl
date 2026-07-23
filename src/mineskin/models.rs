use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct MineSkinErrorItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobDetails {
    pub id: String,
    pub status: JobStatus,
    #[serde(rename = "result")]
    _result: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Unknown,
    Waiting,
    Active,
    Processing,
    Failed,
    Completed,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobSuccessResponse {
    pub success: bool,
    pub job: JobDetails,
    pub skin: Option<SkinResult>,
    #[serde(rename = "rateLimit")]
    _rate_limit: Option<RateLimitInfo>,
    #[serde(rename = "usage")]
    _usage: Option<UsageInfo>,
    #[serde(rename = "errors")]
    _errors: Option<Vec<MineSkinErrorItem>>,
    pub warnings: Option<Vec<MineSkinErrorItem>>,
    pub messages: Option<Vec<MineSkinErrorItem>>,
    #[serde(rename = "links")]
    _links: Option<Links>,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum SkinResult {
    Skin(Box<Skin>),
    Boolean(bool),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Skin {
    pub uuid: String,
    #[serde(rename = "name")]
    _name: Option<String>,
    #[serde(rename = "visibility")]
    _visibility: Visibility,
    #[serde(rename = "variant")]
    _variant: SkinVariant,
    #[serde(rename = "texture")]
    _texture: SkinTexture,
    #[serde(rename = "generator")]
    _generator: GeneratorInfo,
    #[serde(rename = "views")]
    _views: f64,
    #[serde(rename = "duplicate")]
    _duplicate: bool,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Visibility {
    Public,
    Unlisted,
    Private,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SkinVariant {
    Classic,
    Slim,
    Unknown,
}

#[derive(Clone, Debug, Deserialize)]
struct SkinTexture {
    #[serde(rename = "data")]
    _data: ValueAndSignature,
    #[serde(rename = "hash")]
    _hash: Option<SkinHashes>,
    #[serde(rename = "url")]
    _url: Option<SkinUrls>,
}

#[derive(Clone, Debug, Deserialize)]
struct ValueAndSignature {
    #[serde(rename = "value")]
    _value: String,
    #[serde(rename = "signature")]
    _signature: String,
}

#[derive(Clone, Debug, Deserialize)]
struct SkinHashes {
    #[serde(rename = "skin")]
    _skin: String,
    #[serde(rename = "cape")]
    _cape: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct SkinUrls {
    #[serde(rename = "skin")]
    _skin: String,
    #[serde(rename = "cape")]
    _cape: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct GeneratorInfo {
    #[serde(rename = "version")]
    _version: String,
    #[serde(rename = "timestamp")]
    _timestamp: f64,
    #[serde(rename = "duration")]
    _duration: f64,
    #[serde(rename = "account")]
    _account: String,
    #[serde(rename = "server")]
    _server: String,
}

#[derive(Clone, Debug, Deserialize)]
struct RateLimitInfo {
    #[serde(rename = "next")]
    _next: NextRequest,
    #[serde(rename = "delay")]
    _delay: DelayInfo,
    #[serde(rename = "limit")]
    _limit: Option<LimitInfo>,
}

#[derive(Clone, Debug, Deserialize)]
struct NextRequest {
    #[serde(rename = "absolute")]
    _absolute: f64,
    #[serde(rename = "relative")]
    _relative: f64,
}

#[derive(Clone, Debug, Deserialize)]
struct DelayInfo {
    #[serde(rename = "millis")]
    _millis: f64,
    #[serde(rename = "seconds")]
    _seconds: Option<f64>,
}

#[derive(Clone, Debug, Deserialize)]
struct LimitInfo {
    #[serde(rename = "limit")]
    _limit: f64,
    #[serde(rename = "remaining")]
    _remaining: f64,
    #[serde(rename = "reset")]
    _reset: Option<f64>,
}

#[derive(Clone, Debug, Deserialize)]
struct UsageInfo {
    #[serde(rename = "credits")]
    _credits: Option<CreditsUsage>,
    #[serde(rename = "metered")]
    _metered: Option<MeteredUsage>,
}

#[derive(Clone, Debug, Deserialize)]
struct CreditsUsage {
    #[serde(rename = "used")]
    _used: f64,
    #[serde(rename = "remaining")]
    _remaining: f64,
}

#[derive(Clone, Debug, Deserialize)]
struct MeteredUsage {
    #[serde(rename = "used")]
    _used: f64,
}

#[derive(Clone, Debug, Deserialize)]
struct Links {
    #[serde(rename = "self")]
    _self_link: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenericResponse {
    pub success: Option<bool>,
    pub errors: Option<Vec<MineSkinErrorItem>>,
    pub warnings: Option<Vec<MineSkinErrorItem>>,
    pub messages: Option<Vec<MineSkinErrorItem>>,
}

impl GenericResponse {
    #[must_use]
    pub fn error_message(&self) -> String {
        [&self.errors, &self.warnings, &self.messages]
            .into_iter()
            .filter_map(|items| items.as_ref())
            .flatten()
            .find_map(|item| item.message.clone())
            .unwrap_or_else(|| "MineSkin request failed".to_owned())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct EnqueueResponse {
    #[serde(flatten)]
    pub generic: GenericResponse,
    pub job: Option<JobDetails>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CapeResponse {
    #[serde(flatten)]
    pub generic: GenericResponse,
    pub capes: Option<Vec<UpstreamCape>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpstreamCape {
    pub uuid: String,
    pub alias: String,
    pub url: String,
    pub supported: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MeResponse {
    #[serde(flatten)]
    pub generic: GenericResponse,
    pub grants: Option<HashMap<String, Value>>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct SanitizedResponse {
    pub success: bool,
    pub skin: Option<SanitizedSkin>,
    pub warnings: Vec<MineSkinErrorItem>,
    pub messages: Vec<MineSkinErrorItem>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct SanitizedSkin {
    pub url: String,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct Cape {
    pub uuid: String,
    pub alias: String,
    pub url: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CapesResponse {
    pub capes: Vec<Cape>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapeSupportResponse {
    pub has_cape_grant: bool,
    pub capes: Vec<Cape>,
}
