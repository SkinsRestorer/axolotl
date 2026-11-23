mod health;
mod mineskin;

pub(crate) use health::{__path_health, __path_ready};
pub(crate) use health::{HealthResponse, ReadinessResponse, health, ready};
pub(crate) use mineskin::{
    __path_cape_support, __path_decrypt_url, __path_job_status, __path_supported_capes,
    __path_upload_skin,
};
pub(crate) use mineskin::{
    DecryptedUrlResponse, UploadRequest, cape_support, decrypt_url, job_status, supported_capes,
    upload_skin,
};
