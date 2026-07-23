#[cfg(test)]
use aes::cipher::BlockModeEncrypt;
use aes::{
    Aes256,
    cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7},
};
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload, array::Array},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use cbc::Decryptor;
#[cfg(test)]
use cbc::Encryptor;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const MINESKIN_URL_PREFIX: &str = "https://minesk.in/";
pub const ENCRYPTED_URL_SCHEME: &str = "skinsrestorer-axolotl://";

const AUTHENTICATED_PAYLOAD_PREFIX: &str = "v2/";
const AUTHENTICATED_PAYLOAD_AAD: &[u8] = b"skinsrestorer-axolotl:v2";
const GCM_NONCE_LENGTH: usize = 12;
const GCM_TAG_LENGTH: usize = 16;
const MAXIMUM_ENCODED_PAYLOAD_LENGTH: usize = 256;

#[cfg(test)]
type Aes256CbcEncryptor = Encryptor<Aes256>;
type Aes256CbcDecryptor = Decryptor<Aes256>;

#[derive(Clone)]
pub struct UrlCipher {
    key: Option<[u8; 32]>,
}

impl UrlCipher {
    #[must_use]
    pub fn new(secret: Option<&str>) -> Self {
        let key = secret
            .filter(|value| !value.trim().is_empty())
            .map(|value| Sha256::digest(value.as_bytes()).into());
        Self { key }
    }

    pub fn encrypt_uuid(&self, uuid: &str) -> Result<String, CryptoError> {
        let uuid = canonical_uuid(uuid)?;
        let mut nonce = [0_u8; GCM_NONCE_LENGTH];
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;
        self.encrypt_uuid_with_nonce(&uuid, nonce)
    }

    pub fn encrypt_url(&self, url: &str) -> Result<String, CryptoError> {
        let uuid = url
            .strip_prefix(MINESKIN_URL_PREFIX)
            .ok_or(CryptoError::UnsupportedUrl)?;

        self.encrypt_uuid(uuid)
    }

    pub fn decrypt_url(&self, encrypted_url: &str) -> Result<String, CryptoError> {
        let payload = encrypted_url
            .strip_prefix(ENCRYPTED_URL_SCHEME)
            .ok_or(CryptoError::InvalidFormat)?;

        if payload.len() > MAXIMUM_ENCODED_PAYLOAD_LENGTH {
            return Err(CryptoError::InvalidPayload);
        }

        let uuid = if let Some(payload) = payload.strip_prefix(AUTHENTICATED_PAYLOAD_PREFIX) {
            self.decrypt_authenticated_uuid(payload)?
        } else {
            self.decrypt_legacy_uuid(payload)?
        };
        let uuid = canonical_uuid(&uuid).map_err(|_| CryptoError::InvalidPayload)?;

        Ok(format!("{MINESKIN_URL_PREFIX}{uuid}"))
    }

    fn encrypt_uuid_with_nonce(
        &self,
        uuid: &str,
        nonce: [u8; GCM_NONCE_LENGTH],
    ) -> Result<String, CryptoError> {
        let key = self.key()?;
        let cipher = Aes256Gcm::new(&Array(*key));
        let ciphertext = cipher
            .encrypt(
                &Array(nonce),
                Payload {
                    msg: uuid.as_bytes(),
                    aad: AUTHENTICATED_PAYLOAD_AAD,
                },
            )
            .map_err(|_| CryptoError::Encryption)?;
        let mut combined = Vec::with_capacity(nonce.len() + ciphertext.len());
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&ciphertext);

        Ok(format!(
            "{ENCRYPTED_URL_SCHEME}{AUTHENTICATED_PAYLOAD_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(combined)
        ))
    }

    fn decrypt_authenticated_uuid(&self, payload: &str) -> Result<String, CryptoError> {
        let combined = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| CryptoError::InvalidPayload)?;
        if combined.len() <= GCM_NONCE_LENGTH + GCM_TAG_LENGTH {
            return Err(CryptoError::InvalidPayload);
        }

        let (nonce, ciphertext) = combined.split_at(GCM_NONCE_LENGTH);
        let nonce: &[u8; GCM_NONCE_LENGTH] =
            nonce.try_into().map_err(|_| CryptoError::InvalidPayload)?;
        let key = self.key()?;
        let cipher = Aes256Gcm::new(&Array(*key));
        let plaintext = cipher
            .decrypt(
                &Array(*nonce),
                Payload {
                    msg: ciphertext,
                    aad: AUTHENTICATED_PAYLOAD_AAD,
                },
            )
            .map_err(|_| CryptoError::InvalidPayload)?;

        String::from_utf8(plaintext).map_err(|_| CryptoError::InvalidPayload)
    }

    fn decrypt_legacy_uuid(&self, payload: &str) -> Result<String, CryptoError> {
        let mut combined = STANDARD
            .decode(payload)
            .map_err(|_| CryptoError::InvalidPayload)?;

        if combined.len() < 32 || !combined.len().is_multiple_of(16) {
            return Err(CryptoError::InvalidPayload);
        }

        let iv: [u8; 16] = combined
            .get(..16)
            .and_then(|iv| <&[u8; 16]>::try_from(iv).ok())
            .copied()
            .ok_or(CryptoError::InvalidPayload)?;
        combined.drain(..16);
        let key = self.key()?;
        let plaintext_length = Aes256CbcDecryptor::new(key.into(), (&iv).into())
            .decrypt_padded::<Pkcs7>(&mut combined)
            .map_err(|_| CryptoError::InvalidPayload)?
            .len();
        combined.truncate(plaintext_length);

        String::from_utf8(combined).map_err(|_| CryptoError::InvalidPayload)
    }

    #[cfg(test)]
    fn encrypt_uuid_with_iv(&self, uuid: &str, iv: [u8; 16]) -> Result<String, CryptoError> {
        let key = self.key()?;
        let plaintext = uuid.as_bytes();
        let buffer_length = plaintext
            .len()
            .checked_add(16)
            .ok_or(CryptoError::Encryption)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(buffer_length)
            .map_err(|_| CryptoError::Encryption)?;
        buffer.extend_from_slice(plaintext);
        buffer.resize(buffer_length, 0);

        let ciphertext = Aes256CbcEncryptor::new(key.into(), (&iv).into())
            .encrypt_padded::<Pkcs7>(&mut buffer, plaintext.len())
            .map_err(|_| CryptoError::Encryption)?;
        let combined_length = iv
            .len()
            .checked_add(ciphertext.len())
            .ok_or(CryptoError::Encryption)?;
        let mut combined = Vec::new();
        combined
            .try_reserve_exact(combined_length)
            .map_err(|_| CryptoError::Encryption)?;
        combined.extend_from_slice(&iv);
        combined.extend_from_slice(ciphertext);

        Ok(format!(
            "{ENCRYPTED_URL_SCHEME}{}",
            STANDARD.encode(combined)
        ))
    }

    fn key(&self) -> Result<&[u8; 32], CryptoError> {
        self.key.as_ref().ok_or(CryptoError::MissingConfiguration)
    }
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AES_SECRET_KEY environment variable is not set")]
    MissingConfiguration,
    #[error("Invalid encrypted URL format")]
    InvalidFormat,
    #[error("Invalid encrypted URL payload")]
    InvalidPayload,
    #[error("MineSkin encryption only supports https://minesk.in URLs")]
    UnsupportedUrl,
    #[error("MineSkin URL must contain a valid UUID")]
    InvalidUuid,
    #[error("Failed to encrypt MineSkin URL")]
    Encryption,
    #[error("Failed to obtain secure random bytes")]
    Randomness,
}

fn canonical_uuid(value: &str) -> Result<String, CryptoError> {
    Uuid::parse_str(value)
        .map(|uuid| uuid.hyphenated().to_string())
        .map_err(|_| CryptoError::InvalidUuid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const LEGACY_PAYLOAD: &str =
        "AAECAwQFBgcICQoLDA0OD8imM586fmS6OpsiL50KsnvRWjSo4S7vTKK3sl3b3l7RG1vToG52Tih6IdrpltHyHA==";

    #[test]
    fn matches_legacy_crypto_vector() -> Result<(), CryptoError> {
        let cipher = UrlCipher::new(Some("test-secret"));
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        let encrypted = cipher.encrypt_uuid_with_iv(UUID, iv)?;

        assert_eq!(encrypted, format!("{ENCRYPTED_URL_SCHEME}{LEGACY_PAYLOAD}"));
        Ok(())
    }

    #[test]
    fn decrypts_legacy_crypto_vector() -> Result<(), CryptoError> {
        let cipher = UrlCipher::new(Some("test-secret"));

        let decrypted = cipher.decrypt_url(&format!("{ENCRYPTED_URL_SCHEME}{LEGACY_PAYLOAD}"))?;

        assert_eq!(decrypted, format!("{MINESKIN_URL_PREFIX}{UUID}"));
        Ok(())
    }

    #[test]
    fn encrypts_authenticated_urls_and_rejects_tampering() -> Result<(), CryptoError> {
        let cipher = UrlCipher::new(Some("test-secret"));
        let encrypted = cipher.encrypt_uuid_with_nonce(UUID, [0x2a; GCM_NONCE_LENGTH])?;

        assert!(encrypted.starts_with(&format!(
            "{ENCRYPTED_URL_SCHEME}{AUTHENTICATED_PAYLOAD_PREFIX}"
        )));
        assert_eq!(
            cipher.decrypt_url(&encrypted)?,
            format!("{MINESKIN_URL_PREFIX}{UUID}")
        );

        let payload = encrypted
            .strip_prefix(&format!(
                "{ENCRYPTED_URL_SCHEME}{AUTHENTICATED_PAYLOAD_PREFIX}"
            ))
            .ok_or(CryptoError::InvalidFormat)?;
        let mut combined = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| CryptoError::InvalidPayload)?;
        let last = combined.last_mut().ok_or(CryptoError::InvalidPayload)?;
        *last ^= 1;
        let tampered = format!(
            "{ENCRYPTED_URL_SCHEME}{AUTHENTICATED_PAYLOAD_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(combined)
        );

        assert!(matches!(
            cipher.decrypt_url(&tampered),
            Err(CryptoError::InvalidPayload)
        ));
        Ok(())
    }

    #[test]
    fn rejects_blank_secrets_and_invalid_uuids() {
        let cipher = UrlCipher::new(Some("  "));

        assert!(matches!(
            cipher.encrypt_uuid(UUID),
            Err(CryptoError::MissingConfiguration)
        ));

        let cipher = UrlCipher::new(Some("test-secret"));
        assert!(matches!(
            cipher.encrypt_uuid("not-a-uuid"),
            Err(CryptoError::InvalidUuid)
        ));
    }

    #[test]
    fn rejects_non_mineskin_urls() {
        let cipher = UrlCipher::new(Some("test-secret"));

        assert!(matches!(
            cipher.encrypt_url("https://example.com/skin"),
            Err(CryptoError::UnsupportedUrl)
        ));
    }
}
