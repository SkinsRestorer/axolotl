use aes::{
    Aes256,
    cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use cbc::{Decryptor, Encryptor};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MINESKIN_URL_PREFIX: &str = "https://minesk.in/";
pub const ENCRYPTED_URL_SCHEME: &str = "skinsrestorer-axolotl://";

type Aes256CbcEncryptor = Encryptor<Aes256>;
type Aes256CbcDecryptor = Decryptor<Aes256>;

#[derive(Clone)]
pub struct UrlCipher {
    key: Option<[u8; 32]>,
}

impl UrlCipher {
    #[must_use]
    pub fn new(secret: Option<&str>) -> Self {
        let key = secret.map(|value| Sha256::digest(value.as_bytes()).into());
        Self { key }
    }

    pub fn encrypt_uuid(&self, uuid: &str) -> Result<String, CryptoError> {
        let mut iv = [0_u8; 16];
        getrandom::fill(&mut iv).map_err(|_| CryptoError::Randomness)?;
        self.encrypt_uuid_with_iv(uuid, iv)
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
        let combined = STANDARD
            .decode(payload)
            .map_err(|_| CryptoError::InvalidPayload)?;

        if combined.len() < 32 || !combined.len().is_multiple_of(16) {
            return Err(CryptoError::InvalidPayload);
        }

        let (iv, ciphertext) = combined.split_at(16);
        let iv: &[u8; 16] = iv.try_into().map_err(|_| CryptoError::InvalidPayload)?;
        let key = self.key()?;
        let mut buffer = ciphertext.to_vec();
        let plaintext = Aes256CbcDecryptor::new(key.into(), iv.into())
            .decrypt_padded::<Pkcs7>(&mut buffer)
            .map_err(|_| CryptoError::InvalidPayload)?;
        let uuid = String::from_utf8_lossy(plaintext);

        Ok(format!("{MINESKIN_URL_PREFIX}{uuid}"))
    }

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
    #[error("Failed to encrypt MineSkin URL")]
    Encryption,
    #[error("Failed to obtain secure random bytes")]
    Randomness,
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
    fn rejects_non_mineskin_urls() {
        let cipher = UrlCipher::new(Some("test-secret"));

        assert!(matches!(
            cipher.encrypt_url("https://example.com/skin"),
            Err(CryptoError::UnsupportedUrl)
        ));
    }
}
