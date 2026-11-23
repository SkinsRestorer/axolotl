//! Encrypts `MineSkin` skin URLs so clients can store them without learning the
//! skin ID, and decrypts them again.
//!
//! The key is the SHA-256 digest of `AES_SECRET_KEY`. An encrypted URL is
//! `skinsrestorer-axolotl://` followed by one of two payloads:
//!
//! - v2, issued today: `v2/` + unpadded URL-safe base64 of a 12-byte random
//!   nonce, then the AES-256-GCM ciphertext and its 16-byte tag. The additional
//!   authenticated data is `skinsrestorer-axolotl:v2`.
//! - Legacy: padded standard base64 of a 16-byte random IV, then the
//!   AES-256-CBC ciphertext with PKCS#7 padding. It is only decrypted, because
//!   clients still hold these URLs.
//!
//! The plaintext is the skin UUID in any form [`Uuid::parse_str`] accepts.
//! Decryption always returns it as 32 hex digits without hyphens.
//!
//! Both formats are part of the public contract: every URL issued so far must
//! keep decrypting, so never change the key derivation, the layout or the AAD.

#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

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
        let uuid = canonical_uuid(uuid).map_err(|error| {
            tracing::debug!(%error, "Invalid MineSkin UUID");
            CryptoError::InvalidUuid
        })?;
        let mut nonce = [0_u8; GCM_NONCE_LENGTH];
        getrandom::fill(&mut nonce).map_err(|error| {
            tracing::debug!(%error, "Failed to obtain secure random bytes");
            CryptoError::Randomness
        })?;
        self.encrypt_uuid_with_nonce(&uuid, nonce)
    }

    pub fn encrypt_url(&self, url: &str) -> Result<String, CryptoError> {
        let uuid = url
            .strip_prefix(MINESKIN_URL_PREFIX)
            .ok_or(CryptoError::UnsupportedUrl)?;

        self.encrypt_uuid(uuid)
    }

    #[expect(
        clippy::map_err_ignore,
        reason = "invalid encrypted payloads share one error without exposing validation details"
    )]
    pub fn decrypt_url(&self, encrypted_url: &str) -> Result<String, CryptoError> {
        let payload = encrypted_url
            .strip_prefix(ENCRYPTED_URL_SCHEME)
            .ok_or(CryptoError::InvalidFormat)?;
        let key = self.key()?;

        if payload.len() > MAXIMUM_ENCODED_PAYLOAD_LENGTH {
            return Err(CryptoError::InvalidPayload);
        }

        // "v2/" is also valid standard base64, so a legacy payload whose random
        // IV encodes to it must still decrypt as legacy.
        let uuid = payload
            .strip_prefix(AUTHENTICATED_PAYLOAD_PREFIX)
            .ok_or(CryptoError::InvalidPayload)
            .and_then(|payload| Self::decrypt_authenticated_uuid(key, payload))
            .or_else(|_| Self::decrypt_legacy_uuid(key, payload))?;
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
            .map_err(|error| {
                tracing::debug!(%error, "Failed to encrypt MineSkin URL");
                CryptoError::Encryption
            })?;
        let combined_length = nonce
            .len()
            .checked_add(ciphertext.len())
            .ok_or(CryptoError::Encryption)?;
        let mut combined = Vec::with_capacity(combined_length);
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&ciphertext);

        Ok(format!(
            "{ENCRYPTED_URL_SCHEME}{AUTHENTICATED_PAYLOAD_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(combined)
        ))
    }

    #[expect(
        clippy::map_err_ignore,
        reason = "invalid encrypted payloads share one error without exposing validation details"
    )]
    fn decrypt_authenticated_uuid(key: &[u8; 32], payload: &str) -> Result<String, CryptoError> {
        let combined = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| CryptoError::InvalidPayload)?;
        if combined.len() <= GCM_NONCE_LENGTH + GCM_TAG_LENGTH {
            return Err(CryptoError::InvalidPayload);
        }

        let (nonce, ciphertext) = combined
            .split_at_checked(GCM_NONCE_LENGTH)
            .ok_or(CryptoError::InvalidPayload)?;
        let nonce: &[u8; GCM_NONCE_LENGTH] =
            nonce.try_into().map_err(|_| CryptoError::InvalidPayload)?;
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

    #[expect(
        clippy::map_err_ignore,
        reason = "invalid encrypted payloads share one error without exposing validation details"
    )]
    fn decrypt_legacy_uuid(key: &[u8; 32], payload: &str) -> Result<String, CryptoError> {
        // Standard base64 can contain '+'. An unencoded '+' in a query string
        // arrives as a space, and a space is never valid base64, so restoring it
        // cannot change how any valid payload decodes.
        let mut combined = STANDARD
            .decode(payload.replace(' ', "+"))
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
        // Room for the plaintext plus one block of PKCS#7 padding.
        let mut buffer = uuid.as_bytes().to_vec();
        buffer.extend_from_slice(&[0; 16]);
        let ciphertext = Aes256CbcEncryptor::new(key.into(), (&iv).into())
            .encrypt_padded::<Pkcs7>(&mut buffer, uuid.len())
            .expect("the buffer has room for one padding block");
        Ok(format!(
            "{ENCRYPTED_URL_SCHEME}{}",
            STANDARD.encode([iv.as_slice(), ciphertext].concat())
        ))
    }

    fn key(&self) -> Result<&[u8; 32], CryptoError> {
        self.key.as_ref().ok_or(CryptoError::MissingConfiguration)
    }
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("URL encryption is not configured")]
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

/// Formats a skin UUID the way `MineSkin` does: 32 hex digits without hyphens.
/// `MineSkin` rewrites `minesk.in/<id>` links with `[0-9a-zA-Z]+`, so a hyphen
/// would cut the ID short.
fn canonical_uuid(value: &str) -> Result<String, uuid::Error> {
    Uuid::parse_str(value).map(|uuid| uuid.simple().to_string())
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "tests assert inside Result-returning test functions"
)]
mod tests {
    use super::*;

    const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
    /// The same UUID in `MineSkin`'s format, which decrypted URLs use.
    const SKIN_ID: &str = "123e4567e89b12d3a456426614174000";
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

        assert_eq!(decrypted, format!("{MINESKIN_URL_PREFIX}{SKIN_ID}"));
        Ok(())
    }

    /// Pins the v2 format, so a change to the key derivation, layout or AAD
    /// cannot silently break URLs that clients already hold.
    #[test]
    fn matches_authenticated_crypto_vector() -> Result<(), CryptoError> {
        const AUTHENTICATED_URL: &str = "skinsrestorer-axolotl://v2/KioqKioqKioqKioqtq5dgUTJfE0GET3jz43Tjm7slJRHdn_eLAln1DC8dmvjOReZDYMkNvS5iplMDo9r";
        let cipher = UrlCipher::new(Some("test-secret"));

        assert_eq!(
            cipher.encrypt_uuid_with_nonce(SKIN_ID, [0x2a; GCM_NONCE_LENGTH])?,
            AUTHENTICATED_URL
        );
        assert_eq!(
            cipher.decrypt_url(AUTHENTICATED_URL)?,
            format!("{MINESKIN_URL_PREFIX}{SKIN_ID}")
        );
        Ok(())
    }

    #[test]
    fn encrypts_authenticated_urls_and_rejects_tampering() -> Result<(), Box<dyn std::error::Error>>
    {
        let cipher = UrlCipher::new(Some("test-secret"));
        let encrypted = cipher.encrypt_uuid_with_nonce(UUID, [0x2a; GCM_NONCE_LENGTH])?;

        assert!(encrypted.starts_with(&format!(
            "{ENCRYPTED_URL_SCHEME}{AUTHENTICATED_PAYLOAD_PREFIX}"
        )));
        assert_eq!(
            cipher.decrypt_url(&encrypted)?,
            format!("{MINESKIN_URL_PREFIX}{SKIN_ID}")
        );

        let payload = encrypted
            .strip_prefix(&format!(
                "{ENCRYPTED_URL_SCHEME}{AUTHENTICATED_PAYLOAD_PREFIX}"
            ))
            .ok_or(CryptoError::InvalidFormat)?;
        let mut combined = URL_SAFE_NO_PAD.decode(payload)?;
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
    fn rejects_truncated_encrypted_payloads() {
        let cipher = UrlCipher::new(Some("test-secret"));
        let authenticated = URL_SAFE_NO_PAD.encode([0; GCM_NONCE_LENGTH + GCM_TAG_LENGTH]);
        let legacy = STANDARD.encode([0; 16]);

        for payload in [
            format!("{AUTHENTICATED_PAYLOAD_PREFIX}{authenticated}"),
            legacy,
        ] {
            assert!(matches!(
                cipher.decrypt_url(&format!("{ENCRYPTED_URL_SCHEME}{payload}")),
                Err(CryptoError::InvalidPayload)
            ));
        }
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

    fn assert_invalid_payload(cipher: &UrlCipher, payload: &str) {
        assert!(
            matches!(
                cipher.decrypt_url(&format!("{ENCRYPTED_URL_SCHEME}{payload}")),
                Err(CryptoError::InvalidPayload)
            ),
            "payload {payload:?} was not rejected as InvalidPayload"
        );
    }

    #[test]
    fn reports_missing_key_before_validating_payloads() {
        let cipher = UrlCipher::new(None);

        for payload in [LEGACY_PAYLOAD, "not base64!", "v2/AAAA"] {
            assert!(matches!(
                cipher.decrypt_url(&format!("{ENCRYPTED_URL_SCHEME}{payload}")),
                Err(CryptoError::MissingConfiguration)
            ));
        }
    }

    #[test]
    fn decrypts_legacy_payloads_with_unencoded_plus_signs() -> Result<(), CryptoError> {
        let cipher = UrlCipher::new(Some("test-secret"));
        let iv = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let encrypted = cipher.encrypt_uuid_with_iv(UUID, iv)?;
        assert!(encrypted.contains('+'), "test vector must contain '+'");

        let decrypted = cipher.decrypt_url(&encrypted.replace('+', " "))?;

        assert_eq!(decrypted, format!("{MINESKIN_URL_PREFIX}{SKIN_ID}"));
        Ok(())
    }

    #[test]
    fn decrypts_legacy_payloads_that_start_with_the_v2_prefix()
    -> Result<(), Box<dyn std::error::Error>> {
        let cipher = UrlCipher::new(Some("test-secret"));
        let mut iv = [0; 16];
        iv[..3].copy_from_slice(&STANDARD.decode("v2/A")?);
        let encrypted = cipher.encrypt_uuid_with_iv(UUID, iv)?;
        assert!(
            encrypted.starts_with(&format!(
                "{ENCRYPTED_URL_SCHEME}{AUTHENTICATED_PAYLOAD_PREFIX}"
            )),
            "test vector must start with the v2 prefix"
        );

        assert_eq!(
            cipher.decrypt_url(&encrypted)?,
            format!("{MINESKIN_URL_PREFIX}{SKIN_ID}")
        );
        Ok(())
    }

    #[test]
    fn rejects_payloads_encrypted_with_another_key() -> Result<(), CryptoError> {
        let other = UrlCipher::new(Some("other-secret"));
        let legacy = other.encrypt_uuid_with_iv(UUID, [7; 16])?;
        let authenticated = other.encrypt_uuid_with_nonce(UUID, [7; GCM_NONCE_LENGTH])?;
        let cipher = UrlCipher::new(Some("test-secret"));

        for encrypted in [legacy, authenticated] {
            let payload = encrypted
                .strip_prefix(ENCRYPTED_URL_SCHEME)
                .ok_or(CryptoError::InvalidFormat)?;
            assert_invalid_payload(&cipher, payload);
        }
        Ok(())
    }

    #[test]
    fn rejects_oversized_payloads() {
        let cipher = UrlCipher::new(Some("test-secret"));

        assert_invalid_payload(&cipher, &"A".repeat(MAXIMUM_ENCODED_PAYLOAD_LENGTH + 4));
    }

    #[test]
    fn rejects_corrupted_legacy_payloads() -> Result<(), Box<dyn std::error::Error>> {
        let cipher = UrlCipher::new(Some("test-secret"));
        let mut combined = STANDARD.decode(LEGACY_PAYLOAD)?;
        let last = combined.last_mut().ok_or(CryptoError::InvalidPayload)?;
        *last ^= 1;

        assert_invalid_payload(&cipher, &STANDARD.encode(&combined));
        assert_invalid_payload(&cipher, LEGACY_PAYLOAD.trim_end_matches('='));
        Ok(())
    }

    #[test]
    fn rejects_v2_payloads_with_a_changed_nonce_or_format() -> Result<(), Box<dyn std::error::Error>>
    {
        let cipher = UrlCipher::new(Some("test-secret"));
        let encrypted = cipher.encrypt_uuid_with_nonce(UUID, [0x2a; GCM_NONCE_LENGTH])?;
        let payload = encrypted
            .strip_prefix(&format!(
                "{ENCRYPTED_URL_SCHEME}{AUTHENTICATED_PAYLOAD_PREFIX}"
            ))
            .ok_or(CryptoError::InvalidFormat)?;
        let mut combined = URL_SAFE_NO_PAD.decode(payload)?;

        assert_invalid_payload(&cipher, &STANDARD.encode(&combined));

        let first = combined.first_mut().ok_or(CryptoError::InvalidPayload)?;
        *first ^= 1;
        assert_invalid_payload(
            &cipher,
            &format!(
                "{AUTHENTICATED_PAYLOAD_PREFIX}{}",
                URL_SAFE_NO_PAD.encode(&combined)
            ),
        );
        Ok(())
    }

    #[test]
    fn decrypts_every_uuid_form_to_the_mineskin_id() -> Result<(), CryptoError> {
        let cipher = UrlCipher::new(Some("test-secret"));
        let expected = format!("{MINESKIN_URL_PREFIX}{SKIN_ID}");

        for uuid in [
            "123e4567e89b12d3a456426614174000",
            "{123e4567-e89b-12d3-a456-426614174000}",
            "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
            "123E4567-E89B-12D3-A456-426614174000",
        ] {
            assert_eq!(cipher.decrypt_url(&cipher.encrypt_uuid(uuid)?)?, expected);
            assert_eq!(
                cipher.decrypt_url(&cipher.encrypt_uuid_with_iv(uuid, [3; 16])?)?,
                expected
            );
        }
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
