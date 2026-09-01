use crate::{CryptographyError, EncryptionPurpose, VersionedKey, lookup};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use std::{collections::BTreeMap, fmt, sync::Arc};
use uuid::Uuid;
use zeroize::Zeroizing;

const NONCE_LENGTH: usize = 12;

/// Associated-data context binding ciphertext to one intended record and field.
#[derive(Clone, Copy, Debug)]
pub struct EncryptionContext {
    namespace: &'static str,
    record_id: Uuid,
}

impl EncryptionContext {
    /// Creates a context from a stable field namespace and internal record ID.
    #[must_use]
    pub const fn new(namespace: &'static str, record_id: Uuid) -> Self {
        Self {
            namespace,
            record_id,
        }
    }

    fn associated_data(self, purpose: EncryptionPurpose, key_version: i16) -> Vec<u8> {
        let mut value = Vec::with_capacity(64 + self.namespace.len());
        value.extend_from_slice(b"sahayak:field:v1\0");
        value.extend_from_slice(purpose.as_str().as_bytes());
        value.push(0);
        value.extend_from_slice(&key_version.to_be_bytes());
        value.extend_from_slice(&(self.namespace.len() as u64).to_be_bytes());
        value.extend_from_slice(self.namespace.as_bytes());
        value.extend_from_slice(self.record_id.as_bytes());
        value
    }
}

/// Authenticated encrypted value ready for restricted persistence.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedValue {
    /// Independent key purpose used for this data category.
    pub purpose: EncryptionPurpose,
    /// Key version required for decryption.
    pub key_version: i16,
    /// Unique AES-GCM nonce.
    pub nonce: [u8; NONCE_LENGTH],
    /// Ciphertext including the authentication tag.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for EncryptedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedValue")
            .field("purpose", &self.purpose)
            .field("key_version", &self.key_version)
            .field("nonce", &"[REDACTED]")
            .field("ciphertext", &"[REDACTED]")
            .finish()
    }
}

/// One purpose-specific versioned key ring supplied to `CryptoService`.
pub struct EncryptionKeySet {
    purpose: EncryptionPurpose,
    active_version: i16,
    keys: Vec<VersionedKey>,
}

impl EncryptionKeySet {
    /// Defines the active key and readable historical keys for one purpose.
    #[must_use]
    pub fn new(purpose: EncryptionPurpose, active_version: i16, keys: Vec<VersionedKey>) -> Self {
        Self {
            purpose,
            active_version,
            keys,
        }
    }
}

#[derive(Clone)]
struct KeyRing {
    active_version: i16,
    keys: BTreeMap<i16, VersionedKey>,
}

impl KeyRing {
    fn new(
        purpose: &'static str,
        active_version: i16,
        keys: Vec<VersionedKey>,
    ) -> Result<Self, CryptographyError> {
        let mut versions = BTreeMap::new();
        for key in keys {
            let version = key.version();
            if versions.insert(version, key).is_some() {
                return Err(CryptographyError::InvalidKey(format!(
                    "duplicate {purpose} key version {version}"
                )));
            }
        }
        if !versions.contains_key(&active_version) {
            return Err(CryptographyError::ActiveKeyMissing {
                purpose,
                version: active_version,
            });
        }
        Ok(Self {
            active_version,
            keys: versions,
        })
    }

    fn active(&self, purpose: &'static str) -> Result<&VersionedKey, CryptographyError> {
        self.keys
            .get(&self.active_version)
            .ok_or(CryptographyError::ActiveKeyMissing {
                purpose,
                version: self.active_version,
            })
    }

    fn version(&self, version: i16) -> Result<&VersionedKey, CryptographyError> {
        self.keys
            .get(&version)
            .ok_or(CryptographyError::AuthenticationFailed)
    }
}

/// Cloneable cryptographic service with independently rotatable data and lookup keys.
#[derive(Clone)]
pub struct CryptoService {
    encryption_keys: Arc<BTreeMap<EncryptionPurpose, KeyRing>>,
    lookup_keys: Arc<KeyRing>,
}

impl CryptoService {
    /// Creates a service from versioned keys loaded outside the database.
    pub fn new(
        encryption_key_sets: Vec<EncryptionKeySet>,
        active_lookup_version: i16,
        lookup_keys: Vec<VersionedKey>,
    ) -> Result<Self, CryptographyError> {
        let mut encryption_keys = BTreeMap::new();
        for key_set in encryption_key_sets {
            let purpose = key_set.purpose;
            if encryption_keys
                .insert(
                    purpose,
                    KeyRing::new(purpose.as_str(), key_set.active_version, key_set.keys)?,
                )
                .is_some()
            {
                return Err(CryptographyError::InvalidKey(format!(
                    "duplicate encryption key purpose {purpose}"
                )));
            }
        }
        if encryption_keys.is_empty() {
            return Err(CryptographyError::InvalidKey(
                "at least one encryption key purpose is required".to_owned(),
            ));
        }
        Ok(Self {
            encryption_keys: Arc::new(encryption_keys),
            lookup_keys: Arc::new(KeyRing::new(
                "lookup HMAC",
                active_lookup_version,
                lookup_keys,
            )?),
        })
    }

    /// Returns the active data-encryption key version.
    #[must_use]
    pub fn active_encryption_version(&self, purpose: EncryptionPurpose) -> Option<i16> {
        self.encryption_keys
            .get(&purpose)
            .map(|ring| ring.active_version)
    }

    /// Returns the active lookup-HMAC key version.
    #[must_use]
    pub fn active_lookup_version(&self) -> i16 {
        self.lookup_keys.active_version
    }

    /// Parses a mounted keyring secret without storing key bytes in configuration.
    ///
    /// Format: `<purpose>.active=<version>` and `<purpose>.<version>=<base64-key>`.
    /// Supported purposes are the three `EncryptionPurpose` codes and `lookup_hmac`.
    pub fn from_keyring_text(value: &str) -> Result<Self, CryptographyError> {
        let mut active_versions = BTreeMap::<String, i16>::new();
        let mut keys = BTreeMap::<String, Vec<VersionedKey>>::new();
        for line in value.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, content) = line.split_once('=').ok_or_else(|| {
                CryptographyError::InvalidKey("keyring line is missing '='".to_owned())
            })?;
            let (purpose, suffix) = name.rsplit_once('.').ok_or_else(|| {
                CryptographyError::InvalidKey("keyring entry has no version".to_owned())
            })?;
            validate_keyring_purpose(purpose)?;
            if suffix == "active" {
                let version = content.parse::<i16>().map_err(|_| {
                    CryptographyError::InvalidKey("active key version is invalid".to_owned())
                })?;
                if active_versions
                    .insert(purpose.to_owned(), version)
                    .is_some()
                {
                    return Err(CryptographyError::InvalidKey(
                        "duplicate active key declaration".to_owned(),
                    ));
                }
            } else {
                let version = suffix.parse::<i16>().map_err(|_| {
                    CryptographyError::InvalidKey("key version is invalid".to_owned())
                })?;
                keys.entry(purpose.to_owned())
                    .or_default()
                    .push(VersionedKey::from_base64(version, content)?);
            }
        }

        let lookup_active = active_versions.remove("lookup_hmac").ok_or_else(|| {
            CryptographyError::InvalidKey("lookup_hmac active version is missing".to_owned())
        })?;
        let lookup_keys = keys.remove("lookup_hmac").ok_or_else(|| {
            CryptographyError::InvalidKey("lookup_hmac keys are missing".to_owned())
        })?;
        let mut encryption_sets = Vec::new();
        for (purpose_name, purpose) in [
            ("contact_encryption", EncryptionPurpose::Contact),
            ("identity_encryption", EncryptionPurpose::Identity),
            ("integration_encryption", EncryptionPurpose::Integration),
            ("media_encryption", EncryptionPurpose::Media),
        ] {
            match (
                active_versions.remove(purpose_name),
                keys.remove(purpose_name),
            ) {
                (Some(active), Some(purpose_keys)) => {
                    encryption_sets.push(EncryptionKeySet::new(purpose, active, purpose_keys));
                }
                (None, None) => {}
                _ => {
                    return Err(CryptographyError::InvalidKey(format!(
                        "incomplete keyring purpose {purpose_name}"
                    )));
                }
            }
        }
        if !active_versions.is_empty() || !keys.is_empty() {
            return Err(CryptographyError::InvalidKey(
                "keyring contains unsupported entries".to_owned(),
            ));
        }
        Self::new(encryption_sets, lookup_active, lookup_keys)
    }

    /// Encrypts plaintext with AES-256-GCM and record-bound associated data.
    pub fn encrypt(
        &self,
        purpose: EncryptionPurpose,
        context: EncryptionContext,
        plaintext: &[u8],
    ) -> Result<EncryptedValue, CryptographyError> {
        let ring =
            self.encryption_keys
                .get(&purpose)
                .ok_or(CryptographyError::ActiveKeyMissing {
                    purpose: purpose.as_str(),
                    version: 0,
                })?;
        let key = ring.active(purpose.as_str())?;
        let cipher = Aes256Gcm::new_from_slice(key.bytes()).map_err(|_| {
            CryptographyError::InvalidKey("data key must contain 32 bytes".to_owned())
        })?;
        let mut nonce_bytes = [0_u8; NONCE_LENGTH];
        getrandom::fill(&mut nonce_bytes).map_err(|_| CryptographyError::RandomGeneration)?;
        let nonce = Nonce::from(nonce_bytes);
        let associated_data = context.associated_data(purpose, key.version());
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| CryptographyError::AuthenticationFailed)?;
        Ok(EncryptedValue {
            purpose,
            key_version: key.version(),
            nonce: nonce.into(),
            ciphertext,
        })
    }

    /// Authenticates and decrypts a value under the key version stored beside it.
    pub fn decrypt(
        &self,
        context: EncryptionContext,
        encrypted: &EncryptedValue,
    ) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
        let ring = self
            .encryption_keys
            .get(&encrypted.purpose)
            .ok_or(CryptographyError::AuthenticationFailed)?;
        let key = ring.version(encrypted.key_version)?;
        let cipher = Aes256Gcm::new_from_slice(key.bytes())
            .map_err(|_| CryptographyError::AuthenticationFailed)?;
        let nonce = Nonce::from(encrypted.nonce);
        let associated_data = context.associated_data(encrypted.purpose, encrypted.key_version);
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &encrypted.ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| CryptographyError::AuthenticationFailed)?;
        Ok(Zeroizing::new(plaintext))
    }

    /// Produces a versioned HMAC-SHA-256 blind index for exact lookup.
    pub fn blind_index(
        &self,
        namespace: &str,
        normalized_value: &[u8],
    ) -> Result<(i16, [u8; 32]), CryptographyError> {
        let key = self.lookup_keys.active("lookup HMAC")?;
        Ok((
            key.version(),
            lookup::digest(key, namespace, normalized_value)?,
        ))
    }

    /// Produces lookup digests for every configured key during a rotation window.
    pub fn all_blind_indexes(
        &self,
        namespace: &str,
        normalized_value: &[u8],
    ) -> Result<Vec<(i16, [u8; 32])>, CryptographyError> {
        self.lookup_keys
            .keys
            .values()
            .map(|key| {
                Ok((
                    key.version(),
                    lookup::digest(key, namespace, normalized_value)?,
                ))
            })
            .collect()
    }
}

fn validate_keyring_purpose(purpose: &str) -> Result<(), CryptographyError> {
    if matches!(
        purpose,
        "contact_encryption"
            | "identity_encryption"
            | "integration_encryption"
            | "media_encryption"
            | "lookup_hmac"
    ) {
        Ok(())
    } else {
        Err(CryptographyError::InvalidKey(
            "keyring contains an unsupported purpose".to_owned(),
        ))
    }
}

impl fmt::Debug for CryptoService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CryptoService")
            .field(
                "encryption_key_purposes",
                &self.encryption_keys.keys().collect::<Vec<_>>(),
            )
            .field("active_lookup_version", &self.lookup_keys.active_version)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{CryptoService, EncryptionContext, EncryptionKeySet};
    use crate::{EncryptionPurpose, VersionedKey};
    use uuid::Uuid;

    fn service() -> Result<CryptoService, Box<dyn std::error::Error>> {
        Ok(CryptoService::new(
            vec![
                EncryptionKeySet::new(
                    EncryptionPurpose::Contact,
                    1,
                    vec![VersionedKey::from_bytes(1, [11; 32])?],
                ),
                EncryptionKeySet::new(
                    EncryptionPurpose::Identity,
                    1,
                    vec![VersionedKey::from_bytes(1, [13; 32])?],
                ),
                EncryptionKeySet::new(
                    EncryptionPurpose::Integration,
                    1,
                    vec![VersionedKey::from_bytes(1, [17; 32])?],
                ),
                EncryptionKeySet::new(
                    EncryptionPurpose::Media,
                    1,
                    vec![VersionedKey::from_bytes(1, [23; 32])?],
                ),
            ],
            1,
            vec![VersionedKey::from_bytes(1, [29; 32])?],
        )?)
    }

    #[test]
    fn round_trip_requires_matching_context() -> Result<(), Box<dyn std::error::Error>> {
        let service = service()?;
        let record_id = Uuid::now_v7();
        let context =
            EncryptionContext::new(crate::EncryptionNamespace::WHATSAPP_PHONE_E164, record_id);
        let encrypted = service.encrypt(EncryptionPurpose::Contact, context, b"+919876543210")?;
        let plaintext = service.decrypt(context, &encrypted)?;

        assert_eq!(plaintext.as_slice(), b"+919876543210");
        Ok(())
    }

    #[test]
    fn ciphertext_cannot_move_between_records() -> Result<(), Box<dyn std::error::Error>> {
        let service = service()?;
        let first = EncryptionContext::new(
            crate::EncryptionNamespace::WHATSAPP_PHONE_E164,
            Uuid::now_v7(),
        );
        let second = EncryptionContext::new(
            crate::EncryptionNamespace::WHATSAPP_PHONE_E164,
            Uuid::now_v7(),
        );
        let encrypted = service.encrypt(EncryptionPurpose::Contact, first, b"+919876543210")?;

        assert!(service.decrypt(second, &encrypted).is_err());
        Ok(())
    }

    #[test]
    fn profile_photo_ciphertext_is_bound_to_media_namespace_and_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let service = service()?;
        let photo_id = Uuid::now_v7();
        let context = EncryptionContext::new(crate::EncryptionNamespace::PROFILE_PHOTO, photo_id);
        let encrypted = service.encrypt(EncryptionPurpose::Media, context, b"sanitized-jpeg")?;

        assert_eq!(
            service.decrypt(context, &encrypted)?.as_slice(),
            b"sanitized-jpeg"
        );
        assert!(
            service
                .decrypt(
                    EncryptionContext::new(
                        crate::EncryptionNamespace::IDENTITY_PROVIDER_REFERENCE,
                        photo_id,
                    ),
                    &encrypted,
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn randomized_encryption_never_reuses_ciphertext() -> Result<(), Box<dyn std::error::Error>> {
        let service = service()?;
        let context =
            EncryptionContext::new(crate::EncryptionNamespace::WHATSAPP_WA_ID, Uuid::now_v7());
        let first = service.encrypt(EncryptionPurpose::Contact, context, b"919876543210")?;
        let second = service.encrypt(EncryptionPurpose::Contact, context, b"919876543210")?;

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
        Ok(())
    }

    #[test]
    fn debug_output_never_contains_key_material() -> Result<(), Box<dyn std::error::Error>> {
        let service = service()?;
        let output = format!("{service:?}");
        assert!(!output.contains("111111"));
        assert!(!output.contains("292929"));
        Ok(())
    }

    #[test]
    fn rotation_produces_one_lookup_per_configured_version()
    -> Result<(), Box<dyn std::error::Error>> {
        let service = CryptoService::new(
            vec![
                EncryptionKeySet::new(
                    EncryptionPurpose::Contact,
                    1,
                    vec![VersionedKey::from_bytes(1, [11; 32])?],
                ),
                EncryptionKeySet::new(
                    EncryptionPurpose::Identity,
                    1,
                    vec![VersionedKey::from_bytes(1, [13; 32])?],
                ),
                EncryptionKeySet::new(
                    EncryptionPurpose::Integration,
                    1,
                    vec![VersionedKey::from_bytes(1, [17; 32])?],
                ),
                EncryptionKeySet::new(
                    EncryptionPurpose::Media,
                    1,
                    vec![VersionedKey::from_bytes(1, [23; 32])?],
                ),
            ],
            2,
            vec![
                VersionedKey::from_bytes(1, [19; 32])?,
                VersionedKey::from_bytes(2, [29; 32])?,
            ],
        )?;
        let indexes = service.all_blind_indexes("whatsapp:phone_e164", b"+919876543210")?;

        assert_eq!(indexes.len(), 2);
        assert_ne!(indexes[0].1, indexes[1].1);
        Ok(())
    }

    #[test]
    fn parses_process_specific_keyring_file() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let integration = STANDARD.encode([17_u8; 32]);
        let lookup = STANDARD.encode([29_u8; 32]);
        let document = format!(
            "integration_encryption.active=1\nintegration_encryption.1={integration}\nlookup_hmac.active=1\nlookup_hmac.1={lookup}\n"
        );
        let service = CryptoService::from_keyring_text(&document)?;
        assert_eq!(
            service.active_encryption_version(EncryptionPurpose::Integration),
            Some(1)
        );
        assert_eq!(service.active_lookup_version(), 1);
        assert_eq!(
            service.active_encryption_version(EncryptionPurpose::Contact),
            None
        );
        Ok(())
    }
}
