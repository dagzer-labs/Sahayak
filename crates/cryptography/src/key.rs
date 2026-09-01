use crate::CryptographyError;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::fmt;
use zeroize::Zeroizing;

const KEY_LENGTH: usize = 32;

/// Versioned 256-bit secret loaded from a secret manager or protected environment.
#[derive(Clone)]
pub struct VersionedKey {
    version: i16,
    bytes: Zeroizing<[u8; KEY_LENGTH]>,
}

impl VersionedKey {
    /// Parses a base64-encoded 256-bit key.
    pub fn from_base64(version: i16, encoded: &str) -> Result<Self, CryptographyError> {
        if version <= 0 {
            return Err(CryptographyError::InvalidKey(
                "key version must be positive".to_owned(),
            ));
        }
        let decoded = Zeroizing::new(STANDARD.decode(encoded).map_err(|_| {
            CryptographyError::InvalidKey("key material is not valid base64".to_owned())
        })?);
        let bytes: [u8; KEY_LENGTH] = decoded.as_slice().try_into().map_err(|_| {
            CryptographyError::InvalidKey("key material must decode to exactly 32 bytes".to_owned())
        })?;
        Ok(Self {
            version,
            bytes: Zeroizing::new(bytes),
        })
    }

    /// Creates test or externally loaded key material from exactly 32 bytes.
    pub fn from_bytes(version: i16, bytes: [u8; KEY_LENGTH]) -> Result<Self, CryptographyError> {
        if version <= 0 {
            return Err(CryptographyError::InvalidKey(
                "key version must be positive".to_owned(),
            ));
        }
        Ok(Self {
            version,
            bytes: Zeroizing::new(bytes),
        })
    }

    /// Returns the key version stored beside protected data.
    #[must_use]
    pub const fn version(&self) -> i16 {
        self.version
    }

    pub(crate) fn bytes(&self) -> &[u8; KEY_LENGTH] {
        &self.bytes
    }
}

impl fmt::Debug for VersionedKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VersionedKey")
            .field("version", &self.version)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::VersionedKey;
    use base64::{Engine, engine::general_purpose::STANDARD};

    #[test]
    fn parses_exactly_256_bits() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = STANDARD.encode([7_u8; 32]);
        let key = VersionedKey::from_base64(1, &encoded)?;
        assert_eq!(key.version(), 1);
        assert!(!format!("{key:?}").contains(&encoded));
        Ok(())
    }

    #[test]
    fn rejects_wrong_key_length() {
        let encoded = STANDARD.encode([7_u8; 16]);
        assert!(VersionedKey::from_base64(1, &encoded).is_err());
    }
}
