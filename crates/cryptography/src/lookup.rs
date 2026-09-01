use crate::{CryptographyError, VersionedKey};
use hmac::{Hmac, Mac, digest::KeyInit};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn digest(
    key: &VersionedKey,
    namespace: &str,
    value: &[u8],
) -> Result<[u8; 32], CryptographyError> {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key.bytes()).map_err(|_| {
        CryptographyError::InvalidKey("lookup key must contain 32 bytes".to_owned())
    })?;
    mac.update(b"sahayak:lookup:v1\0");
    update_length_prefixed(&mut mac, namespace.as_bytes());
    update_length_prefixed(&mut mac, value);

    let bytes = mac.finalize().into_bytes();
    Ok(bytes.into())
}

fn update_length_prefixed(mac: &mut HmacSha256, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

#[cfg(test)]
mod tests {
    use super::digest;
    use crate::VersionedKey;

    #[test]
    fn digest_is_stable_and_domain_separated() -> Result<(), Box<dyn std::error::Error>> {
        let key = VersionedKey::from_bytes(1, [9; 32])?;
        let first = digest(&key, "whatsapp:phone_e164", b"+919876543210")?;
        let repeated = digest(&key, "whatsapp:phone_e164", b"+919876543210")?;
        let other_namespace = digest(&key, "whatsapp:wa_id", b"+919876543210")?;

        assert_eq!(first, repeated);
        assert_ne!(first, other_namespace);
        Ok(())
    }
}
