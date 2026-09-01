use sha2::{Digest, Sha256};

/// Computes a stable SHA-256 digest for collision detection of normalized content.
///
/// This digest is not suitable for searching low-entropy private identifiers; use
/// the versioned HMAC blind index for phone numbers and provider identities.
#[must_use]
pub fn content_sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

#[cfg(test)]
mod tests {
    use super::content_sha256;

    #[test]
    fn content_digest_is_stable() {
        assert_eq!(content_sha256(b"event"), content_sha256(b"event"));
        assert_ne!(content_sha256(b"event"), content_sha256(b"other"));
    }
}
