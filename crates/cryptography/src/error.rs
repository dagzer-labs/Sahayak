use thiserror::Error;

/// Error returned by cryptographic key loading or field protection.
#[derive(Debug, Error)]
pub enum CryptographyError {
    /// A key version or key length is invalid.
    #[error("invalid cryptographic key configuration: {0}")]
    InvalidKey(String),

    /// An active key version is absent from the configured key ring.
    #[error("active {purpose} key version {version} is not configured")]
    ActiveKeyMissing {
        /// Key purpose used by the failed operation.
        purpose: &'static str,
        /// Missing version number.
        version: i16,
    },

    /// Ciphertext authentication failed or its key is unavailable.
    #[error("encrypted value could not be authenticated")]
    AuthenticationFailed,

    /// The operating system could not provide a cryptographically secure nonce.
    #[error("secure random number generation failed")]
    RandomGeneration,

    /// Input is not a canonical E.164 phone number.
    #[error("phone number must be a canonical Indian mobile E.164 number")]
    InvalidPhoneNumber,

    /// Legal name is empty, oversized, or contains control characters.
    #[error("legal name is not valid normalized private identity data")]
    InvalidLegalName,
}
