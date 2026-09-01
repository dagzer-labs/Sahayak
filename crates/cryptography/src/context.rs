use std::fmt;

/// Independent encryption-key domain for one category of private data.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EncryptionPurpose {
    /// WhatsApp identifiers and contact phone numbers.
    Contact,
    /// Legal identity and verification-provider references.
    Identity,
    /// Trusted inbound provider payloads retained for processing.
    Integration,
    /// Sanitized professional profile media.
    Media,
}

impl EncryptionPurpose {
    /// Returns the stable database key-purpose code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Contact => "contact_encryption",
            Self::Identity => "identity_encryption",
            Self::Integration => "integration_encryption",
            Self::Media => "media_encryption",
        }
    }
}

impl fmt::Display for EncryptionPurpose {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable associated-data namespaces for encrypted Sahayak fields.
///
/// Names are part of the cryptographic contract and must not be renamed when
/// Rust modules or database tables are reorganized.
pub struct EncryptionNamespace;

impl EncryptionNamespace {
    /// Meta WhatsApp account identifier.
    pub const WHATSAPP_WA_ID: &'static str = "private_data.whatsapp_identity.wa_id.v1";
    /// Canonical phone number disclosed only under contact rules.
    pub const WHATSAPP_PHONE_E164: &'static str = "private_data.whatsapp_identity.phone_e164.v1";
    /// Versioned private legal-identity payload.
    pub const ACCOUNT_IDENTITY_PAYLOAD: &'static str = "private_data.account_identity.payload.v1";
    /// Normalized trusted inbound provider-event payload.
    pub const INBOUND_EVENT_PAYLOAD: &'static str = "integration.inbound_event.payload.v1";
    /// Validated serialized outbound provider request.
    pub const OUTBOUND_MESSAGE_PAYLOAD: &'static str = "messaging.outbound_message.payload.v1";
    /// Sanitized JPEG bytes for a private professional profile photo record.
    pub const PROFILE_PHOTO: &'static str = "private_data.profile_photo.sanitized_jpeg.v1";
    /// Random opaque identity-provider reference.
    pub const IDENTITY_PROVIDER_REFERENCE: &'static str =
        "private_data.identity_verification.provider_reference.v1";
    /// Optional private text attached to an introduction review revision.
    pub const REVIEW_FEEDBACK: &'static str = "review.review_revision.feedback.v1";
    /// Private reporter-authored safety incident description.
    pub const SAFETY_REPORT_DESCRIPTION: &'static str = "safety.report.description.v1";
}
