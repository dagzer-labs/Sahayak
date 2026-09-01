use std::fmt;
use thiserror::Error;

/// Operational treatment for a failed Meta send request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureClass {
    /// Safe to retry under bounded backoff when the send outcome is known to be rejected.
    Retryable,
    /// Request cannot succeed without changing message data or account state.
    Terminal,
    /// Credential, permission, or account-integrity intervention is required.
    Authorization,
    /// Free-form content was rejected because the customer-service window closed.
    ServiceWindowClosed,
    /// Meta may have accepted the message even though no receipt was obtained.
    Ambiguous,
}

/// Structured Meta Graph API failure with sensitive free text redacted from diagnostics.
#[derive(Clone)]
pub struct ApiFailure {
    /// HTTP response status.
    pub http_status: u16,
    /// Stable Meta error code when supplied.
    pub code: Option<i64>,
    /// Operational classification derived primarily from Meta's code.
    pub class: FailureClass,
    /// Opaque Meta trace identifier useful for support escalation.
    pub trace_id: Option<String>,
    /// Provider retry hint when a numeric `Retry-After` header is present.
    pub retry_after_seconds: Option<u64>,
}

impl fmt::Debug for ApiFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiFailure")
            .field("http_status", &self.http_status)
            .field("code", &self.code)
            .field("class", &self.class)
            .field("trace_id", &self.trace_id)
            .field("retry_after_seconds", &self.retry_after_seconds)
            .finish()
    }
}

/// Error returned by WhatsApp transport construction or delivery.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WhatsAppError {
    /// Client configuration is unsafe or malformed.
    #[error("invalid WhatsApp client configuration: {0}")]
    InvalidConfiguration(String),

    /// Connection failed before a response was received.
    #[error("WhatsApp API connection failed")]
    Connection,

    /// Timeout or transport interruption left the delivery outcome unknown.
    #[error("WhatsApp API send outcome is ambiguous")]
    AmbiguousTransport,

    /// Meta returned a structured rejection.
    #[error("WhatsApp API rejected the message")]
    Api(ApiFailure),

    /// Meta returned a success response that did not satisfy its documented contract.
    #[error("WhatsApp API returned an invalid success response")]
    InvalidSuccessResponse,

    /// Meta media metadata or downloaded bytes violated the expected contract.
    #[error("WhatsApp media response is invalid")]
    InvalidMediaResponse,

    /// A media download exceeded the configured transport bound.
    #[error("WhatsApp media exceeds the configured size limit")]
    MediaTooLarge,

    /// Meta returned a media URL that is not safe for an authenticated request.
    #[error("WhatsApp media download URL is not allowed")]
    UnsafeMediaUrl,

    /// Media retrieval failed without changing any externally visible state.
    #[error("WhatsApp media retrieval failed")]
    MediaTransport,
}

impl ApiFailure {
    pub(crate) fn classify(http_status: u16, code: Option<i64>) -> FailureClass {
        match code {
            Some(131_047) => FailureClass::ServiceWindowClosed,
            Some(0 | 3 | 10 | 190 | 368 | 131_031) => FailureClass::Authorization,
            Some(200..=299) => FailureClass::Authorization,
            Some(
                1 | 2 | 4 | 80_007 | 130_429 | 131_000 | 131_016 | 131_048 | 131_056 | 131_057,
            ) => FailureClass::Retryable,
            _ if http_status == 401 || http_status == 403 => FailureClass::Authorization,
            _ if http_status == 429 => FailureClass::Retryable,
            _ if http_status >= 500 && code.is_some() => FailureClass::Retryable,
            _ if http_status >= 500 => FailureClass::Ambiguous,
            _ => FailureClass::Terminal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiFailure, FailureClass};

    #[test]
    fn classifies_operationally_important_codes() {
        assert_eq!(
            ApiFailure::classify(400, Some(131_047)),
            FailureClass::ServiceWindowClosed
        );
        assert_eq!(
            ApiFailure::classify(400, Some(130_429)),
            FailureClass::Retryable
        );
        assert_eq!(
            ApiFailure::classify(401, Some(190)),
            FailureClass::Authorization
        );
        assert_eq!(ApiFailure::classify(500, None), FailureClass::Ambiguous);
        assert_eq!(
            ApiFailure::classify(429, Some(999_999)),
            FailureClass::Retryable
        );
        assert_eq!(
            ApiFailure::classify(403, Some(999_999)),
            FailureClass::Authorization
        );
    }
}
