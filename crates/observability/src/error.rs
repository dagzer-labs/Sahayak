use thiserror::Error;

/// Error returned while initializing process observability.
#[derive(Debug, Error)]
pub enum ObservabilityError {
    /// The configured tracing filter is not valid.
    #[error("invalid log filter: {0}")]
    InvalidFilter(String),

    /// A global tracing subscriber was already installed.
    #[error("failed to install global tracing subscriber: {0}")]
    Subscriber(String),

    /// Sentry DSN could not be loaded or parsed.
    #[error("invalid Sentry configuration")]
    Sentry,
}
