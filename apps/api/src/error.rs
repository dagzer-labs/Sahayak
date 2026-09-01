use sahayak_persistence::PersistenceError;
use std::{io, time::Duration};
use thiserror::Error;

/// Fatal API process error.
#[derive(Debug, Error)]
pub enum ApiError {
    /// PostgreSQL configuration or startup failed.
    #[error(transparent)]
    Persistence(#[from] PersistenceError),

    /// The TCP listener could not be created.
    #[error("failed to bind API listener: {0}")]
    Bind(#[source] io::Error),

    /// The HTTP server terminated unexpectedly.
    #[error("API server failed: {0}")]
    Serve(#[source] io::Error),

    /// In-flight requests did not drain within the configured deadline.
    #[error("API shutdown exceeded the {0:?} grace period")]
    ShutdownTimeout(Duration),

    /// WhatsApp secrets, keys, or transport configuration could not initialize.
    #[error("WhatsApp transport initialization failed: {0}")]
    WhatsAppInitialization(String),

    /// Razorpay secrets or webhook processing could not initialize.
    #[error("Razorpay initialization failed: {0}")]
    RazorpayInitialization(String),
}
