use sahayak_persistence::PersistenceError;
use std::io;
use thiserror::Error;

/// Fatal background-worker process error.
#[derive(Debug, Error)]
pub enum WorkerError {
    /// PostgreSQL configuration or startup failed.
    #[error(transparent)]
    Persistence(#[from] PersistenceError),

    /// The operating-system shutdown signal could not be observed.
    #[error("failed to listen for worker shutdown signal: {0}")]
    ShutdownSignal(#[source] io::Error),

    /// Repeated database probes failed and the process must be restarted.
    #[error("database remained unhealthy for the configured failure budget")]
    DatabaseUnhealthy,

    /// WhatsApp access token, keyring, or client configuration is invalid.
    #[error("WhatsApp worker initialization failed: {0}")]
    WhatsAppInitialization(String),

    /// Razorpay credentials or client configuration are invalid.
    #[error("Razorpay worker initialization failed: {0}")]
    RazorpayInitialization(String),
}
