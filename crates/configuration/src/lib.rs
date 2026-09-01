//! Typed, validated configuration shared by every Sahayak process.

mod environment;
mod error;
mod secret_file;
mod settings;

pub use environment::RuntimeEnvironment;
pub use error::SettingsError;
pub use secret_file::{SecretFileError, load_secret_file};
pub use settings::{
    DatabaseSettings, HttpSettings, LogFormat, ObservabilitySettings, RazorpaySettings, Settings,
    WhatsAppSettings, WorkerSettings,
};
