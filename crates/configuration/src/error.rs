use thiserror::Error;

/// Error returned when application settings cannot be loaded or validated.
#[derive(Debug, Error)]
pub enum SettingsError {
    /// The configuration source could not be read or deserialized.
    #[error("failed to load application configuration: {0}")]
    Load(#[from] config::ConfigError),

    /// A setting was syntactically valid but unsafe or internally inconsistent.
    #[error("invalid application configuration: {0}")]
    Invalid(String),
}
