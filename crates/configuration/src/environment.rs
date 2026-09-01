use serde::Deserialize;
use std::fmt;

/// Identifies the operational environment in which a Sahayak process runs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEnvironment {
    /// Developer workstation or local containers.
    Development,
    /// Automated test execution.
    Test,
    /// Production-like environment for release validation.
    Staging,
    /// Live environment containing real user data.
    Production,
}

impl RuntimeEnvironment {
    /// Returns true only for the live production environment.
    #[must_use]
    pub const fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }
}

impl fmt::Display for RuntimeEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Development => "development",
            Self::Test => "test",
            Self::Staging => "staging",
            Self::Production => "production",
        };

        formatter.write_str(value)
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeEnvironment;

    #[test]
    fn deserializes_supported_environment_names() -> Result<(), serde_json::Error> {
        let production: RuntimeEnvironment = serde_json::from_str("\"production\"")?;
        let development: RuntimeEnvironment = serde_json::from_str("\"development\"")?;

        assert!(production.is_production());
        assert!(!development.is_production());
        Ok(())
    }

    #[test]
    fn renders_stable_environment_name() {
        assert_eq!(RuntimeEnvironment::Staging.to_string(), "staging");
    }
}
