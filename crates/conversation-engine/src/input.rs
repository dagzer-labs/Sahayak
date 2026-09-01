use sahayak_domain::OutboundMessageId;
use std::fmt;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

/// Input normalization failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum InputError {
    #[error("text input is empty, oversized, or contains controls")]
    InvalidText,
    #[error("action identifier is not a bounded machine code")]
    InvalidAction,
}

/// Unicode-normalized text used only for deterministic command matching.
#[derive(Clone, Eq, PartialEq)]
pub struct NormalizedText {
    value: String,
    command: String,
}

impl NormalizedText {
    /// Applies NFKC, trims Unicode whitespace, and collapses internal whitespace.
    pub fn parse(value: &str) -> Result<Self, InputError> {
        let normalized: String = value.nfkc().collect();
        if normalized.chars().any(char::is_control) {
            return Err(InputError::InvalidText);
        }
        let collapsed = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
        if collapsed.is_empty() || collapsed.chars().count() > 1_024 {
            return Err(InputError::InvalidText);
        }
        let command = collapsed.chars().flat_map(char::to_lowercase).collect();
        Ok(Self {
            value: collapsed,
            command,
        })
    }

    /// Returns normalized text for state-specific exact matching.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns case-normalized text for reserved command matching.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }
}

impl fmt::Debug for NormalizedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NormalizedText([REDACTED])")
    }
}

/// Language-neutral bounded action identifier returned by a channel adapter.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ActionId(String);

impl ActionId {
    /// Parses a stable machine action code.
    pub fn parse(value: &str) -> Result<Self, InputError> {
        let valid = !value.is_empty()
            && value.len() <= 128
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-' | b':')
            });
        if !valid {
            return Err(InputError::InvalidAction);
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the machine identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ActionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ActionId").field(&self.0).finish()
    }
}

/// Canonical input understood by the provider-neutral engine.
#[derive(Clone, Debug)]
pub enum UserInput {
    /// Normalized user text.
    Text(NormalizedText),
    /// Interactive action plus resolved internal prompt reference.
    Action {
        id: ActionId,
        reply_to: Option<OutboundMessageId>,
    },
    /// Valid location supplied when the current workflow requests it.
    Location,
    /// Media supplied when the current workflow requests it.
    Media,
    /// Provider content not supported in the current state.
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::{ActionId, NormalizedText};

    #[test]
    fn normalizes_unicode_and_whitespace() -> Result<(), Box<dyn std::error::Error>> {
        let text = NormalizedText::parse("  ＭＥＮＵ   Test  ")?;
        assert_eq!(text.value(), "MENU Test");
        assert_eq!(text.command(), "menu test");
        assert!(!format!("{text:?}").contains("MENU"));
        Ok(())
    }

    #[test]
    fn action_ids_are_language_neutral_machine_codes() {
        assert!(ActionId::parse("main.find").is_ok());
        assert!(ActionId::parse("मदद").is_err());
        assert!(ActionId::parse("Main Find").is_err());
    }
}
