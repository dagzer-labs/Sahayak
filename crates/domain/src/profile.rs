use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

/// A normalized, bounded display name safe for review and publication.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProfessionalDisplayName(String);

impl ProfessionalDisplayName {
    /// Validates an already-trimmed NFKC display name.
    pub fn parse(value: impl Into<String>) -> Result<Self, DisplayNameError> {
        let value = value.into();
        if value.trim() != value {
            return Err(DisplayNameError::NotTrimmed);
        }
        let normalized: String = value.nfkc().collect();
        if normalized != value {
            return Err(DisplayNameError::NotNormalized);
        }
        let length = value.chars().count();
        if !(1..=80).contains(&length) {
            return Err(DisplayNameError::InvalidLength);
        }
        if value.chars().any(is_control_or_bidi) {
            return Err(DisplayNameError::ControlCharacter);
        }
        if looks_like_phone_number(&value) {
            return Err(DisplayNameError::PhoneNumber);
        }
        let lowercase = value.to_lowercase();
        if looks_like_url(&lowercase) {
            return Err(DisplayNameError::Url);
        }
        if lowercase
            .split(|character: char| !character.is_alphanumeric())
            .any(|word| {
                matches!(
                    word,
                    "sahayak" | "admin" | "administrator" | "moderator" | "support"
                )
            })
            || ["सहायक", "प्रशासक", "एडमिन", "समर्थन"]
                .iter()
                .any(|reserved| lowercase.contains(reserved))
        {
            return Err(DisplayNameError::Reserved);
        }
        Ok(Self(value))
    }

    /// Returns the validated display name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the value object and returns its validated string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for ProfessionalDisplayName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Display-name policy failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DisplayNameError {
    #[error("display name must be trimmed")]
    NotTrimmed,
    #[error("display name must be normalized as Unicode NFKC")]
    NotNormalized,
    #[error("display name must contain between 1 and 80 characters")]
    InvalidLength,
    #[error("display name contains a control or bidirectional formatting character")]
    ControlCharacter,
    #[error("display name must not be a phone number")]
    PhoneNumber,
    #[error("display name must not contain a URL")]
    Url,
    #[error("display name contains a reserved Sahayak role or brand term")]
    Reserved,
}

fn is_control_or_bidi(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn looks_like_phone_number(value: &str) -> bool {
    let mut digits = 0;
    for character in value.chars() {
        if character.is_numeric() {
            digits += 1;
            if digits >= 7 {
                return true;
            }
        } else if digits > 0
            && (character.is_whitespace() || matches!(character, '+' | '-' | '(' | ')' | '.'))
        {
            continue;
        } else {
            digits = 0;
        }
    }
    false
}

fn looks_like_url(lowercase: &str) -> bool {
    lowercase.contains("://")
        || lowercase.contains("www.")
        || lowercase.contains(".com")
        || lowercase.contains(".org")
        || lowercase.contains(".net")
        || lowercase.contains(".in")
        || lowercase.contains(".co")
}

/// Supported service-area radius in kilometres.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[repr(i16)]
pub enum ServiceRadiusKm {
    Two = 2,
    Five = 5,
    Ten = 10,
    TwentyFive = 25,
}

impl ServiceRadiusKm {
    #[must_use]
    pub const fn value(self) -> i16 {
        self as i16
    }

    pub const fn from_value(value: i16) -> Option<Self> {
        match value {
            2 => Some(Self::Two),
            5 => Some(Self::Five),
            10 => Some(Self::Ten),
            25 => Some(Self::TwentyFive),
            _ => None,
        }
    }
}

/// Professional languages supported during the pilot.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ProfessionalLanguage {
    #[serde(rename = "en-IN")]
    EnglishIndia,
    #[serde(rename = "hi-IN")]
    HindiIndia,
    #[serde(rename = "mr-IN")]
    MarathiIndia,
}

impl ProfessionalLanguage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EnglishIndia => "en-IN",
            Self::HindiIndia => "hi-IN",
            Self::MarathiIndia => "mr-IN",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "en-IN" => Some(Self::EnglishIndia),
            "hi-IN" => Some(Self::HindiIndia),
            "mr-IN" => Some(Self::MarathiIndia),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DisplayNameError, ProfessionalDisplayName};

    #[test]
    fn accepts_common_non_unique_names() -> Result<(), DisplayNameError> {
        assert_eq!(ProfessionalDisplayName::parse("Ravi")?.as_str(), "Ravi");
        assert_eq!(ProfessionalDisplayName::parse("Ravi")?.as_str(), "Ravi");
        Ok(())
    }

    #[test]
    fn rejects_sensitive_or_deceptive_display_names() {
        for value in [
            " Ravi ",
            "+91 98765 43210",
            "https://example.com",
            "Sahayak Admin",
            "९८७६५४३२१०",
            "सहायक प्रशासक",
            "Ravi\u{202e}name",
        ] {
            assert!(ProfessionalDisplayName::parse(value).is_err(), "{value}");
        }
    }
}
