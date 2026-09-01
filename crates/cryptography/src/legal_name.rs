use crate::CryptographyError;
use std::fmt;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// NFC-normalized legal name retained only inside an explicit private-data flow.
#[derive(Clone, Eq, PartialEq)]
pub struct NormalizedLegalName(Zeroizing<String>);

impl NormalizedLegalName {
    /// Trims outer whitespace, rejects controls, and normalizes Unicode to NFC.
    pub fn parse(value: &str) -> Result<Self, CryptographyError> {
        let trimmed = value.trim();
        let normalized: String = trimmed.nfc().collect();
        let valid = !normalized.is_empty()
            && normalized.chars().count() <= 200
            && !normalized.chars().any(char::is_control);
        if !valid {
            return Err(CryptographyError::InvalidLegalName);
        }
        Ok(Self(Zeroizing::new(normalized)))
    }

    /// Returns normalized text only at an authorized encryption boundary.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for NormalizedLegalName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NormalizedLegalName([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::NormalizedLegalName;

    #[test]
    fn trims_and_normalizes_without_case_folding() -> Result<(), Box<dyn std::error::Error>> {
        let name = NormalizedLegalName::parse("  Jose\u{301} Kumar  ")?;
        assert_eq!(name.expose(), "Jos\u{e9} Kumar");
        assert!(!format!("{name:?}").contains("Kumar"));
        Ok(())
    }

    #[test]
    fn rejects_control_characters_and_empty_values() {
        assert!(NormalizedLegalName::parse("   ").is_err());
        assert!(NormalizedLegalName::parse("Name\nInjected").is_err());
    }
}
