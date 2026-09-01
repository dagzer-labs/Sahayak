use crate::CryptographyError;
use std::fmt;
use zeroize::Zeroizing;

/// Canonical E.164 phone number suitable for encryption and blind indexing.
#[derive(Clone, Eq, PartialEq)]
pub struct NormalizedPhoneNumber(Zeroizing<String>);

impl NormalizedPhoneNumber {
    /// Validates an already normalized E.164 phone number.
    pub fn parse(value: &str) -> Result<Self, CryptographyError> {
        let national_number = value
            .strip_prefix("+91")
            .ok_or(CryptographyError::InvalidPhoneNumber)?;
        let valid = national_number.len() == 10
            && national_number
                .as_bytes()
                .first()
                .is_some_and(|digit| matches!(digit, b'6'..=b'9'))
            && national_number.bytes().all(|byte| byte.is_ascii_digit());
        if !valid {
            return Err(CryptographyError::InvalidPhoneNumber);
        }
        Ok(Self(Zeroizing::new(value.to_owned())))
    }

    /// Returns canonical E.164 text at an explicit integration boundary.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for NormalizedPhoneNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NormalizedPhoneNumber([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::NormalizedPhoneNumber;

    #[test]
    fn accepts_canonical_e164() -> Result<(), Box<dyn std::error::Error>> {
        let phone = NormalizedPhoneNumber::parse("+919876543210")?;
        assert_eq!(phone.expose(), "+919876543210");
        assert!(!format!("{phone:?}").contains("9876543210"));
        Ok(())
    }

    #[test]
    fn rejects_local_or_formatted_numbers() {
        assert!(NormalizedPhoneNumber::parse("9876543210").is_err());
        assert!(NormalizedPhoneNumber::parse("+91 98765 43210").is_err());
        assert!(NormalizedPhoneNumber::parse("+0123456789").is_err());
        assert!(NormalizedPhoneNumber::parse("+14155552671").is_err());
        assert!(NormalizedPhoneNumber::parse("+915123456789").is_err());
    }
}
