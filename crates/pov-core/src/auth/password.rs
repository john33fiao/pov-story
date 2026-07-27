use std::{error::Error, fmt, str};

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use super::secret::SecretBytes;

const MAX_RAW_PASSWORD_BYTES: usize = 1024;
const MIN_NORMALIZED_CODE_POINTS: usize = 15;
const MAX_NORMALIZED_CODE_POINTS: usize = 128;

/// A password after the exact input boundary and NFC policy have been applied.
pub struct NormalizedPassword {
    secret: SecretBytes,
}

impl NormalizedPassword {
    /// Validate raw request bytes and retain the NFC-normalized password.
    ///
    /// Spaces and Unicode are preserved. No trimming, truncation, case folding,
    /// or composition rule is applied beyond NFC.
    pub fn parse(raw: SecretBytes) -> Result<Self, PasswordInputError> {
        if raw.expose_secret().len() > MAX_RAW_PASSWORD_BYTES {
            return Err(PasswordInputError::RawInputTooLong);
        }
        let decoded =
            str::from_utf8(raw.expose_secret()).map_err(|_| PasswordInputError::InvalidUtf8)?;
        if decoded.contains('\0') {
            return Err(PasswordInputError::ContainsNul);
        }

        let normalized = Zeroizing::new(decoded.nfc().collect::<String>());
        let code_points = normalized.chars().count();
        if !(MIN_NORMALIZED_CODE_POINTS..=MAX_NORMALIZED_CODE_POINTS).contains(&code_points) {
            return Err(PasswordInputError::NormalizedLengthOutOfRange);
        }

        Ok(Self {
            secret: SecretBytes::new(normalized.as_bytes().to_vec()),
        })
    }

    #[cfg(test)]
    pub(crate) fn parse_bytes(raw: &[u8]) -> Result<Self, PasswordInputError> {
        Self::parse(SecretBytes::new(raw.to_vec()))
    }

    #[cfg(test)]
    pub(super) fn normalized_str(&self) -> &str {
        str::from_utf8(self.secret.expose_secret()).expect("normalized password is valid UTF-8")
    }

    pub(super) fn copy_secret_for_worker(&self) -> SecretBytes {
        self.secret.copy_for_worker()
    }
}

impl fmt::Debug for NormalizedPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NormalizedPassword([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordInputError {
    RawInputTooLong,
    InvalidUtf8,
    ContainsNul,
    NormalizedLengthOutOfRange,
}

impl fmt::Display for PasswordInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RawInputTooLong => "password input is too long",
            Self::InvalidUtf8 => "password input is not valid UTF-8",
            Self::ContainsNul => "password input contains a forbidden code point",
            Self::NormalizedLengthOutOfRange => {
                "normalized password length is outside the supported range"
            }
        })
    }
}

impl Error for PasswordInputError {}

#[cfg(test)]
mod tests {
    use super::{NormalizedPassword, PasswordInputError};

    #[test]
    fn accepts_exact_code_point_boundaries_and_preserves_spaces() {
        let minimum =
            NormalizedPassword::parse_bytes("  12345678901  ".as_bytes()).expect("15 points");
        assert_eq!(minimum.normalized_str(), "  12345678901  ");

        let maximum_raw = "가".repeat(128);
        let maximum = NormalizedPassword::parse_bytes(maximum_raw.as_bytes())
            .expect("128 code points accepted");
        assert_eq!(maximum.normalized_str().chars().count(), 128);
    }

    #[test]
    fn rejects_code_point_and_raw_byte_boundaries() {
        assert_eq!(
            NormalizedPassword::parse_bytes(b"12345678901234").unwrap_err(),
            PasswordInputError::NormalizedLengthOutOfRange
        );
        assert_eq!(
            NormalizedPassword::parse_bytes("가".repeat(129).as_bytes()).unwrap_err(),
            PasswordInputError::NormalizedLengthOutOfRange
        );
        assert_eq!(
            NormalizedPassword::parse_bytes(&vec![b'a'; 1025]).unwrap_err(),
            PasswordInputError::RawInputTooLong
        );
    }

    #[test]
    fn rejects_invalid_utf8_and_nul_without_echoing_input() {
        assert_eq!(
            NormalizedPassword::parse_bytes(&[0xff]).unwrap_err(),
            PasswordInputError::InvalidUtf8
        );
        let error = NormalizedPassword::parse_bytes(b"123456789012345\0").unwrap_err();
        assert_eq!(error, PasswordInputError::ContainsNul);
        assert!(!format!("{error:?}").contains("123456789012345"));
    }

    #[test]
    fn applies_only_nfc_normalization() {
        let decomposed = "Cafe\u{301} password 123";
        let normalized = NormalizedPassword::parse_bytes(decomposed.as_bytes())
            .expect("valid normalized password");

        assert_eq!(normalized.normalized_str(), "Café password 123");
    }

    #[test]
    fn debug_is_redacted() {
        let password =
            NormalizedPassword::parse_bytes(b"synthetic password").expect("valid password input");
        let rendered = format!("{password:?}");

        assert_eq!(rendered, "NormalizedPassword([REDACTED])");
        assert!(!rendered.contains("synthetic"));
    }
}
