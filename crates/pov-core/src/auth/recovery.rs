use std::{error::Error, fmt};

use base64ct::{Base64UrlUnpadded, Encoding};
use zeroize::Zeroizing;

use super::secret::SecretBytes;

const RECOVERY_PREFIX: &[u8] = b"povrec1_";
const RECOVERY_PAYLOAD_BYTES: usize = 16;
const RECOVERY_PAYLOAD_ENCODED_BYTES: usize = 22;
const RECOVERY_CODE_BYTES: usize = RECOVERY_PREFIX.len() + RECOVERY_PAYLOAD_ENCODED_BYTES;

/// A canonical saved recovery code.
pub struct RecoveryCode {
    secret: SecretBytes,
}

impl RecoveryCode {
    /// Generate a new code from the operating system CSPRNG.
    pub fn generate() -> Result<Self, RecoveryCodeError> {
        let mut payload = Zeroizing::new([0_u8; RECOVERY_PAYLOAD_BYTES]);
        getrandom::fill(payload.as_mut()).map_err(|_| RecoveryCodeError::RandomnessUnavailable)?;
        let encoded = Zeroizing::new(Base64UrlUnpadded::encode_string(payload.as_ref()));

        let mut code = Vec::with_capacity(RECOVERY_CODE_BYTES);
        code.extend_from_slice(RECOVERY_PREFIX);
        code.extend_from_slice(encoded.as_bytes());
        Self::parse(SecretBytes::new(code))
    }

    /// Parse an exact `povrec1_` code without normalization or alternate syntax.
    pub fn parse(raw: SecretBytes) -> Result<Self, RecoveryCodeError> {
        if raw.expose_secret().len() != RECOVERY_CODE_BYTES
            || !raw.expose_secret().starts_with(RECOVERY_PREFIX)
        {
            return Err(RecoveryCodeError::InvalidFormat);
        }
        let payload_text = raw
            .expose_secret()
            .get(RECOVERY_PREFIX.len()..)
            .ok_or(RecoveryCodeError::InvalidFormat)?;
        let payload_text =
            std::str::from_utf8(payload_text).map_err(|_| RecoveryCodeError::InvalidFormat)?;
        let mut payload = Zeroizing::new([0_u8; RECOVERY_PAYLOAD_BYTES]);
        let decoded_len = Base64UrlUnpadded::decode(payload_text, payload.as_mut())
            .map_err(|_| RecoveryCodeError::InvalidFormat)?
            .len();
        if decoded_len != RECOVERY_PAYLOAD_BYTES {
            return Err(RecoveryCodeError::InvalidFormat);
        }
        let canonical = Zeroizing::new(Base64UrlUnpadded::encode_string(payload.as_ref()));
        if canonical.as_bytes() != payload_text.as_bytes() {
            return Err(RecoveryCodeError::InvalidFormat);
        }

        Ok(Self { secret: raw })
    }

    #[cfg(test)]
    pub(crate) fn parse_bytes(raw: &[u8]) -> Result<Self, RecoveryCodeError> {
        Self::parse(SecretBytes::new(raw.to_vec()))
    }

    pub(super) fn copy_secret_for_worker(&self) -> SecretBytes {
        self.secret.copy_for_worker()
    }

    #[cfg(test)]
    pub(super) fn synthetic_display_bytes(&self) -> &[u8] {
        self.secret.expose_secret()
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryCode([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryCodeError {
    InvalidFormat,
    RandomnessUnavailable,
}

impl fmt::Display for RecoveryCodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFormat => "recovery code format is invalid",
            Self::RandomnessUnavailable => "recovery code generation is unavailable",
        })
    }
}

impl Error for RecoveryCodeError {}

#[cfg(test)]
mod tests {
    use super::{RecoveryCode, RecoveryCodeError};

    const CANONICAL: &[u8] = b"povrec1_AAECAwQFBgcICQoLDA0ODw";

    #[test]
    fn accepts_exact_canonical_code() {
        let code = RecoveryCode::parse_bytes(CANONICAL).expect("canonical recovery code");
        assert_eq!(code.synthetic_display_bytes(), CANONICAL);
    }

    #[test]
    fn rejects_prefix_length_alphabet_case_and_whitespace_variants() {
        for invalid in [
            b"POVREC1_AAECAwQFBgcICQoLDA0ODw".as_slice(),
            b"povrec1-AAECAwQFBgcICQoLDA0ODw".as_slice(),
            b"povrec1_AAECAwQFBgcICQoLDA0OD".as_slice(),
            b"povrec1_AAECAwQFBgcICQoLDA0ODw=".as_slice(),
            b"povrec1_AAECAwQFBgcICQoLDA0OD+".as_slice(),
            b" povrec1_AAECAwQFBgcICQoLDA0ODw".as_slice(),
            b"povrec1_AAECAwQFBgcICQoLDA0ODw\n".as_slice(),
        ] {
            assert_eq!(
                RecoveryCode::parse_bytes(invalid).unwrap_err(),
                RecoveryCodeError::InvalidFormat
            );
        }
    }

    #[test]
    fn rejects_noncanonical_last_bits() {
        assert_eq!(
            RecoveryCode::parse_bytes(b"povrec1_AAECAwQFBgcICQoLDA0ODx").unwrap_err(),
            RecoveryCodeError::InvalidFormat
        );
    }

    #[test]
    fn generated_codes_round_trip_and_differ() {
        let first = RecoveryCode::generate().expect("first code");
        let second = RecoveryCode::generate().expect("second code");

        assert_ne!(
            first.synthetic_display_bytes(),
            second.synthetic_display_bytes()
        );
        RecoveryCode::parse_bytes(first.synthetic_display_bytes()).expect("first code round trips");
        RecoveryCode::parse_bytes(second.synthetic_display_bytes())
            .expect("second code round trips");
    }

    #[test]
    fn debug_and_errors_do_not_echo_the_code() {
        let code = RecoveryCode::parse_bytes(CANONICAL).expect("canonical recovery code");
        let rendered = format!("{code:?}");
        assert_eq!(rendered, "RecoveryCode([REDACTED])");
        assert!(!rendered.contains("povrec1_"));

        let error = RecoveryCode::parse_bytes(b"povrec1_private").unwrap_err();
        assert!(!format!("{error:?}").contains("private"));
    }
}
