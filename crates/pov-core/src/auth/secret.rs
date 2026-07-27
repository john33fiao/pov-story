use std::fmt;

use zeroize::Zeroizing;

/// Owned secret bytes that are zeroized on drop and never formatted as content.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Take ownership of a raw secret buffer so every drop path zeroizes it.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    pub(crate) fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub(crate) fn copy_for_worker(&self) -> Self {
        Self::new(self.expose_secret().to_vec())
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::SecretBytes;

    #[test]
    fn debug_is_content_free() {
        let secret = SecretBytes::new(b"synthetic-secret".to_vec());
        let rendered = format!("{secret:?}");

        assert_eq!(rendered, "SecretBytes([REDACTED])");
        assert!(!rendered.contains("synthetic"));
    }
}
