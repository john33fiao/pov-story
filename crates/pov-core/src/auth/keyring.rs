use std::{error::Error, fmt, num::NonZeroU64, str};

use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::SecretBytes;

const KEYRING_MAGIC: &[u8; 8] = b"POVKEYR\0";
const KEYRING_FORMAT_VERSION: u16 = 1;
pub(super) const ACTIVE_ONLY_LENGTH: usize = 170;
pub(super) const WITH_VERIFY_ONLY_LENGTH: usize = 261;
const ACTIVE_PUBLIC_OFFSET: usize = 30;
const ACTIVE_SEED_OFFSET: usize = 62;
const ACTIVE_KID_OFFSET: usize = 94;
const VERIFY_ONLY_TAG_OFFSET: usize = 137;
const VERIFY_ONLY_ACTIVATED_OFFSET: usize = 138;
const VERIFY_ONLY_UNTIL_OFFSET: usize = 146;
const VERIFY_ONLY_PUBLIC_OFFSET: usize = 154;
const VERIFY_ONLY_KID_OFFSET: usize = 186;
const CHECKSUM_BYTES: usize = 32;
const KEY_BYTES: usize = 32;
const KID_BYTES: usize = 43;
const VERIFY_ONLY_OVERLAP_MICROS: u64 = 11 * 60 * 1_000_000;
const PLANNED_ROTATION_MICROS: u64 = 90 * 24 * 60 * 60 * 1_000_000;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct KeyId([u8; KID_BYTES]);

impl KeyId {
    fn from_verifying_key(verifying_key: &VerifyingKey) -> Self {
        let encoded_public = Base64UrlUnpadded::encode_string(verifying_key.as_bytes());
        let canonical_jwk =
            format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{encoded_public}\"}}");
        let digest = Sha256::digest(canonical_jwk.as_bytes());
        let encoded_kid = Base64UrlUnpadded::encode_string(&digest);
        let mut bytes = [0_u8; KID_BYTES];
        bytes.copy_from_slice(encoded_kid.as_bytes());
        Self(bytes)
    }

    pub(super) fn from_stored_bytes(bytes: &[u8]) -> Result<Self, KeyringError> {
        let bytes: [u8; KID_BYTES] = bytes
            .try_into()
            .map_err(|_| KeyringError::InvalidEncoding)?;
        let text = str::from_utf8(&bytes).map_err(|_| KeyringError::InvalidKeyMaterial)?;
        let mut decoded = [0_u8; KEY_BYTES];
        let decoded_len = Base64UrlUnpadded::decode(text, &mut decoded)
            .map_err(|_| KeyringError::InvalidKeyMaterial)?
            .len();
        if decoded_len != KEY_BYTES
            || Base64UrlUnpadded::encode_string(&decoded).as_bytes() != bytes
        {
            return Err(KeyringError::InvalidKeyMaterial);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn as_str(&self) -> &str {
        str::from_utf8(&self.0).expect("derived key IDs are canonical ASCII")
    }

    pub(super) fn as_bytes(&self) -> &[u8; KID_BYTES] {
        &self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("KeyId")
            .field(&self.as_str())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyringVersion(NonZeroU64);

impl KeyringVersion {
    pub(crate) fn new(value: u64) -> Result<Self, KeyringError> {
        if value > i64::MAX as u64 {
            return Err(KeyringError::InvalidLifecycle);
        }
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(KeyringError::InvalidLifecycle)
    }

    pub(crate) fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct AuthTimestampMicros(u64);

impl AuthTimestampMicros {
    pub(crate) fn new(value: u64) -> Result<Self, KeyringError> {
        if value > i64::MAX as u64 {
            return Err(KeyringError::InvalidLifecycle);
        }
        Ok(Self(value))
    }

    pub(crate) fn get(self) -> u64 {
        self.0
    }

    fn checked_add(self, delta: u64) -> Result<Self, KeyringError> {
        let value = self
            .0
            .checked_add(delta)
            .ok_or(KeyringError::InvalidLifecycle)?;
        Self::new(value)
    }
}

struct ActiveKey {
    activated_at: AuthTimestampMicros,
    signing_key: SigningKey,
    kid: KeyId,
}

struct VerifyOnlyKey {
    activated_at: AuthTimestampMicros,
    verify_until: AuthTimestampMicros,
    verifying_key: VerifyingKey,
    kid: KeyId,
}

pub(crate) struct Keyring {
    version: KeyringVersion,
    active: ActiveKey,
    verify_only: Option<VerifyOnlyKey>,
}

impl Keyring {
    pub(crate) fn generate(
        version: KeyringVersion,
        activated_at: AuthTimestampMicros,
    ) -> Result<Self, KeyringError> {
        for _ in 0..8 {
            let mut seed = Zeroizing::new([0_u8; KEY_BYTES]);
            getrandom::fill(seed.as_mut()).map_err(|_| KeyringError::OperationFailed)?;
            if seed.iter().all(|byte| *byte == 0) {
                continue;
            }
            if let Ok(active) = active_from_seed(activated_at, &seed) {
                return Ok(Self {
                    version,
                    active,
                    verify_only: None,
                });
            }
        }
        Err(KeyringError::OperationFailed)
    }

    pub(crate) fn decode(encoded: SecretBytes) -> Result<Self, KeyringError> {
        let bytes = encoded.expose_secret();
        if bytes.len() != ACTIVE_ONLY_LENGTH && bytes.len() != WITH_VERIFY_ONLY_LENGTH {
            return Err(KeyringError::InvalidEncoding);
        }

        let checksum_offset = bytes
            .len()
            .checked_sub(CHECKSUM_BYTES)
            .ok_or(KeyringError::InvalidEncoding)?;
        let expected_checksum = Sha256::digest(&bytes[..checksum_offset]);
        if expected_checksum.as_slice() != &bytes[checksum_offset..] {
            return Err(KeyringError::ChecksumMismatch);
        }
        if &bytes[..KEYRING_MAGIC.len()] != KEYRING_MAGIC {
            return Err(KeyringError::InvalidEncoding);
        }
        if read_u16(bytes, 8)? != KEYRING_FORMAT_VERSION {
            return Err(KeyringError::UnsupportedVersion);
        }
        if read_u32(bytes, 10)? as usize != bytes.len() {
            return Err(KeyringError::InvalidEncoding);
        }

        let version = KeyringVersion::new(read_u64(bytes, 14)?)?;
        let activated_at = AuthTimestampMicros::new(read_u64(bytes, 22)?)?;

        let mut seed = Zeroizing::new([0_u8; KEY_BYTES]);
        seed.copy_from_slice(read_exact::<KEY_BYTES>(bytes, ACTIVE_SEED_OFFSET)?);
        if seed.iter().all(|byte| *byte == 0) {
            return Err(KeyringError::InvalidKeyMaterial);
        }
        let active = active_from_seed(activated_at, &seed)?;
        let stored_public = read_exact::<KEY_BYTES>(bytes, ACTIVE_PUBLIC_OFFSET)?;
        let parsed_public = VerifyingKey::from_bytes(stored_public)
            .map_err(|_| KeyringError::InvalidKeyMaterial)?;
        if parsed_public.is_weak() || parsed_public != active.signing_key.verifying_key() {
            return Err(KeyringError::InconsistentKeyMaterial);
        }
        let stored_kid =
            KeyId::from_stored_bytes(read_exact::<KID_BYTES>(bytes, ACTIVE_KID_OFFSET)?)?;
        if stored_kid != active.kid {
            return Err(KeyringError::InconsistentKeyMaterial);
        }

        let verify_only = match bytes[VERIFY_ONLY_TAG_OFFSET] {
            0 if bytes.len() == ACTIVE_ONLY_LENGTH => None,
            1 if bytes.len() == WITH_VERIFY_ONLY_LENGTH => {
                let previous_activated_at =
                    AuthTimestampMicros::new(read_u64(bytes, VERIFY_ONLY_ACTIVATED_OFFSET)?)?;
                let verify_until =
                    AuthTimestampMicros::new(read_u64(bytes, VERIFY_ONLY_UNTIL_OFFSET)?)?;
                let expected_until = activated_at.checked_add(VERIFY_ONLY_OVERLAP_MICROS)?;
                if previous_activated_at > activated_at || verify_until != expected_until {
                    return Err(KeyringError::InvalidLifecycle);
                }

                let previous_public = read_exact::<KEY_BYTES>(bytes, VERIFY_ONLY_PUBLIC_OFFSET)?;
                let verifying_key = VerifyingKey::from_bytes(previous_public)
                    .map_err(|_| KeyringError::InvalidKeyMaterial)?;
                if verifying_key.is_weak() {
                    return Err(KeyringError::InvalidKeyMaterial);
                }
                let stored_previous_kid = KeyId::from_stored_bytes(read_exact::<KID_BYTES>(
                    bytes,
                    VERIFY_ONLY_KID_OFFSET,
                )?)?;
                let derived_previous_kid = KeyId::from_verifying_key(&verifying_key);
                if stored_previous_kid != derived_previous_kid || stored_previous_kid == active.kid
                {
                    return Err(KeyringError::InconsistentKeyMaterial);
                }
                Some(VerifyOnlyKey {
                    activated_at: previous_activated_at,
                    verify_until,
                    verifying_key,
                    kid: stored_previous_kid,
                })
            }
            0 | 1 => return Err(KeyringError::InvalidEncoding),
            _ => return Err(KeyringError::InvalidEncoding),
        };

        Ok(Self {
            version,
            active,
            verify_only,
        })
    }

    pub(crate) fn encode(&self) -> SecretBytes {
        let length = if self.verify_only.is_some() {
            WITH_VERIFY_ONLY_LENGTH
        } else {
            ACTIVE_ONLY_LENGTH
        };
        let checksum_offset = length - CHECKSUM_BYTES;
        let mut bytes = Zeroizing::new(vec![0_u8; length]);
        bytes[..KEYRING_MAGIC.len()].copy_from_slice(KEYRING_MAGIC);
        write_u16(&mut bytes, 8, KEYRING_FORMAT_VERSION);
        write_u32(
            &mut bytes,
            10,
            u32::try_from(length).expect("keyring length fits u32"),
        );
        write_u64(&mut bytes, 14, self.version.get());
        write_u64(&mut bytes, 22, self.active.activated_at.get());
        bytes[ACTIVE_PUBLIC_OFFSET..ACTIVE_PUBLIC_OFFSET + KEY_BYTES]
            .copy_from_slice(self.active.signing_key.verifying_key().as_bytes());
        let seed = Zeroizing::new(self.active.signing_key.to_bytes());
        bytes[ACTIVE_SEED_OFFSET..ACTIVE_SEED_OFFSET + KEY_BYTES].copy_from_slice(seed.as_ref());
        bytes[ACTIVE_KID_OFFSET..ACTIVE_KID_OFFSET + KID_BYTES]
            .copy_from_slice(self.active.kid.as_bytes());

        if let Some(previous) = &self.verify_only {
            bytes[VERIFY_ONLY_TAG_OFFSET] = 1;
            write_u64(
                &mut bytes,
                VERIFY_ONLY_ACTIVATED_OFFSET,
                previous.activated_at.get(),
            );
            write_u64(
                &mut bytes,
                VERIFY_ONLY_UNTIL_OFFSET,
                previous.verify_until.get(),
            );
            bytes[VERIFY_ONLY_PUBLIC_OFFSET..VERIFY_ONLY_PUBLIC_OFFSET + KEY_BYTES]
                .copy_from_slice(previous.verifying_key.as_bytes());
            bytes[VERIFY_ONLY_KID_OFFSET..VERIFY_ONLY_KID_OFFSET + KID_BYTES]
                .copy_from_slice(previous.kid.as_bytes());
        }

        let checksum = Sha256::digest(&bytes[..checksum_offset]);
        bytes[checksum_offset..].copy_from_slice(&checksum);
        SecretBytes::from_zeroizing(bytes)
    }

    pub(crate) fn version(&self) -> KeyringVersion {
        self.version
    }

    pub(crate) fn active_kid(&self) -> KeyId {
        self.active.kid
    }

    pub(super) fn active_activated_at(&self) -> AuthTimestampMicros {
        self.active.activated_at
    }

    pub(crate) fn planned_rotation_due(
        &self,
        now: AuthTimestampMicros,
    ) -> Result<bool, KeyringError> {
        if now < self.active.activated_at {
            return Err(KeyringError::ClockRegressed);
        }
        Ok(now
            >= self
                .active
                .activated_at
                .checked_add(PLANNED_ROTATION_MICROS)?)
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.active.signing_key.sign(message).to_bytes()
    }

    pub(crate) fn verify(
        &self,
        kid: KeyId,
        message: &[u8],
        signature: &[u8; 64],
        now: AuthTimestampMicros,
    ) -> Result<bool, KeyringError> {
        let signature = Signature::from_bytes(signature);
        if kid == self.active.kid {
            return Ok(self
                .active
                .signing_key
                .verifying_key()
                .verify_strict(message, &signature)
                .is_ok());
        }
        if let Some(previous) = &self.verify_only
            && kid == previous.kid
        {
            if now < self.active.activated_at {
                return Err(KeyringError::ClockRegressed);
            }
            if now >= previous.verify_until {
                return Ok(false);
            }
            return Ok(previous
                .verifying_key
                .verify_strict(message, &signature)
                .is_ok());
        }
        Ok(false)
    }

    #[cfg(test)]
    pub(super) fn from_test_seeds(
        version: u64,
        active_activated_at: u64,
        active_seed: [u8; KEY_BYTES],
        previous: Option<(u64, [u8; KEY_BYTES])>,
    ) -> Result<Self, KeyringError> {
        let version = KeyringVersion::new(version)?;
        let active_activated_at = AuthTimestampMicros::new(active_activated_at)?;
        let active = active_from_seed(active_activated_at, &active_seed)?;
        let verify_only = previous
            .map(|(previous_activated_at, previous_seed)| {
                let previous_activated_at = AuthTimestampMicros::new(previous_activated_at)?;
                let previous_signing = active_from_seed(previous_activated_at, &previous_seed)?;
                let verifying_key = previous_signing.signing_key.verifying_key();
                let kid = previous_signing.kid;
                if previous_activated_at > active_activated_at || kid == active.kid {
                    return Err(KeyringError::InvalidLifecycle);
                }
                Ok(VerifyOnlyKey {
                    activated_at: previous_activated_at,
                    verify_until: active_activated_at.checked_add(VERIFY_ONLY_OVERLAP_MICROS)?,
                    verifying_key,
                    kid,
                })
            })
            .transpose()?;
        Ok(Self {
            version,
            active,
            verify_only,
        })
    }
}

impl fmt::Debug for Keyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Keyring")
            .field("version", &self.version)
            .field("active_kid", &self.active.kid)
            .field("active_private_key", &"[REDACTED]")
            .field(
                "verify_only_kid",
                &self.verify_only.as_ref().map(|key| key.kid),
            )
            .finish()
    }
}

fn active_from_seed(
    activated_at: AuthTimestampMicros,
    seed: &[u8; KEY_BYTES],
) -> Result<ActiveKey, KeyringError> {
    if seed.iter().all(|byte| *byte == 0) {
        return Err(KeyringError::InvalidKeyMaterial);
    }
    let signing_key = SigningKey::from_bytes(seed);
    let verifying_key = signing_key.verifying_key();
    if verifying_key.is_weak() {
        return Err(KeyringError::InvalidKeyMaterial);
    }
    let kid = KeyId::from_verifying_key(&verifying_key);
    Ok(ActiveKey {
        activated_at,
        signing_key,
        kid,
    })
}

fn read_exact<const LENGTH: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<&[u8; LENGTH], KeyringError> {
    bytes
        .get(offset..offset + LENGTH)
        .ok_or(KeyringError::InvalidEncoding)?
        .try_into()
        .map_err(|_| KeyringError::InvalidEncoding)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, KeyringError> {
    Ok(u16::from_be_bytes(*read_exact(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, KeyringError> {
    Ok(u32::from_be_bytes(*read_exact(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, KeyringError> {
    Ok(u64::from_be_bytes(*read_exact(bytes, offset)?))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyringError {
    InvalidEncoding,
    UnsupportedVersion,
    ChecksumMismatch,
    InvalidKeyMaterial,
    InconsistentKeyMaterial,
    InvalidLifecycle,
    ClockRegressed,
    OperationFailed,
}

impl fmt::Display for KeyringError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "authentication keyring encoding is invalid",
            Self::UnsupportedVersion => "authentication keyring version is unsupported",
            Self::ChecksumMismatch => "authentication keyring integrity check failed",
            Self::InvalidKeyMaterial => "authentication keyring material is invalid",
            Self::InconsistentKeyMaterial => "authentication keyring material is inconsistent",
            Self::InvalidLifecycle => "authentication keyring lifecycle is invalid",
            Self::ClockRegressed => "authentication keyring clock regressed",
            Self::OperationFailed => "authentication keyring operation failed",
        })
    }
}

impl Error for KeyringError {}

#[cfg(test)]
mod tests {
    use super::{
        ACTIVE_KID_OFFSET, ACTIVE_ONLY_LENGTH, ACTIVE_PUBLIC_OFFSET, ACTIVE_SEED_OFFSET,
        AuthTimestampMicros, CHECKSUM_BYTES, KEYRING_FORMAT_VERSION, KEYRING_MAGIC, KID_BYTES,
        KeyId, Keyring, KeyringError, KeyringVersion, VERIFY_ONLY_ACTIVATED_OFFSET,
        VERIFY_ONLY_KID_OFFSET, VERIFY_ONLY_OVERLAP_MICROS, VERIFY_ONLY_PUBLIC_OFFSET,
        VERIFY_ONLY_TAG_OFFSET, VERIFY_ONLY_UNTIL_OFFSET, WITH_VERIFY_ONLY_LENGTH, write_u16,
        write_u32, write_u64,
    };
    use crate::auth::SecretBytes;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    const RFC8032_SEED_ONE: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC8032_PUBLIC_ONE: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    const RFC8032_SEED_TWO: [u8; 32] = [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
    ];
    const RFC8032_PUBLIC_TWO: [u8; 32] = [
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e,
        0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4,
        0x66, 0x0c,
    ];
    const ACTIVE_AT: u64 = 1_700_000_000_000_000;
    const PREVIOUS_AT: u64 = 1_690_000_000_000_000;

    #[test]
    fn rfc8032_key_derives_the_exact_rfc7638_kid() {
        let signing_key = SigningKey::from_bytes(&RFC8032_SEED_ONE);
        assert_eq!(signing_key.verifying_key().to_bytes(), RFC8032_PUBLIC_ONE);
        let kid = KeyId::from_verifying_key(&signing_key.verifying_key());
        assert_eq!(kid.as_str(), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    }

    #[test]
    fn active_only_encoding_matches_the_v1_golden_layout_and_round_trips() {
        let keyring =
            Keyring::from_test_seeds(1, ACTIVE_AT, RFC8032_SEED_ONE, None).expect("golden keyring");
        let encoded = keyring.encode();
        let bytes = encoded.expose_secret();
        assert_eq!(bytes.len(), ACTIVE_ONLY_LENGTH);
        assert_eq!(&bytes[..8], KEYRING_MAGIC);
        assert_eq!(
            u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
            KEYRING_FORMAT_VERSION
        );
        assert_eq!(
            u32::from_be_bytes(bytes[10..14].try_into().unwrap()) as usize,
            ACTIVE_ONLY_LENGTH
        );
        assert_eq!(
            &bytes[ACTIVE_PUBLIC_OFFSET..ACTIVE_PUBLIC_OFFSET + 32],
            &RFC8032_PUBLIC_ONE
        );
        assert_eq!(
            &bytes[ACTIVE_SEED_OFFSET..ACTIVE_SEED_OFFSET + 32],
            &RFC8032_SEED_ONE
        );
        assert_eq!(
            &bytes[ACTIVE_KID_OFFSET..ACTIVE_KID_OFFSET + KID_BYTES],
            b"kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
        assert_eq!(bytes[VERIFY_ONLY_TAG_OFFSET], 0);
        assert_eq!(
            hex(&bytes[ACTIVE_ONLY_LENGTH - CHECKSUM_BYTES..]),
            "b4ab6fa7d504b4e7ff616e815c4d8e21ddb14c131f2ca41e083bc7610153d390"
        );

        let expected = bytes.to_vec();
        let decoded = Keyring::decode(encoded).expect("golden keyring decodes");
        assert_eq!(decoded.encode().expose_secret(), expected);
    }

    #[test]
    fn verify_only_encoding_matches_the_v1_golden_layout_and_round_trips() {
        let keyring = Keyring::from_test_seeds(
            2,
            ACTIVE_AT,
            RFC8032_SEED_TWO,
            Some((PREVIOUS_AT, RFC8032_SEED_ONE)),
        )
        .expect("rotated golden keyring");
        let encoded = keyring.encode();
        let bytes = encoded.expose_secret();
        assert_eq!(bytes.len(), WITH_VERIFY_ONLY_LENGTH);
        assert_eq!(
            &bytes[ACTIVE_PUBLIC_OFFSET..ACTIVE_PUBLIC_OFFSET + 32],
            &RFC8032_PUBLIC_TWO
        );
        assert_eq!(
            &bytes[ACTIVE_KID_OFFSET..ACTIVE_KID_OFFSET + KID_BYTES],
            b"FtIu-VbGrfe_KB6CH7GNwODB72MNxj_ml11dEvO-7kk"
        );
        assert_eq!(bytes[VERIFY_ONLY_TAG_OFFSET], 1);
        assert_eq!(
            u64::from_be_bytes(
                bytes[VERIFY_ONLY_ACTIVATED_OFFSET..VERIFY_ONLY_ACTIVATED_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            PREVIOUS_AT
        );
        assert_eq!(
            u64::from_be_bytes(
                bytes[VERIFY_ONLY_UNTIL_OFFSET..VERIFY_ONLY_UNTIL_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            ACTIVE_AT + VERIFY_ONLY_OVERLAP_MICROS
        );
        assert_eq!(
            &bytes[VERIFY_ONLY_PUBLIC_OFFSET..VERIFY_ONLY_PUBLIC_OFFSET + 32],
            &RFC8032_PUBLIC_ONE
        );
        assert_eq!(
            &bytes[VERIFY_ONLY_KID_OFFSET..VERIFY_ONLY_KID_OFFSET + KID_BYTES],
            b"kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
        assert_eq!(
            hex(&bytes[WITH_VERIFY_ONLY_LENGTH - CHECKSUM_BYTES..]),
            "3f1d9ab57f65221b0cd8b4a48fce24a12e0d7ceedb86268a2278eff499f78e9a"
        );

        let expected = bytes.to_vec();
        let decoded = Keyring::decode(encoded).expect("rotated golden keyring decodes");
        assert_eq!(decoded.encode().expose_secret(), expected);
    }

    #[test]
    fn every_truncation_and_an_appended_byte_are_rejected() {
        for keyring in [
            Keyring::from_test_seeds(1, ACTIVE_AT, RFC8032_SEED_ONE, None).expect("active keyring"),
            Keyring::from_test_seeds(
                2,
                ACTIVE_AT,
                RFC8032_SEED_TWO,
                Some((PREVIOUS_AT, RFC8032_SEED_ONE)),
            )
            .expect("rotated keyring"),
        ] {
            let encoded = keyring.encode();
            let bytes = encoded.expose_secret();
            for length in 0..bytes.len() {
                assert!(
                    Keyring::decode(SecretBytes::new(bytes[..length].to_vec())).is_err(),
                    "truncated length {length} of {}",
                    bytes.len()
                );
            }
            let mut appended = bytes.to_vec();
            appended.push(0);
            assert_eq!(
                Keyring::decode(SecretBytes::new(appended)).unwrap_err(),
                KeyringError::InvalidEncoding
            );
        }
    }

    #[test]
    fn checksummed_structural_and_semantic_corruption_are_rejected() {
        let keyring =
            Keyring::from_test_seeds(1, ACTIVE_AT, RFC8032_SEED_ONE, None).expect("keyring");
        let original = keyring.encode().expose_secret().to_vec();

        let mut checksum_corrupt = original.clone();
        checksum_corrupt[ACTIVE_SEED_OFFSET] ^= 1;
        assert_eq!(
            Keyring::decode(SecretBytes::new(checksum_corrupt)).unwrap_err(),
            KeyringError::ChecksumMismatch
        );

        let mut wrong_public = original.clone();
        wrong_public[ACTIVE_PUBLIC_OFFSET..ACTIVE_PUBLIC_OFFSET + 32]
            .copy_from_slice(&RFC8032_PUBLIC_TWO);
        refresh_checksum(&mut wrong_public);
        assert_eq!(
            Keyring::decode(SecretBytes::new(wrong_public)).unwrap_err(),
            KeyringError::InconsistentKeyMaterial
        );

        let mut wrong_kid = original.clone();
        wrong_kid[ACTIVE_KID_OFFSET] = if wrong_kid[ACTIVE_KID_OFFSET] == b'A' {
            b'B'
        } else {
            b'A'
        };
        refresh_checksum(&mut wrong_kid);
        assert_eq!(
            Keyring::decode(SecretBytes::new(wrong_kid)).unwrap_err(),
            KeyringError::InconsistentKeyMaterial
        );

        let mut zero_seed = original.clone();
        zero_seed[ACTIVE_SEED_OFFSET..ACTIVE_SEED_OFFSET + 32].fill(0);
        refresh_checksum(&mut zero_seed);
        assert_eq!(
            Keyring::decode(SecretBytes::new(zero_seed)).unwrap_err(),
            KeyringError::InvalidKeyMaterial
        );

        let mut unsupported = original.clone();
        write_u16(&mut unsupported, 8, 2);
        refresh_checksum(&mut unsupported);
        assert_eq!(
            Keyring::decode(SecretBytes::new(unsupported)).unwrap_err(),
            KeyringError::UnsupportedVersion
        );

        let mut wrong_magic = original.clone();
        wrong_magic[0] ^= 1;
        refresh_checksum(&mut wrong_magic);
        assert_eq!(
            Keyring::decode(SecretBytes::new(wrong_magic)).unwrap_err(),
            KeyringError::InvalidEncoding
        );

        let mut wrong_length = original.clone();
        write_u32(&mut wrong_length, 10, 1);
        refresh_checksum(&mut wrong_length);
        assert_eq!(
            Keyring::decode(SecretBytes::new(wrong_length)).unwrap_err(),
            KeyringError::InvalidEncoding
        );

        let mut unknown_tag = original;
        unknown_tag[VERIFY_ONLY_TAG_OFFSET] = 2;
        refresh_checksum(&mut unknown_tag);
        assert_eq!(
            Keyring::decode(SecretBytes::new(unknown_tag)).unwrap_err(),
            KeyringError::InvalidEncoding
        );
    }

    #[test]
    fn verify_only_semantics_reject_duplicate_weak_and_wrong_lifetime_records() {
        let keyring = Keyring::from_test_seeds(
            2,
            ACTIVE_AT,
            RFC8032_SEED_TWO,
            Some((PREVIOUS_AT, RFC8032_SEED_ONE)),
        )
        .expect("rotated keyring");
        let original = keyring.encode().expose_secret().to_vec();

        let mut duplicate = original.clone();
        duplicate[VERIFY_ONLY_PUBLIC_OFFSET..VERIFY_ONLY_PUBLIC_OFFSET + 32]
            .copy_from_slice(&RFC8032_PUBLIC_TWO);
        let active_kid = duplicate[ACTIVE_KID_OFFSET..ACTIVE_KID_OFFSET + KID_BYTES].to_vec();
        duplicate[VERIFY_ONLY_KID_OFFSET..VERIFY_ONLY_KID_OFFSET + KID_BYTES]
            .copy_from_slice(&active_kid);
        refresh_checksum(&mut duplicate);
        assert_eq!(
            Keyring::decode(SecretBytes::new(duplicate)).unwrap_err(),
            KeyringError::InconsistentKeyMaterial
        );

        let mut weak = original.clone();
        weak[VERIFY_ONLY_PUBLIC_OFFSET..VERIFY_ONLY_PUBLIC_OFFSET + 32].fill(0);
        refresh_checksum(&mut weak);
        assert!(matches!(
            Keyring::decode(SecretBytes::new(weak)),
            Err(KeyringError::InvalidKeyMaterial | KeyringError::InconsistentKeyMaterial)
        ));

        let mut wrong_lifetime = original.clone();
        write_u64(
            &mut wrong_lifetime,
            VERIFY_ONLY_UNTIL_OFFSET,
            ACTIVE_AT + VERIFY_ONLY_OVERLAP_MICROS - 1,
        );
        refresh_checksum(&mut wrong_lifetime);
        assert_eq!(
            Keyring::decode(SecretBytes::new(wrong_lifetime)).unwrap_err(),
            KeyringError::InvalidLifecycle
        );

        let mut previous_after_active = original;
        write_u64(
            &mut previous_after_active,
            VERIFY_ONLY_ACTIVATED_OFFSET,
            ACTIVE_AT + 1,
        );
        refresh_checksum(&mut previous_after_active);
        assert_eq!(
            Keyring::decode(SecretBytes::new(previous_after_active)).unwrap_err(),
            KeyringError::InvalidLifecycle
        );
    }

    #[test]
    fn numeric_bounds_and_rotation_clock_are_fail_closed() {
        assert_eq!(
            KeyringVersion::new(0).unwrap_err(),
            KeyringError::InvalidLifecycle
        );
        assert_eq!(
            KeyringVersion::new(i64::MAX as u64 + 1).unwrap_err(),
            KeyringError::InvalidLifecycle
        );
        assert_eq!(
            AuthTimestampMicros::new(i64::MAX as u64 + 1).unwrap_err(),
            KeyringError::InvalidLifecycle
        );

        let keyring =
            Keyring::from_test_seeds(1, ACTIVE_AT, RFC8032_SEED_ONE, None).expect("keyring");
        let canonical = keyring.encode().expose_secret().to_vec();
        for (offset, invalid_value) in [
            (14_usize, 0_u64),
            (14, i64::MAX as u64 + 1),
            (22, i64::MAX as u64 + 1),
        ] {
            let mut invalid = canonical.clone();
            write_u64(&mut invalid, offset, invalid_value);
            refresh_checksum(&mut invalid);
            assert_eq!(
                Keyring::decode(SecretBytes::new(invalid)).unwrap_err(),
                KeyringError::InvalidLifecycle
            );
        }

        assert_eq!(
            keyring
                .planned_rotation_due(AuthTimestampMicros::new(ACTIVE_AT - 1).unwrap())
                .unwrap_err(),
            KeyringError::ClockRegressed
        );
        assert!(
            !keyring
                .planned_rotation_due(
                    AuthTimestampMicros::new(ACTIVE_AT + super::PLANNED_ROTATION_MICROS - 1)
                        .unwrap()
                )
                .unwrap()
        );
        assert!(
            keyring
                .planned_rotation_due(
                    AuthTimestampMicros::new(ACTIVE_AT + super::PLANNED_ROTATION_MICROS).unwrap()
                )
                .unwrap()
        );

        let mut overflow = Keyring::from_test_seeds(
            2,
            ACTIVE_AT,
            RFC8032_SEED_TWO,
            Some((PREVIOUS_AT, RFC8032_SEED_ONE)),
        )
        .expect("rotated keyring")
        .encode()
        .expose_secret()
        .to_vec();
        write_u64(
            &mut overflow,
            22,
            i64::MAX as u64 - VERIFY_ONLY_OVERLAP_MICROS + 1,
        );
        refresh_checksum(&mut overflow);
        assert_eq!(
            Keyring::decode(SecretBytes::new(overflow)).unwrap_err(),
            KeyringError::InvalidLifecycle
        );
    }

    #[test]
    fn active_and_verify_only_signatures_obey_the_exact_overlap_boundary() {
        let keyring = Keyring::from_test_seeds(
            2,
            ACTIVE_AT,
            RFC8032_SEED_TWO,
            Some((PREVIOUS_AT, RFC8032_SEED_ONE)),
        )
        .expect("rotated keyring");
        let message = b"synthetic JWT signing input";

        let active_signature = keyring.sign(message);
        assert!(
            keyring
                .verify(
                    keyring.active_kid(),
                    message,
                    &active_signature,
                    AuthTimestampMicros::new(ACTIVE_AT).unwrap()
                )
                .unwrap()
        );

        let old_signing = SigningKey::from_bytes(&RFC8032_SEED_ONE);
        let old_kid = KeyId::from_verifying_key(&old_signing.verifying_key());
        let old_signature = old_signing.sign(message).to_bytes();
        assert_eq!(
            keyring
                .verify(
                    old_kid,
                    message,
                    &old_signature,
                    AuthTimestampMicros::new(ACTIVE_AT - 1).unwrap()
                )
                .unwrap_err(),
            KeyringError::ClockRegressed
        );
        assert!(
            keyring
                .verify(
                    old_kid,
                    message,
                    &old_signature,
                    AuthTimestampMicros::new(ACTIVE_AT).unwrap()
                )
                .unwrap()
        );
        assert!(
            keyring
                .verify(
                    old_kid,
                    message,
                    &old_signature,
                    AuthTimestampMicros::new(ACTIVE_AT + VERIFY_ONLY_OVERLAP_MICROS - 1).unwrap()
                )
                .unwrap()
        );
        assert!(
            !keyring
                .verify(
                    old_kid,
                    message,
                    &old_signature,
                    AuthTimestampMicros::new(ACTIVE_AT + VERIFY_ONLY_OVERLAP_MICROS).unwrap()
                )
                .unwrap()
        );
        assert!(
            !keyring
                .verify(
                    KeyId(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                    message,
                    &active_signature,
                    AuthTimestampMicros::new(ACTIVE_AT).unwrap()
                )
                .unwrap()
        );
    }

    #[test]
    fn generated_keyrings_are_distinct_canonical_and_redacted() {
        let first = Keyring::generate(
            KeyringVersion::new(1).unwrap(),
            AuthTimestampMicros::new(ACTIVE_AT).unwrap(),
        )
        .expect("first generated keyring");
        let second = Keyring::generate(
            KeyringVersion::new(1).unwrap(),
            AuthTimestampMicros::new(ACTIVE_AT).unwrap(),
        )
        .expect("second generated keyring");
        assert_ne!(first.active_kid(), second.active_kid());

        let encoded = first.encode();
        let canary = hex(&encoded.expose_secret()[ACTIVE_SEED_OFFSET..ACTIVE_SEED_OFFSET + 32]);
        let decoded = Keyring::decode(encoded).expect("generated keyring decodes");
        assert_eq!(decoded.version().get(), 1);
        let rendered = format!("{decoded:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(&canary));
        assert!(
            !KeyringError::InvalidKeyMaterial
                .to_string()
                .contains(&canary)
        );
    }

    fn refresh_checksum(bytes: &mut [u8]) {
        let checksum_offset = bytes.len() - CHECKSUM_BYTES;
        let checksum = Sha256::digest(&bytes[..checksum_offset]);
        bytes[checksum_offset..].copy_from_slice(&checksum);
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut rendered = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            rendered.push(char::from(HEX[usize::from(byte >> 4)]));
            rendered.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        rendered
    }
}
