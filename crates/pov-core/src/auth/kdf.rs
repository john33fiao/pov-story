use std::{
    error::Error,
    fmt, str,
    sync::{Arc, LazyLock},
};

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use base64ct::{Base64Unpadded, Encoding};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use super::{password::NormalizedPassword, recovery::RecoveryCode, secret::SecretBytes};

const MEMORY_COST_KIB: u32 = 65_536;
const TIME_COST: u32 = 3;
const PARALLELISM: u32 = 4;
const SALT_BYTES: usize = 16;
const OUTPUT_BYTES: usize = 32;
const SALT_ENCODED_BYTES: usize = 22;
const OUTPUT_ENCODED_BYTES: usize = 43;
const PHC_PREFIX: &str = "$argon2id$v=19$m=65536,t=3,p=4$";

static KDF_SLOT: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));

/// A canonical verifier pinned to the current Argon2id profile.
pub struct ValidatedVerifier {
    phc: SecretBytes,
}

impl ValidatedVerifier {
    /// Strictly parse an active verifier before admitting authentication.
    pub fn parse(phc: SecretBytes) -> Result<Self, VerifierValidationError> {
        let phc_text = str::from_utf8(phc.expose_secret())
            .map_err(|_| VerifierValidationError::MalformedOrUnsupported)?;
        validate_canonical_phc(phc_text)?;
        Ok(Self { phc })
    }

    #[cfg(test)]
    fn parse_str(phc: &str) -> Result<Self, VerifierValidationError> {
        Self::parse(SecretBytes::new(phc.as_bytes().to_vec()))
    }

    pub(crate) fn expose_phc(&self) -> &str {
        str::from_utf8(self.phc.expose_secret()).expect("validated PHC is ASCII")
    }

    pub(crate) fn is_canonical_encoded(raw: &[u8]) -> bool {
        str::from_utf8(raw)
            .ok()
            .is_some_and(|value| validate_canonical_phc(value).is_ok())
    }

    pub(crate) fn encoded_salts_are_independent(left: &[u8], right: &[u8]) -> bool {
        fn salt(raw: &[u8]) -> Option<&str> {
            str::from_utf8(raw)
                .ok()?
                .rsplit_once('$')
                .and_then(|(prefix, _)| prefix.rsplit_once('$'))
                .map(|(_, salt)| salt)
        }
        matches!((salt(left), salt(right)), (Some(left), Some(right)) if left != right)
    }

    fn copy_for_worker(&self) -> SecretBytes {
        SecretBytes::new(self.expose_phc().as_bytes().to_vec())
    }
}

impl fmt::Debug for ValidatedVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedVerifier([REDACTED])")
    }
}

pub async fn hash_password(password: &NormalizedPassword) -> Result<ValidatedVerifier, KdfError> {
    hash_secret(password.copy_secret_for_worker()).await
}

pub async fn verify_password(
    password: &NormalizedPassword,
    verifier: &ValidatedVerifier,
) -> Result<bool, KdfError> {
    verify_secret(
        password.copy_secret_for_worker(),
        verifier.copy_for_worker(),
    )
    .await
}

pub async fn hash_recovery_code(
    recovery_code: &RecoveryCode,
) -> Result<ValidatedVerifier, KdfError> {
    hash_secret(recovery_code.copy_secret_for_worker()).await
}

pub async fn verify_recovery_code(
    recovery_code: &RecoveryCode,
    verifier: &ValidatedVerifier,
) -> Result<bool, KdfError> {
    verify_secret(
        recovery_code.copy_secret_for_worker(),
        verifier.copy_for_worker(),
    )
    .await
}

async fn hash_secret(secret: SecretBytes) -> Result<ValidatedVerifier, KdfError> {
    run_with_kdf_slot(move || {
        let mut salt_bytes = Zeroizing::new([0_u8; SALT_BYTES]);
        getrandom::fill(salt_bytes.as_mut()).map_err(|_| KdfError::OperationFailed)?;
        let salt =
            SaltString::encode_b64(salt_bytes.as_ref()).map_err(|_| KdfError::OperationFailed)?;
        let phc = current_argon2()
            .hash_password(secret.expose_secret(), &salt)
            .map_err(|_| KdfError::OperationFailed)?
            .to_string();
        ValidatedVerifier::parse(SecretBytes::new(phc.into_bytes()))
            .map_err(|_| KdfError::OperationFailed)
    })
    .await
}

async fn verify_secret(secret: SecretBytes, verifier: SecretBytes) -> Result<bool, KdfError> {
    run_with_kdf_slot(move || {
        let phc_text =
            str::from_utf8(verifier.expose_secret()).map_err(|_| KdfError::OperationFailed)?;
        let parsed = PasswordHash::new(phc_text).map_err(|_| KdfError::OperationFailed)?;
        match current_argon2().verify_password(secret.expose_secret(), &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(_) => Err(KdfError::OperationFailed),
        }
    })
    .await
}

fn current_argon2() -> Argon2<'static> {
    let params = Params::new(MEMORY_COST_KIB, TIME_COST, PARALLELISM, Some(OUTPUT_BYTES))
        .expect("the accepted Argon2id profile is valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

async fn run_with_kdf_slot<T, F>(work: F) -> Result<T, KdfError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, KdfError> + Send + 'static,
{
    run_with_kdf_slot_inner(work, || {}).await
}

async fn run_with_kdf_slot_inner<T, F, R>(work: F, after_release: R) -> Result<T, KdfError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, KdfError> + Send + 'static,
    R: FnOnce() + Send + 'static,
{
    let permit = Arc::clone(&KDF_SLOT)
        .try_acquire_owned()
        .map_err(|_| KdfError::Busy)?;
    tokio::task::spawn_blocking(move || {
        let result = work();
        drop(permit);
        after_release();
        result
    })
    .await
    .map_err(|_| KdfError::OperationFailed)?
}

fn validate_canonical_phc(phc: &str) -> Result<(), VerifierValidationError> {
    let remainder = phc
        .strip_prefix(PHC_PREFIX)
        .ok_or(VerifierValidationError::MalformedOrUnsupported)?;
    let (salt_text, output_text) = remainder
        .split_once('$')
        .ok_or(VerifierValidationError::MalformedOrUnsupported)?;
    if output_text.contains('$')
        || salt_text.len() != SALT_ENCODED_BYTES
        || output_text.len() != OUTPUT_ENCODED_BYTES
    {
        return Err(VerifierValidationError::MalformedOrUnsupported);
    }

    let mut salt = Zeroizing::new([0_u8; SALT_BYTES]);
    let salt_len = Base64Unpadded::decode(salt_text, salt.as_mut())
        .map_err(|_| VerifierValidationError::MalformedOrUnsupported)?
        .len();
    let mut output = Zeroizing::new([0_u8; OUTPUT_BYTES]);
    let output_len = Base64Unpadded::decode(output_text, output.as_mut())
        .map_err(|_| VerifierValidationError::MalformedOrUnsupported)?
        .len();
    if salt_len != SALT_BYTES || output_len != OUTPUT_BYTES {
        return Err(VerifierValidationError::MalformedOrUnsupported);
    }
    let canonical_salt = Zeroizing::new(Base64Unpadded::encode_string(salt.as_ref()));
    let canonical_output = Zeroizing::new(Base64Unpadded::encode_string(output.as_ref()));
    if canonical_salt.as_str() != salt_text || canonical_output.as_str() != output_text {
        return Err(VerifierValidationError::MalformedOrUnsupported);
    }

    PasswordHash::new(phc).map_err(|_| VerifierValidationError::MalformedOrUnsupported)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifierValidationError {
    MalformedOrUnsupported,
}

impl fmt::Display for VerifierValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("credential verifier is malformed or unsupported")
    }
}

impl Error for VerifierValidationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KdfError {
    Busy,
    OperationFailed,
}

impl fmt::Display for KdfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Busy => "credential verifier is busy",
            Self::OperationFailed => "credential verifier operation failed",
        })
    }
}

impl Error for KdfError {}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use tokio::sync::{Mutex, oneshot};

    use super::{
        KdfError, ValidatedVerifier, VerifierValidationError, hash_password, hash_recovery_code,
        run_with_kdf_slot, run_with_kdf_slot_inner, verify_password, verify_recovery_code,
    };
    use crate::auth::{NormalizedPassword, RecoveryCode};

    const SYNTHETIC_VALID_PHC: &str = concat!(
        "$argon2id$v=19$m=65536,t=3,p=4$",
        "AAAAAAAAAAAAAAAAAAAAAA$",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );

    static KDF_TEST_SERIAL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    #[test]
    fn strict_verifier_accepts_only_exact_current_profile() {
        ValidatedVerifier::parse_str(SYNTHETIC_VALID_PHC).expect("exact current PHC");

        for invalid in [
            "",
            "$argon2i$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "$argon2id$v=16$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "$argon2id$v=19$m=65536,t=4,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "$argon2id$v=19$t=3,m=65536,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "$argon2id$v=19$m=65536,t=3,p=4,keyid=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA=$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAB$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
        ] {
            assert_eq!(
                ValidatedVerifier::parse_str(invalid).unwrap_err(),
                VerifierValidationError::MalformedOrUnsupported
            );
        }
    }

    #[test]
    fn verifier_debug_is_redacted() {
        let verifier = ValidatedVerifier::parse_str(SYNTHETIC_VALID_PHC).expect("valid PHC");
        let rendered = format!("{verifier:?}");
        assert_eq!(rendered, "ValidatedVerifier([REDACTED])");
        assert!(!rendered.contains("argon2"));
        assert!(
            !format!("{:?}", VerifierValidationError::MalformedOrUnsupported)
                .contains(SYNTHETIC_VALID_PHC)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn password_hash_is_salted_exact_profile_and_verifies() {
        let _serial = KDF_TEST_SERIAL.lock().await;
        let password =
            NormalizedPassword::parse_bytes(b"correct horse battery staple").expect("password");
        let wrong =
            NormalizedPassword::parse_bytes(b"different horse battery staple").expect("password");

        let first = hash_password(&password).await.expect("first hash");
        let second = hash_password(&password).await.expect("second hash");
        assert!(first.expose_phc().starts_with(super::PHC_PREFIX));
        assert_ne!(first.expose_phc(), second.expose_phc());
        assert!(
            verify_password(&password, &first)
                .await
                .expect("matching verify")
        );
        assert!(
            !verify_password(&wrong, &first)
                .await
                .expect("mismatch verify")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recovery_uses_same_profile_and_exact_code_bytes() {
        let _serial = KDF_TEST_SERIAL.lock().await;
        let recovery =
            RecoveryCode::parse_bytes(b"povrec1_AAECAwQFBgcICQoLDA0ODw").expect("recovery");
        let other = RecoveryCode::parse_bytes(b"povrec1_EAECAwQFBgcICQoLDA0ODw").expect("recovery");
        let verifier = hash_recovery_code(&recovery).await.expect("hash");

        assert!(
            verify_recovery_code(&recovery, &verifier)
                .await
                .expect("matching verify")
        );
        assert!(
            !verify_recovery_code(&other, &verifier)
                .await
                .expect("mismatch verify")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn busy_attempt_is_rejected_without_waiting() {
        let _serial = KDF_TEST_SERIAL.lock().await;
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let holder = tokio::spawn(run_with_kdf_slot(move || {
            let _ = started_tx.send(());
            let _ = release_rx.blocking_recv();
            Ok(())
        }));
        started_rx.await.expect("worker started");

        assert_eq!(
            run_with_kdf_slot(|| Ok(())).await.unwrap_err(),
            KdfError::Busy
        );
        release_tx.send(()).expect("release worker");
        holder
            .await
            .expect("holder task")
            .expect("holder operation");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_caller_does_not_release_slot_before_worker_finishes() {
        let _serial = KDF_TEST_SERIAL.lock().await;
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let (slot_released_tx, slot_released_rx) = oneshot::channel();
        let caller = tokio::spawn(run_with_kdf_slot_inner(
            move || {
                let _ = started_tx.send(());
                let _ = release_rx.blocking_recv();
                Ok(())
            },
            move || {
                let _ = slot_released_tx.send(());
            },
        ));
        started_rx.await.expect("worker started");
        caller.abort();
        let _ = caller.await;

        assert_eq!(
            run_with_kdf_slot(|| Ok(())).await.unwrap_err(),
            KdfError::Busy
        );
        release_tx.send(()).expect("release worker");
        slot_released_rx
            .await
            .expect("worker observed slot release after finishing");
        run_with_kdf_slot(|| Ok(()))
            .await
            .expect("slot is available after worker completion");
    }
}
