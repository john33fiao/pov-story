//! Credential and initialization-maintenance primitives for local authentication.
//!
//! The public surface validates and hashes credentials. Crate-private,
//! production-unwired maintenance code performs durable initialization transitions,
//! but no production authenticated owner-context issuer exists yet.

mod kdf;
#[cfg_attr(not(test), allow(dead_code))]
mod keyring;
#[cfg_attr(not(test), allow(dead_code))]
#[cfg(unix)]
mod maintenance;
mod password;
mod recovery;
mod secret;
#[cfg_attr(not(test), allow(dead_code))]
#[cfg(unix)]
mod secret_fs;
mod throttle;
#[cfg_attr(not(test), allow(dead_code))]
mod transition;

pub use kdf::{
    KdfError, ValidatedVerifier, VerifierValidationError, hash_password, hash_recovery_code,
    verify_password, verify_recovery_code,
};
pub use password::{NormalizedPassword, PasswordInputError};
pub use recovery::{RecoveryCode, RecoveryCodeError};
pub use secret::SecretBytes;
pub use throttle::{AuthenticatorKind, ThrottleFailureUpdate, ThrottleMathError, ThrottleState};
#[cfg(unix)]
pub(crate) use transition::{
    InitializationSourceExpectation, InitializationSourceSeed, PersistedLifecycleKeyId,
    PersistedLifecycleKeyringVersion, PersistedLifecycleTimestamp, PersistedLifecycleTransitionId,
    PlannedRotationSourceExpectation, TransitionKind,
};
