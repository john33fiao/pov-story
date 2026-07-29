//! Credential and initialization-maintenance primitives for local authentication.
//!
//! The public surface validates and hashes credentials. Crate-private,
//! production-unwired maintenance code performs durable initialization transitions,
//! but no production authenticated owner-context issuer exists yet.

#[cfg_attr(not(test), allow(dead_code))]
mod jwt;
mod kdf;
#[cfg_attr(not(test), allow(dead_code))]
mod keyring;
#[cfg_attr(not(test), allow(dead_code))]
#[cfg(unix)]
mod maintenance;
#[cfg(unix)]
mod operator;
mod password;
mod recovery;
mod secret;
#[cfg_attr(not(test), allow(dead_code))]
#[cfg(unix)]
mod secret_fs;
#[cfg(unix)]
mod session;
mod throttle;
#[cfg_attr(not(test), allow(dead_code))]
mod transition;

pub use jwt::AuthProfile;
pub use kdf::{
    KdfError, ValidatedVerifier, VerifierValidationError, hash_password, hash_recovery_code,
    verify_password, verify_recovery_code,
};
#[cfg(all(test, unix))]
pub(crate) use keyring::{AuthTimestampMicros, Keyring};
#[cfg(unix)]
pub use operator::{
    AuthInitializationError, ConfirmedOperatorInit, OperatorInitError, complete_operator_init,
    initialize_confirmed, prepare_operator_init, run_operator_init,
};
pub use password::{NormalizedPassword, PasswordInputError};
pub use recovery::{RecoveryCode, RecoveryCodeError};
pub use secret::SecretBytes;
#[cfg(unix)]
pub use session::{
    AccessDenied, AuthInputError, AuthRuntime, AuthRuntimeError, CredentialMutationOutcome,
    IssuedSession, LoginOutcome, LoginRequest, LogoutAllOutcome, LogoutOutcome, RefreshOutcome,
};
pub use throttle::{AuthenticatorKind, ThrottleFailureUpdate, ThrottleMathError, ThrottleState};
#[cfg(all(test, unix))]
pub(crate) use transition::{
    AuditId, AuthOwnerId, PlannedRotationMetadataInput, PlannedRotationPreparationV1,
    SourceTimestampMicros, TransitionId,
};
#[cfg(unix)]
pub(crate) use transition::{
    InitializationSourceExpectation, InitializationSourceSeed, KeyTransitionSourceExpectation,
    PersistedLifecycleKeyId, PersistedLifecycleKeyringVersion, PersistedLifecycleTimestamp,
    PersistedLifecycleTransitionId, PlannedRotationSourceExpectation, RetireSourceExpectation,
    TransitionKind,
};
