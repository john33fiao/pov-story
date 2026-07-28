use std::{fmt, path::Path};

use super::{
    kdf::{KdfError, hash_password, hash_recovery_code},
    keyring::{AuthTimestampMicros, Keyring, KeyringVersion},
    maintenance::AuthMaintenanceActor,
    password::NormalizedPassword,
    recovery::RecoveryCode,
    secret_fs::{
        AuthInitializationActiveKeyInstallOutcome, AuthInitializationCleanupOutcome,
        AuthInitializationFinalLifecycleOutcome, AuthInitializationPrepareOutcome,
        AuthInitializationSourceOutcome, AuthInstanceLayout,
    },
    transition::{
        AuditId, AuthOwnerId, InitializationMetadataInput, InitializationPreparationV1, LoginId,
        SourceTimestampMicros, TransitionId,
    },
};
use crate::storage::StoreSet;

/// Complete a confirmed clean-instance initialization while holding the auth
/// maintenance lock for every durable step.
///
/// The caller is responsible for displaying the recovery code on the intended
/// controlling terminal and obtaining explicit confirmation before calling this
/// function. No durable auth artifact is created before both verifiers and the
/// canonical initialization preparation have been built successfully.
pub async fn initialize_confirmed(
    instance_root: impl AsRef<Path>,
    stores: &StoreSet,
    login_id: &str,
    password: &NormalizedPassword,
    recovery_code: &RecoveryCode,
    now_micros: u64,
) -> Result<(), AuthInitializationError> {
    let layout =
        AuthInstanceLayout::open_or_create(instance_root).map_err(|_| AuthInitializationError)?;
    let locked = layout.lock().map_err(|_| AuthInitializationError)?;
    let context = locked
        .bind_conversation(&stores.conversation)
        .map_err(|_| AuthInitializationError)?;
    let actor = AuthMaintenanceActor::start(context).map_err(|_| AuthInitializationError)?;

    let result = initialize_with_actor(&actor, login_id, password, recovery_code, now_micros).await;
    let shutdown = actor.shutdown().await;
    match (result, shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        _ => Err(AuthInitializationError),
    }
}

async fn initialize_with_actor(
    actor: &AuthMaintenanceActor,
    login_id: &str,
    password: &NormalizedPassword,
    recovery_code: &RecoveryCode,
    now_micros: u64,
) -> Result<(), AuthInitializationError> {
    let login_id = LoginId::parse(login_id.as_bytes()).map_err(|_| AuthInitializationError)?;
    let activated_at = AuthTimestampMicros::new(now_micros).map_err(|_| AuthInitializationError)?;
    let source_at = SourceTimestampMicros::new(now_micros).map_err(|_| AuthInitializationError)?;
    let password_verifier = hash_password(password).await.map_err(map_kdf)?;
    let recovery_verifier = hash_recovery_code(recovery_code).await.map_err(map_kdf)?;
    let keyring = Keyring::generate(
        KeyringVersion::new(1).map_err(|_| AuthInitializationError)?,
        activated_at,
    )
    .map_err(|_| AuthInitializationError)?;
    let preparation = InitializationPreparationV1::from_keyring(
        InitializationMetadataInput {
            transition_id: TransitionId::new(),
            owner_id: AuthOwnerId::new(),
            audit_id: AuditId::new(),
            source_at_micros: source_at,
            login_id,
            password_verifier,
            recovery_verifier,
        },
        &keyring,
    )
    .map_err(|_| AuthInitializationError)?;

    match actor
        .prepare_initialization(preparation)
        .await
        .map_err(|_| AuthInitializationError)?
    {
        AuthInitializationPrepareOutcome::Prepared => {}
        AuthInitializationPrepareOutcome::PreconditionNotClean(_) => {
            return Err(AuthInitializationError);
        }
    }
    match actor
        .commit_initialization_source()
        .await
        .map_err(|_| AuthInitializationError)?
    {
        AuthInitializationSourceOutcome::Committed
        | AuthInitializationSourceOutcome::AlreadyCommitted => {}
        AuthInitializationSourceOutcome::ConfirmedNotCommitted
        | AuthInitializationSourceOutcome::LegacyPrepared
        | AuthInitializationSourceOutcome::NotPrepared(_)
        | AuthInitializationSourceOutcome::PreconditionChanged => {
            return Err(AuthInitializationError);
        }
    }
    match actor
        .install_initialization_active_key()
        .await
        .map_err(|_| AuthInitializationError)?
    {
        AuthInitializationActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas
        | AuthInitializationActiveKeyInstallOutcome::AlreadyAwaitingFinalDbCas => {}
        AuthInitializationActiveKeyInstallOutcome::NotInstallable(_) => {
            return Err(AuthInitializationError);
        }
    }
    match actor
        .commit_initialization_final_lifecycle()
        .await
        .map_err(|_| AuthInitializationError)?
    {
        AuthInitializationFinalLifecycleOutcome::ActivatedAwaitingCleanup
        | AuthInitializationFinalLifecycleOutcome::AlreadyActivatedAwaitingCleanup => {}
        AuthInitializationFinalLifecycleOutcome::ConfirmedNotActivated
        | AuthInitializationFinalLifecycleOutcome::NotActivatable(_) => {
            return Err(AuthInitializationError);
        }
    }
    match actor
        .cleanup_initialization()
        .await
        .map_err(|_| AuthInitializationError)?
    {
        AuthInitializationCleanupOutcome::Completed
        | AuthInitializationCleanupOutcome::AlreadyCompleted => Ok(()),
        AuthInitializationCleanupOutcome::NotCleanable(_) => Err(AuthInitializationError),
    }
}

fn map_kdf(_: KdfError) -> AuthInitializationError {
    AuthInitializationError
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthInitializationError;

impl fmt::Display for AuthInitializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("authentication initialization failed")
    }
}

impl std::error::Error for AuthInitializationError {}

#[cfg(test)]
mod tests {
    use super::initialize_confirmed;
    use crate::{
        auth::{NormalizedPassword, RecoveryCode, SecretBytes, session::AuthRuntime},
        storage::StoreSet,
    };

    #[tokio::test]
    async fn confirmed_initialization_reaches_listener_ready_terminal_state() {
        let _serial = super::super::kdf::KDF_TEST_SERIAL.lock().await;
        let directory = tempfile::tempdir().expect("temporary instance");
        let root = directory.path().join("instance");
        let stores = StoreSet::open(root.join("stores"))
            .await
            .expect("open stores");
        let password =
            NormalizedPassword::parse(SecretBytes::new(b"correct horse battery staple".to_vec()))
                .expect("password");
        let recovery =
            RecoveryCode::parse(SecretBytes::new(b"povrec1_AAECAwQFBgcICQoLDA0ODw".to_vec()))
                .expect("recovery");

        initialize_confirmed(
            &root,
            &stores,
            "owner_01",
            &password,
            &recovery,
            1_700_000_000_000_000,
        )
        .await
        .expect("initialization");
        let runtime = AuthRuntime::open(&root, &stores, 1_700_000_000_000_001)
            .await
            .expect("listener-ready runtime");
        drop(runtime);
        stores.close().await.expect("close stores");
    }

    #[tokio::test]
    async fn confirmed_initialization_is_no_replace() {
        let _serial = super::super::kdf::KDF_TEST_SERIAL.lock().await;
        let directory = tempfile::tempdir().expect("temporary instance");
        let root = directory.path().join("instance");
        let stores = StoreSet::open(root.join("stores"))
            .await
            .expect("open stores");
        let password =
            NormalizedPassword::parse(SecretBytes::new(b"correct horse battery staple".to_vec()))
                .expect("password");
        let recovery =
            RecoveryCode::parse(SecretBytes::new(b"povrec1_AAECAwQFBgcICQoLDA0ODw".to_vec()))
                .expect("recovery");

        initialize_confirmed(
            &root,
            &stores,
            "owner_01",
            &password,
            &recovery,
            1_700_000_000_000_000,
        )
        .await
        .expect("first initialization");
        assert!(
            initialize_confirmed(
                &root,
                &stores,
                "owner_01",
                &password,
                &recovery,
                1_700_000_000_000_001
            )
            .await
            .is_err()
        );
        stores.close().await.expect("close stores");
    }
}
