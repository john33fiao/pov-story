use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, IsTerminal, Read, Write},
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
};

use rustix::{
    process::getpgrp,
    termios::{LocalModes, OptionalActions, Termios, tcgetattr, tcgetpgrp, tcsetattr},
};

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

const INIT_FAILURE: &str = "authentication operator initialization failed";

/// Execute the production `auth init` interaction exclusively on `/dev/tty`.
///
/// Standard input is checked but never read. This deliberately rejects redirected
/// input rather than accidentally accepting a password from a pipeline.
pub async fn run_operator_init(
    instance_root: impl AsRef<Path>,
    stores: &StoreSet,
    login_id: &str,
    now_micros: u64,
) -> Result<(), OperatorInitError> {
    let mut terminal = ControllingTerminal::open()?;
    let (password, recovery) = collect_confirmation(&mut terminal)?;
    initialize_confirmed(
        instance_root,
        stores,
        login_id,
        &password,
        &recovery,
        now_micros,
    )
    .await
    .map_err(|_| OperatorInitError)
}

trait OperatorTerminal {
    fn prompt_password(&mut self) -> Result<NormalizedPassword, OperatorInitError>;
    fn show_recovery(&mut self, recovery: &RecoveryCode) -> Result<(), OperatorInitError>;
    fn confirm_saved(&mut self) -> Result<bool, OperatorInitError>;
}

fn collect_confirmation(
    terminal: &mut impl OperatorTerminal,
) -> Result<(NormalizedPassword, RecoveryCode), OperatorInitError> {
    catch_unwind(AssertUnwindSafe(|| {
        let password = terminal.prompt_password()?;
        let recovery = RecoveryCode::generate().map_err(|_| OperatorInitError)?;
        terminal.show_recovery(&recovery)?;
        if !terminal.confirm_saved()? {
            return Err(OperatorInitError);
        }
        Ok((password, recovery))
    }))
    .unwrap_or(Err(OperatorInitError))
}

struct ControllingTerminal {
    file: File,
}

impl ControllingTerminal {
    fn open() -> Result<Self, OperatorInitError> {
        if !io::stdin().is_terminal() {
            return Err(OperatorInitError);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|_| OperatorInitError)?;
        let foreground = tcgetpgrp(&file).map_err(|_| OperatorInitError)?;
        if foreground != getpgrp() {
            return Err(OperatorInitError);
        }
        // Refuse to start unless both reading and restoring terminal state work.
        let original = tcgetattr(&file).map_err(|_| OperatorInitError)?;
        tcsetattr(&file, OptionalActions::Now, &original).map_err(|_| OperatorInitError)?;
        Ok(Self { file })
    }

    fn ensure_foreground(&self) -> Result<(), OperatorInitError> {
        if tcgetpgrp(&self.file).map_err(|_| OperatorInitError)? != getpgrp() {
            Err(OperatorInitError)
        } else {
            Ok(())
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), OperatorInitError> {
        self.ensure_foreground()?;
        self.file.write_all(bytes).map_err(|_| OperatorInitError)?;
        self.file.flush().map_err(|_| OperatorInitError)
    }

    fn read_line(&mut self, maximum: usize) -> Result<Vec<u8>, OperatorInitError> {
        self.ensure_foreground()?;
        let mut line = Vec::new();
        BufReader::new(&self.file)
            .take((maximum + 2) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| OperatorInitError)?;
        self.ensure_foreground()?;
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.len() > maximum {
            return Err(OperatorInitError);
        }
        Ok(line)
    }
}

struct EchoGuard<'a> {
    file: &'a File,
    original: Termios,
}

impl Drop for EchoGuard<'_> {
    fn drop(&mut self) {
        let _ = tcsetattr(self.file, OptionalActions::Now, &self.original);
    }
}

impl OperatorTerminal for ControllingTerminal {
    fn prompt_password(&mut self) -> Result<NormalizedPassword, OperatorInitError> {
        self.write_all(b"New password: ")?;
        let original = tcgetattr(&self.file).map_err(|_| OperatorInitError)?;
        let mut hidden = original.clone();
        hidden.local_modes.remove(LocalModes::ECHO);
        tcsetattr(&self.file, OptionalActions::Now, &hidden).map_err(|_| OperatorInitError)?;
        let guard = EchoGuard {
            file: &self.file,
            original,
        };
        let mut line = Vec::new();
        BufReader::new(&self.file)
            .take(1026)
            .read_until(b'\n', &mut line)
            .map_err(|_| OperatorInitError)?;
        drop(guard);
        self.write_all(b"\n")?;
        self.ensure_foreground()?;
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        NormalizedPassword::parse(super::SecretBytes::new(line)).map_err(|_| OperatorInitError)
    }

    fn show_recovery(&mut self, recovery: &RecoveryCode) -> Result<(), OperatorInitError> {
        self.write_all(b"Recovery code (shown once): ")?;
        self.write_all(recovery.expose_to_operator())?;
        self.write_all(b"\nStore it securely.\n")
    }

    fn confirm_saved(&mut self) -> Result<bool, OperatorInitError> {
        self.write_all(b"Type SAVED to confirm secure storage: ")?;
        Ok(self.read_line(16)? == b"SAVED")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorInitError;

impl fmt::Display for OperatorInitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(INIT_FAILURE)
    }
}

impl std::error::Error for OperatorInitError {}

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
    use super::{OperatorInitError, OperatorTerminal, collect_confirmation, initialize_confirmed};
    use crate::{
        auth::{NormalizedPassword, RecoveryCode, SecretBytes, session::AuthRuntime},
        storage::StoreSet,
    };

    struct PromptSeam {
        outcome: SeamOutcome,
        recovery_writes: usize,
    }

    enum SeamOutcome {
        Confirm,
        Cancel,
        OutputError,
        Panic,
    }

    impl OperatorTerminal for PromptSeam {
        fn prompt_password(&mut self) -> Result<NormalizedPassword, OperatorInitError> {
            if matches!(self.outcome, SeamOutcome::Panic) {
                panic!("synthetic catchable interruption");
            }
            NormalizedPassword::parse(SecretBytes::new(b"correct horse battery staple".to_vec()))
                .map_err(|_| OperatorInitError)
        }

        fn show_recovery(&mut self, _: &RecoveryCode) -> Result<(), OperatorInitError> {
            self.recovery_writes += 1;
            if matches!(self.outcome, SeamOutcome::OutputError) {
                Err(OperatorInitError)
            } else {
                Ok(())
            }
        }

        fn confirm_saved(&mut self) -> Result<bool, OperatorInitError> {
            Ok(matches!(self.outcome, SeamOutcome::Confirm))
        }
    }

    #[test]
    fn in_memory_prompt_seam_requires_confirmation_and_redacts_failures() {
        let mut confirmed = PromptSeam {
            outcome: SeamOutcome::Confirm,
            recovery_writes: 0,
        };
        assert!(collect_confirmation(&mut confirmed).is_ok());
        assert_eq!(confirmed.recovery_writes, 1);
        for outcome in [
            SeamOutcome::Cancel,
            SeamOutcome::OutputError,
            SeamOutcome::Panic,
        ] {
            let mut seam = PromptSeam {
                outcome,
                recovery_writes: 0,
            };
            let error = collect_confirmation(&mut seam).unwrap_err();
            assert_eq!(format!("{error:?}"), "OperatorInitError");
            assert!(!format!("{error}").contains("povrec1_"));
        }
    }

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
