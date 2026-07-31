use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, IsTerminal, Write},
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
    login_id: &str,
    now_micros: u64,
) -> Result<(), OperatorInitError> {
    let confirmed = prepare_operator_init(instance_root, login_id, now_micros)?;
    complete_operator_init(confirmed).await
}

/// Secret-bearing, non-debuggable handoff created only after the terminal and
/// signal lifecycle has been explicitly restored.
pub struct ConfirmedOperatorInit {
    instance_root: std::path::PathBuf,
    login_id: String,
    password: NormalizedPassword,
    recovery: RecoveryCode,
    now_micros: u64,
}

pub fn prepare_operator_init(
    instance_root: impl AsRef<Path>,
    login_id: &str,
    now_micros: u64,
) -> Result<ConfirmedOperatorInit, OperatorInitError> {
    let instance_root = instance_root.as_ref();
    preflight_instance_root(instance_root)?;
    let mut terminal = ControllingTerminal::open()?;
    let collected = collect_confirmation(&mut terminal);
    // This is the normal/error lifecycle, not Drop: restore the original
    // terminal, stop/join coordination, and restore the creating thread's mask.
    terminal.finish()?;
    let (password, recovery) = collected?;
    preflight_instance_root(instance_root)?;
    Ok(ConfirmedOperatorInit {
        instance_root: instance_root.to_path_buf(),
        login_id: login_id.to_owned(),
        password,
        recovery,
        now_micros,
    })
}

pub async fn complete_operator_init(
    confirmed: ConfirmedOperatorInit,
) -> Result<(), OperatorInitError> {
    let ConfirmedOperatorInit {
        instance_root,
        login_id,
        password,
        recovery,
        now_micros,
    } = confirmed;
    // Opening StoreSet bootstraps the instance's store directory and SQLite files.
    // Keep that filesystem mutation strictly after the operator confirmation.
    let stores = StoreSet::open(instance_root.join("stores"))
        .await
        .map_err(|_| OperatorInitError)?;
    let result = initialize_confirmed(
        instance_root,
        &stores,
        &login_id,
        &password,
        &recovery,
        now_micros,
    )
    .await
    .map_err(|_| OperatorInitError);
    let close = stores.close().await.map_err(|_| OperatorInitError);
    result.and(close)
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
    signals: signal_coordination::SignalCoordinator,
    original: Termios,
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
        // Coordination is established before echo can be disabled. It uses
        // sigwait on a helper thread; no process-wide signal handler is installed.
        let signals = signal_coordination::SignalCoordinator::start()?;
        Ok(Self {
            file,
            signals,
            original,
        })
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

    fn finish(mut self) -> Result<(), OperatorInitError> {
        self.ensure_foreground()?;
        tcsetattr(&self.file, OptionalActions::Now, &self.original)
            .map_err(|_| OperatorInitError)?;
        if !termios_matches(
            &tcgetattr(&self.file).map_err(|_| OperatorInitError)?,
            &self.original,
        ) {
            return Err(OperatorInitError);
        }
        self.signals.finish()
    }

    fn read_line(&mut self, maximum: usize) -> Result<Vec<u8>, OperatorInitError> {
        self.ensure_foreground()?;
        let mut line = Vec::new();
        self.signals.read_line(&self.file, maximum, &mut line)?;
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

fn termios_matches(left: &Termios, right: &Termios) -> bool {
    let matches = left.input_modes == right.input_modes
        && left.output_modes == right.output_modes
        && left.control_modes == right.control_modes
        && left.local_modes == right.local_modes
        // rustix intentionally keeps the SpecialCodes array opaque; its Debug
        // representation covers every element and is stable within this build.
        && format!("{:?}", left.special_codes) == format!("{:?}", right.special_codes)
        && left.input_speed() == right.input_speed()
        && left.output_speed() == right.output_speed();
    #[cfg(target_os = "linux")]
    let matches = matches && left.line_discipline == right.line_discipline;
    matches
}

struct EchoGuard<'a> {
    file: &'a File,
    original: Option<Termios>,
}

impl EchoGuard<'_> {
    fn restore(&mut self) -> Result<(), OperatorInitError> {
        let original = self.original.as_ref().ok_or(OperatorInitError)?;
        tcsetattr(self.file, OptionalActions::Now, original).map_err(|_| OperatorInitError)?;
        self.original = None;
        Ok(())
    }
}

impl Drop for EchoGuard<'_> {
    fn drop(&mut self) {
        if let Some(original) = &self.original {
            let _ = tcsetattr(self.file, OptionalActions::Now, original);
        }
    }
}

impl OperatorTerminal for ControllingTerminal {
    fn prompt_password(&mut self) -> Result<NormalizedPassword, OperatorInitError> {
        self.write_all(b"New password: ")?;
        let original = tcgetattr(&self.file).map_err(|_| OperatorInitError)?;
        let mut hidden = original.clone();
        hidden.local_modes.remove(LocalModes::ECHO);
        tcsetattr(&self.file, OptionalActions::Now, &hidden).map_err(|_| OperatorInitError)?;
        let mut guard = EchoGuard {
            file: &self.file,
            original: Some(original),
        };
        let mut line = Vec::new();
        let read = self.signals.read_line(&self.file, 1024, &mut line);
        // Drop remains the unwind/error fallback, but a successful prompt must
        // observe restoration rather than silently discarding its error.
        guard.restore()?;
        read?;
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

fn preflight_instance_root(root: &Path) -> Result<(), OperatorInitError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(OperatorInitError),
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(OperatorInitError);
    }
    for child in ["stores", "secrets"] {
        let path = root.join(child);
        match std::fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == rustix::process::geteuid().as_raw()
                    && metadata.permissions().mode() & 0o077 == 0 => {}
            Ok(_) => return Err(OperatorInitError),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(OperatorInitError),
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod signal_coordination {
    use std::{
        fs::File,
        io::Read,
        os::fd::AsFd,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicI32, Ordering},
            mpsc,
        },
        thread,
    };

    use super::OperatorInitError;
    use nix::{
        poll::{PollFd, PollFlags, PollTimeout, poll},
        sys::{
            pthread::{Pthread, pthread_kill, pthread_self},
            signal::{SigSet, SigmaskHow, Signal, kill, pthread_sigmask},
        },
        unistd::getpid,
    };

    const SIGNALS: [Signal; 4] = [
        Signal::SIGINT,
        Signal::SIGTERM,
        Signal::SIGHUP,
        Signal::SIGQUIT,
    ];

    pub(super) struct SignalCoordinator {
        previous: SigSet,
        stopped: Arc<AtomicBool>,
        caught: Arc<AtomicI32>,
        worker: Option<thread::JoinHandle<()>>,
        worker_pthread: Pthread,
    }

    impl SignalCoordinator {
        pub(super) fn start() -> Result<Self, OperatorInitError> {
            let mut mask = SigSet::empty();
            for signal in SIGNALS {
                mask.add(signal);
            }
            // SIGUSR1 is a private wakeup used only to join the sigwait thread.
            mask.add(Signal::SIGUSR1);
            let mut previous = SigSet::empty();
            pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&mask), Some(&mut previous))
                .map_err(|_| OperatorInitError)?;
            let stopped = Arc::new(AtomicBool::new(false));
            let caught = Arc::new(AtomicI32::new(0));
            let worker_stopped = Arc::clone(&stopped);
            let worker_caught = Arc::clone(&caught);
            let (pthread_sender, pthread_receiver) = mpsc::sync_channel(1);
            let worker = thread::Builder::new()
                .name("pov-auth-sigwait".into())
                .spawn(move || {
                    let _ = pthread_sender.send(pthread_self());
                    if let Ok(signal) = mask.wait()
                        && !worker_stopped.load(Ordering::Acquire)
                        && SIGNALS.contains(&signal)
                    {
                        worker_caught.store(signal as i32, Ordering::Release);
                    }
                })
                .map_err(|_| {
                    let _ = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&previous), None);
                    OperatorInitError
                })?;
            let worker_pthread = pthread_receiver.recv().map_err(|_| OperatorInitError)?;
            Ok(Self {
                previous,
                stopped,
                caught,
                worker: Some(worker),
                worker_pthread,
            })
        }

        pub(super) fn read_line(
            &self,
            file: &File,
            maximum: usize,
            output: &mut Vec<u8>,
        ) -> Result<(), OperatorInitError> {
            loop {
                if self.caught.load(Ordering::Acquire) != 0 {
                    return Err(OperatorInitError);
                }
                let mut fds = [PollFd::new(file.as_fd(), PollFlags::POLLIN)];
                if poll(&mut fds, PollTimeout::from(20_u16)).map_err(|_| OperatorInitError)? == 0 {
                    continue;
                }
                let mut byte = [0_u8; 1];
                if (&*file).read(&mut byte).map_err(|_| OperatorInitError)? != 1 {
                    return Err(OperatorInitError);
                }
                output.push(byte[0]);
                if byte[0] == b'\n' {
                    return Ok(());
                }
                if output.len() > maximum + 1 {
                    return Err(OperatorInitError);
                }
            }
        }

        pub(super) fn finish(&mut self) -> Result<(), OperatorInitError> {
            self.cleanup(true)
        }

        fn cleanup(&mut self, strict: bool) -> Result<(), OperatorInitError> {
            self.stopped.store(true, Ordering::Release);
            if self.caught.load(Ordering::Acquire) == 0 {
                // Thread-directed and synchronously consumed by sigwait: the
                // private wakeup never becomes a process-pending application signal.
                pthread_kill(self.worker_pthread, Signal::SIGUSR1)
                    .map_err(|_| OperatorInitError)?;
            }
            if let Some(worker) = self.worker.take() {
                worker.join().map_err(|_| OperatorInitError)?;
            }
            let signal = self.caught.load(Ordering::Acquire);
            if signal != 0 {
                let signal = Signal::try_from(signal).map_err(|_| OperatorInitError)?;
                kill(getpid(), signal).map_err(|_| OperatorInitError)?;
            }
            pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&self.previous), None)
                .map_err(|_| OperatorInitError)?;
            if signal != 0 && strict {
                // A default/custom disposition normally does not return. An
                // ignored inherited disposition remains preserved and becomes
                // an operator failure rather than permitting mutation.
                return Err(OperatorInitError);
            }
            Ok(())
        }
    }

    impl Drop for SignalCoordinator {
        fn drop(&mut self) {
            let _ = self.cleanup(false);
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod signal_coordination {
    use super::OperatorInitError;
    pub(super) struct SignalCoordinator;
    impl SignalCoordinator {
        pub(super) fn start() -> Result<Self, OperatorInitError> {
            Err(OperatorInitError)
        }
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
