use std::{
    collections::HashMap,
    error::Error,
    ffi::OsString,
    fmt,
    future::Future,
    io,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

#[cfg(unix)]
use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop, ProcessGroup};
#[cfg(unix)]
use rustix::{
    io::Errno,
    process::{Pid, test_kill_process_group},
};
#[cfg(unix)]
use std::process::{ExitStatus, Stdio};
use tempfile::{Builder as TempDirBuilder, TempDir};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    runtime::Handle,
    sync::{Semaphore, mpsc, oneshot},
    task::JoinHandle,
    time,
};
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::provider::{ProviderErrorKind, Sha256Digest};

const MAX_WALL_TIME: Duration = Duration::from_secs(10 * 60);
const MAX_CLEANUP_TIME: Duration = Duration::from_secs(30);
const MAX_STREAM_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const PIPE_READ_BUFFER_BYTES: usize = 16 * 1024;
static PROCESS_SLOT: Semaphore = Semaphore::const_new(1);
static PROCESS_POISONED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExecutableId {
    MediaProbe,
    AudioNormalize,
    SpeechTranscribe,
    SyntheticFixture,
}

#[derive(Clone)]
pub struct ExecutableRegistration {
    id: ExecutableId,
    canonical_path: PathBuf,
    expected_sha256: Sha256Digest,
    fixed_arguments: Arc<[OsString]>,
}

impl ExecutableRegistration {
    #[must_use]
    pub fn new(
        id: ExecutableId,
        canonical_path: impl Into<PathBuf>,
        expected_sha256: Sha256Digest,
        fixed_arguments: impl IntoIterator<Item = OsString>,
    ) -> Self {
        Self {
            id,
            canonical_path: canonical_path.into(),
            expected_sha256,
            fixed_arguments: fixed_arguments.into_iter().collect(),
        }
    }

    #[must_use]
    pub const fn id(&self) -> ExecutableId {
        self.id
    }
}

impl fmt::Debug for ExecutableRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutableRegistration")
            .field("id", &self.id)
            .field("canonical_path", &"[REDACTED]")
            .field("expected_sha256", &self.expected_sha256)
            .field("fixed_arguments", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustViolation {
    UnsupportedPlatform,
    RootNotAbsolute,
    RootIsSymlink,
    RootNotCanonical,
    RootNotDirectory,
    RootWritableByOthers,
    RootIdentityChanged,
    ExecutableNotAbsolute,
    ExecutableIsSymlink,
    ExecutableNotCanonical,
    ExecutableOutsideRoot,
    ExecutableAncestorIsSymlink,
    ExecutableAncestorNotDirectory,
    ExecutableAncestorNotOwnedByRootOwner,
    ExecutableAncestorWritableByOthers,
    ExecutableNotRegularFile,
    ExecutableNotOwnedByRootOwner,
    ExecutableWritableByOthers,
    ExecutableNotRunnable,
    ExecutableHasMultipleLinks,
    ExecutableFormatUnsupported,
    ExecutableIdentityChanged,
    ExecutableHashMismatch,
    DuplicateIdentifier,
    UnknownIdentifier,
    Io(io::ErrorKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustError {
    executable: Option<ExecutableId>,
    violation: TrustViolation,
}

impl TrustError {
    const fn root(violation: TrustViolation) -> Self {
        Self {
            executable: None,
            violation,
        }
    }

    const fn executable(executable: ExecutableId, violation: TrustViolation) -> Self {
        Self {
            executable: Some(executable),
            violation,
        }
    }

    #[must_use]
    pub const fn executable_id(self) -> Option<ExecutableId> {
        self.executable
    }

    #[must_use]
    pub const fn violation(self) -> TrustViolation {
        self.violation
    }
}

impl fmt::Display for TrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.executable {
            Some(executable) => write!(
                formatter,
                "trusted executable {executable:?} was rejected: {:?}",
                self.violation
            ),
            None => write!(
                formatter,
                "trusted executable root was rejected: {:?}",
                self.violation
            ),
        }
    }
}

impl Error for TrustError {}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    owner: u32,
}

#[cfg(not(unix))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecutableIdentity {
    file: FileIdentity,
    ancestors: Arc<[FileIdentity]>,
}

#[derive(Clone)]
struct RegisteredExecutable {
    registration: ExecutableRegistration,
    identity: ExecutableIdentity,
}

#[derive(Clone)]
pub struct TrustedExecutableRegistry {
    trusted_root: PathBuf,
    trusted_root_identity: FileIdentity,
    executables: Arc<HashMap<ExecutableId, RegisteredExecutable>>,
}

impl TrustedExecutableRegistry {
    pub fn try_new(
        trusted_root: impl Into<PathBuf>,
        registrations: impl IntoIterator<Item = ExecutableRegistration>,
    ) -> Result<Self, TrustError> {
        let trusted_root = trusted_root.into();
        let (trusted_root, trusted_root_identity, trusted_root_owner) =
            validate_trusted_root(&trusted_root)?;
        let mut executables = HashMap::new();

        for registration in registrations {
            if executables.contains_key(&registration.id) {
                return Err(TrustError::executable(
                    registration.id,
                    TrustViolation::DuplicateIdentifier,
                ));
            }
            let identity =
                validate_executable(&trusted_root, trusted_root_owner, &registration, None)?;
            executables.insert(
                registration.id,
                RegisteredExecutable {
                    registration,
                    identity,
                },
            );
        }

        Ok(Self {
            trusted_root,
            trusted_root_identity,
            executables: Arc::new(executables),
        })
    }

    fn revalidate(&self, id: ExecutableId) -> Result<ExecutableRegistration, TrustError> {
        let (_, root_identity, root_owner) = validate_trusted_root(&self.trusted_root)?;
        if root_identity != self.trusted_root_identity {
            return Err(TrustError::root(TrustViolation::RootIdentityChanged));
        }
        let executable = self
            .executables
            .get(&id)
            .ok_or_else(|| TrustError::executable(id, TrustViolation::UnknownIdentifier))?;
        validate_executable(
            &self.trusted_root,
            root_owner,
            &executable.registration,
            Some(&executable.identity),
        )?;
        Ok(executable.registration.clone())
    }
}

impl fmt::Debug for TrustedExecutableRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let identifiers: Vec<_> = self.executables.keys().copied().collect();
        formatter
            .debug_struct("TrustedExecutableRegistry")
            .field("trusted_root", &"[REDACTED]")
            .field("identifiers", &identifiers)
            .finish()
    }
}

#[cfg(unix)]
fn validate_trusted_root(path: &Path) -> Result<(PathBuf, FileIdentity, u32), TrustError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !path.is_absolute() {
        return Err(TrustError::root(TrustViolation::RootNotAbsolute));
    }
    let link_metadata = std::fs::symlink_metadata(path)
        .map_err(|error| TrustError::root(TrustViolation::Io(error.kind())))?;
    if link_metadata.file_type().is_symlink() {
        return Err(TrustError::root(TrustViolation::RootIsSymlink));
    }
    if !link_metadata.is_dir() {
        return Err(TrustError::root(TrustViolation::RootNotDirectory));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| TrustError::root(TrustViolation::Io(error.kind())))?;
    if canonical != path {
        return Err(TrustError::root(TrustViolation::RootNotCanonical));
    }
    if link_metadata.permissions().mode() & 0o022 != 0 {
        return Err(TrustError::root(TrustViolation::RootWritableByOthers));
    }
    let identity = FileIdentity {
        device: link_metadata.dev(),
        inode: link_metadata.ino(),
        owner: link_metadata.uid(),
    };
    Ok((canonical, identity, link_metadata.uid()))
}

#[cfg(not(unix))]
fn validate_trusted_root(_path: &Path) -> Result<(PathBuf, FileIdentity, u32), TrustError> {
    Err(TrustError::root(TrustViolation::UnsupportedPlatform))
}

#[cfg(unix)]
fn validate_executable(
    trusted_root: &Path,
    trusted_root_owner: u32,
    registration: &ExecutableRegistration,
    expected_identity: Option<&ExecutableIdentity>,
) -> Result<ExecutableIdentity, TrustError> {
    use std::io::{Read, Seek};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let reject = |violation| TrustError::executable(registration.id, violation);
    let path = &registration.canonical_path;
    if !path.is_absolute() {
        return Err(reject(TrustViolation::ExecutableNotAbsolute));
    }
    let link_metadata = std::fs::symlink_metadata(path)
        .map_err(|error| reject(TrustViolation::Io(error.kind())))?;
    if link_metadata.file_type().is_symlink() {
        return Err(reject(TrustViolation::ExecutableIsSymlink));
    }
    let canonical =
        std::fs::canonicalize(path).map_err(|error| reject(TrustViolation::Io(error.kind())))?;
    if canonical != *path {
        return Err(reject(TrustViolation::ExecutableNotCanonical));
    }
    if canonical == trusted_root || !canonical.starts_with(trusted_root) {
        return Err(reject(TrustViolation::ExecutableOutsideRoot));
    }
    let relative = canonical
        .strip_prefix(trusted_root)
        .expect("starts_with was checked");
    let mut ancestor_path = trusted_root.to_path_buf();
    let mut ancestors = Vec::new();
    for component in relative
        .components()
        .take(relative.components().count().saturating_sub(1))
    {
        ancestor_path.push(component);
        let ancestor = std::fs::symlink_metadata(&ancestor_path)
            .map_err(|error| reject(TrustViolation::Io(error.kind())))?;
        if ancestor.file_type().is_symlink() {
            return Err(reject(TrustViolation::ExecutableAncestorIsSymlink));
        }
        if !ancestor.is_dir() {
            return Err(reject(TrustViolation::ExecutableAncestorNotDirectory));
        }
        if ancestor.uid() != trusted_root_owner {
            return Err(reject(
                TrustViolation::ExecutableAncestorNotOwnedByRootOwner,
            ));
        }
        if ancestor.permissions().mode() & 0o022 != 0 {
            return Err(reject(TrustViolation::ExecutableAncestorWritableByOthers));
        }
        ancestors.push(FileIdentity {
            device: ancestor.dev(),
            inode: ancestor.ino(),
            owner: ancestor.uid(),
        });
    }

    let mut executable = std::fs::File::open(&canonical)
        .map_err(|error| reject(TrustViolation::Io(error.kind())))?;
    let metadata = executable
        .metadata()
        .map_err(|error| reject(TrustViolation::Io(error.kind())))?;
    if !metadata.is_file() {
        return Err(reject(TrustViolation::ExecutableNotRegularFile));
    }
    if metadata.uid() != trusted_root_owner {
        return Err(reject(TrustViolation::ExecutableNotOwnedByRootOwner));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(reject(TrustViolation::ExecutableWritableByOthers));
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(reject(TrustViolation::ExecutableNotRunnable));
    }
    if metadata.nlink() != 1 {
        return Err(reject(TrustViolation::ExecutableHasMultipleLinks));
    }

    let file_identity = FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
    };
    let path_identity = FileIdentity {
        device: link_metadata.dev(),
        inode: link_metadata.ino(),
        owner: link_metadata.uid(),
    };
    if file_identity != path_identity {
        return Err(reject(TrustViolation::ExecutableIdentityChanged));
    }
    let identity = ExecutableIdentity {
        file: file_identity,
        ancestors: ancestors.into(),
    };
    if expected_identity.is_some_and(|expected| expected != &identity) {
        return Err(reject(TrustViolation::ExecutableIdentityChanged));
    }
    let mut magic = [0_u8; 4];
    executable
        .read_exact(&mut magic)
        .map_err(|error| reject(TrustViolation::Io(error.kind())))?;
    if !native_executable_magic(magic) {
        return Err(reject(TrustViolation::ExecutableFormatUnsupported));
    }
    executable
        .rewind()
        .map_err(|error| reject(TrustViolation::Io(error.kind())))?;
    let actual_sha256 = Sha256Digest::of_reader(&mut executable)
        .map_err(|error| reject(TrustViolation::Io(error.kind())))?;
    if actual_sha256 != registration.expected_sha256 {
        return Err(reject(TrustViolation::ExecutableHashMismatch));
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
const fn native_executable_magic(magic: [u8; 4]) -> bool {
    matches!(magic, [0x7f, b'E', b'L', b'F'])
}

#[cfg(target_os = "macos")]
const fn native_executable_magic(magic: [u8; 4]) -> bool {
    matches!(
        magic,
        [0xce, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xce]
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xca, 0xfe, 0xba, 0xbf]
            | [0xbf, 0xba, 0xfe, 0xca]
    )
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const fn native_executable_magic(_magic: [u8; 4]) -> bool {
    false
}

#[cfg(not(unix))]
fn validate_executable(
    _trusted_root: &Path,
    _trusted_root_owner: u32,
    registration: &ExecutableRegistration,
    _expected_identity: Option<&ExecutableIdentity>,
) -> Result<ExecutableIdentity, TrustError> {
    Err(TrustError::executable(
        registration.id,
        TrustViolation::UnsupportedPlatform,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessPolicyError {
    ZeroWallTime,
    WallTimeTooLarge,
    ZeroCleanupTime,
    CleanupTimeTooLarge,
    ZeroOutputLimit,
    OutputLimitTooLarge,
}

impl fmt::Display for ProcessPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid process policy: {self:?}")
    }
}

impl Error for ProcessPolicyError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessPolicy {
    wall_time: Duration,
    cleanup_time: Duration,
    stream_output_bytes: usize,
}

impl ProcessPolicy {
    pub fn try_new(
        wall_time: Duration,
        cleanup_time: Duration,
        stream_output_bytes: usize,
    ) -> Result<Self, ProcessPolicyError> {
        if wall_time.is_zero() {
            return Err(ProcessPolicyError::ZeroWallTime);
        }
        if wall_time > MAX_WALL_TIME {
            return Err(ProcessPolicyError::WallTimeTooLarge);
        }
        if cleanup_time.is_zero() {
            return Err(ProcessPolicyError::ZeroCleanupTime);
        }
        if cleanup_time > MAX_CLEANUP_TIME {
            return Err(ProcessPolicyError::CleanupTimeTooLarge);
        }
        if stream_output_bytes == 0 {
            return Err(ProcessPolicyError::ZeroOutputLimit);
        }
        if stream_output_bytes > MAX_STREAM_OUTPUT_BYTES {
            return Err(ProcessPolicyError::OutputLimitTooLarge);
        }
        Ok(Self {
            wall_time,
            cleanup_time,
            stream_output_bytes,
        })
    }

    #[must_use]
    pub const fn wall_time(self) -> Duration {
        self.wall_time
    }

    #[must_use]
    pub const fn cleanup_time(self) -> Duration {
        self.cleanup_time
    }

    #[must_use]
    pub const fn stream_output_bytes(self) -> usize {
        self.stream_output_bytes
    }
}

impl Default for ProcessPolicy {
    fn default() -> Self {
        Self {
            wall_time: Duration::from_secs(5 * 60),
            cleanup_time: Duration::from_secs(5),
            stream_output_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkRootViolation {
    UnsupportedPlatform,
    NotAbsolute,
    IsSymlink,
    NotCanonical,
    NotDirectory,
    NotOwnerOnly,
    IdentityChanged,
    Io(io::ErrorKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkRootError {
    violation: WorkRootViolation,
}

impl WorkRootError {
    const fn new(violation: WorkRootViolation) -> Self {
        Self { violation }
    }

    #[must_use]
    pub const fn violation(self) -> WorkRootViolation {
        self.violation
    }
}

impl fmt::Display for WorkRootError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "process work root was rejected: {:?}",
            self.violation
        )
    }
}

impl Error for WorkRootError {}

#[cfg(unix)]
fn validate_work_root(path: &Path) -> Result<(PathBuf, FileIdentity), WorkRootError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let reject = |violation| WorkRootError::new(violation);
    if !path.is_absolute() {
        return Err(reject(WorkRootViolation::NotAbsolute));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| reject(WorkRootViolation::Io(error.kind())))?;
    if metadata.file_type().is_symlink() {
        return Err(reject(WorkRootViolation::IsSymlink));
    }
    if !metadata.is_dir() {
        return Err(reject(WorkRootViolation::NotDirectory));
    }
    let canonical =
        std::fs::canonicalize(path).map_err(|error| reject(WorkRootViolation::Io(error.kind())))?;
    if canonical != path {
        return Err(reject(WorkRootViolation::NotCanonical));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(reject(WorkRootViolation::NotOwnerOnly));
    }
    Ok((
        canonical,
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
        },
    ))
}

#[cfg(not(unix))]
fn validate_work_root(_path: &Path) -> Result<(PathBuf, FileIdentity), WorkRootError> {
    Err(WorkRootError::new(WorkRootViolation::UnsupportedPlatform))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessStartError {
    NoTokioRuntime,
}

impl fmt::Display for ProcessStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a running Tokio runtime is required to start a supervised process")
    }
}

impl Error for ProcessStartError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupFailure {
    Kill(io::ErrorKind),
    ReapTimedOut,
    Wait(io::ErrorKind),
    GroupIdentityMissing,
    GroupStillAlive,
    GroupCheck(io::ErrorKind),
    PipeDrainTimedOut(OutputStream),
    PipeTaskFailed(OutputStream),
    AttemptRemovalTimedOut,
    AttemptRemovalTaskFailed,
    AttemptRemoval(io::ErrorKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupStatus {
    NotRequired,
    Complete,
    Failed(CleanupFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionTerminal {
    Success,
    ExecutableRejected(TrustError),
    WorkRootRejected(WorkRootError),
    AttemptCreateFailed(io::ErrorKind),
    SpawnFailed(io::ErrorKind),
    NonZeroExit(i32),
    Signalled(i32),
    TimedOut,
    Cancelled,
    OutputLimitExceeded(OutputStream),
    OutputReadFailed(OutputStream, io::ErrorKind),
    WaitFailed(io::ErrorKind),
    SupervisorPoisoned,
    InternalFailure,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapturedOutput {
    bytes: Vec<u8>,
}

impl CapturedOutput {
    fn empty() -> Self {
        Self { bytes: Vec::new() }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for CapturedOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedOutput")
            .field("length", &self.bytes.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionReport {
    executable: ExecutableId,
    terminal: ExecutionTerminal,
    cleanup: CleanupStatus,
    elapsed: Duration,
    executable_sha256: Option<Sha256Digest>,
    stdout: CapturedOutput,
    stderr: CapturedOutput,
}

impl ExecutionReport {
    #[must_use]
    pub const fn executable(&self) -> ExecutableId {
        self.executable
    }

    #[must_use]
    pub const fn terminal(&self) -> ExecutionTerminal {
        self.terminal
    }

    #[must_use]
    pub const fn cleanup(&self) -> CleanupStatus {
        self.cleanup
    }

    #[must_use]
    pub const fn elapsed(&self) -> Duration {
        self.elapsed
    }

    #[must_use]
    pub const fn executable_sha256(&self) -> Option<Sha256Digest> {
        self.executable_sha256
    }

    #[must_use]
    pub const fn stdout(&self) -> &CapturedOutput {
        &self.stdout
    }

    #[must_use]
    pub const fn stderr(&self) -> &CapturedOutput {
        &self.stderr
    }

    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self.terminal, ExecutionTerminal::Success)
            && matches!(self.cleanup, CleanupStatus::Complete)
    }

    #[must_use]
    pub const fn provider_error_kind(&self) -> Option<ProviderErrorKind> {
        if self.is_success() {
            return None;
        }
        if matches!(self.cleanup, CleanupStatus::Failed(_)) {
            return Some(ProviderErrorKind::BackendFailure);
        }
        Some(match self.terminal {
            ExecutionTerminal::Cancelled => ProviderErrorKind::Cancelled,
            ExecutionTerminal::ExecutableRejected(_)
            | ExecutionTerminal::WorkRootRejected(_)
            | ExecutionTerminal::AttemptCreateFailed(_)
            | ExecutionTerminal::SpawnFailed(_) => ProviderErrorKind::Unavailable,
            ExecutionTerminal::OutputLimitExceeded(_)
            | ExecutionTerminal::OutputReadFailed(_, _) => ProviderErrorKind::ProtocolFailure,
            ExecutionTerminal::Success
            | ExecutionTerminal::NonZeroExit(_)
            | ExecutionTerminal::Signalled(_)
            | ExecutionTerminal::TimedOut
            | ExecutionTerminal::WaitFailed(_)
            | ExecutionTerminal::SupervisorPoisoned
            | ExecutionTerminal::InternalFailure => ProviderErrorKind::BackendFailure,
        })
    }

    fn without_attempt(
        executable: ExecutableId,
        terminal: ExecutionTerminal,
        elapsed: Duration,
    ) -> Self {
        Self {
            executable,
            terminal,
            cleanup: CleanupStatus::NotRequired,
            elapsed,
            executable_sha256: None,
            stdout: CapturedOutput::empty(),
            stderr: CapturedOutput::empty(),
        }
    }
}

impl fmt::Debug for ExecutionReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionReport")
            .field("executable", &self.executable)
            .field("terminal", &self.terminal)
            .field("cleanup", &self.cleanup)
            .field("elapsed", &self.elapsed)
            .field("executable_sha256", &self.executable_sha256)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .finish()
    }
}

#[derive(Clone)]
pub struct ProcessSupervisor {
    inner: Arc<SupervisorInner>,
}

struct SupervisorInner {
    registry: TrustedExecutableRegistry,
    work_root: PathBuf,
    work_root_identity: FileIdentity,
    policy: ProcessPolicy,
}

impl ProcessSupervisor {
    pub fn try_new(
        registry: TrustedExecutableRegistry,
        work_root: impl Into<PathBuf>,
        policy: ProcessPolicy,
    ) -> Result<Self, WorkRootError> {
        let (work_root, work_root_identity) = validate_work_root(&work_root.into())?;
        Ok(Self {
            inner: Arc::new(SupervisorInner {
                registry,
                work_root,
                work_root_identity,
                policy,
            }),
        })
    }

    pub fn start(&self, executable: ExecutableId) -> Result<ProcessRun, ProcessStartError> {
        let runtime = Handle::try_current().map_err(|_| ProcessStartError::NoTokioRuntime)?;
        let cancellation = CancellationToken::new();
        let guard = cancellation.clone().drop_guard();
        let (sender, receiver) = oneshot::channel();
        let inner = Arc::clone(&self.inner);
        let actor_cancellation = cancellation.clone();
        runtime.spawn(async move {
            let report = run_actor(inner, executable, actor_cancellation).await;
            let _ = sender.send(report);
        });
        Ok(ProcessRun {
            executable,
            receiver,
            guard: Some(guard),
        })
    }

    pub async fn run(
        &self,
        executable: ExecutableId,
    ) -> Result<ExecutionReport, ProcessExecutionError> {
        self.start(executable)
            .map_err(ProcessExecutionError::Start)?
            .await
            .map_err(ProcessExecutionError::Run)
    }

    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        PROCESS_POISONED.load(Ordering::Acquire)
    }
}

impl fmt::Debug for ProcessSupervisor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessSupervisor")
            .field("registry", &self.inner.registry)
            .field("work_root", &"[REDACTED]")
            .field("policy", &self.inner.policy)
            .finish()
    }
}

pub struct ProcessRun {
    executable: ExecutableId,
    receiver: oneshot::Receiver<ExecutionReport>,
    guard: Option<DropGuard>,
}

impl ProcessRun {
    pub fn cancel(&self) {
        if let Some(guard) = &self.guard {
            guard.token().cancel();
        }
    }
}

impl fmt::Debug for ProcessRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessRun")
            .field("executable", &self.executable)
            .finish_non_exhaustive()
    }
}

impl Future for ProcessRun {
    type Output = Result<ExecutionReport, ProcessRunError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(context) {
            Poll::Ready(Ok(report)) => {
                if let Some(guard) = self.guard.take() {
                    let _ = guard.disarm();
                }
                Poll::Ready(Ok(report))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(ProcessRunError::ActorLost)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessRunError {
    ActorLost,
}

impl fmt::Display for ProcessRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("supervised process lifecycle actor ended without a report")
    }
}

impl Error for ProcessRunError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessExecutionError {
    Start(ProcessStartError),
    Run(ProcessRunError),
}

impl fmt::Display for ProcessExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(error) => error.fmt(formatter),
            Self::Run(error) => error.fmt(formatter),
        }
    }
}

impl Error for ProcessExecutionError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DrainEvent {
    LimitExceeded(OutputStream),
    ReadFailed(OutputStream, io::ErrorKind),
}

struct PipeDrain {
    output: CapturedOutput,
    terminal: Option<DrainEvent>,
}

async fn run_actor(
    inner: Arc<SupervisorInner>,
    executable: ExecutableId,
    cancellation: CancellationToken,
) -> ExecutionReport {
    let started = Instant::now();
    let permit = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            return ExecutionReport::without_attempt(
                executable,
                ExecutionTerminal::Cancelled,
                started.elapsed(),
            );
        }
        permit = PROCESS_SLOT.acquire() => permit.expect("process semaphore is never closed"),
    };
    if PROCESS_POISONED.load(Ordering::Acquire) {
        return ExecutionReport::without_attempt(
            executable,
            ExecutionTerminal::SupervisorPoisoned,
            started.elapsed(),
        );
    }

    let report = run_with_slot(&inner, executable, &cancellation, started).await;
    if matches!(report.cleanup, CleanupStatus::Failed(_)) {
        PROCESS_POISONED.store(true, Ordering::Release);
    }
    drop(permit);
    report
}

async fn run_with_slot(
    inner: &SupervisorInner,
    executable: ExecutableId,
    cancellation: &CancellationToken,
    started: Instant,
) -> ExecutionReport {
    let registration = match inner.registry.revalidate(executable) {
        Ok(registration) => registration,
        Err(error) => {
            return ExecutionReport::without_attempt(
                executable,
                ExecutionTerminal::ExecutableRejected(error),
                started.elapsed(),
            );
        }
    };
    if let Err(error) = revalidate_work_root(&inner.work_root, inner.work_root_identity) {
        return ExecutionReport::without_attempt(
            executable,
            ExecutionTerminal::WorkRootRejected(error),
            started.elapsed(),
        );
    }
    if cancellation.is_cancelled() {
        return ExecutionReport::without_attempt(
            executable,
            ExecutionTerminal::Cancelled,
            started.elapsed(),
        );
    }

    let attempt = match TempDirBuilder::new()
        .prefix("pov-process-")
        .tempdir_in(&inner.work_root)
    {
        Ok(attempt) => attempt,
        Err(error) => {
            return ExecutionReport::without_attempt(
                executable,
                ExecutionTerminal::AttemptCreateFailed(error.kind()),
                started.elapsed(),
            );
        }
    };
    if let Err(error) = make_attempt_owner_only(&attempt) {
        let cleanup_deadline = time::Instant::now() + inner.policy.cleanup_time;
        let cleanup = remove_attempt(attempt, cleanup_deadline).await;
        return ExecutionReport {
            executable,
            terminal: ExecutionTerminal::AttemptCreateFailed(error.kind()),
            cleanup,
            elapsed: started.elapsed(),
            executable_sha256: Some(registration.expected_sha256),
            stdout: CapturedOutput::empty(),
            stderr: CapturedOutput::empty(),
        };
    }

    run_attempt(
        executable,
        registration,
        attempt,
        inner.policy,
        cancellation,
        started,
    )
    .await
}

#[cfg(unix)]
fn make_attempt_owner_only(attempt: &TempDir) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(attempt.path(), std::fs::Permissions::from_mode(0o700))?;
    let metadata = std::fs::symlink_metadata(attempt.path())?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "attempt directory is not owner-only",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn make_attempt_owner_only(_attempt: &TempDir) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "process supervision is unavailable on this platform",
    ))
}

fn revalidate_work_root(
    work_root: &Path,
    expected_identity: FileIdentity,
) -> Result<(), WorkRootError> {
    let (_, identity) = validate_work_root(work_root)?;
    if identity != expected_identity {
        return Err(WorkRootError::new(WorkRootViolation::IdentityChanged));
    }
    Ok(())
}

#[cfg(unix)]
async fn run_attempt(
    executable: ExecutableId,
    registration: ExecutableRegistration,
    attempt: TempDir,
    policy: ProcessPolicy,
    cancellation: &CancellationToken,
    started: Instant,
) -> ExecutionReport {
    let attempt_path = attempt.path().to_path_buf();
    let mut command = CommandWrap::with_new(&registration.canonical_path, |command| {
        command
            .args(registration.fixed_arguments.iter())
            .env_clear()
            .env("HOME", &attempt_path)
            .env("TMPDIR", &attempt_path)
            .env("XDG_CACHE_HOME", &attempt_path)
            .env("XDG_CONFIG_HOME", &attempt_path)
            .env("XDG_DATA_HOME", &attempt_path)
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .current_dir(&attempt_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    });
    command.wrap(KillOnDrop).wrap(ProcessGroup::leader());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let cleanup_deadline = time::Instant::now() + policy.cleanup_time;
            let cleanup = remove_attempt(attempt, cleanup_deadline).await;
            return ExecutionReport {
                executable,
                terminal: ExecutionTerminal::SpawnFailed(error.kind()),
                cleanup,
                elapsed: started.elapsed(),
                executable_sha256: Some(registration.expected_sha256),
                stdout: CapturedOutput::empty(),
                stderr: CapturedOutput::empty(),
            };
        }
    };
    let group_leader = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw);

    let Some(stdout) = child.stdout().take() else {
        return internal_after_spawn(
            executable,
            registration.expected_sha256,
            child,
            group_leader,
            attempt,
            policy.cleanup_time,
            started,
        )
        .await;
    };
    let Some(stderr) = child.stderr().take() else {
        return internal_after_spawn(
            executable,
            registration.expected_sha256,
            child,
            group_leader,
            attempt,
            policy.cleanup_time,
            started,
        )
        .await;
    };

    let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
    let stdout_task = tokio::spawn(drain_pipe(
        stdout,
        OutputStream::Stdout,
        policy.stream_output_bytes,
        event_sender.clone(),
    ));
    let stderr_task = tokio::spawn(drain_pipe(
        stderr,
        OutputStream::Stderr,
        policy.stream_output_bytes,
        event_sender.clone(),
    ));

    let wall_deadline = time::Instant::now() + policy.wall_time;
    let terminal = tokio::select! {
        biased;
        () = cancellation.cancelled() => ExecutionTerminal::Cancelled,
        event = event_receiver.recv() => {
            match event {
                Some(DrainEvent::LimitExceeded(stream)) => {
                    ExecutionTerminal::OutputLimitExceeded(stream)
                }
                Some(DrainEvent::ReadFailed(stream, kind)) => {
                    ExecutionTerminal::OutputReadFailed(stream, kind)
                }
                None => ExecutionTerminal::InternalFailure,
            }
        }
        () = time::sleep_until(wall_deadline) => ExecutionTerminal::TimedOut,
        status = child.wait() => {
            match status {
                Ok(status) => terminal_from_status(status),
                Err(error) => ExecutionTerminal::WaitFailed(error.kind()),
            }
        }
    };
    drop(event_sender);

    let cleanup_deadline = time::Instant::now() + policy.cleanup_time;
    let cleanup = cleanup_process_group(&mut child, group_leader, cleanup_deadline).await;
    let (stdout_drain, stdout_cleanup) =
        collect_pipe(stdout_task, OutputStream::Stdout, cleanup_deadline).await;
    let (stderr_drain, stderr_cleanup) =
        collect_pipe(stderr_task, OutputStream::Stderr, cleanup_deadline).await;
    let terminal =
        reconcile_drain_terminal(terminal, stdout_drain.terminal.or(stderr_drain.terminal));
    let cleanup = merge_cleanup(cleanup, stdout_cleanup);
    let cleanup = merge_cleanup(cleanup, stderr_cleanup);
    let cleanup = merge_cleanup(cleanup, remove_attempt(attempt, cleanup_deadline).await);

    ExecutionReport {
        executable,
        terminal,
        cleanup,
        elapsed: started.elapsed(),
        executable_sha256: Some(registration.expected_sha256),
        stdout: stdout_drain.output,
        stderr: stderr_drain.output,
    }
}

#[cfg(not(unix))]
async fn run_attempt(
    executable: ExecutableId,
    _registration: ExecutableRegistration,
    attempt: TempDir,
    policy: ProcessPolicy,
    _cancellation: &CancellationToken,
    started: Instant,
) -> ExecutionReport {
    let cleanup_deadline = time::Instant::now() + policy.cleanup_time;
    let cleanup = remove_attempt(attempt, cleanup_deadline).await;
    ExecutionReport {
        executable,
        terminal: ExecutionTerminal::ExecutableRejected(TrustError::executable(
            executable,
            TrustViolation::UnsupportedPlatform,
        )),
        cleanup,
        elapsed: started.elapsed(),
        executable_sha256: None,
        stdout: CapturedOutput::empty(),
        stderr: CapturedOutput::empty(),
    }
}

#[cfg(unix)]
async fn internal_after_spawn(
    executable: ExecutableId,
    sha256: Sha256Digest,
    mut child: Box<dyn ChildWrapper>,
    group_leader: Option<Pid>,
    attempt: TempDir,
    cleanup_time: Duration,
    started: Instant,
) -> ExecutionReport {
    let cleanup_deadline = time::Instant::now() + cleanup_time;
    let cleanup = cleanup_process_group(&mut child, group_leader, cleanup_deadline).await;
    let cleanup = merge_cleanup(cleanup, remove_attempt(attempt, cleanup_deadline).await);
    ExecutionReport {
        executable,
        terminal: ExecutionTerminal::InternalFailure,
        cleanup,
        elapsed: started.elapsed(),
        executable_sha256: Some(sha256),
        stdout: CapturedOutput::empty(),
        stderr: CapturedOutput::empty(),
    }
}

async fn drain_pipe(
    mut pipe: impl AsyncRead + Unpin,
    stream: OutputStream,
    limit: usize,
    events: mpsc::UnboundedSender<DrainEvent>,
) -> PipeDrain {
    let mut bytes = Vec::with_capacity(limit.min(PIPE_READ_BUFFER_BYTES));
    let mut buffer = [0_u8; PIPE_READ_BUFFER_BYTES];
    loop {
        match pipe.read(&mut buffer).await {
            Ok(0) => {
                return PipeDrain {
                    output: CapturedOutput { bytes },
                    terminal: None,
                };
            }
            Ok(read) => {
                let remaining = limit.saturating_sub(bytes.len());
                let retained = remaining.min(read);
                bytes.extend_from_slice(&buffer[..retained]);
                if retained != read {
                    let terminal = DrainEvent::LimitExceeded(stream);
                    let _ = events.send(terminal);
                    return PipeDrain {
                        output: CapturedOutput { bytes },
                        terminal: Some(terminal),
                    };
                }
            }
            Err(error) => {
                let terminal = DrainEvent::ReadFailed(stream, error.kind());
                let _ = events.send(terminal);
                return PipeDrain {
                    output: CapturedOutput { bytes },
                    terminal: Some(terminal),
                };
            }
        }
    }
}

const fn reconcile_drain_terminal(
    terminal: ExecutionTerminal,
    drain_terminal: Option<DrainEvent>,
) -> ExecutionTerminal {
    if !matches!(
        terminal,
        ExecutionTerminal::Success
            | ExecutionTerminal::NonZeroExit(_)
            | ExecutionTerminal::Signalled(_)
    ) {
        return terminal;
    }
    match drain_terminal {
        Some(DrainEvent::LimitExceeded(stream)) => ExecutionTerminal::OutputLimitExceeded(stream),
        Some(DrainEvent::ReadFailed(stream, kind)) => {
            ExecutionTerminal::OutputReadFailed(stream, kind)
        }
        None => terminal,
    }
}

#[cfg(unix)]
async fn cleanup_process_group(
    child: &mut Box<dyn ChildWrapper>,
    group_leader: Option<Pid>,
    deadline: time::Instant,
) -> CleanupStatus {
    let kill_failure = match child.start_kill() {
        Ok(()) => None,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.raw_os_error() == Some(Errno::SRCH.raw_os_error()) =>
        {
            None
        }
        Err(error) => Some(CleanupFailure::Kill(error.kind())),
    };
    let wait_failure = match time::timeout_at(deadline, child.wait()).await {
        Ok(Ok(_)) => None,
        Ok(Err(error)) => Some(CleanupFailure::Wait(error.kind())),
        Err(_) => Some(CleanupFailure::ReapTimedOut),
    };
    let group_failure = match group_leader {
        Some(group_leader) => wait_for_process_group_exit(group_leader, deadline).await,
        None => Some(CleanupFailure::GroupIdentityMissing),
    };

    match wait_failure.or(kill_failure).or(group_failure) {
        Some(failure) => CleanupStatus::Failed(failure),
        None => CleanupStatus::Complete,
    }
}

#[cfg(unix)]
async fn wait_for_process_group_exit(
    group_leader: Pid,
    deadline: time::Instant,
) -> Option<CleanupFailure> {
    loop {
        match test_kill_process_group(group_leader) {
            Err(Errno::SRCH) => return None,
            Err(error) => return Some(CleanupFailure::GroupCheck(error.kind())),
            Ok(()) if time::Instant::now() >= deadline => {
                return Some(CleanupFailure::GroupStillAlive);
            }
            Ok(()) => {
                time::sleep_until(deadline.min(time::Instant::now() + Duration::from_millis(10)))
                    .await;
            }
        }
    }
}

async fn collect_pipe(
    mut task: JoinHandle<PipeDrain>,
    stream: OutputStream,
    deadline: time::Instant,
) -> (PipeDrain, CleanupStatus) {
    match time::timeout_at(deadline, &mut task).await {
        Ok(Ok(output)) => (output, CleanupStatus::Complete),
        Ok(Err(_)) => (
            PipeDrain {
                output: CapturedOutput::empty(),
                terminal: None,
            },
            CleanupStatus::Failed(CleanupFailure::PipeTaskFailed(stream)),
        ),
        Err(_) => {
            task.abort();
            let _ = task.await;
            (
                PipeDrain {
                    output: CapturedOutput::empty(),
                    terminal: None,
                },
                CleanupStatus::Failed(CleanupFailure::PipeDrainTimedOut(stream)),
            )
        }
    }
}

async fn remove_attempt(attempt: TempDir, deadline: time::Instant) -> CleanupStatus {
    let mut removal = tokio::task::spawn_blocking(move || attempt.close());
    match time::timeout_at(deadline, &mut removal).await {
        Ok(Ok(Ok(()))) => CleanupStatus::Complete,
        Ok(Ok(Err(error))) => CleanupStatus::Failed(CleanupFailure::AttemptRemoval(error.kind())),
        Ok(Err(_)) => CleanupStatus::Failed(CleanupFailure::AttemptRemovalTaskFailed),
        Err(_) => {
            removal.abort();
            CleanupStatus::Failed(CleanupFailure::AttemptRemovalTimedOut)
        }
    }
}

const fn merge_cleanup(current: CleanupStatus, next: CleanupStatus) -> CleanupStatus {
    match (current, next) {
        (CleanupStatus::Failed(failure), _) | (_, CleanupStatus::Failed(failure)) => {
            CleanupStatus::Failed(failure)
        }
        (CleanupStatus::NotRequired, CleanupStatus::NotRequired) => CleanupStatus::NotRequired,
        _ => CleanupStatus::Complete,
    }
}

#[cfg(unix)]
fn terminal_from_status(status: ExitStatus) -> ExecutionTerminal {
    use std::os::unix::process::ExitStatusExt;

    if status.success() {
        ExecutionTerminal::Success
    } else if let Some(code) = status.code() {
        ExecutionTerminal::NonZeroExit(code)
    } else if let Some(signal) = status.signal() {
        ExecutionTerminal::Signalled(signal)
    } else {
        ExecutionTerminal::InternalFailure
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_policy_rejects_unbounded_values() {
        assert_eq!(
            ProcessPolicy::try_new(Duration::ZERO, Duration::from_secs(1), 1),
            Err(ProcessPolicyError::ZeroWallTime)
        );
        assert_eq!(
            ProcessPolicy::try_new(
                MAX_WALL_TIME + Duration::from_nanos(1),
                Duration::from_secs(1),
                1,
            ),
            Err(ProcessPolicyError::WallTimeTooLarge)
        );
        assert_eq!(
            ProcessPolicy::try_new(Duration::from_secs(1), Duration::ZERO, 1),
            Err(ProcessPolicyError::ZeroCleanupTime)
        );
        assert_eq!(
            ProcessPolicy::try_new(
                Duration::from_secs(1),
                MAX_CLEANUP_TIME + Duration::from_nanos(1),
                1,
            ),
            Err(ProcessPolicyError::CleanupTimeTooLarge)
        );
        assert_eq!(
            ProcessPolicy::try_new(Duration::from_secs(1), Duration::from_secs(1), 0),
            Err(ProcessPolicyError::ZeroOutputLimit)
        );
        assert_eq!(
            ProcessPolicy::try_new(
                Duration::from_secs(1),
                Duration::from_secs(1),
                MAX_STREAM_OUTPUT_BYTES + 1,
            ),
            Err(ProcessPolicyError::OutputLimitTooLarge)
        );
    }

    #[test]
    fn cleanup_failure_always_maps_to_backend_failure() {
        let report = ExecutionReport {
            executable: ExecutableId::SyntheticFixture,
            terminal: ExecutionTerminal::Cancelled,
            cleanup: CleanupStatus::Failed(CleanupFailure::ReapTimedOut),
            elapsed: Duration::ZERO,
            executable_sha256: None,
            stdout: CapturedOutput::empty(),
            stderr: CapturedOutput::empty(),
        };

        assert_eq!(
            report.provider_error_kind(),
            Some(ProviderErrorKind::BackendFailure)
        );
        assert!(!report.is_success());
    }

    #[test]
    fn debug_output_discloses_lengths_but_not_bytes() {
        let output = CapturedOutput {
            bytes: b"private transcript".to_vec(),
        };

        let rendered = format!("{output:?}");
        assert!(rendered.contains("18"));
        assert!(!rendered.contains("private transcript"));
    }
}
