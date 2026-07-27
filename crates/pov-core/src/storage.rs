use std::{
    error::Error,
    fmt,
    future::Future,
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio_rusqlite::{
    Connection,
    rusqlite::{
        self, Connection as RawConnection, OpenFlags, TransactionBehavior,
        backup::Backup,
        config::DbConfig,
        hooks::{AuthAction, AuthContext, Authorization},
    },
};

#[cfg(unix)]
use crate::auth::{
    InitializationSourceExpectation, InitializationSourceSeed, PersistedLifecycleKeyId,
    PersistedLifecycleKeyringVersion, PersistedLifecycleTimestamp, PersistedLifecycleTransitionId,
    PlannedRotationSourceExpectation, TransitionKind,
};
use crate::identity::SourceDomain;

#[cfg(unix)]
#[cfg_attr(not(test), allow(dead_code))]
mod auth_records;
pub(crate) mod conversation_records;
pub(crate) mod job_records;

pub const BUSY_TIMEOUT_MILLIS: u64 = 5_000;
const STORE_INITIALIZATION_MARKER: &[u8] = b"POV_STORE_INITIALIZATION_V1\n";

#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct ConversationOperationGate {
    reached: Arc<std::sync::Barrier>,
    resume: Arc<std::sync::Barrier>,
}

#[cfg(test)]
impl ConversationOperationGate {
    pub(crate) fn new() -> Self {
        Self {
            reached: Arc::new(std::sync::Barrier::new(2)),
            resume: Arc::new(std::sync::Barrier::new(2)),
        }
    }

    pub(crate) fn pause(&self) {
        self.reached.wait();
        self.resume.wait();
    }

    pub(crate) fn wait_until_paused(&self) {
        self.reached.wait();
    }

    pub(crate) fn resume(&self) {
        self.resume.wait();
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ConversationAppendFault {
    None,
    #[cfg(test)]
    BeforeOutboxInsert,
    #[cfg(test)]
    AfterCommitBeforeReadback,
    #[cfg(test)]
    PauseAfterCommitBeforeReadback(ConversationOperationGate),
    #[cfg(test)]
    PauseBeforeUncertainTransaction(ConversationOperationGate),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StoreKind {
    Conversation,
    Knowledge,
    Calendar,
    Embedding,
}

impl StoreKind {
    pub const ALL: [Self; 4] = [
        Self::Conversation,
        Self::Knowledge,
        Self::Calendar,
        Self::Embedding,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Conversation => "conversation",
            Self::Knowledge => "knowledge",
            Self::Calendar => "calendar",
            Self::Embedding => "embedding",
        }
    }

    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::Conversation => "conversation.sqlite3",
            Self::Knowledge => "knowledge.sqlite3",
            Self::Calendar => "calendar.sqlite3",
            Self::Embedding => "embedding.sqlite3",
        }
    }

    #[must_use]
    pub const fn sqlite_migration_namespace(self) -> &'static str {
        match self {
            Self::Conversation => "sqlite/conversation",
            Self::Knowledge => "sqlite/knowledge",
            Self::Calendar => "sqlite/calendar",
            Self::Embedding => "sqlite/embedding",
        }
    }
}

impl fmt::Display for StoreKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreRole {
    Source,
    Derivative,
}

impl StoreRole {
    #[must_use]
    pub const fn for_kind(kind: StoreKind) -> Self {
        match kind {
            StoreKind::Conversation | StoreKind::Knowledge | StoreKind::Calendar => Self::Source,
            StoreKind::Embedding => Self::Derivative,
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

pub trait StoreBoundary: sealed::Sealed + Send + Sync + 'static {
    const KIND: StoreKind;
}

pub trait SourceStoreBoundary: StoreBoundary {
    const DOMAIN: SourceDomain;
}
pub trait DerivativeStoreBoundary: StoreBoundary {}

#[derive(Debug)]
pub enum ConversationStore {}
#[derive(Debug)]
pub enum KnowledgeStore {}
#[derive(Debug)]
pub enum CalendarStore {}
#[derive(Debug)]
pub enum EmbeddingStore {}

macro_rules! source_store {
    ($store:ty, $kind:expr, $domain:expr) => {
        impl sealed::Sealed for $store {}
        impl StoreBoundary for $store {
            const KIND: StoreKind = $kind;
        }
        impl SourceStoreBoundary for $store {
            const DOMAIN: SourceDomain = $domain;
        }
    };
}

source_store!(
    ConversationStore,
    StoreKind::Conversation,
    SourceDomain::Conversation
);
source_store!(
    KnowledgeStore,
    StoreKind::Knowledge,
    SourceDomain::Knowledge
);
source_store!(CalendarStore, StoreKind::Calendar, SourceDomain::Calendar);

impl sealed::Sealed for EmbeddingStore {}
impl StoreBoundary for EmbeddingStore {
    const KIND: StoreKind = StoreKind::Embedding;
}
impl DerivativeStoreBoundary for EmbeddingStore {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedMigration {
    pub namespace: String,
    pub version: u32,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreReport {
    pub kind: StoreKind,
    pub role: StoreRole,
    pub file_name: &'static str,
    pub migration_namespace: &'static str,
    pub journal_mode: String,
    pub synchronous: String,
    pub foreign_keys: bool,
    pub recursive_triggers: bool,
    pub busy_timeout_millis: u64,
    pub trusted_schema: bool,
    pub cell_size_check: bool,
    pub defensive: bool,
    pub integrity_check: String,
    pub attached_databases: usize,
    pub applied_migrations: Vec<AppliedMigration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupArtifact {
    pub kind: StoreKind,
    pub source_file_name: &'static str,
    pub migration_namespace: &'static str,
    pub integrity_check: String,
    pub applied_migrations: Vec<AppliedMigration>,
}

pub trait BackupHook {
    fn backup_to_new_file(
        &self,
        destination: impl AsRef<Path> + Send,
    ) -> impl Future<Output = Result<BackupArtifact, StoreError>> + Send;
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct StoreFileIdentity {
    device: u64,
    inode: u64,
    owner: u32,
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct StoreDirectoryIdentity {
    device: u64,
    inode: u64,
    owner: u32,
}

#[cfg(unix)]
impl StoreDirectoryIdentity {
    pub(crate) fn matches(&self, device: u64, inode: u64, owner: u32) -> bool {
        self.device == device && self.inode == inode && self.owner == owner
    }
}

#[cfg(unix)]
impl fmt::Debug for StoreDirectoryIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("StoreDirectoryIdentity")
            .field(&"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
struct StoreLocation {
    path: PathBuf,
    #[cfg(unix)]
    identity: StoreFileIdentity,
    #[cfg(unix)]
    directory_identity: StoreDirectoryIdentity,
}

impl fmt::Debug for StoreLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreLocation")
            .field("path", &"[REDACTED]")
            .field("identity", &"[REDACTED]")
            .finish()
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum ExistingConnectionAccess {
    ReadWrite,
    ReadOnly,
}

pub struct SqliteStore<S: StoreBoundary> {
    connection: Connection,
    #[cfg(unix)]
    location: Arc<StoreLocation>,
    operation_poisoned: Arc<AtomicBool>,
    marker: PhantomData<S>,
}

impl<S: StoreBoundary> fmt::Debug for SqliteStore<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteStore")
            .field("kind", &S::KIND)
            .finish_non_exhaustive()
    }
}

impl<S: StoreBoundary> SqliteStore<S> {
    pub async fn report(&self) -> Result<StoreReport, StoreError> {
        let kind = S::KIND;
        if self.operation_poisoned.load(Ordering::Acquire) {
            return Err(StoreError::OperationPoisoned { kind });
        }
        let operation_poisoned = Arc::clone(&self.operation_poisoned);
        let migrations = migrations_for_kind(kind);
        self.connection
            .call(move |connection| {
                if operation_poisoned.load(Ordering::Acquire) {
                    return Err(StoreError::OperationPoisoned { kind });
                }
                let report = read_report(connection, kind)?;
                validate_current_migration_history(connection, kind, migrations)?;
                validate_store_report(&report)?;
                Ok(report)
            })
            .await
            .map_err(map_call_error)
    }

    pub async fn close(self) -> Result<(), StoreError> {
        self.connection.close().await.map_err(map_close_error)
    }

    #[must_use]
    pub const fn kind(&self) -> StoreKind {
        S::KIND
    }

    #[must_use]
    pub const fn file_name(&self) -> &'static str {
        S::KIND.file_name()
    }
}

#[cfg(unix)]
impl SqliteStore<ConversationStore> {
    pub(crate) fn auth_directory_identity(&self) -> Result<StoreDirectoryIdentity, StoreError> {
        self.auth_maintenance_binding()?.directory_identity()
    }

    pub(crate) fn auth_maintenance_binding(
        &self,
    ) -> Result<AuthConversationStoreBinding, StoreError> {
        let binding = AuthConversationStoreBinding {
            location: Arc::clone(&self.location),
            operation_poisoned: Arc::clone(&self.operation_poisoned),
        };
        binding.directory_identity()?;
        Ok(binding)
    }
}

#[cfg(unix)]
pub(crate) struct AuthConversationStoreBinding {
    location: Arc<StoreLocation>,
    operation_poisoned: Arc<AtomicBool>,
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthInitializationSourceMutationOutcome {
    Committed,
    AlreadyCommitted,
    ConfirmedNotCommitted,
    PreconditionChanged,
}

#[cfg(unix)]
impl fmt::Debug for AuthInitializationSourceMutationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Committed => "AuthInitializationSourceMutationOutcome::Committed",
            Self::AlreadyCommitted => "AuthInitializationSourceMutationOutcome::AlreadyCommitted",
            Self::ConfirmedNotCommitted => {
                "AuthInitializationSourceMutationOutcome::ConfirmedNotCommitted"
            }
            Self::PreconditionChanged => {
                "AuthInitializationSourceMutationOutcome::PreconditionChanged"
            }
        })
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct AuthInitializationSourceMutationError;

#[cfg(unix)]
impl fmt::Debug for AuthInitializationSourceMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthInitializationSourceMutationError")
    }
}

#[cfg(unix)]
impl fmt::Display for AuthInitializationSourceMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("authentication initialization source mutation failed")
    }
}

#[cfg(unix)]
impl Error for AuthInitializationSourceMutationError {}

#[cfg(all(test, unix))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthInitializationSourceMutationTestFault {
    AfterCommitResponseLoss,
    DeferredForeignKeyCommitFailure,
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthInitializationFinalLifecycleMutationOutcome {
    Committed,
    AlreadyCommitted,
    ConfirmedNotCommitted,
    PreconditionChanged,
}

#[cfg(unix)]
impl fmt::Debug for AuthInitializationFinalLifecycleMutationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Committed => "AuthInitializationFinalLifecycleMutationOutcome::Committed",
            Self::AlreadyCommitted => {
                "AuthInitializationFinalLifecycleMutationOutcome::AlreadyCommitted"
            }
            Self::ConfirmedNotCommitted => {
                "AuthInitializationFinalLifecycleMutationOutcome::ConfirmedNotCommitted"
            }
            Self::PreconditionChanged => {
                "AuthInitializationFinalLifecycleMutationOutcome::PreconditionChanged"
            }
        })
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct AuthInitializationFinalLifecycleMutationError;

#[cfg(unix)]
impl fmt::Debug for AuthInitializationFinalLifecycleMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthInitializationFinalLifecycleMutationError")
    }
}

#[cfg(unix)]
impl fmt::Display for AuthInitializationFinalLifecycleMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("authentication initialization final lifecycle mutation failed")
    }
}

#[cfg(unix)]
impl Error for AuthInitializationFinalLifecycleMutationError {}

#[cfg(all(test, unix))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthInitializationFinalLifecycleMutationTestFault {
    AfterCommitResponseLoss,
    DeferredForeignKeyCommitFailure,
}

#[cfg(unix)]
impl AuthConversationStoreBinding {
    pub(crate) fn directory_identity(&self) -> Result<StoreDirectoryIdentity, StoreError> {
        let kind = StoreKind::Conversation;
        if self.operation_poisoned.load(Ordering::Acquire) {
            return Err(StoreError::OperationPoisoned { kind });
        }
        validate_store_location(&self.location, "auth conversation store binding")?;
        Ok(self.location.directory_identity)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn inspect_auth_lifecycle(
        &self,
    ) -> Result<AuthDatabaseLifecycleObservation, StoreError> {
        let kind = StoreKind::Conversation;
        if self.operation_poisoned.load(Ordering::Acquire) {
            return Err(StoreError::OperationPoisoned { kind });
        }
        let result = auth_records::inspect_auth_lifecycle(&self.location);
        if result.is_err() {
            self.poison();
        }
        result
    }

    pub(crate) fn inspect_auth_reconciliation(
        &self,
        expectation: Option<InitializationSourceExpectation<'_>>,
    ) -> Result<AuthDatabaseReconciliationObservation, StoreError> {
        let kind = StoreKind::Conversation;
        if self.operation_poisoned.load(Ordering::Acquire) {
            return Err(StoreError::OperationPoisoned { kind });
        }
        let result = auth_records::inspect_auth_reconciliation(&self.location, expectation);
        if result.is_err() {
            self.poison();
        }
        result
    }

    pub(crate) fn inspect_auth_planned_rotation(
        &self,
        expectation: Option<PlannedRotationSourceExpectation<'_>>,
    ) -> Result<AuthPlannedRotationDatabaseObservation, StoreError> {
        let kind = StoreKind::Conversation;
        if self.operation_poisoned.load(Ordering::Acquire) {
            return Err(StoreError::OperationPoisoned { kind });
        }
        let result = auth_records::inspect_auth_planned_rotation(&self.location, expectation);
        if result.is_err() {
            self.poison();
        }
        result
    }

    pub(crate) fn commit_initialization_source(
        &self,
        seed: InitializationSourceSeed<'_>,
    ) -> Result<AuthInitializationSourceMutationOutcome, AuthInitializationSourceMutationError>
    {
        self.commit_initialization_source_inner(
            seed,
            #[cfg(test)]
            None,
        )
    }

    #[cfg(test)]
    pub(crate) fn commit_initialization_source_with_test_fault(
        &self,
        seed: InitializationSourceSeed<'_>,
        fault: AuthInitializationSourceMutationTestFault,
    ) -> Result<AuthInitializationSourceMutationOutcome, AuthInitializationSourceMutationError>
    {
        self.commit_initialization_source_inner(seed, Some(fault))
    }

    fn commit_initialization_source_inner(
        &self,
        seed: InitializationSourceSeed<'_>,
        #[cfg(test)] fault: Option<AuthInitializationSourceMutationTestFault>,
    ) -> Result<AuthInitializationSourceMutationOutcome, AuthInitializationSourceMutationError>
    {
        if self.operation_poisoned.load(Ordering::Acquire) {
            return Err(AuthInitializationSourceMutationError);
        }
        let result = auth_records::commit_initialization_source(
            &self.location,
            &self.operation_poisoned,
            seed,
            #[cfg(test)]
            fault,
        );
        if result.is_err() {
            self.poison();
        }
        result.map_err(|_| AuthInitializationSourceMutationError)
    }

    pub(crate) fn commit_initialization_final_lifecycle(
        &self,
        expectation: InitializationSourceExpectation<'_>,
    ) -> Result<
        AuthInitializationFinalLifecycleMutationOutcome,
        AuthInitializationFinalLifecycleMutationError,
    > {
        self.commit_initialization_final_lifecycle_inner(
            expectation,
            #[cfg(test)]
            None,
        )
    }

    #[cfg(test)]
    pub(crate) fn commit_initialization_final_lifecycle_with_test_fault(
        &self,
        expectation: InitializationSourceExpectation<'_>,
        fault: AuthInitializationFinalLifecycleMutationTestFault,
    ) -> Result<
        AuthInitializationFinalLifecycleMutationOutcome,
        AuthInitializationFinalLifecycleMutationError,
    > {
        self.commit_initialization_final_lifecycle_inner(expectation, Some(fault))
    }

    fn commit_initialization_final_lifecycle_inner(
        &self,
        expectation: InitializationSourceExpectation<'_>,
        #[cfg(test)] fault: Option<AuthInitializationFinalLifecycleMutationTestFault>,
    ) -> Result<
        AuthInitializationFinalLifecycleMutationOutcome,
        AuthInitializationFinalLifecycleMutationError,
    > {
        if self.operation_poisoned.load(Ordering::Acquire) {
            return Err(AuthInitializationFinalLifecycleMutationError);
        }
        let result = auth_records::commit_initialization_final_lifecycle(
            &self.location,
            &self.operation_poisoned,
            expectation,
            #[cfg(test)]
            fault,
        );
        if result.is_err() {
            self.poison();
        }
        result.map_err(|_| AuthInitializationFinalLifecycleMutationError)
    }

    pub(crate) fn poison(&self) {
        self.operation_poisoned.store(true, Ordering::Release);
    }

    pub(crate) fn poison_handle(&self) -> AuthStorePoisonHandle {
        AuthStorePoisonHandle {
            operation_poisoned: Arc::clone(&self.operation_poisoned),
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct AuthInitializingLifecycleFacts {
    pub(crate) state_revision: u64,
    pub(crate) transition_id: PersistedLifecycleTransitionId,
    pub(crate) expected_kid: PersistedLifecycleKeyId,
    pub(crate) keyring_version: PersistedLifecycleKeyringVersion,
    pub(crate) updated_at_micros: PersistedLifecycleTimestamp,
}

#[cfg(unix)]
impl fmt::Debug for AuthInitializingLifecycleFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthInitializingLifecycleFacts([REDACTED])")
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct AuthActiveLifecycleFacts {
    pub(crate) state_revision: u64,
    pub(crate) expected_kid: PersistedLifecycleKeyId,
    pub(crate) keyring_version: PersistedLifecycleKeyringVersion,
    pub(crate) updated_at_micros: PersistedLifecycleTimestamp,
}

#[cfg(unix)]
impl fmt::Debug for AuthActiveLifecycleFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthActiveLifecycleFacts([REDACTED])")
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct AuthTransitioningLifecycleFacts {
    pub(crate) state_revision: u64,
    pub(crate) kind: TransitionKind,
    pub(crate) transition_id: PersistedLifecycleTransitionId,
    pub(crate) expected_kid: PersistedLifecycleKeyId,
    pub(crate) keyring_version: PersistedLifecycleKeyringVersion,
    pub(crate) updated_at_micros: PersistedLifecycleTimestamp,
}

#[cfg(unix)]
impl fmt::Debug for AuthTransitioningLifecycleFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthTransitioningLifecycleFacts([REDACTED])")
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthDatabaseLifecycleObservation {
    CleanUninitialized,
    Initializing(AuthInitializingLifecycleFacts),
    Active(AuthActiveLifecycleFacts),
    Transitioning(AuthTransitioningLifecycleFacts),
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthInitializationSourceMatch {
    NotApplicable,
    Exact,
    Mismatch,
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct AuthInitializationSourceFingerprint([u8; 32]);

#[cfg(unix)]
impl AuthInitializationSourceFingerprint {
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[cfg(unix)]
impl fmt::Debug for AuthInitializationSourceFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthInitializationSourceFingerprint([REDACTED])")
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct AuthDatabaseReconciliationObservation {
    pub(crate) lifecycle: AuthDatabaseLifecycleObservation,
    pub(crate) source: AuthInitializationSourceMatch,
    pub(crate) source_fingerprint: Option<AuthInitializationSourceFingerprint>,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthPlannedRotationSourceMatch {
    NotApplicable,
    Canonical,
    Exact,
    Mismatch,
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct AuthPlannedRotationSourceFingerprint([u8; 32]);

#[cfg(unix)]
impl AuthPlannedRotationSourceFingerprint {
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[cfg(unix)]
impl fmt::Debug for AuthPlannedRotationSourceFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthPlannedRotationSourceFingerprint([REDACTED])")
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct AuthPlannedRotationDatabaseObservation {
    pub(crate) lifecycle: AuthDatabaseLifecycleObservation,
    pub(crate) source: AuthPlannedRotationSourceMatch,
    pub(crate) source_fingerprint: Option<AuthPlannedRotationSourceFingerprint>,
}

#[cfg(unix)]
impl fmt::Debug for AuthPlannedRotationDatabaseObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.source {
            AuthPlannedRotationSourceMatch::NotApplicable => {
                "AuthPlannedRotationDatabaseObservation([REDACTED], NotApplicable)"
            }
            AuthPlannedRotationSourceMatch::Canonical => {
                "AuthPlannedRotationDatabaseObservation([REDACTED], Canonical)"
            }
            AuthPlannedRotationSourceMatch::Exact => {
                "AuthPlannedRotationDatabaseObservation([REDACTED], Exact)"
            }
            AuthPlannedRotationSourceMatch::Mismatch => {
                "AuthPlannedRotationDatabaseObservation([REDACTED], Mismatch)"
            }
        })
    }
}

#[cfg(unix)]
impl fmt::Debug for AuthDatabaseReconciliationObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.source {
            AuthInitializationSourceMatch::NotApplicable => {
                "AuthDatabaseReconciliationObservation([REDACTED], NotApplicable)"
            }
            AuthInitializationSourceMatch::Exact => {
                "AuthDatabaseReconciliationObservation([REDACTED], Exact)"
            }
            AuthInitializationSourceMatch::Mismatch => {
                "AuthDatabaseReconciliationObservation([REDACTED], Mismatch)"
            }
        })
    }
}

#[cfg(unix)]
impl fmt::Debug for AuthDatabaseLifecycleObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CleanUninitialized => "AuthDatabaseLifecycleObservation::CleanUninitialized",
            Self::Initializing(_) => "AuthDatabaseLifecycleObservation::Initializing([REDACTED])",
            Self::Active(_) => "AuthDatabaseLifecycleObservation::Active([REDACTED])",
            Self::Transitioning(_) => "AuthDatabaseLifecycleObservation::Transitioning([REDACTED])",
        })
    }
}

#[cfg(unix)]
impl fmt::Debug for AuthConversationStoreBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AuthConversationStoreBinding")
            .field(&"[BOUND]")
            .finish()
    }
}

#[cfg(unix)]
pub(crate) struct AuthStorePoisonHandle {
    operation_poisoned: Arc<AtomicBool>,
}

#[cfg(unix)]
impl AuthStorePoisonHandle {
    pub(crate) fn poison(&self) {
        self.operation_poisoned.store(true, Ordering::Release);
    }
}

#[cfg(unix)]
impl fmt::Debug for AuthStorePoisonHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AuthStorePoisonHandle")
            .field(&"[BOUND]")
            .finish()
    }
}

impl<S: StoreBoundary> BackupHook for SqliteStore<S> {
    fn backup_to_new_file(
        &self,
        destination: impl AsRef<Path> + Send,
    ) -> impl Future<Output = Result<BackupArtifact, StoreError>> + Send {
        let destination = resolve_secure_file_path(destination.as_ref(), "backup destination");
        async move {
            let destination = destination?;
            let kind = S::KIND;
            if self.operation_poisoned.load(Ordering::Acquire) {
                return Err(StoreError::OperationPoisoned { kind });
            }
            let operation_poisoned = Arc::clone(&self.operation_poisoned);
            let migrations = migrations_for_kind(kind);
            self.connection
                .call(move |connection| {
                    if operation_poisoned.load(Ordering::Acquire) {
                        return Err(StoreError::OperationPoisoned { kind });
                    }
                    backup_to_new_file(connection, kind, migrations, destination)
                })
                .await
                .map_err(map_call_error)
        }
    }
}

pub struct StoreSet {
    pub conversation: SqliteStore<ConversationStore>,
    pub knowledge: SqliteStore<KnowledgeStore>,
    pub calendar: SqliteStore<CalendarStore>,
    pub embedding: SqliteStore<EmbeddingStore>,
}

impl fmt::Debug for StoreSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreSet")
            .field("conversation", &self.conversation)
            .field("knowledge", &self.knowledge)
            .field("calendar", &self.calendar)
            .field("embedding", &self.embedding)
            .finish()
    }
}

impl StoreSet {
    pub async fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = prepare_store_root(root.as_ref())?;

        let conversation = open_store::<ConversationStore>(&root).await?;
        let knowledge = match open_store::<KnowledgeStore>(&root).await {
            Ok(store) => store,
            Err(error) => {
                let close_errors = [conversation.close().await.err()]
                    .into_iter()
                    .flatten()
                    .collect();
                return Err(with_close_errors(StoreKind::Knowledge, error, close_errors));
            }
        };
        let calendar = match open_store::<CalendarStore>(&root).await {
            Ok(store) => store,
            Err(error) => {
                let close_errors = [
                    knowledge.close().await.err(),
                    conversation.close().await.err(),
                ]
                .into_iter()
                .flatten()
                .collect();
                return Err(with_close_errors(StoreKind::Calendar, error, close_errors));
            }
        };
        let embedding = match open_store::<EmbeddingStore>(&root).await {
            Ok(store) => store,
            Err(error) => {
                let close_errors = [
                    calendar.close().await.err(),
                    knowledge.close().await.err(),
                    conversation.close().await.err(),
                ]
                .into_iter()
                .flatten()
                .collect();
                return Err(with_close_errors(StoreKind::Embedding, error, close_errors));
            }
        };

        Ok(Self {
            conversation,
            knowledge,
            calendar,
            embedding,
        })
    }

    pub async fn reports(&self) -> Result<Vec<StoreReport>, StoreError> {
        Ok(vec![
            self.conversation.report().await?,
            self.knowledge.report().await?,
            self.calendar.report().await?,
            self.embedding.report().await?,
        ])
    }

    pub async fn close(self) -> Result<(), StoreError> {
        let Self {
            conversation,
            knowledge,
            calendar,
            embedding,
        } = self;
        let mut first_error = None;

        for result in [
            conversation.close().await,
            knowledge.close().await,
            calendar.close().await,
            embedding.close().await,
        ] {
            if first_error.is_none() {
                first_error = result.err();
            }
        }

        first_error.map_or(Ok(()), Err)
    }
}

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    ExecutorClosed,
    OperationPoisoned {
        kind: StoreKind,
    },
    WrongStoreKind {
        expected: StoreKind,
        actual: String,
    },
    MigrationNamespace {
        expected: &'static str,
        actual: String,
    },
    MigrationDrift {
        namespace: &'static str,
        version: u32,
    },
    FutureMigration {
        namespace: &'static str,
        version: u32,
    },
    MissingStoreContract {
        expected: StoreKind,
    },
    UnrecognizedDatabase {
        expected: StoreKind,
        schema_objects: usize,
        application_id: i64,
        user_version: i64,
    },
    MigrationHistory {
        namespace: &'static str,
        expected_version: u32,
        actual_version: u32,
    },
    MissingMigrationHistory {
        namespace: &'static str,
    },
    IncompleteMigrationHistory {
        namespace: &'static str,
        expected_version: u32,
    },
    InvalidMigrationDefinition {
        namespace: &'static str,
        detail: String,
    },
    StorePolicy {
        kind: StoreKind,
        setting: &'static str,
        expected: String,
        actual: String,
    },
    IntegrityCheck {
        kind: StoreKind,
        result: String,
    },
    AttachedDatabase {
        kind: StoreKind,
        count: usize,
    },
    AuthControlPlaneCorrupt,
    BackupDestinationExists,
    BackupValidation {
        kind: StoreKind,
        detail: String,
    },
    UnsafeFilesystemPath {
        purpose: &'static str,
        path: PathBuf,
    },
    InsecureFilesystemPermissions {
        purpose: &'static str,
        path: PathBuf,
        actual_mode: u32,
        expected_mode: u32,
    },
    InsecureFilesystemOwner {
        purpose: &'static str,
        path: PathBuf,
        actual_uid: u32,
        expected_uid: u32,
    },
    FilesystemIdentityChanged {
        purpose: &'static str,
        path: PathBuf,
    },
    LifecycleCleanup {
        kind: StoreKind,
        operation: &'static str,
        primary_error: String,
        cleanup_error: String,
    },
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "store filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "SQLite error: {error}"),
            Self::ExecutorClosed => formatter.write_str("SQLite executor is closed"),
            Self::OperationPoisoned { kind } => {
                write!(formatter, "{kind} store operation state is poisoned")
            }
            Self::WrongStoreKind { expected, actual } => {
                write!(formatter, "expected {expected} store, found {actual}")
            }
            Self::MigrationNamespace { expected, actual } => write!(
                formatter,
                "expected migration namespace {expected}, found {actual}"
            ),
            Self::MigrationDrift { namespace, version } => {
                write!(
                    formatter,
                    "migration {namespace}/{version} changed after apply"
                )
            }
            Self::FutureMigration { namespace, version } => write!(
                formatter,
                "database has unknown future migration {namespace}/{version}"
            ),
            Self::MissingStoreContract { expected } => {
                write!(formatter, "{expected} store contract is missing")
            }
            Self::UnrecognizedDatabase {
                expected,
                schema_objects,
                application_id,
                user_version,
            } => write!(
                formatter,
                "refusing to adopt existing database as {expected}: schema_objects={schema_objects}, application_id={application_id}, user_version={user_version}"
            ),
            Self::MigrationHistory {
                namespace,
                expected_version,
                actual_version,
            } => write!(
                formatter,
                "migration history {namespace} expected version {expected_version}, found {actual_version}"
            ),
            Self::MissingMigrationHistory { namespace } => {
                write!(
                    formatter,
                    "recognized store has no migration history for {namespace}"
                )
            }
            Self::IncompleteMigrationHistory {
                namespace,
                expected_version,
            } => write!(
                formatter,
                "current store is missing migration {namespace}/{expected_version}"
            ),
            Self::InvalidMigrationDefinition { namespace, detail } => {
                write!(
                    formatter,
                    "invalid migration definition for {namespace}: {detail}"
                )
            }
            Self::StorePolicy {
                kind,
                setting,
                expected,
                actual,
            } => write!(
                formatter,
                "{kind} connection policy {setting} expected {expected}, found {actual}"
            ),
            Self::IntegrityCheck { kind, result } => {
                write!(formatter, "{kind} integrity check returned {result}")
            }
            Self::AttachedDatabase { kind, count } => write!(
                formatter,
                "{kind} connection has {count} databases attached instead of one"
            ),
            Self::AuthControlPlaneCorrupt => {
                formatter.write_str("authentication control plane is corrupt")
            }
            Self::BackupDestinationExists => {
                formatter.write_str("backup destination already exists")
            }
            Self::BackupValidation { kind, detail } => {
                write!(formatter, "{kind} backup validation failed: {detail}")
            }
            Self::UnsafeFilesystemPath { purpose, path } => {
                write!(formatter, "unsafe {purpose} path: {}", path.display())
            }
            Self::InsecureFilesystemPermissions {
                purpose,
                path,
                actual_mode,
                expected_mode,
            } => write!(
                formatter,
                "{purpose} {} has mode {actual_mode:o}; expected {expected_mode:o}",
                path.display()
            ),
            Self::InsecureFilesystemOwner {
                purpose,
                path,
                actual_uid,
                expected_uid,
            } => write!(
                formatter,
                "{purpose} {} is owned by uid {actual_uid}; expected effective uid {expected_uid}",
                path.display()
            ),
            Self::FilesystemIdentityChanged { purpose, path } => write!(
                formatter,
                "{purpose} {} changed filesystem identity",
                path.display()
            ),
            Self::LifecycleCleanup {
                kind,
                operation,
                primary_error,
                cleanup_error,
            } => write!(
                formatter,
                "{kind} {operation} failed ({primary_error}) and cleanup also failed ({cleanup_error})"
            ),
        }
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

fn with_close_errors(
    kind: StoreKind,
    primary: StoreError,
    close_errors: Vec<StoreError>,
) -> StoreError {
    if close_errors.is_empty() {
        primary
    } else {
        StoreError::LifecycleCleanup {
            kind,
            operation: "partial open",
            primary_error: primary.to_string(),
            cleanup_error: close_errors
                .into_iter()
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("; "),
        }
    }
}

#[derive(Clone, Copy)]
struct Migration {
    version: u32,
    name: &'static str,
    sql: &'static str,
}

const CONVERSATION_MIGRATIONS: [Migration; 5] = [
    Migration {
        version: 1,
        name: "store-contract",
        sql: include_str!("../migrations/sqlite/conversation/0001_store_contract.sql"),
    },
    Migration {
        version: 2,
        name: "conversation-append-outbox",
        sql: include_str!("../migrations/sqlite/conversation/0002_conversation_append_outbox.sql"),
    },
    Migration {
        version: 3,
        name: "durable-job-queue",
        sql: include_str!("../migrations/sqlite/conversation/0003_durable_job_queue.sql"),
    },
    Migration {
        version: 4,
        name: "local-auth-control-plane",
        sql: include_str!("../migrations/sqlite/conversation/0004_local_auth_control_plane.sql"),
    },
    Migration {
        version: 5,
        name: "auth-throttle-bounds",
        sql: include_str!("../migrations/sqlite/conversation/0005_auth_throttle_bounds.sql"),
    },
];
const KNOWLEDGE_MIGRATIONS: [Migration; 1] = [Migration {
    version: 1,
    name: "store-contract",
    sql: include_str!("../migrations/sqlite/knowledge/0001_store_contract.sql"),
}];
const CALENDAR_MIGRATIONS: [Migration; 1] = [Migration {
    version: 1,
    name: "store-contract",
    sql: include_str!("../migrations/sqlite/calendar/0001_store_contract.sql"),
}];
const EMBEDDING_MIGRATIONS: [Migration; 1] = [Migration {
    version: 1,
    name: "store-contract",
    sql: include_str!("../migrations/sqlite/embedding/0001_store_contract.sql"),
}];

fn migrations_for_kind(kind: StoreKind) -> &'static [Migration] {
    match kind {
        StoreKind::Conversation => &CONVERSATION_MIGRATIONS,
        StoreKind::Knowledge => &KNOWLEDGE_MIGRATIONS,
        StoreKind::Calendar => &CALENDAR_MIGRATIONS,
        StoreKind::Embedding => &EMBEDDING_MIGRATIONS,
    }
}

async fn open_store<S: StoreBoundary>(root: &Path) -> Result<SqliteStore<S>, StoreError> {
    let path = root.join(S::KIND.file_name());
    open_store_path::<S>(path).await
}

async fn open_store_path<S: StoreBoundary>(path: PathBuf) -> Result<SqliteStore<S>, StoreError> {
    let kind = S::KIND;
    let mut prepared = prepare_store_file(&path, kind)?;
    let path = prepared.path.clone();
    let initialization_authorized = prepared.initialization_authorized();
    let location = capture_store_location(&path, "store database")?;
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE;
    let connection = match Connection::open_with_flags(path.clone(), flags).await {
        Ok(connection) => connection,
        Err(error) => {
            let primary_error = StoreError::from(error);
            if let Err(cleanup_error) = prepared.cleanup_owned_files() {
                return Err(StoreError::LifecycleCleanup {
                    kind,
                    operation: "open",
                    primary_error: primary_error.to_string(),
                    cleanup_error: cleanup_error.to_string(),
                });
            }
            return Err(primary_error);
        }
    };
    prepared.disarm_drop_cleanup();
    if let Err(error) = validate_store_location(&location, "store database") {
        return match connection.close().await {
            Ok(()) => Err(error),
            Err(close_error) => Err(StoreError::LifecycleCleanup {
                kind,
                operation: "post-open identity validation",
                primary_error: error.to_string(),
                cleanup_error: close_error.to_string(),
            }),
        };
    }
    let migrations = migrations_for_kind(kind);

    let initialization = connection
        .call(move |connection| {
            initialize_connection(connection, kind, migrations, initialization_authorized)
        })
        .await
        .map_err(map_call_error);
    if let Err(error) = initialization {
        if let Err(close_error) = connection.close().await {
            return Err(StoreError::LifecycleCleanup {
                kind,
                operation: "initialization",
                primary_error: error.to_string(),
                cleanup_error: format!(
                    "{close_error}; reserved database and recovery marker were preserved"
                ),
            });
        }
        if let Err(cleanup_error) = prepared.cleanup_owned_files() {
            return Err(StoreError::LifecycleCleanup {
                kind,
                operation: "initialization",
                primary_error: error.to_string(),
                cleanup_error: cleanup_error.to_string(),
            });
        }
        return Err(error);
    }

    if let Err(marker_error) = prepared.remove_initialization_marker() {
        return match connection.close().await {
            Ok(()) => Err(StoreError::Io(marker_error)),
            Err(close_error) => Err(StoreError::LifecycleCleanup {
                kind,
                operation: "initialization marker cleanup",
                primary_error: marker_error.to_string(),
                cleanup_error: close_error.to_string(),
            }),
        };
    }

    Ok(SqliteStore {
        connection,
        #[cfg(unix)]
        location: Arc::new(location),
        operation_poisoned: Arc::new(AtomicBool::new(false)),
        marker: PhantomData,
    })
}

fn backup_to_new_file(
    source: &RawConnection,
    kind: StoreKind,
    migrations: &'static [Migration],
    destination: PathBuf,
) -> Result<BackupArtifact, StoreError> {
    ensure_database_sidecars_absent(&destination, "backup destination")?;
    reserve_owner_only_file(&destination, kind, "backup reservation").map_err(|error| {
        if matches!(
            &error,
            StoreError::Io(io_error)
                if io_error.kind() == std::io::ErrorKind::AlreadyExists
        ) {
            StoreError::BackupDestinationExists
        } else {
            error
        }
    })?;

    let result = (|| {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut destination_connection = RawConnection::open_with_flags(&destination, flags)?;
        destination_connection.pragma_update(None, "trusted_schema", "OFF")?;
        destination_connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        install_connection_authorizer(&destination_connection);
        {
            let backup = Backup::new(source, &mut destination_connection)?;
            backup.run_to_completion(64, Duration::from_millis(10), None)?;
        }

        validate_store_contract_row(&destination_connection, kind)?;
        let applied_migrations =
            validate_current_migration_history(&destination_connection, kind, migrations)?;
        let integrity_check: String =
            destination_connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if integrity_check != "ok" {
            return Err(StoreError::BackupValidation {
                kind,
                detail: integrity_check,
            });
        }
        let attached_databases = attached_database_count(&destination_connection)?;
        if attached_databases != 1 {
            return Err(StoreError::BackupValidation {
                kind,
                detail: format!("snapshot has {attached_databases} databases attached"),
            });
        }

        Ok(BackupArtifact {
            kind,
            source_file_name: kind.file_name(),
            migration_namespace: kind.sqlite_migration_namespace(),
            integrity_check,
            applied_migrations,
        })
    })();

    match result {
        Ok(artifact) => Ok(artifact),
        Err(error) => match cleanup_database_files(&destination) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(StoreError::LifecycleCleanup {
                kind,
                operation: "backup",
                primary_error: error.to_string(),
                cleanup_error: cleanup_error.to_string(),
            }),
        },
    }
}

fn initialize_connection(
    connection: &mut RawConnection,
    kind: StoreKind,
    migrations: &'static [Migration],
    initialization_authorized: bool,
) -> Result<(), StoreError> {
    let authorizer_state = configure_connection_policy(connection)?;

    let existing_store =
        validate_existing_store_contract(connection, kind, initialization_authorized)?;
    if existing_store {
        let applied = validate_migration_history(connection, kind, migrations)?;
        if applied.is_empty() {
            return Err(StoreError::MissingMigrationHistory {
                namespace: kind.sqlite_migration_namespace(),
            });
        }
    }

    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    apply_migrations(connection, kind, migrations, &authorizer_state)?;
    validate_current_migration_history(connection, kind, migrations)?;

    let report = read_report(connection, kind)?;
    validate_store_report(&report)
}

fn configure_connection_policy(
    connection: &mut RawConnection,
) -> Result<ConnectionAuthorizerState, StoreError> {
    connection.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MILLIS))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "recursive_triggers", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    connection.pragma_update(None, "cell_size_check", "ON")?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    Ok(install_connection_authorizer(connection))
}

#[cfg(unix)]
fn open_existing_store_connection(
    location: &StoreLocation,
    kind: StoreKind,
    access: ExistingConnectionAccess,
) -> Result<RawConnection, StoreError> {
    validate_store_location(location, "existing store database")?;
    let flags = match access {
        ExistingConnectionAccess::ReadWrite => OpenFlags::SQLITE_OPEN_READ_WRITE,
        ExistingConnectionAccess::ReadOnly => OpenFlags::SQLITE_OPEN_READ_ONLY,
    } | OpenFlags::SQLITE_OPEN_NOFOLLOW
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE;
    let mut connection = RawConnection::open_with_flags(&location.path, flags)?;

    let validation = (|| {
        validate_store_location(location, "existing store database")?;
        configure_connection_policy(&mut connection)?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        validate_store_contract_row(&connection, kind)?;
        validate_current_migration_history(&connection, kind, migrations_for_kind(kind))?;
        let report = read_report(&connection, kind)?;
        validate_store_report(&report)
    })();
    if let Err(error) = validation {
        return match connection.close() {
            Ok(()) => Err(error),
            Err((_connection, close_error)) => Err(StoreError::LifecycleCleanup {
                kind,
                operation: "fresh connection validation",
                primary_error: error.to_string(),
                cleanup_error: close_error.to_string(),
            }),
        };
    }

    Ok(connection)
}

#[derive(Clone, Default)]
struct ConnectionAuthorizerState {
    migration_sql_active: Arc<AtomicBool>,
}

struct MigrationSqlGuard<'a> {
    active: &'a AtomicBool,
}

impl Drop for MigrationSqlGuard<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

impl ConnectionAuthorizerState {
    fn enter_migration_sql(&self) -> MigrationSqlGuard<'_> {
        self.migration_sql_active.store(true, Ordering::Release);
        MigrationSqlGuard {
            active: &self.migration_sql_active,
        }
    }
}

fn install_connection_authorizer(connection: &RawConnection) -> ConnectionAuthorizerState {
    let state = ConnectionAuthorizerState::default();
    let callback_state = state.clone();
    connection.authorizer(Some(move |context: AuthContext<'_>| {
        let migration_sql_active = callback_state.migration_sql_active.load(Ordering::Acquire);
        match context.action {
            AuthAction::Attach { .. } | AuthAction::Detach { .. } => Authorization::Deny,
            AuthAction::Transaction { .. } | AuthAction::Savepoint { .. }
                if migration_sql_active =>
            {
                Authorization::Deny
            }
            AuthAction::Pragma {
                pragma_value: Some(_),
                ..
            } if migration_sql_active => Authorization::Deny,
            _ => Authorization::Allow,
        }
    }));
    state
}

fn validate_store_report(report: &StoreReport) -> Result<(), StoreError> {
    let kind = report.kind;
    for (setting, expected, actual) in [
        (
            "journal_mode",
            "wal".to_owned(),
            report.journal_mode.clone(),
        ),
        ("synchronous", "full".to_owned(), report.synchronous.clone()),
        (
            "foreign_keys",
            "on".to_owned(),
            if report.foreign_keys { "on" } else { "off" }.to_owned(),
        ),
        (
            "recursive_triggers",
            "on".to_owned(),
            if report.recursive_triggers {
                "on"
            } else {
                "off"
            }
            .to_owned(),
        ),
        (
            "busy_timeout",
            BUSY_TIMEOUT_MILLIS.to_string(),
            report.busy_timeout_millis.to_string(),
        ),
        (
            "trusted_schema",
            "off".to_owned(),
            if report.trusted_schema { "on" } else { "off" }.to_owned(),
        ),
        (
            "cell_size_check",
            "on".to_owned(),
            if report.cell_size_check { "on" } else { "off" }.to_owned(),
        ),
        (
            "defensive",
            "on".to_owned(),
            if report.defensive { "on" } else { "off" }.to_owned(),
        ),
    ] {
        if actual != expected {
            return Err(StoreError::StorePolicy {
                kind,
                setting,
                expected,
                actual,
            });
        }
    }

    if report.integrity_check != "ok" {
        return Err(StoreError::IntegrityCheck {
            kind,
            result: report.integrity_check.clone(),
        });
    }
    if report.attached_databases != 1 {
        return Err(StoreError::AttachedDatabase {
            kind,
            count: report.attached_databases,
        });
    }

    Ok(())
}

fn validate_existing_store_contract(
    connection: &RawConnection,
    expected: StoreKind,
    initialization_authorized: bool,
) -> Result<bool, StoreError> {
    let table_exists: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_schema
            WHERE type = 'table' AND name = '_pov_store_contract'
        )",
        [],
        |row| row.get(0),
    )?;

    if !table_exists {
        let schema_objects: usize = connection.query_row(
            "SELECT count(*)
             FROM sqlite_schema
             WHERE type IN ('table', 'index', 'view', 'trigger')
               AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        let application_id: i64 =
            connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
        let user_version: i64 =
            connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        return if initialization_authorized
            && schema_objects == 0
            && application_id == 0
            && user_version == 0
        {
            Ok(false)
        } else {
            Err(StoreError::UnrecognizedDatabase {
                expected,
                schema_objects,
                application_id,
                user_version,
            })
        };
    }

    validate_store_contract_row(connection, expected)?;
    Ok(true)
}

type MigrationRow = (String, u32, String, String);

fn validate_migration_definitions(
    namespace: &'static str,
    migrations: &[Migration],
) -> Result<(), StoreError> {
    let mut previous = 0;
    for migration in migrations {
        if migration.version == 0 || migration.version <= previous {
            return Err(StoreError::InvalidMigrationDefinition {
                namespace,
                detail: format!(
                    "version {} must be positive and strictly greater than {previous}",
                    migration.version
                ),
            });
        }
        previous = migration.version;
    }
    Ok(())
}

fn read_migration_rows(connection: &RawConnection) -> Result<Vec<MigrationRow>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT namespace, version, name, migration_sql
         FROM _pov_migrations
         ORDER BY version",
    )?;
    Ok(statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?)
}

fn validate_migration_history(
    connection: &RawConnection,
    kind: StoreKind,
    migrations: &'static [Migration],
) -> Result<Vec<AppliedMigration>, StoreError> {
    let namespace = kind.sqlite_migration_namespace();
    validate_migration_definitions(namespace, migrations)?;
    let existing = read_migration_rows(connection)?;

    for (index, (actual_namespace, version, name, sql)) in existing.iter().enumerate() {
        if actual_namespace != namespace {
            return Err(StoreError::MigrationNamespace {
                expected: namespace,
                actual: actual_namespace.clone(),
            });
        }

        let Some(expected) = migrations.get(index) else {
            return Err(StoreError::FutureMigration {
                namespace,
                version: *version,
            });
        };
        if expected.version != *version {
            return Err(StoreError::MigrationHistory {
                namespace,
                expected_version: expected.version,
                actual_version: *version,
            });
        }
        if expected.name != name || expected.sql != sql {
            return Err(StoreError::MigrationDrift {
                namespace,
                version: *version,
            });
        }
    }

    Ok(existing
        .into_iter()
        .map(|(namespace, version, name, _)| AppliedMigration {
            namespace,
            version,
            name,
        })
        .collect())
}

fn validate_current_migration_history(
    connection: &RawConnection,
    kind: StoreKind,
    migrations: &'static [Migration],
) -> Result<Vec<AppliedMigration>, StoreError> {
    let applied = validate_migration_history(connection, kind, migrations)?;
    if applied.is_empty() {
        return Err(StoreError::MissingMigrationHistory {
            namespace: kind.sqlite_migration_namespace(),
        });
    }
    if applied.len() < migrations.len() {
        return Err(StoreError::IncompleteMigrationHistory {
            namespace: kind.sqlite_migration_namespace(),
            expected_version: migrations[applied.len()].version,
        });
    }
    Ok(applied)
}

fn apply_migrations(
    connection: &mut RawConnection,
    kind: StoreKind,
    migrations: &'static [Migration],
    authorizer_state: &ConnectionAuthorizerState,
) -> Result<(), StoreError> {
    let namespace = kind.sqlite_migration_namespace();
    validate_migration_definitions(namespace, migrations)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS _pov_migrations (
            namespace TEXT NOT NULL,
            version INTEGER NOT NULL CHECK(version > 0),
            name TEXT NOT NULL,
            migration_sql TEXT NOT NULL,
            PRIMARY KEY(namespace, version)
        ) STRICT;",
    )?;

    let existing = validate_migration_history(&transaction, kind, migrations)?;

    for migration in migrations.iter().skip(existing.len()) {
        {
            let _guard = authorizer_state.enter_migration_sql();
            transaction.execute_batch(migration.sql)?;
        }
        transaction.execute(
            "INSERT INTO _pov_migrations(namespace, version, name, migration_sql)
             VALUES (?1, ?2, ?3, ?4)",
            (namespace, migration.version, migration.name, migration.sql),
        )?;
    }

    validate_store_contract_row(&transaction, kind)?;
    validate_current_migration_history(&transaction, kind, migrations)?;
    transaction.commit()?;
    Ok(())
}

fn validate_store_contract_row(
    connection: &RawConnection,
    expected: StoreKind,
) -> Result<(), StoreError> {
    let (actual_kind, actual_namespace): (String, String) = connection
        .query_row(
            "SELECT store_kind, migration_namespace
             FROM _pov_store_contract
             WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => StoreError::MissingStoreContract { expected },
            other => StoreError::Sqlite(other),
        })?;

    if actual_kind != expected.as_str() {
        return Err(StoreError::WrongStoreKind {
            expected,
            actual: actual_kind,
        });
    }
    if actual_namespace != expected.sqlite_migration_namespace() {
        return Err(StoreError::MigrationNamespace {
            expected: expected.sqlite_migration_namespace(),
            actual: actual_namespace,
        });
    }

    Ok(())
}

fn read_report(connection: &RawConnection, kind: StoreKind) -> Result<StoreReport, StoreError> {
    let journal_mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let synchronous_value: u8 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let foreign_keys: bool = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let recursive_triggers: bool =
        connection.query_row("PRAGMA recursive_triggers", [], |row| row.get(0))?;
    let busy_timeout_millis: u64 =
        connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    let trusted_schema: bool =
        connection.query_row("PRAGMA trusted_schema", [], |row| row.get(0))?;
    let cell_size_check: bool =
        connection.query_row("PRAGMA cell_size_check", [], |row| row.get(0))?;
    let defensive = connection.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)?;
    let integrity_check: String =
        connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    let attached_databases = attached_database_count(connection)?;
    let applied_migrations = read_applied_migrations(connection)?;

    Ok(StoreReport {
        kind,
        role: StoreRole::for_kind(kind),
        file_name: kind.file_name(),
        migration_namespace: kind.sqlite_migration_namespace(),
        journal_mode: journal_mode.to_ascii_lowercase(),
        synchronous: match synchronous_value {
            0 => "off",
            1 => "normal",
            2 => "full",
            3 => "extra",
            _ => "unknown",
        }
        .to_owned(),
        foreign_keys,
        recursive_triggers,
        busy_timeout_millis,
        trusted_schema,
        cell_size_check,
        defensive,
        integrity_check,
        attached_databases,
        applied_migrations,
    })
}

fn attached_database_count(connection: &RawConnection) -> Result<usize, StoreError> {
    let mut statement = connection.prepare("PRAGMA database_list")?;
    let database_names = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(database_names
        .into_iter()
        .filter(|name| name != "temp")
        .count())
}

fn read_applied_migrations(
    connection: &RawConnection,
) -> Result<Vec<AppliedMigration>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT namespace, version, name
         FROM _pov_migrations
         ORDER BY version",
    )?;
    Ok(statement
        .query_map([], |row| {
            Ok(AppliedMigration {
                namespace: row.get(0)?,
                version: row.get(1)?,
                name: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?)
}

fn prepare_store_root(root: &Path) -> Result<PathBuf, StoreError> {
    let absolute = if root.is_absolute() {
        root.to_owned()
    } else {
        std::env::current_dir()?.join(root)
    };

    match std::fs::symlink_metadata(&absolute) {
        Ok(metadata) => validate_secure_directory(&absolute, &metadata, "store root")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true).mode(0o700).create(&absolute)?;
            }
            #[cfg(not(unix))]
            std::fs::create_dir_all(&absolute)?;

            let metadata = std::fs::symlink_metadata(&absolute)?;
            validate_secure_directory(&absolute, &metadata, "store root")?;
        }
        Err(error) => return Err(StoreError::Io(error)),
    }

    Ok(std::fs::canonicalize(absolute)?)
}

fn resolve_secure_file_path(path: &Path, purpose: &'static str) -> Result<PathBuf, StoreError> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let file_name = absolute
        .file_name()
        .ok_or_else(|| StoreError::UnsafeFilesystemPath {
            purpose,
            path: absolute.clone(),
        })?
        .to_owned();
    let parent = absolute
        .parent()
        .ok_or_else(|| StoreError::UnsafeFilesystemPath {
            purpose,
            path: absolute.clone(),
        })?;
    let canonical_parent = std::fs::canonicalize(parent)?;
    let parent_metadata = std::fs::symlink_metadata(&canonical_parent)?;
    validate_secure_directory(&canonical_parent, &parent_metadata, "database parent")?;
    let resolved = canonical_parent.join(file_name);

    if let Ok(metadata) = std::fs::symlink_metadata(&resolved)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(StoreError::UnsafeFilesystemPath {
            purpose,
            path: resolved,
        });
    }

    Ok(resolved)
}

fn capture_store_location(path: &Path, purpose: &'static str) -> Result<StoreLocation, StoreError> {
    let resolved = resolve_secure_file_path(path, purpose)?;
    let metadata = std::fs::symlink_metadata(&resolved)?;
    validate_secure_file(&resolved, &metadata, purpose)?;
    #[cfg(unix)]
    let directory_identity = {
        let parent = resolved
            .parent()
            .ok_or_else(|| StoreError::UnsafeFilesystemPath {
                purpose,
                path: resolved.clone(),
            })?;
        let parent_metadata = std::fs::symlink_metadata(parent)?;
        validate_secure_directory(parent, &parent_metadata, purpose)?;
        store_directory_identity(&parent_metadata)
    };
    Ok(StoreLocation {
        path: resolved,
        #[cfg(unix)]
        identity: store_file_identity(&metadata),
        #[cfg(unix)]
        directory_identity,
    })
}

fn validate_store_location(
    location: &StoreLocation,
    purpose: &'static str,
) -> Result<(), StoreError> {
    let resolved = resolve_secure_file_path(&location.path, purpose)?;
    if resolved != location.path {
        return Err(StoreError::FilesystemIdentityChanged {
            purpose,
            path: location.path.clone(),
        });
    }
    let metadata = std::fs::symlink_metadata(&resolved)?;
    validate_secure_file(&resolved, &metadata, purpose)?;
    #[cfg(unix)]
    {
        if store_file_identity(&metadata) != location.identity {
            return Err(StoreError::FilesystemIdentityChanged {
                purpose,
                path: location.path.clone(),
            });
        }
        let parent = resolved
            .parent()
            .ok_or_else(|| StoreError::UnsafeFilesystemPath {
                purpose,
                path: location.path.clone(),
            })?;
        let parent_metadata = std::fs::symlink_metadata(parent)?;
        validate_secure_directory(parent, &parent_metadata, purpose)?;
        if store_directory_identity(&parent_metadata) != location.directory_identity {
            return Err(StoreError::FilesystemIdentityChanged {
                purpose,
                path: location.path.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn store_file_identity(metadata: &std::fs::Metadata) -> StoreFileIdentity {
    use std::os::unix::fs::MetadataExt;

    StoreFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
    }
}

#[cfg(unix)]
fn store_directory_identity(metadata: &std::fs::Metadata) -> StoreDirectoryIdentity {
    use std::os::unix::fs::MetadataExt;

    StoreDirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
    }
}

struct PreparedStoreFile {
    path: PathBuf,
    initialization_marker: Option<PathBuf>,
    main_created_this_call: bool,
    marker_created_this_call: bool,
    drop_cleanup_armed: bool,
}

impl PreparedStoreFile {
    fn initialization_authorized(&self) -> bool {
        self.initialization_marker.is_some()
    }

    fn disarm_drop_cleanup(&mut self) {
        self.drop_cleanup_armed = false;
    }

    fn cleanup_owned_files(&mut self) -> Result<(), std::io::Error> {
        if self.main_created_this_call {
            cleanup_database_files(&self.path)?;
            self.main_created_this_call = false;
        }

        if self.marker_created_this_call
            && let Some(marker) = &self.initialization_marker
        {
            remove_file_if_present(marker)?;
            self.initialization_marker = None;
            self.marker_created_this_call = false;
        }

        self.drop_cleanup_armed = false;
        Ok(())
    }

    fn remove_initialization_marker(&mut self) -> Result<(), std::io::Error> {
        if let Some(marker) = &self.initialization_marker {
            remove_file_if_present(marker)?;
        }
        self.initialization_marker = None;
        self.marker_created_this_call = false;
        Ok(())
    }
}

impl Drop for PreparedStoreFile {
    fn drop(&mut self) {
        if self.drop_cleanup_armed {
            let _ = self.cleanup_owned_files();
        }
    }
}

fn prepare_store_file(path: &Path, kind: StoreKind) -> Result<PreparedStoreFile, StoreError> {
    let path = resolve_secure_file_path(path, "store database")?;
    let initialization_marker_path = store_initialization_marker_path(&path);
    let (initialization_marker, marker_created_this_call) =
        prepare_initialization_marker_if_present(&initialization_marker_path)?;

    let mut prepared = PreparedStoreFile {
        path: path.clone(),
        initialization_marker,
        main_created_this_call: false,
        marker_created_this_call,
        drop_cleanup_armed: marker_created_this_call,
    };

    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            validate_secure_file(&path, &metadata, "store database")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure_database_sidecars_absent(&path, "store database")?;
            if prepared.initialization_marker.is_none() {
                reserve_initialization_marker(&initialization_marker_path, kind)?;
                prepared.initialization_marker = Some(initialization_marker_path);
                prepared.marker_created_this_call = true;
                prepared.drop_cleanup_armed = true;
            }
            match reserve_owner_only_file(&path, kind, "store reservation") {
                Ok(()) => {
                    prepared.main_created_this_call = true;
                    prepared.drop_cleanup_armed = true;
                }
                Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let metadata = std::fs::symlink_metadata(&path)?;
                    validate_secure_file(&path, &metadata, "store database")?;
                }
                Err(error) => {
                    if let Err(cleanup_error) = prepared.cleanup_owned_files() {
                        return Err(StoreError::LifecycleCleanup {
                            kind,
                            operation: "store reservation",
                            primary_error: error.to_string(),
                            cleanup_error: cleanup_error.to_string(),
                        });
                    }
                    return Err(error);
                }
            }
        }
        Err(error) => return Err(StoreError::Io(error)),
    }

    Ok(prepared)
}

fn store_initialization_marker_path(path: &Path) -> PathBuf {
    let mut marker = path.as_os_str().to_owned();
    marker.push("-init");
    PathBuf::from(marker)
}

fn prepare_initialization_marker_if_present(
    marker: &Path,
) -> Result<(Option<PathBuf>, bool), StoreError> {
    match std::fs::symlink_metadata(marker) {
        Ok(metadata) => {
            validate_secure_file(marker, &metadata, "store initialization marker")?;
            if std::fs::read(marker)? != STORE_INITIALIZATION_MARKER {
                return Err(StoreError::UnsafeFilesystemPath {
                    purpose: "store initialization marker",
                    path: marker.to_owned(),
                });
            }
            Ok((Some(marker.to_owned()), false))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((None, false)),
        Err(error) => Err(StoreError::Io(error)),
    }
}

fn reserve_initialization_marker(marker: &Path, kind: StoreKind) -> Result<(), StoreError> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let result = (|| {
        let mut file = options.open(marker)?;
        file.write_all(STORE_INITIALIZATION_MARKER)?;
        file.sync_all()?;
        drop(file);
        let metadata = std::fs::symlink_metadata(marker)?;
        validate_secure_file(marker, &metadata, "store initialization marker")
    })();

    match result {
        Ok(()) => Ok(()),
        Err(error) => match remove_file_if_present(marker) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(StoreError::LifecycleCleanup {
                kind,
                operation: "initialization marker reservation",
                primary_error: error.to_string(),
                cleanup_error: cleanup_error.to_string(),
            }),
        },
    }
}

fn reserve_owner_only_file(
    path: &Path,
    kind: StoreKind,
    operation: &'static str,
) -> Result<(), StoreError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    drop(options.open(path)?);
    let validation = std::fs::symlink_metadata(path)
        .map_err(StoreError::from)
        .and_then(|metadata| validate_secure_file(path, &metadata, "database file"));
    match validation {
        Ok(()) => Ok(()),
        Err(error) => match remove_file_if_present(path) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(StoreError::LifecycleCleanup {
                kind,
                operation,
                primary_error: error.to_string(),
                cleanup_error: cleanup_error.to_string(),
            }),
        },
    }
}

fn ensure_database_sidecars_absent(path: &Path, purpose: &'static str) -> Result<(), StoreError> {
    for sidecar in database_sidecar_paths(path) {
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) => {
                return Err(StoreError::UnsafeFilesystemPath {
                    purpose,
                    path: sidecar,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::Io(error)),
        }
    }
    Ok(())
}

fn validate_secure_directory(
    path: &Path,
    metadata: &std::fs::Metadata,
    purpose: &'static str,
) -> Result<(), StoreError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StoreError::UnsafeFilesystemPath {
            purpose,
            path: path.to_owned(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        validate_effective_owner(
            path,
            purpose,
            metadata.uid(),
            rustix::process::geteuid().as_raw(),
        )?;
        let actual_mode = metadata.permissions().mode() & 0o777;
        if actual_mode != 0o700 {
            return Err(StoreError::InsecureFilesystemPermissions {
                purpose,
                path: path.to_owned(),
                actual_mode,
                expected_mode: 0o700,
            });
        }
    }
    Ok(())
}

fn validate_secure_file(
    path: &Path,
    metadata: &std::fs::Metadata,
    purpose: &'static str,
) -> Result<(), StoreError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StoreError::UnsafeFilesystemPath {
            purpose,
            path: path.to_owned(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        validate_effective_owner(
            path,
            purpose,
            metadata.uid(),
            rustix::process::geteuid().as_raw(),
        )?;
        let actual_mode = metadata.permissions().mode() & 0o777;
        if metadata.nlink() != 1 {
            return Err(StoreError::UnsafeFilesystemPath {
                purpose,
                path: path.to_owned(),
            });
        }
        if actual_mode != 0o600 {
            return Err(StoreError::InsecureFilesystemPermissions {
                purpose,
                path: path.to_owned(),
                actual_mode,
                expected_mode: 0o600,
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_effective_owner(
    path: &Path,
    purpose: &'static str,
    actual_uid: u32,
    expected_uid: u32,
) -> Result<(), StoreError> {
    if actual_uid != expected_uid {
        return Err(StoreError::InsecureFilesystemOwner {
            purpose,
            path: path.to_owned(),
            actual_uid,
            expected_uid,
        });
    }
    Ok(())
}

fn cleanup_database_files(path: &Path) -> Result<(), std::io::Error> {
    let mut first_error = remove_file_if_present(path).err();
    for sidecar in database_sidecar_paths(path) {
        if let Err(error) = remove_file_if_present(&sidecar)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn database_sidecar_paths(path: &Path) -> [PathBuf; 3] {
    ["-journal", "-shm", "-wal"].map(|suffix| {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        PathBuf::from(sidecar)
    })
}

fn remove_file_if_present(path: &Path) -> Result<(), std::io::Error> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn map_call_error(error: tokio_rusqlite::Error<StoreError>) -> StoreError {
    match error {
        tokio_rusqlite::Error::ConnectionClosed => StoreError::ExecutorClosed,
        tokio_rusqlite::Error::Close((_, error)) => StoreError::Sqlite(error),
        tokio_rusqlite::Error::Error(error) => error,
        _ => StoreError::ExecutorClosed,
    }
}

fn map_close_error(error: tokio_rusqlite::Error) -> StoreError {
    match error {
        tokio_rusqlite::Error::ConnectionClosed => StoreError::ExecutorClosed,
        tokio_rusqlite::Error::Close((_, error)) | tokio_rusqlite::Error::Error(error) => {
            StoreError::Sqlite(error)
        }
        _ => StoreError::ExecutorClosed,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, path::PathBuf, thread::ThreadId};

    use tempfile::tempdir;
    use tokio_rusqlite::rusqlite::{
        Connection as RawConnection, Error as SqliteError, ErrorCode, OpenFlags,
    };

    #[cfg(unix)]
    use super::AuthInitializationSourceFingerprint;
    use super::{
        BackupHook, ConversationStore, KnowledgeStore, Migration, PreparedStoreFile, SqliteStore,
        StoreError, StoreKind, StoreSet, apply_migrations, attached_database_count,
        database_sidecar_paths, install_connection_authorizer, open_store, open_store_path,
        prepare_store_file, prepare_store_root, reserve_initialization_marker,
        reserve_owner_only_file, store_initialization_marker_path,
        validate_current_migration_history, validate_migration_definitions,
        validate_migration_history,
    };

    #[cfg(unix)]
    #[test]
    fn initialization_source_fingerprint_debug_is_fully_redacted() {
        let fingerprint = AuthInitializationSourceFingerprint::from_bytes([0xab; 32]);

        assert_eq!(
            format!("{fingerprint:?}"),
            "AuthInitializationSourceFingerprint([REDACTED])"
        );
    }

    fn is_authorization_denied(error: &StoreError) -> bool {
        matches!(
            error,
            StoreError::Sqlite(SqliteError::SqliteFailure(code, _))
                if code.code == ErrorCode::AuthorizationForStatementDenied
        )
    }

    async fn worker_thread<S: super::StoreBoundary>(store: &SqliteStore<S>) -> ThreadId {
        store
            .connection
            .call_raw(|_| std::thread::current().id())
            .await
            .expect("worker thread should answer")
    }

    #[tokio::test]
    async fn each_store_uses_a_distinct_blocking_executor_thread() {
        let directory = tempdir().expect("temporary store directory");
        let root = directory.path().join("stores");
        let stores = StoreSet::open(&root).await.expect("stores should open");
        let caller = std::thread::current().id();
        let workers = [
            worker_thread(&stores.conversation).await,
            worker_thread(&stores.knowledge).await,
            worker_thread(&stores.calendar).await,
            worker_thread(&stores.embedding).await,
        ];

        assert!(workers.iter().all(|worker| *worker != caller));
        assert_eq!(workers.into_iter().collect::<HashSet<_>>().len(), 4);
    }

    #[tokio::test]
    async fn attach_is_denied_by_connection_policy() {
        let directory = tempdir().expect("temporary store directory");
        let root = directory.path().join("stores");
        let stores = StoreSet::open(&root).await.expect("stores should open");

        let attach = stores
            .conversation
            .connection
            .call(|connection| {
                connection
                    .execute_batch("ATTACH DATABASE ':memory:' AS other")
                    .map_err(StoreError::from)
            })
            .await;

        assert!(matches!(
            attach,
            Err(tokio_rusqlite::Error::Error(ref error))
                if is_authorization_denied(error)
        ));
        assert_eq!(
            stores
                .conversation
                .report()
                .await
                .expect("connection report")
                .attached_databases,
            1
        );
    }

    #[test]
    fn detach_is_denied_when_an_attachment_already_exists() {
        let connection = RawConnection::open_in_memory().expect("in-memory connection");
        connection
            .execute_batch("ATTACH DATABASE ':memory:' AS other")
            .expect("synthetic pre-policy attachment");
        install_connection_authorizer(&connection);

        let error = connection
            .execute_batch("DETACH DATABASE other")
            .expect_err("detach must be denied");

        assert!(is_authorization_denied(&StoreError::from(error)));
        assert_eq!(
            attached_database_count(&connection).expect("database list"),
            2
        );
    }

    #[test]
    fn migration_time_attach_is_denied_and_the_transaction_rolls_back() {
        static MIGRATIONS: [Migration; 2] = [
            Migration {
                version: 1,
                name: "store-contract",
                sql: include_str!("../migrations/sqlite/conversation/0001_store_contract.sql"),
            },
            Migration {
                version: 2,
                name: "forbidden-attach",
                sql: "ATTACH DATABASE ':memory:' AS forbidden;",
            },
        ];

        let mut connection = RawConnection::open_in_memory().expect("in-memory connection");
        connection
            .set_db_config(
                tokio_rusqlite::rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE,
                true,
            )
            .expect("defensive mode");
        let authorizer_state = install_connection_authorizer(&connection);

        let error = apply_migrations(
            &mut connection,
            StoreKind::Conversation,
            &MIGRATIONS,
            &authorizer_state,
        )
        .expect_err("migration-time attach must fail");

        assert!(is_authorization_denied(&error));
        let pov_tables: usize = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name LIKE '_pov_%'",
                [],
                |row| row.get(0),
            )
            .expect("schema count");
        assert_eq!(pov_tables, 0);
        assert_eq!(
            attached_database_count(&connection).expect("database list"),
            1
        );
    }

    #[test]
    fn migration_sql_cannot_escape_transaction_or_change_owned_pragmas() {
        static COMMIT_MIGRATIONS: [Migration; 2] = [
            Migration {
                version: 1,
                name: "store-contract",
                sql: include_str!("../migrations/sqlite/conversation/0001_store_contract.sql"),
            },
            Migration {
                version: 2,
                name: "forbidden-commit",
                sql: "COMMIT;
                      CREATE TABLE escaped(id INTEGER PRIMARY KEY) STRICT;",
            },
        ];
        static SAVEPOINT_MIGRATIONS: [Migration; 2] = [
            Migration {
                version: 1,
                name: "store-contract",
                sql: include_str!("../migrations/sqlite/conversation/0001_store_contract.sql"),
            },
            Migration {
                version: 2,
                name: "forbidden-savepoint",
                sql: "SAVEPOINT forbidden;
                      CREATE TABLE escaped(id INTEGER PRIMARY KEY) STRICT;
                      RELEASE forbidden;",
            },
        ];
        static PRAGMA_MIGRATIONS: [Migration; 2] = [
            Migration {
                version: 1,
                name: "store-contract",
                sql: include_str!("../migrations/sqlite/conversation/0001_store_contract.sql"),
            },
            Migration {
                version: 2,
                name: "forbidden-pragma",
                sql: "PRAGMA user_version = 77;
                      CREATE TABLE escaped(id INTEGER PRIMARY KEY) STRICT;",
            },
        ];

        for migrations in [
            &COMMIT_MIGRATIONS[..],
            &SAVEPOINT_MIGRATIONS[..],
            &PRAGMA_MIGRATIONS[..],
        ] {
            let mut connection = RawConnection::open_in_memory().expect("in-memory connection");
            connection
                .set_db_config(
                    tokio_rusqlite::rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE,
                    true,
                )
                .expect("defensive mode");
            let authorizer_state = install_connection_authorizer(&connection);

            let error = apply_migrations(
                &mut connection,
                StoreKind::Conversation,
                migrations,
                &authorizer_state,
            )
            .expect_err("migration transaction control must fail");

            assert!(is_authorization_denied(&error));
            let persistent_objects: usize = connection
                .query_row(
                    "SELECT count(*)
                     FROM sqlite_schema
                     WHERE name LIKE '_pov_%' OR name = 'escaped'",
                    [],
                    |row| row.get(0),
                )
                .expect("schema count");
            assert_eq!(persistent_objects, 0);
            let user_version: i64 = connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .expect("user version");
            assert_eq!(user_version, 0);
        }
    }

    #[test]
    fn migration_cannot_commit_tampered_prior_history() {
        static BASE_MIGRATIONS: [Migration; 1] = [Migration {
            version: 1,
            name: "store-contract",
            sql: include_str!("../migrations/sqlite/conversation/0001_store_contract.sql"),
        }];
        static TAMPERING_MIGRATIONS: [Migration; 2] = [
            Migration {
                version: 1,
                name: "store-contract",
                sql: include_str!("../migrations/sqlite/conversation/0001_store_contract.sql"),
            },
            Migration {
                version: 2,
                name: "tamper-history",
                sql: "UPDATE _pov_migrations
                      SET migration_sql = '-- tampered in migration'
                      WHERE version = 1;
                      CREATE TABLE escaped(id INTEGER PRIMARY KEY) STRICT;",
            },
        ];

        let mut connection = RawConnection::open_in_memory().expect("in-memory connection");
        let authorizer_state = install_connection_authorizer(&connection);
        apply_migrations(
            &mut connection,
            StoreKind::Conversation,
            &BASE_MIGRATIONS,
            &authorizer_state,
        )
        .expect("base migration");

        let error = apply_migrations(
            &mut connection,
            StoreKind::Conversation,
            &TAMPERING_MIGRATIONS,
            &authorizer_state,
        )
        .expect_err("history tamper must fail before commit");

        assert!(matches!(
            error,
            StoreError::MigrationDrift { version: 1, .. }
        ));
        validate_current_migration_history(&connection, StoreKind::Conversation, &BASE_MIGRATIONS)
            .expect("base history remains current");
        let escaped_exists: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_schema
                    WHERE type = 'table' AND name = 'escaped'
                )",
                [],
                |row| row.get(0),
            )
            .expect("escaped table query");
        assert!(!escaped_exists);
    }

    #[tokio::test]
    async fn foreign_keys_reject_orphans() {
        let directory = tempdir().expect("temporary store directory");
        let root = directory.path().join("stores");
        let stores = StoreSet::open(&root).await.expect("stores should open");

        let result = stores
            .conversation
            .connection
            .call(|connection| {
                connection.execute_batch(
                    "CREATE TABLE synthetic_parent(id INTEGER PRIMARY KEY) STRICT;
                     CREATE TABLE synthetic_child(
                         id INTEGER PRIMARY KEY,
                         parent_id INTEGER NOT NULL
                             REFERENCES synthetic_parent(id)
                     ) STRICT;
                     INSERT INTO synthetic_child(id, parent_id) VALUES (1, 404);",
                )?;
                Ok::<_, StoreError>(())
            })
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn wrong_store_kind_fails_before_mixing_migrations() {
        let directory = tempdir().expect("temporary store directory");
        let root = directory.path().join("stores");
        let stores = StoreSet::open(&root).await.expect("stores should open");
        stores.close().await.expect("stores should close");

        let conversation_path = std::fs::canonicalize(&root)
            .expect("canonical store root")
            .join(StoreKind::Conversation.file_name());
        let error = open_store_path::<KnowledgeStore>(conversation_path)
            .await
            .expect_err("knowledge must not open a conversation file");

        assert!(matches!(
            error,
            StoreError::WrongStoreKind {
                expected: StoreKind::Knowledge,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn markerless_nonempty_database_gets_no_pov_schema_or_wal_mode() {
        let directory = tempdir().expect("temporary store directory");
        let root = prepare_store_root(&directory.path().join("stores")).expect("secure store root");
        let path = root.join(StoreKind::Conversation.file_name());
        reserve_owner_only_file(&path, StoreKind::Conversation, "test reservation")
            .expect("owner-only synthetic database");
        let connection = RawConnection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("synthetic database");
        connection
            .execute_batch("CREATE TABLE unrelated(id INTEGER PRIMARY KEY) STRICT;")
            .expect("unrelated schema");
        drop(connection);

        let error = open_store::<ConversationStore>(&root)
            .await
            .expect_err("unrecognized database must fail closed");

        assert!(matches!(
            error,
            StoreError::UnrecognizedDatabase {
                expected: StoreKind::Conversation,
                schema_objects: 1,
                ..
            }
        ));
        let connection = RawConnection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("database remains readable");
        let unrelated_exists: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_schema
                    WHERE type = 'table' AND name = 'unrelated'
                )",
                [],
                |row| row.get(0),
            )
            .expect("unrelated table query");
        let pov_objects: usize = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name LIKE '_pov_%'",
                [],
                |row| row.get(0),
            )
            .expect("POV schema query");
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("journal mode");

        assert!(unrelated_exists);
        assert_eq!(pov_objects, 0);
        assert_eq!(journal_mode, "delete");
    }

    #[test]
    fn dropped_prepared_reservation_removes_only_owned_main_and_marker() {
        let directory = tempdir().expect("temporary store directory");
        let root = prepare_store_root(&directory.path().join("stores")).expect("secure store root");
        let path = root.join(StoreKind::Conversation.file_name());
        let marker = store_initialization_marker_path(&path);

        {
            let prepared =
                prepare_store_file(&path, StoreKind::Conversation).expect("prepared reservation");
            assert!(prepared.main_created_this_call);
            assert!(prepared.marker_created_this_call);
            assert!(path.exists());
            assert!(marker.exists());
        }

        assert!(!path.exists());
        assert!(!marker.exists());
    }

    #[test]
    fn failed_main_cleanup_preserves_recovery_marker() {
        let directory = tempdir().expect("temporary store directory");
        let root = prepare_store_root(&directory.path().join("stores")).expect("secure store root");
        let path = root.join(StoreKind::Conversation.file_name());
        let marker = store_initialization_marker_path(&path);
        std::fs::create_dir(&path).expect("synthetic cleanup blocker");
        reserve_initialization_marker(&marker, StoreKind::Conversation).expect("recovery marker");

        let mut prepared = PreparedStoreFile {
            path,
            initialization_marker: Some(marker.clone()),
            main_created_this_call: true,
            marker_created_this_call: true,
            drop_cleanup_armed: true,
        };
        prepared
            .cleanup_owned_files()
            .expect_err("main cleanup must fail");

        assert_eq!(
            std::fs::read(&marker).expect("marker remains"),
            super::STORE_INITIALIZATION_MARKER
        );
        prepared.disarm_drop_cleanup();
    }

    #[tokio::test]
    async fn interrupted_empty_store_initialization_recovers_and_removes_marker() {
        let directory = tempdir().expect("temporary store directory");
        let root = prepare_store_root(&directory.path().join("stores")).expect("secure store root");
        let path = root.join(StoreKind::Conversation.file_name());
        let marker = store_initialization_marker_path(&path);
        reserve_initialization_marker(&marker, StoreKind::Conversation).expect("recovery marker");
        reserve_owner_only_file(&path, StoreKind::Conversation, "test reservation")
            .expect("owner-only synthetic database");
        let connection = RawConnection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("synthetic database");
        connection
            .execute_batch(
                "CREATE TABLE interrupted_initialization(id INTEGER PRIMARY KEY) STRICT;
                 DROP TABLE interrupted_initialization;",
            )
            .expect("format otherwise-empty SQLite file");
        drop(connection);

        let store = open_store::<ConversationStore>(&root)
            .await
            .expect("reserved empty database should recover");
        let report = store.report().await.expect("recovered store report");
        assert_eq!(report.kind, StoreKind::Conversation);
        assert_eq!(
            report
                .applied_migrations
                .iter()
                .map(|migration| migration.version)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        assert!(!marker.exists());
        store.close().await.expect("recovered store closes");
    }

    #[cfg(not(unix))]
    #[tokio::test]
    async fn non_unix_conversation_store_keeps_auth_schema_without_auth_maintenance() {
        let directory = tempdir().expect("temporary store directory");
        let root = directory.path().join("stores");
        let stores = StoreSet::open(&root).await.expect("stores should open");
        let report = stores
            .conversation
            .report()
            .await
            .expect("conversation store report");

        assert_eq!(
            report
                .applied_migrations
                .iter()
                .map(|migration| (migration.version, migration.name.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (1, "store-contract"),
                (2, "conversation-append-outbox"),
                (3, "durable-job-queue"),
                (4, "local-auth-control-plane"),
                (5, "auth-throttle-bounds"),
            ]
        );

        let lifecycle = stores
            .conversation
            .connection
            .call(|connection| {
                connection
                    .query_row(
                        "SELECT
                            state,
                            state_revision,
                            expected_kid,
                            transition_kind,
                            transition_id,
                            keyring_version,
                            updated_at_micros
                         FROM auth_key_lifecycle
                         WHERE singleton = 1",
                        [],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, Option<String>>(2)?,
                                row.get::<_, Option<String>>(3)?,
                                row.get::<_, Option<Vec<u8>>>(4)?,
                                row.get::<_, Option<i64>>(5)?,
                                row.get::<_, i64>(6)?,
                            ))
                        },
                    )
                    .map_err(StoreError::from)
            })
            .await
            .expect("canonical auth lifecycle sentinel");

        assert_eq!(
            lifecycle,
            ("uninitialized".to_owned(), 0, None, None, None, None, 0,)
        );
        stores.close().await.expect("stores should close");
    }

    #[tokio::test]
    async fn committed_store_with_leftover_marker_reopens_and_clears_marker() {
        let directory = tempdir().expect("temporary store directory");
        let root = prepare_store_root(&directory.path().join("stores")).expect("secure store root");
        let path = root.join(StoreKind::Conversation.file_name());
        let marker = store_initialization_marker_path(&path);
        open_store::<ConversationStore>(&root)
            .await
            .expect("store initializes")
            .close()
            .await
            .expect("store closes");
        reserve_initialization_marker(&marker, StoreKind::Conversation)
            .expect("synthetic leftover marker");

        let reopened = open_store::<ConversationStore>(&root)
            .await
            .expect("committed store recovers");

        assert!(!marker.exists());
        reopened.close().await.expect("reopened store closes");
    }

    #[tokio::test]
    async fn formatted_empty_database_without_marker_is_not_adopted() {
        let directory = tempdir().expect("temporary store directory");
        let root = prepare_store_root(&directory.path().join("stores")).expect("secure store root");
        let path = root.join(StoreKind::Conversation.file_name());
        reserve_owner_only_file(&path, StoreKind::Conversation, "test reservation")
            .expect("owner-only synthetic database");
        let connection = RawConnection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("synthetic database");
        connection
            .execute_batch(
                "CREATE TABLE unrelated(id INTEGER PRIMARY KEY) STRICT;
                 DROP TABLE unrelated;",
            )
            .expect("format otherwise-empty SQLite file");
        drop(connection);

        let error = open_store::<ConversationStore>(&root)
            .await
            .expect_err("markerless empty database must fail closed");
        assert!(matches!(
            error,
            StoreError::UnrecognizedDatabase {
                expected: StoreKind::Conversation,
                schema_objects: 0,
                application_id: 0,
                user_version: 0,
            }
        ));
        assert!(!store_initialization_marker_path(&path).exists());

        let connection = RawConnection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("database remains readable");
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("journal mode");
        assert_eq!(journal_mode, "delete");
    }

    #[tokio::test]
    async fn invalid_initialization_marker_is_rejected_without_creating_main_file() {
        let directory = tempdir().expect("temporary store directory");
        let root = prepare_store_root(&directory.path().join("stores")).expect("secure store root");
        let path = root.join(StoreKind::Conversation.file_name());
        let marker = store_initialization_marker_path(&path);
        reserve_owner_only_file(&marker, StoreKind::Conversation, "test marker reservation")
            .expect("owner-only marker");
        std::fs::write(&marker, b"not a POV initialization marker\n")
            .expect("invalid marker content");

        assert!(matches!(
            open_store::<ConversationStore>(&root).await,
            Err(StoreError::UnsafeFilesystemPath {
                purpose: "store initialization marker",
                ..
            })
        ));
        assert!(!path.exists());
        assert_eq!(
            std::fs::read(&marker).expect("invalid marker remains"),
            b"not a POV initialization marker\n"
        );
    }

    #[tokio::test]
    async fn valid_marker_does_not_authorize_adopting_foreign_schema() {
        let directory = tempdir().expect("temporary store directory");
        let root = prepare_store_root(&directory.path().join("stores")).expect("secure store root");
        let path = root.join(StoreKind::Conversation.file_name());
        let marker = store_initialization_marker_path(&path);
        reserve_initialization_marker(&marker, StoreKind::Conversation).expect("recovery marker");
        reserve_owner_only_file(&path, StoreKind::Conversation, "test reservation")
            .expect("owner-only synthetic database");
        let connection = RawConnection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("synthetic database");
        connection
            .execute_batch("CREATE TABLE unrelated(id INTEGER PRIMARY KEY) STRICT;")
            .expect("foreign schema");
        drop(connection);

        let error = open_store::<ConversationStore>(&root)
            .await
            .expect_err("marker must not authorize foreign schema");
        assert!(matches!(
            error,
            StoreError::UnrecognizedDatabase {
                expected: StoreKind::Conversation,
                schema_objects: 1,
                ..
            }
        ));
        assert_eq!(
            std::fs::read(&marker).expect("recovery marker remains"),
            super::STORE_INITIALIZATION_MARKER
        );

        let connection = RawConnection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("database remains readable");
        let unrelated_exists: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_schema
                    WHERE type = 'table' AND name = 'unrelated'
                )",
                [],
                |row| row.get(0),
            )
            .expect("unrelated table query");
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("journal mode");
        assert!(unrelated_exists);
        assert_eq!(journal_mode, "delete");
    }

    #[tokio::test]
    async fn preexisting_store_sidecar_is_preserved_and_blocks_initialization() {
        let directory = tempdir().expect("temporary store directory");
        let root = prepare_store_root(&directory.path().join("stores")).expect("secure store root");
        let path = root.join(StoreKind::Conversation.file_name());
        let wal = database_sidecar_paths(&path)[2].clone();
        std::fs::write(&wal, b"preexisting sidecar").expect("synthetic sidecar");

        assert!(matches!(
            open_store::<ConversationStore>(&root).await,
            Err(StoreError::UnsafeFilesystemPath { .. })
        ));
        assert!(!path.exists());
        assert_eq!(
            std::fs::read(&wal).expect("sidecar remains"),
            b"preexisting sidecar"
        );
    }

    #[tokio::test]
    async fn preformatted_markerless_database_is_never_adopted() {
        let directory = tempdir().expect("temporary store directory");
        let root = prepare_store_root(&directory.path().join("stores")).expect("secure store root");
        let path = root.join(StoreKind::Conversation.file_name());
        reserve_owner_only_file(&path, StoreKind::Conversation, "test reservation")
            .expect("owner-only synthetic database");
        let connection = RawConnection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("synthetic database");
        connection
            .execute_batch(
                "PRAGMA application_id = 1347376723;
                 PRAGMA user_version = 77;",
            )
            .expect("synthetic foreign identifiers");
        drop(connection);

        let error = open_store::<ConversationStore>(&root)
            .await
            .expect_err("preformatted database must fail closed");
        assert!(matches!(
            error,
            StoreError::UnrecognizedDatabase {
                expected: StoreKind::Conversation,
                schema_objects: 0,
                application_id: 1_347_376_723,
                user_version: 77,
            }
        ));

        let connection = RawConnection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("database remains readable");
        let application_id: i64 = connection
            .query_row("PRAGMA application_id", [], |row| row.get(0))
            .expect("application id");
        let user_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("user version");
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("journal mode");
        assert_eq!(application_id, 1_347_376_723);
        assert_eq!(user_version, 77);
        assert_eq!(journal_mode, "delete");
    }

    #[tokio::test]
    async fn recognized_store_without_history_fails_before_persistent_changes() {
        let directory = tempdir().expect("temporary store directory");
        let root = prepare_store_root(&directory.path().join("stores")).expect("secure store root");
        let path = root.join(StoreKind::Conversation.file_name());
        reserve_owner_only_file(&path, StoreKind::Conversation, "test reservation")
            .expect("owner-only synthetic database");
        let connection = RawConnection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("synthetic database");
        connection
            .execute_batch(
                "CREATE TABLE _pov_store_contract (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    store_kind TEXT NOT NULL CHECK (store_kind = 'conversation'),
                    migration_namespace TEXT NOT NULL
                        CHECK (migration_namespace = 'sqlite/conversation')
                ) STRICT;
                INSERT INTO _pov_store_contract(singleton, store_kind, migration_namespace)
                VALUES (1, 'conversation', 'sqlite/conversation');
                CREATE TABLE _pov_migrations (
                    namespace TEXT NOT NULL,
                    version INTEGER NOT NULL CHECK(version > 0),
                    name TEXT NOT NULL,
                    migration_sql TEXT NOT NULL,
                    PRIMARY KEY(namespace, version)
                ) STRICT;",
            )
            .expect("synthetic incomplete store");
        drop(connection);

        let error = open_store::<ConversationStore>(&root)
            .await
            .expect_err("missing migration history must fail");
        assert!(matches!(
            error,
            StoreError::MissingMigrationHistory {
                namespace: "sqlite/conversation"
            }
        ));

        let connection = RawConnection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("database remains readable");
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("journal mode");
        let migrations: usize = connection
            .query_row("SELECT count(*) FROM _pov_migrations", [], |row| row.get(0))
            .expect("migration count");
        assert_eq!(journal_mode, "delete");
        assert_eq!(migrations, 0);
    }

    #[tokio::test]
    async fn migration_sql_drift_and_future_versions_fail_closed() {
        let drift_directory = tempdir().expect("temporary drift directory");
        let drift_root = drift_directory.path().join("stores");
        let drift_stores = StoreSet::open(&drift_root)
            .await
            .expect("stores should open");
        drift_stores.close().await.expect("stores should close");
        let drift_path = std::fs::canonicalize(&drift_root)
            .expect("canonical drift root")
            .join(StoreKind::Conversation.file_name());
        let drift_connection =
            RawConnection::open(&drift_path).expect("direct synthetic connection");
        drift_connection
            .execute(
                "UPDATE _pov_migrations
                 SET migration_sql = '-- changed'
                 WHERE namespace = ?1 AND version = 1",
                [StoreKind::Conversation.sqlite_migration_namespace()],
            )
            .expect("synthetic drift");
        drop(drift_connection);

        let drift_error = open_store::<ConversationStore>(&drift_root)
            .await
            .expect_err("migration drift must fail");
        assert!(matches!(drift_error, StoreError::MigrationDrift { .. }));

        let future_directory = tempdir().expect("temporary future directory");
        let future_root = future_directory.path().join("stores");
        let future_stores = StoreSet::open(&future_root)
            .await
            .expect("stores should open");
        future_stores.close().await.expect("stores should close");
        let future_path = std::fs::canonicalize(&future_root)
            .expect("canonical future root")
            .join(StoreKind::Conversation.file_name());
        let future_connection =
            RawConnection::open(&future_path).expect("direct synthetic connection");
        future_connection
            .execute(
                "INSERT INTO _pov_migrations(namespace, version, name, migration_sql)
                 VALUES (?1, 99, 'future', '-- future')",
                [StoreKind::Conversation.sqlite_migration_namespace()],
            )
            .expect("synthetic future migration");
        drop(future_connection);

        let future_error = open_store::<ConversationStore>(&future_root)
            .await
            .expect_err("future migration must fail");
        assert!(matches!(
            future_error,
            StoreError::FutureMigration { version: 99, .. }
        ));
    }

    #[test]
    fn migration_definitions_and_history_must_be_an_exact_ordered_prefix() {
        static MIGRATIONS: [Migration; 2] = [
            Migration {
                version: 1,
                name: "store-contract",
                sql: include_str!("../migrations/sqlite/conversation/0001_store_contract.sql"),
            },
            Migration {
                version: 2,
                name: "second",
                sql: "CREATE TABLE synthetic_second(id INTEGER PRIMARY KEY) STRICT;",
            },
        ];
        static DUPLICATE_VERSIONS: [Migration; 2] = [
            Migration {
                version: 1,
                name: "one",
                sql: "SELECT 1;",
            },
            Migration {
                version: 1,
                name: "duplicate",
                sql: "SELECT 2;",
            },
        ];

        assert!(matches!(
            validate_migration_definitions(
                StoreKind::Conversation.sqlite_migration_namespace(),
                &DUPLICATE_VERSIONS,
            ),
            Err(StoreError::InvalidMigrationDefinition { .. })
        ));

        let mut connection = RawConnection::open_in_memory().expect("in-memory connection");
        let authorizer_state = install_connection_authorizer(&connection);
        apply_migrations(
            &mut connection,
            StoreKind::Conversation,
            &MIGRATIONS,
            &authorizer_state,
        )
        .expect("synthetic migrations");
        connection
            .execute("DELETE FROM _pov_migrations WHERE version = 1", [])
            .expect("synthetic history gap");

        assert!(matches!(
            validate_migration_history(&connection, StoreKind::Conversation, &MIGRATIONS),
            Err(StoreError::MigrationHistory {
                expected_version: 1,
                actual_version: 2,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn backup_preserves_rows_and_rejects_tampered_migration_history() {
        let directory = tempdir().expect("temporary store directory");
        let root = directory.path().join("stores");
        let stores = StoreSet::open(&root).await.expect("stores should open");
        let root = std::fs::canonicalize(root).expect("canonical store root");
        stores
            .conversation
            .connection
            .call(|connection| {
                connection.execute_batch(
                    "CREATE TABLE synthetic_backup(
                        id INTEGER PRIMARY KEY,
                        value TEXT NOT NULL
                    ) STRICT;
                    INSERT INTO synthetic_backup(id, value) VALUES (1, 'preserved');",
                )?;
                Ok::<_, StoreError>(())
            })
            .await
            .expect("synthetic source row");

        let valid_backup = root.join("valid.backup");
        stores
            .conversation
            .backup_to_new_file(&valid_backup)
            .await
            .expect("valid backup");
        let snapshot = RawConnection::open_with_flags(
            &valid_backup,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("snapshot");
        let value: String = snapshot
            .query_row(
                "SELECT value FROM synthetic_backup WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .expect("preserved snapshot row");
        assert_eq!(value, "preserved");
        drop(snapshot);

        let reserved_backup = root.join("preexisting-sidecar.backup");
        let reserved_wal = database_sidecar_paths(&reserved_backup)[2].clone();
        std::fs::write(&reserved_wal, b"do not delete").expect("synthetic backup sidecar");
        assert!(matches!(
            stores
                .conversation
                .backup_to_new_file(&reserved_backup)
                .await,
            Err(StoreError::UnsafeFilesystemPath { .. })
        ));
        assert!(!reserved_backup.exists());
        assert_eq!(
            std::fs::read(&reserved_wal).expect("backup sidecar remains"),
            b"do not delete"
        );

        stores
            .conversation
            .connection
            .call(|connection| {
                connection.execute(
                    "UPDATE _pov_migrations
                     SET migration_sql = '-- tampered after open'
                     WHERE namespace = ?1 AND version = 1",
                    [StoreKind::Conversation.sqlite_migration_namespace()],
                )?;
                Ok::<_, StoreError>(())
            })
            .await
            .expect("synthetic post-open tamper");
        let rejected_backup = root.join("rejected.backup");
        let error = stores
            .conversation
            .backup_to_new_file(&rejected_backup)
            .await
            .expect_err("tampered history must reject backup");

        assert!(matches!(
            error,
            StoreError::MigrationDrift { version: 1, .. }
        ));
        assert!(!rejected_backup.exists());
        for suffix in ["-journal", "-shm", "-wal"] {
            let mut sidecar = rejected_backup.as_os_str().to_owned();
            sidecar.push(suffix);
            assert!(!PathBuf::from(sidecar).exists());
        }
    }

    #[tokio::test]
    async fn report_and_backup_reject_missing_current_migration_history() {
        let directory = tempdir().expect("temporary store directory");
        let root = directory.path().join("stores");
        let stores = StoreSet::open(&root).await.expect("stores should open");
        let root = std::fs::canonicalize(root).expect("canonical store root");
        stores
            .conversation
            .connection
            .call(|connection| {
                connection.execute("DELETE FROM _pov_migrations", [])?;
                Ok::<_, StoreError>(())
            })
            .await
            .expect("synthetic history deletion");

        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::MissingMigrationHistory {
                namespace: "sqlite/conversation"
            })
        ));

        let rejected_backup = root.join("missing-history.backup");
        assert!(matches!(
            stores
                .conversation
                .backup_to_new_file(&rejected_backup)
                .await,
            Err(StoreError::MissingMigrationHistory {
                namespace: "sqlite/conversation"
            })
        ));
        assert!(!rejected_backup.exists());
        for suffix in ["-journal", "-shm", "-wal"] {
            let mut sidecar = rejected_backup.as_os_str().to_owned();
            sidecar.push(suffix);
            assert!(!PathBuf::from(sidecar).exists());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn store_directory_and_files_are_owner_only() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let parent = tempdir().expect("temporary parent directory");
        let directory = parent.path().join("stores");
        let stores = StoreSet::open(&directory)
            .await
            .expect("stores should open");
        let effective_uid = rustix::process::geteuid().as_raw();
        let root_metadata = std::fs::metadata(&directory).expect("directory metadata");

        assert_eq!(root_metadata.permissions().mode() & 0o777, 0o700);
        assert_eq!(root_metadata.uid(), effective_uid);
        for kind in StoreKind::ALL {
            let metadata =
                std::fs::metadata(directory.join(kind.file_name())).expect("store metadata");
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(metadata.uid(), effective_uid);
        }

        stores.close().await.expect("stores should close");
    }

    #[cfg(unix)]
    #[test]
    fn effective_owner_validation_fails_closed_without_touching_the_path() {
        let directory = tempdir().expect("temporary parent directory");
        let path = directory.path().join("unopened-store.sqlite3");
        let effective_uid = rustix::process::geteuid().as_raw();
        let different_uid = effective_uid.wrapping_add(1);

        super::validate_effective_owner(
            &path,
            "synthetic existing store",
            effective_uid,
            effective_uid,
        )
        .expect("matching effective owner should pass");
        let error = super::validate_effective_owner(
            &path,
            "synthetic existing store",
            different_uid,
            effective_uid,
        )
        .expect_err("different owner must fail closed");

        assert!(matches!(
            error,
            StoreError::InsecureFilesystemOwner {
                purpose: "synthetic existing store",
                actual_uid,
                expected_uid,
                ..
            } if actual_uid == different_uid && expected_uid == effective_uid
        ));
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn existing_insecure_root_is_rejected_without_changing_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let parent = tempdir().expect("temporary parent directory");
        let root = parent.path().join("shared");
        std::fs::create_dir(&root).expect("synthetic shared directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
            .expect("synthetic insecure mode");

        let error = StoreSet::open(&root)
            .await
            .expect_err("insecure root must be rejected");

        assert!(matches!(
            error,
            StoreError::InsecureFilesystemPermissions {
                expected_mode: 0o700,
                actual_mode: 0o755,
                ..
            }
        ));
        assert_eq!(
            std::fs::metadata(&root)
                .expect("root metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn store_root_and_database_symlinks_are_rejected_without_following_them() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let parent = tempdir().expect("temporary parent directory");
        let real_root = parent.path().join("real-root");
        std::fs::create_dir(&real_root).expect("real root");
        std::fs::set_permissions(&real_root, std::fs::Permissions::from_mode(0o700))
            .expect("secure real root");
        let root_link = parent.path().join("root-link");
        symlink(&real_root, &root_link).expect("root symlink");

        assert!(matches!(
            StoreSet::open(&root_link).await,
            Err(StoreError::UnsafeFilesystemPath { .. })
        ));
        assert_eq!(
            std::fs::metadata(&real_root)
                .expect("real root metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        let target = real_root.join("target.sqlite3");
        reserve_owner_only_file(&target, StoreKind::Conversation, "test reservation")
            .expect("owner-only target");
        std::fs::write(&target, b"do not follow").expect("target content");
        let store_link = real_root.join(StoreKind::Conversation.file_name());
        symlink(&target, &store_link).expect("store symlink");

        assert!(matches!(
            open_store::<ConversationStore>(&real_root).await,
            Err(StoreError::UnsafeFilesystemPath { .. })
        ));
        assert_eq!(
            std::fs::read(&target).expect("target remains"),
            b"do not follow"
        );
        assert_eq!(
            std::fs::metadata(&target)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        std::fs::remove_file(&store_link).expect("remove synthetic symlink");
        std::fs::hard_link(&target, &store_link).expect("store hard link");
        assert!(matches!(
            open_store::<ConversationStore>(&real_root).await,
            Err(StoreError::UnsafeFilesystemPath { .. })
        ));
        assert_eq!(
            std::fs::read(&target).expect("hard-link target remains"),
            b"do not follow"
        );
    }
}
