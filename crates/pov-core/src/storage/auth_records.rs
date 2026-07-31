use std::{
    fmt,
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use sha2::{Digest, Sha256};
use tokio_rusqlite::rusqlite::{
    self, Connection as RawConnection, DropBehavior, Row, Transaction, TransactionBehavior, params,
    types::ValueRef,
};

use super::{
    AuthActiveLifecycleFacts, AuthDatabaseLifecycleObservation,
    AuthDatabaseReconciliationObservation, AuthInitializationFinalLifecycleMutationOutcome,
    AuthInitializationSourceFingerprint, AuthInitializationSourceMatch,
    AuthInitializationSourceMutationOutcome, AuthInitializingLifecycleFacts,
    AuthPlannedRotationDatabaseObservation, AuthPlannedRotationFinalLifecycleMutationOutcome,
    AuthPlannedRotationSourceFingerprint, AuthPlannedRotationSourceMatch,
    AuthPlannedRotationSourceMutationOutcome, AuthTransitioningLifecycleFacts, ConversationStore,
    ExistingConnectionAccess, SqliteStore, StoreError, StoreKind, StoreLocation,
    migrations_for_kind, open_existing_store_connection, validate_current_migration_history,
    validate_store_contract_row, validate_store_location,
};
#[cfg(test)]
use super::{
    AuthInitializationFinalLifecycleMutationTestFault, AuthInitializationSourceMutationTestFault,
    AuthPlannedRotationFinalLifecycleMutationTestFault, AuthPlannedRotationSourceMutationTestFault,
};
use crate::auth::{
    InitializationSourceExpectation, InitializationSourceSeed, KeyTransitionSourceExpectation,
    PersistedLifecycleKeyId, PersistedLifecycleKeyringVersion, PersistedLifecycleTimestamp,
    PersistedLifecycleTransitionId, PlannedRotationSourceExpectation, RetireSourceExpectation,
    TransitionKind,
};

#[derive(Clone)]
pub(crate) struct AuthMutationExecutor {
    location: Arc<StoreLocation>,
    operation_poisoned: Arc<AtomicBool>,
    operation_serial: Arc<std::sync::Mutex<()>>,
    #[cfg(test)]
    runtime_test_fault: Arc<std::sync::Mutex<Option<AuthRuntimeMutationTestFault>>>,
}

impl AuthMutationExecutor {
    fn new(store: &SqliteStore<ConversationStore>) -> Self {
        Self {
            location: Arc::clone(&store.location),
            operation_poisoned: Arc::clone(&store.operation_poisoned),
            operation_serial: Arc::new(std::sync::Mutex::new(())),
            #[cfg(test)]
            runtime_test_fault: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    pub(super) fn from_runtime_store(
        location: Arc<StoreLocation>,
        operation_poisoned: Arc<AtomicBool>,
    ) -> Self {
        Self {
            location,
            operation_poisoned,
            operation_serial: Arc::new(std::sync::Mutex::new(())),
            #[cfg(test)]
            runtime_test_fault: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    #[cfg(test)]
    pub(crate) fn inject_next_runtime_test_fault(&self, fault: AuthRuntimeMutationTestFault) {
        *self
            .runtime_test_fault
            .lock()
            .expect("runtime auth test-fault lock must not be poisoned") = Some(fault);
    }

    pub(crate) async fn execute_runtime<N, A, C>(
        &self,
        apply: A,
        classify: C,
    ) -> Result<AuthRuntimeMutationOutcome<N>, AuthRecordsError>
    where
        N: Send + Sync + 'static,
        A: for<'connection> Fn(
                &Transaction<'connection>,
            )
                -> Result<AuthRuntimeApplyDecision<N>, AuthRecordsError>
            + Send
            + Sync
            + 'static,
        C: Fn(&mut RawConnection) -> Result<AuthRuntimeMutationPostcondition, AuthRecordsError>
            + Send
            + Sync
            + 'static,
    {
        #[cfg(test)]
        let fault = self
            .runtime_test_fault
            .lock()
            .map_err(|_| AuthRecordsError::ExecutorFailed)?
            .take()
            .map(CommitFault::from)
            .unwrap_or(CommitFault::None);
        #[cfg(not(test))]
        let fault = CommitFault::None;
        self.execute(AuthRuntimeMutation { apply, classify }, fault)
            .await
            .map(|run| match run {
                MutationRun::ExpectedNoCommit(outcome) => {
                    AuthRuntimeMutationOutcome::ExpectedNoCommit(outcome)
                }
                MutationRun::CommitResolved(execution) => match execution.disposition {
                    MutationDisposition::Committed => AuthRuntimeMutationOutcome::Committed,
                    MutationDisposition::NotCommitted => {
                        AuthRuntimeMutationOutcome::ConfirmedNotCommitted
                    }
                },
            })
    }

    async fn execute<M>(
        &self,
        mutation: M,
        fault: CommitFault,
    ) -> Result<MutationRun<M::ExpectedNoCommit>, AuthRecordsError>
    where
        M: AuthMutation + Send + 'static,
        M::ExpectedNoCommit: Send + 'static,
    {
        ensure_operation_available(&self.operation_poisoned)?;
        let location = Arc::clone(&self.location);
        let operation_poisoned = Arc::clone(&self.operation_poisoned);
        let blocking_poison = Arc::clone(&operation_poisoned);
        let operation_serial = Arc::clone(&self.operation_serial);
        let result = tokio::task::spawn_blocking(move || {
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                let _panic_guard = WorkerPanicPoisonGuard::new(Arc::clone(&blocking_poison));
                let _serial = operation_serial
                    .lock()
                    .map_err(|_| AuthRecordsError::ExecutorFailed)?;
                fault.pause_before_poison_check();
                ensure_operation_available(&blocking_poison)?;
                fault.panic_before_execute();
                execute_blocking(&location, &blocking_poison, &mutation, &fault)
            }))
            .unwrap_or(Err(AuthRecordsError::ExecutorFailed));
            if result.is_err() {
                blocking_poison.store(true, Ordering::Release);
            }
            fault.complete();
            result
        })
        .await;

        match result {
            Ok(result) => result,
            Err(_) => {
                operation_poisoned.store(true, Ordering::Release);
                Err(AuthRecordsError::ExecutorFailed)
            }
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthRuntimeMutationTestFault {
    AfterCommitResponseLoss,
    DeferredForeignKeyCommitFailure,
}

#[cfg(test)]
impl From<AuthRuntimeMutationTestFault> for CommitFault {
    fn from(value: AuthRuntimeMutationTestFault) -> Self {
        match value {
            AuthRuntimeMutationTestFault::AfterCommitResponseLoss => Self::AfterCommitResponseLoss,
            AuthRuntimeMutationTestFault::DeferredForeignKeyCommitFailure => {
                Self::DeferredForeignKeyCommitFailure
            }
        }
    }
}

pub(crate) enum AuthRuntimeApplyDecision<N> {
    Commit,
    ExpectedNoCommit(N),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthRuntimeMutationPostcondition {
    Committed,
    NotCommitted,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthRuntimeMutationOutcome<N> {
    Committed,
    ConfirmedNotCommitted,
    ExpectedNoCommit(N),
}

struct AuthRuntimeMutation<A, C> {
    apply: A,
    classify: C,
}

impl<N, A, C> AuthMutation for AuthRuntimeMutation<A, C>
where
    A: for<'connection> Fn(
        &Transaction<'connection>,
    ) -> Result<AuthRuntimeApplyDecision<N>, AuthRecordsError>,
    C: Fn(&mut RawConnection) -> Result<AuthRuntimeMutationPostcondition, AuthRecordsError>,
{
    type ExpectedNoCommit = N;

    fn apply(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<ApplyDecision<Self::ExpectedNoCommit>, AuthRecordsError> {
        Ok(match (self.apply)(transaction)? {
            AuthRuntimeApplyDecision::Commit => ApplyDecision::Commit,
            AuthRuntimeApplyDecision::ExpectedNoCommit(outcome) => {
                ApplyDecision::ExpectedNoCommit(outcome)
            }
        })
    }

    fn classify(
        &self,
        committed_view: &mut RawConnection,
    ) -> Result<MutationPostcondition, AuthRecordsError> {
        Ok(match (self.classify)(committed_view)? {
            AuthRuntimeMutationPostcondition::Committed => MutationPostcondition::Committed,
            AuthRuntimeMutationPostcondition::NotCommitted => MutationPostcondition::NotCommitted,
            AuthRuntimeMutationPostcondition::Ambiguous => MutationPostcondition::Ambiguous,
        })
    }
}

fn ensure_operation_available(operation_poisoned: &AtomicBool) -> Result<(), AuthRecordsError> {
    if operation_poisoned.load(Ordering::Acquire) {
        return Err(AuthRecordsError::Store(StoreError::OperationPoisoned {
            kind: StoreKind::Conversation,
        }));
    }
    Ok(())
}

struct WorkerPanicPoisonGuard {
    operation_poisoned: Arc<AtomicBool>,
}

impl WorkerPanicPoisonGuard {
    fn new(operation_poisoned: Arc<AtomicBool>) -> Self {
        Self { operation_poisoned }
    }
}

impl Drop for WorkerPanicPoisonGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.operation_poisoned.store(true, Ordering::Release);
        }
    }
}

trait AuthMutation {
    type ExpectedNoCommit;

    fn apply(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<ApplyDecision<Self::ExpectedNoCommit>, AuthRecordsError>;

    fn classify(
        &self,
        committed_view: &mut RawConnection,
    ) -> Result<MutationPostcondition, AuthRecordsError>;
}

enum ApplyDecision<N> {
    Commit,
    ExpectedNoCommit(N),
}

#[derive(Debug)]
enum MutationRun<N> {
    CommitResolved(MutationExecution),
    ExpectedNoCommit(N),
}

#[derive(Clone)]
enum CommitFault {
    None,
    #[cfg(test)]
    AfterCommitResponseLoss,
    #[cfg(test)]
    DeferredForeignKeyCommitFailure,
    #[cfg(test)]
    PauseAfterCommitBeforeQuiesce(OperationGate),
    #[cfg(test)]
    PauseBeforePoisonCheck(OperationGate),
    #[cfg(test)]
    PanicBeforeExecute(OperationGate),
    #[cfg(all(test, unix))]
    LeakStatementBeforeWriterClose,
}

impl CommitFault {
    fn observation(&self, commit_succeeded: bool) -> CommitObservation {
        if !commit_succeeded {
            return CommitObservation::Uncertain;
        }
        #[cfg(test)]
        if matches!(self, Self::AfterCommitResponseLoss) {
            return CommitObservation::Uncertain;
        }
        CommitObservation::Succeeded
    }

    fn pause_after_commit(&self) {
        #[cfg(test)]
        if let Self::PauseAfterCommitBeforeQuiesce(gate) = self {
            gate.pause();
        }
    }

    fn pause_before_poison_check(&self) {
        #[cfg(test)]
        if let Self::PauseBeforePoisonCheck(gate) = self {
            gate.pause();
        }
    }

    fn panic_before_execute(&self) {
        #[cfg(test)]
        if let Self::PanicBeforeExecute(gate) = self {
            gate.pause();
            panic!("synthetic auth mutation worker panic");
        }
    }

    fn inject_writer_close_failure(&self, _writer: &RawConnection) -> Result<(), AuthRecordsError> {
        #[cfg(all(test, unix))]
        if matches!(self, Self::LeakStatementBeforeWriterClose) {
            let statement = _writer.prepare("SELECT 1")?;
            std::mem::forget(statement);
        }
        Ok(())
    }

    fn inject_before_commit(&self, _transaction: &Transaction<'_>) -> Result<(), AuthRecordsError> {
        #[cfg(test)]
        if matches!(self, Self::DeferredForeignKeyCommitFailure) {
            const MISSING_OWNER: [u8; 16] = [0xD1; 16];
            _transaction.pragma_update(None, "defer_foreign_keys", "ON")?;
            _transaction.execute(
                "INSERT INTO auth_authenticator_throttles(
                    owner_id, authenticator, failure_count, next_allowed_at_micros,
                    throttle_revision, updated_at_micros
                 ) VALUES (?1, 'password', 0, 0, 1, 1)",
                params![MISSING_OWNER.as_slice()],
            )?;
        }
        Ok(())
    }

    fn complete(&self) {
        #[cfg(test)]
        match self {
            Self::PauseAfterCommitBeforeQuiesce(gate)
            | Self::PauseBeforePoisonCheck(gate)
            | Self::PanicBeforeExecute(gate) => gate.complete(),
            _ => {}
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitObservation {
    Succeeded,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MutationDisposition {
    Committed,
    NotCommitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MutationPostcondition {
    Committed,
    NotCommitted,
    Ambiguous,
}

#[derive(Debug)]
struct MutationExecution {
    disposition: MutationDisposition,
    observation: CommitObservation,
    rolled_back_active_transaction: bool,
}

struct WriterQuiesced {
    rolled_back_active_transaction: bool,
}

struct FreshWriterGuard {
    connection: Option<RawConnection>,
    operation_poisoned: Arc<AtomicBool>,
}

impl FreshWriterGuard {
    fn new(connection: RawConnection, operation_poisoned: Arc<AtomicBool>) -> Self {
        Self {
            connection: Some(connection),
            operation_poisoned,
        }
    }

    fn connection(&self) -> &RawConnection {
        self.connection
            .as_ref()
            .expect("fresh writer must exist until it is consumed")
    }

    fn connection_mut(&mut self) -> &mut RawConnection {
        self.connection
            .as_mut()
            .expect("fresh writer must exist until it is consumed")
    }

    fn into_connection(mut self) -> RawConnection {
        self.connection
            .take()
            .expect("fresh writer must exist until it is consumed")
    }
}

impl Drop for FreshWriterGuard {
    fn drop(&mut self) {
        let Some(connection) = self.connection.take() else {
            return;
        };
        connection.flush_prepared_statement_cache();
        if connection.close().is_err() {
            self.operation_poisoned.store(true, Ordering::Release);
        }
    }
}

#[derive(Debug)]
pub(crate) enum AuthRecordsError {
    Store(StoreError),
    Sqlite(rusqlite::Error),
    ExecutorFailed,
    WriterCloseFailed,
    WriterNotQuiesced,
    ReaderCloseFailed,
    UnexpectedMutationCardinality,
    AmbiguousCommittedView,
}

impl fmt::Display for AuthRecordsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "auth store error: {error}"),
            Self::Sqlite(error) => write!(formatter, "auth SQLite error: {error}"),
            Self::ExecutorFailed => formatter.write_str("auth storage executor failed"),
            Self::WriterCloseFailed => formatter.write_str("auth writer close failed"),
            Self::WriterNotQuiesced => formatter.write_str("auth writer did not quiesce"),
            Self::ReaderCloseFailed => formatter.write_str("auth committed-view close failed"),
            Self::UnexpectedMutationCardinality => {
                formatter.write_str("auth mutation changed an unexpected number of rows")
            }
            Self::AmbiguousCommittedView => {
                formatter.write_str("auth mutation postcondition is ambiguous")
            }
        }
    }
}

impl From<StoreError> for AuthRecordsError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<rusqlite::Error> for AuthRecordsError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

fn execute_blocking<M>(
    location: &StoreLocation,
    operation_poisoned: &Arc<AtomicBool>,
    mutation: &M,
    fault: &CommitFault,
) -> Result<MutationRun<M::ExpectedNoCommit>, AuthRecordsError>
where
    M: AuthMutation,
{
    let mut writer = FreshWriterGuard::new(
        open_existing_store_connection(
            location,
            StoreKind::Conversation,
            ExistingConnectionAccess::ReadWrite,
        )?,
        Arc::clone(operation_poisoned),
    );
    let mut transaction = writer
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(AuthRecordsError::Sqlite)?;

    let precommit = mutation.apply(&transaction).and_then(|decision| {
        validate_store_contract_row(&transaction, StoreKind::Conversation)?;
        validate_current_migration_history(
            &transaction,
            StoreKind::Conversation,
            migrations_for_kind(StoreKind::Conversation),
        )?;
        Ok(decision)
    });
    let decision = match precommit {
        Ok(decision) => decision,
        Err(error) => {
            let rollback = transaction.rollback();
            close_after_precommit_error(writer.into_connection())?;
            rollback?;
            return Err(error);
        }
    };

    if let ApplyDecision::ExpectedNoCommit(outcome) = decision {
        let rollback = transaction.rollback();
        let close_fault = fault.inject_writer_close_failure(writer.connection());
        close_after_precommit_error(writer.into_connection())?;
        rollback?;
        close_fault?;
        return Ok(MutationRun::ExpectedNoCommit(outcome));
    }

    if let Err(error) = fault.inject_before_commit(&transaction) {
        let rollback = transaction.rollback();
        close_after_precommit_error(writer.into_connection())?;
        rollback?;
        return Err(error);
    }

    transaction.set_drop_behavior(DropBehavior::Ignore);
    let commit_succeeded = transaction.commit().is_ok();
    let observation = fault.observation(commit_succeeded);
    fault.pause_after_commit();
    if let Err(error) = fault.inject_writer_close_failure(writer.connection()) {
        close_after_precommit_error(writer.into_connection())?;
        return Err(error);
    }

    let writer_quiesced = quiesce_writer(writer.into_connection())?;
    let rolled_back_active_transaction = writer_quiesced.rolled_back_active_transaction;
    let mut committed_view = open_committed_view(location, writer_quiesced)?;
    let postcondition = mutation.classify(&mut committed_view);
    close_committed_view(committed_view)?;
    let postcondition = postcondition?;

    let disposition = match (observation, postcondition) {
        (_, MutationPostcondition::Committed) => MutationDisposition::Committed,
        (CommitObservation::Uncertain, MutationPostcondition::NotCommitted) => {
            MutationDisposition::NotCommitted
        }
        (CommitObservation::Succeeded, MutationPostcondition::NotCommitted)
        | (_, MutationPostcondition::Ambiguous) => {
            return Err(AuthRecordsError::AmbiguousCommittedView);
        }
    };

    Ok(MutationRun::CommitResolved(MutationExecution {
        disposition,
        observation,
        rolled_back_active_transaction,
    }))
}

fn close_after_precommit_error(writer: RawConnection) -> Result<(), AuthRecordsError> {
    let rollback = if writer.is_autocommit() {
        Ok(())
    } else {
        writer.execute_batch("ROLLBACK")
    };
    let still_active = !writer.is_autocommit();
    writer.flush_prepared_statement_cache();
    let close = writer.close();

    if close.is_err() {
        return Err(AuthRecordsError::WriterCloseFailed);
    }
    rollback?;
    if still_active {
        return Err(AuthRecordsError::WriterNotQuiesced);
    }
    Ok(())
}

fn quiesce_writer(writer: RawConnection) -> Result<WriterQuiesced, AuthRecordsError> {
    let rolled_back_active_transaction = !writer.is_autocommit();
    let rollback = if rolled_back_active_transaction {
        writer.execute_batch("ROLLBACK")
    } else {
        Ok(())
    };
    let still_active = !writer.is_autocommit();
    writer.flush_prepared_statement_cache();
    let close = writer.close();

    if close.is_err() {
        return Err(AuthRecordsError::WriterCloseFailed);
    }
    rollback?;
    if still_active {
        return Err(AuthRecordsError::WriterNotQuiesced);
    }
    Ok(WriterQuiesced {
        rolled_back_active_transaction,
    })
}

fn open_committed_view(
    location: &StoreLocation,
    _writer_quiesced: WriterQuiesced,
) -> Result<RawConnection, AuthRecordsError> {
    open_existing_store_connection(
        location,
        StoreKind::Conversation,
        ExistingConnectionAccess::ReadOnly,
    )
    .map_err(AuthRecordsError::from)
}

fn close_committed_view(committed_view: RawConnection) -> Result<(), AuthRecordsError> {
    let unexpectedly_active = !committed_view.is_autocommit();
    committed_view.flush_prepared_statement_cache();
    let close = committed_view.close();
    if close.is_err() {
        return Err(AuthRecordsError::ReaderCloseFailed);
    }
    if unexpectedly_active {
        return Err(AuthRecordsError::WriterNotQuiesced);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitializationSourceExpectedNoCommit {
    AlreadyCommitted,
    PreconditionChanged,
}

struct InitializationSourceMutation<'a> {
    seed: InitializationSourceSeed<'a>,
}

impl AuthMutation for InitializationSourceMutation<'_> {
    type ExpectedNoCommit = InitializationSourceExpectedNoCommit;

    fn apply(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<ApplyDecision<Self::ExpectedNoCommit>, AuthRecordsError> {
        validate_store_contract_row(transaction, StoreKind::Conversation)?;
        validate_current_migration_history(
            transaction,
            StoreKind::Conversation,
            migrations_for_kind(StoreKind::Conversation),
        )?;
        validate_auth_table_inventory(transaction)?;

        let changed = transaction.execute(
            "UPDATE auth_key_lifecycle
             SET state = 'initializing',
                 state_revision = 1,
                 expected_kid = ?1,
                 transition_kind = 'initialize',
                 transition_id = ?2,
                 keyring_version = ?3,
                 updated_at_micros = ?4
             WHERE singleton = 1
               AND state = 'uninitialized'
               AND state_revision = 0
               AND expected_kid IS NULL
               AND transition_kind IS NULL
               AND transition_id IS NULL
               AND keyring_version IS NULL
               AND updated_at_micros = 0
               AND NOT EXISTS (SELECT 1 FROM auth_accounts)
               AND NOT EXISTS (SELECT 1 FROM auth_password_credentials)
               AND NOT EXISTS (SELECT 1 FROM auth_recovery_credentials)
               AND NOT EXISTS (SELECT 1 FROM auth_authenticator_throttles)
               AND NOT EXISTS (SELECT 1 FROM auth_login_control)
               AND NOT EXISTS (SELECT 1 FROM auth_login_attempt_markers)
               AND NOT EXISTS (SELECT 1 FROM auth_login_attempt_outcomes)
               AND NOT EXISTS (SELECT 1 FROM auth_sessions)
               AND NOT EXISTS (SELECT 1 FROM auth_refresh_families)
               AND NOT EXISTS (SELECT 1 FROM auth_refresh_tokens)
               AND NOT EXISTS (SELECT 1 FROM auth_audit)
               AND NOT EXISTS (
                   SELECT 1 FROM sqlite_sequence WHERE name = 'auth_audit'
               )",
            params![
                self.seed.result_kid(),
                self.seed.transition_id().as_slice(),
                self.seed.result_keyring_version(),
                self.seed.source_at_micros(),
            ],
        )?;

        match changed {
            0 => return self.classify_expected_no_commit(transaction),
            1 => {}
            _ => return Err(AuthRecordsError::UnexpectedMutationCardinality),
        }

        expect_mutation_cardinality(
            transaction.execute(
                "INSERT INTO auth_accounts(
                    singleton, owner_id, login_id, account_state, credential_version,
                    account_revision, created_at_micros, updated_at_micros
                 ) VALUES (1, ?1, ?2, 'enabled', 1, 1, ?3, ?3)",
                params![
                    self.seed.owner_id().as_slice(),
                    self.seed.login_id(),
                    self.seed.source_at_micros(),
                ],
            )?,
            1,
        )?;
        expect_mutation_cardinality(
            transaction.execute(
                "INSERT INTO auth_password_credentials(
                    singleton, owner_id, verifier_phc, authenticator_state,
                    credential_revision, blocklist_version, created_at_micros,
                    updated_at_micros
                 ) VALUES (1, ?1, ?2, 'enabled', 1, ?3, ?4, ?4)",
                params![
                    self.seed.owner_id().as_slice(),
                    self.seed.password_phc(),
                    self.seed.legacy_policy_provenance(),
                    self.seed.source_at_micros(),
                ],
            )?,
            1,
        )?;
        expect_mutation_cardinality(
            transaction.execute(
                "INSERT INTO auth_recovery_credentials(
                    singleton, owner_id, verifier_phc, credential_revision,
                    created_at_micros, updated_at_micros
                 ) VALUES (1, ?1, ?2, 1, ?3, ?3)",
                params![
                    self.seed.owner_id().as_slice(),
                    self.seed.recovery_phc(),
                    self.seed.source_at_micros(),
                ],
            )?,
            1,
        )?;
        for authenticator in ["password", "recovery"] {
            expect_mutation_cardinality(
                transaction.execute(
                    "INSERT INTO auth_authenticator_throttles(
                        owner_id, authenticator, failure_count, next_allowed_at_micros,
                        throttle_revision, updated_at_micros
                     ) VALUES (?1, ?2, 0, 0, 1, ?3)",
                    params![
                        self.seed.owner_id().as_slice(),
                        authenticator,
                        self.seed.source_at_micros(),
                    ],
                )?,
                1,
            )?;
        }
        expect_mutation_cardinality(
            transaction.execute(
                "INSERT INTO auth_login_control(
                    singleton, owner_id, admission_revision, clock_floor_micros,
                    control_revision, created_at_micros, updated_at_micros
                 ) VALUES (1, ?1, 1, ?2, 1, ?2, ?2)",
                params![
                    self.seed.owner_id().as_slice(),
                    self.seed.source_at_micros(),
                ],
            )?,
            1,
        )?;
        expect_mutation_cardinality(
            transaction.execute(
                "INSERT INTO auth_audit(
                    owner_id, audit_id, action, profile, session_id, attempt_id,
                    happened_at_micros
                 ) VALUES (?1, ?2, 'auth_initialized', NULL, NULL, NULL, ?3)",
                params![
                    self.seed.owner_id().as_slice(),
                    self.seed.audit_id().as_slice(),
                    self.seed.source_at_micros(),
                ],
            )?,
            1,
        )?;

        let lifecycle = read_auth_lifecycle_observation(transaction)?;
        let AuthDatabaseLifecycleObservation::Initializing(facts) = lifecycle else {
            return Err(AuthRecordsError::Store(StoreError::AuthControlPlaneCorrupt));
        };
        let inspection = read_initialization_source_match(
            transaction,
            facts.into(),
            Some(self.seed.expectation()),
        )?;
        if inspection.source_match != AuthInitializationSourceMatch::Exact {
            return Err(AuthRecordsError::Store(StoreError::AuthControlPlaneCorrupt));
        }

        Ok(ApplyDecision::Commit)
    }

    fn classify(
        &self,
        committed_view: &mut RawConnection,
    ) -> Result<MutationPostcondition, AuthRecordsError> {
        let observation =
            inspect_auth_reconciliation_snapshot(committed_view, Some(self.seed.expectation()))?;
        Ok(match (observation.lifecycle, observation.source) {
            (
                AuthDatabaseLifecycleObservation::CleanUninitialized,
                AuthInitializationSourceMatch::NotApplicable,
            ) => MutationPostcondition::NotCommitted,
            (
                AuthDatabaseLifecycleObservation::Initializing(_),
                AuthInitializationSourceMatch::Exact,
            ) => MutationPostcondition::Committed,
            _ => MutationPostcondition::Ambiguous,
        })
    }
}

impl InitializationSourceMutation<'_> {
    fn classify_expected_no_commit(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<ApplyDecision<InitializationSourceExpectedNoCommit>, AuthRecordsError> {
        let lifecycle = read_auth_lifecycle_observation(transaction)?;
        if let AuthDatabaseLifecycleObservation::Initializing(facts) = lifecycle {
            let inspection = read_initialization_source_match(
                transaction,
                facts.into(),
                Some(self.seed.expectation()),
            )?;
            if inspection.source_match == AuthInitializationSourceMatch::Exact {
                return Ok(ApplyDecision::ExpectedNoCommit(
                    InitializationSourceExpectedNoCommit::AlreadyCommitted,
                ));
            }
        }
        Ok(ApplyDecision::ExpectedNoCommit(
            InitializationSourceExpectedNoCommit::PreconditionChanged,
        ))
    }
}

fn expect_mutation_cardinality(actual: usize, expected: usize) -> Result<(), AuthRecordsError> {
    if actual == expected {
        Ok(())
    } else {
        Err(AuthRecordsError::UnexpectedMutationCardinality)
    }
}

pub(super) fn commit_initialization_source(
    location: &StoreLocation,
    operation_poisoned: &Arc<AtomicBool>,
    seed: InitializationSourceSeed<'_>,
    #[cfg(test)] test_fault: Option<AuthInitializationSourceMutationTestFault>,
) -> Result<AuthInitializationSourceMutationOutcome, AuthRecordsError> {
    let fault = {
        #[cfg(test)]
        {
            match test_fault {
                None => CommitFault::None,
                Some(AuthInitializationSourceMutationTestFault::AfterCommitResponseLoss) => {
                    CommitFault::AfterCommitResponseLoss
                }
                Some(
                    AuthInitializationSourceMutationTestFault::DeferredForeignKeyCommitFailure,
                ) => CommitFault::DeferredForeignKeyCommitFailure,
            }
        }
        #[cfg(not(test))]
        {
            CommitFault::None
        }
    };

    ensure_operation_available(operation_poisoned)?;
    let poison = Arc::clone(operation_poisoned);
    let mutation = InitializationSourceMutation { seed };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _panic_guard = WorkerPanicPoisonGuard::new(Arc::clone(&poison));
        ensure_operation_available(&poison)?;
        execute_blocking(location, &poison, &mutation, &fault)
    }))
    .unwrap_or(Err(AuthRecordsError::ExecutorFailed));
    if result.is_err() {
        poison.store(true, Ordering::Release);
    }

    result.map(|run| match run {
        MutationRun::ExpectedNoCommit(InitializationSourceExpectedNoCommit::AlreadyCommitted) => {
            AuthInitializationSourceMutationOutcome::AlreadyCommitted
        }
        MutationRun::ExpectedNoCommit(
            InitializationSourceExpectedNoCommit::PreconditionChanged,
        ) => AuthInitializationSourceMutationOutcome::PreconditionChanged,
        MutationRun::CommitResolved(execution) => match execution.disposition {
            MutationDisposition::Committed => AuthInitializationSourceMutationOutcome::Committed,
            MutationDisposition::NotCommitted => {
                AuthInitializationSourceMutationOutcome::ConfirmedNotCommitted
            }
        },
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitializationFinalLifecycleExpectedNoCommit {
    AlreadyCommitted,
    PreconditionChanged,
}

struct InitializationFinalLifecycleMutation<'a> {
    expectation: InitializationSourceExpectation<'a>,
}

impl AuthMutation for InitializationFinalLifecycleMutation<'_> {
    type ExpectedNoCommit = InitializationFinalLifecycleExpectedNoCommit;

    fn apply(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<ApplyDecision<Self::ExpectedNoCommit>, AuthRecordsError> {
        validate_store_contract_row(transaction, StoreKind::Conversation)?;
        validate_current_migration_history(
            transaction,
            StoreKind::Conversation,
            migrations_for_kind(StoreKind::Conversation),
        )?;
        validate_auth_table_inventory(transaction)?;

        let lifecycle = read_auth_lifecycle_observation(transaction)?;
        match lifecycle {
            AuthDatabaseLifecycleObservation::Initializing(facts) => {
                let inspection = read_initialization_source_match(
                    transaction,
                    facts.into(),
                    Some(self.expectation),
                )?;
                if inspection.source_match != AuthInitializationSourceMatch::Exact {
                    return Ok(ApplyDecision::ExpectedNoCommit(
                        InitializationFinalLifecycleExpectedNoCommit::PreconditionChanged,
                    ));
                }
            }
            AuthDatabaseLifecycleObservation::Active(facts)
                if facts.state_revision == 2 && facts.keyring_version.get() == 1 =>
            {
                let inspection = read_initialization_source_match(
                    transaction,
                    facts.into(),
                    Some(self.expectation),
                )?;
                let outcome = if inspection.source_match == AuthInitializationSourceMatch::Exact {
                    InitializationFinalLifecycleExpectedNoCommit::AlreadyCommitted
                } else {
                    InitializationFinalLifecycleExpectedNoCommit::PreconditionChanged
                };
                return Ok(ApplyDecision::ExpectedNoCommit(outcome));
            }
            AuthDatabaseLifecycleObservation::CleanUninitialized
            | AuthDatabaseLifecycleObservation::Active(_)
            | AuthDatabaseLifecycleObservation::Transitioning(_) => {
                return Ok(ApplyDecision::ExpectedNoCommit(
                    InitializationFinalLifecycleExpectedNoCommit::PreconditionChanged,
                ));
            }
        }

        let changed = transaction.execute(
            "UPDATE auth_key_lifecycle
             SET state = 'active',
                 state_revision = 2,
                 transition_kind = NULL,
                 transition_id = NULL
             WHERE singleton = 1
               AND state = 'initializing'
               AND state_revision = 1
               AND expected_kid = ?1
               AND transition_kind = 'initialize'
               AND transition_id = ?2
               AND keyring_version = ?3
               AND updated_at_micros = ?4",
            params![
                self.expectation.result_kid(),
                self.expectation.transition_id().as_slice(),
                self.expectation.result_keyring_version(),
                self.expectation.source_at_micros(),
            ],
        )?;
        expect_mutation_cardinality(changed, 1)?;

        let lifecycle = read_auth_lifecycle_observation(transaction)?;
        let AuthDatabaseLifecycleObservation::Active(facts) = lifecycle else {
            return Err(AuthRecordsError::Store(StoreError::AuthControlPlaneCorrupt));
        };
        let inspection =
            read_initialization_source_match(transaction, facts.into(), Some(self.expectation))?;
        if inspection.source_match != AuthInitializationSourceMatch::Exact {
            return Err(AuthRecordsError::Store(StoreError::AuthControlPlaneCorrupt));
        }

        Ok(ApplyDecision::Commit)
    }

    fn classify(
        &self,
        committed_view: &mut RawConnection,
    ) -> Result<MutationPostcondition, AuthRecordsError> {
        let observation =
            inspect_auth_reconciliation_snapshot(committed_view, Some(self.expectation))?;
        Ok(match (observation.lifecycle, observation.source) {
            (
                AuthDatabaseLifecycleObservation::Active(facts),
                AuthInitializationSourceMatch::Exact,
            ) if facts.state_revision == 2 && facts.keyring_version.get() == 1 => {
                MutationPostcondition::Committed
            }
            (
                AuthDatabaseLifecycleObservation::Initializing(_),
                AuthInitializationSourceMatch::Exact,
            ) => MutationPostcondition::NotCommitted,
            _ => MutationPostcondition::Ambiguous,
        })
    }
}

pub(super) fn commit_initialization_final_lifecycle(
    location: &StoreLocation,
    operation_poisoned: &Arc<AtomicBool>,
    expectation: InitializationSourceExpectation<'_>,
    #[cfg(test)] test_fault: Option<AuthInitializationFinalLifecycleMutationTestFault>,
) -> Result<AuthInitializationFinalLifecycleMutationOutcome, AuthRecordsError> {
    let fault = {
        #[cfg(test)]
        {
            match test_fault {
                None => CommitFault::None,
                Some(
                    AuthInitializationFinalLifecycleMutationTestFault::AfterCommitResponseLoss,
                ) => CommitFault::AfterCommitResponseLoss,
                Some(
                    AuthInitializationFinalLifecycleMutationTestFault::DeferredForeignKeyCommitFailure,
                ) => CommitFault::DeferredForeignKeyCommitFailure,
            }
        }
        #[cfg(not(test))]
        {
            CommitFault::None
        }
    };

    ensure_operation_available(operation_poisoned)?;
    let poison = Arc::clone(operation_poisoned);
    let mutation = InitializationFinalLifecycleMutation { expectation };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _panic_guard = WorkerPanicPoisonGuard::new(Arc::clone(&poison));
        ensure_operation_available(&poison)?;
        execute_blocking(location, &poison, &mutation, &fault)
    }))
    .unwrap_or(Err(AuthRecordsError::ExecutorFailed));
    if result.is_err() {
        poison.store(true, Ordering::Release);
    }

    result.map(|run| match run {
        MutationRun::ExpectedNoCommit(
            InitializationFinalLifecycleExpectedNoCommit::AlreadyCommitted,
        ) => AuthInitializationFinalLifecycleMutationOutcome::AlreadyCommitted,
        MutationRun::ExpectedNoCommit(
            InitializationFinalLifecycleExpectedNoCommit::PreconditionChanged,
        ) => AuthInitializationFinalLifecycleMutationOutcome::PreconditionChanged,
        MutationRun::CommitResolved(execution) => match execution.disposition {
            MutationDisposition::Committed => {
                AuthInitializationFinalLifecycleMutationOutcome::Committed
            }
            MutationDisposition::NotCommitted => {
                AuthInitializationFinalLifecycleMutationOutcome::ConfirmedNotCommitted
            }
        },
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlannedRotationExpectedNoCommit {
    AlreadyCommitted,
    PreconditionChanged,
}

struct KeyTransitionSourceMutation<E> {
    expectation: E,
}

impl<E> AuthMutation for KeyTransitionSourceMutation<E>
where
    E: KeyTransitionSourceExpectation,
{
    type ExpectedNoCommit = PlannedRotationExpectedNoCommit;

    fn apply(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<ApplyDecision<Self::ExpectedNoCommit>, AuthRecordsError> {
        validate_store_contract_row(transaction, StoreKind::Conversation)?;
        validate_current_migration_history(
            transaction,
            StoreKind::Conversation,
            migrations_for_kind(StoreKind::Conversation),
        )?;
        validate_auth_table_inventory(transaction)?;

        let lifecycle = read_auth_lifecycle_observation(transaction)?;
        let inspection =
            read_planned_rotation_source_match(transaction, lifecycle, Some(self.expectation))?;
        match planned_rotation_lifecycle_stage(lifecycle, self.expectation) {
            Some(PlannedRotationLifecycleStage::PreSource)
                if inspection.source_match == AuthPlannedRotationSourceMatch::Exact => {}
            Some(
                PlannedRotationLifecycleStage::PostSource | PlannedRotationLifecycleStage::Final,
            ) if inspection.source_match == AuthPlannedRotationSourceMatch::Exact => {
                return Ok(ApplyDecision::ExpectedNoCommit(
                    PlannedRotationExpectedNoCommit::AlreadyCommitted,
                ));
            }
            _ => {
                return Ok(ApplyDecision::ExpectedNoCommit(
                    PlannedRotationExpectedNoCommit::PreconditionChanged,
                ));
            }
        }

        let changed = transaction.execute(
            "UPDATE auth_key_lifecycle
             SET state = 'transitioning',
                 state_revision = ?1,
                 expected_kid = ?2,
                 transition_kind = ?3,
                 transition_id = ?4,
                 keyring_version = ?5,
                 updated_at_micros = ?6
             WHERE singleton = 1
               AND state = 'active'
               AND state_revision = ?7
               AND expected_kid = ?8
               AND transition_kind IS NULL
               AND transition_id IS NULL
               AND keyring_version = ?9
               AND updated_at_micros = ?10",
            params![
                self.expectation.transitioning_lifecycle_revision(),
                self.expectation.result_kid(),
                self.expectation.transition_kind().as_str(),
                self.expectation.transition_id().as_slice(),
                self.expectation.result_keyring_version(),
                self.expectation.source_at_micros(),
                self.expectation.expected_lifecycle_revision(),
                self.expectation.expected_active_kid(),
                self.expectation.expected_keyring_version(),
                self.expectation.expected_lifecycle_updated_at_micros(),
            ],
        )?;
        if changed == 0 {
            return self.classify_expected_no_commit(transaction);
        }
        expect_mutation_cardinality(changed, 1)?;

        expect_mutation_cardinality(
            transaction.execute(
                "INSERT INTO auth_audit(
                    owner_id, audit_id, action, profile, session_id, attempt_id,
                    happened_at_micros
                 ) VALUES (?1, ?2, ?3, NULL, NULL, NULL, ?4)",
                params![
                    self.expectation.owner_id().as_slice(),
                    self.expectation.audit_id().as_slice(),
                    self.expectation.audit_action(),
                    self.expectation.source_at_micros(),
                ],
            )?,
            1,
        )?;

        let lifecycle = read_auth_lifecycle_observation(transaction)?;
        let inspection =
            read_planned_rotation_source_match(transaction, lifecycle, Some(self.expectation))?;
        if planned_rotation_lifecycle_stage(lifecycle, self.expectation)
            != Some(PlannedRotationLifecycleStage::PostSource)
            || inspection.source_match != AuthPlannedRotationSourceMatch::Exact
        {
            return Err(AuthRecordsError::Store(StoreError::AuthControlPlaneCorrupt));
        }

        Ok(ApplyDecision::Commit)
    }

    fn classify(
        &self,
        committed_view: &mut RawConnection,
    ) -> Result<MutationPostcondition, AuthRecordsError> {
        let observation =
            inspect_auth_key_transition_snapshot(committed_view, Some(self.expectation))?;
        Ok(
            match (
                planned_rotation_lifecycle_stage(observation.lifecycle, self.expectation),
                observation.source,
            ) {
                (
                    Some(PlannedRotationLifecycleStage::PostSource),
                    AuthPlannedRotationSourceMatch::Exact,
                )
                | (
                    Some(PlannedRotationLifecycleStage::Final),
                    AuthPlannedRotationSourceMatch::Exact,
                ) => MutationPostcondition::Committed,
                (
                    Some(PlannedRotationLifecycleStage::PreSource),
                    AuthPlannedRotationSourceMatch::Exact,
                ) => MutationPostcondition::NotCommitted,
                _ => MutationPostcondition::Ambiguous,
            },
        )
    }
}

impl<E> KeyTransitionSourceMutation<E>
where
    E: KeyTransitionSourceExpectation,
{
    fn classify_expected_no_commit(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<ApplyDecision<PlannedRotationExpectedNoCommit>, AuthRecordsError> {
        let lifecycle = read_auth_lifecycle_observation(transaction)?;
        let inspection =
            read_planned_rotation_source_match(transaction, lifecycle, Some(self.expectation))?;
        let outcome = match (
            planned_rotation_lifecycle_stage(lifecycle, self.expectation),
            inspection.source_match,
        ) {
            (
                Some(
                    PlannedRotationLifecycleStage::PostSource
                    | PlannedRotationLifecycleStage::Final,
                ),
                AuthPlannedRotationSourceMatch::Exact,
            ) => PlannedRotationExpectedNoCommit::AlreadyCommitted,
            _ => PlannedRotationExpectedNoCommit::PreconditionChanged,
        };
        Ok(ApplyDecision::ExpectedNoCommit(outcome))
    }
}

pub(super) fn commit_planned_rotation_source(
    location: &StoreLocation,
    operation_poisoned: &Arc<AtomicBool>,
    expectation: PlannedRotationSourceExpectation<'_>,
    #[cfg(test)] test_fault: Option<AuthPlannedRotationSourceMutationTestFault>,
) -> Result<AuthPlannedRotationSourceMutationOutcome, AuthRecordsError> {
    let fault = {
        #[cfg(test)]
        {
            match test_fault {
                None => CommitFault::None,
                Some(AuthPlannedRotationSourceMutationTestFault::AfterCommitResponseLoss) => {
                    CommitFault::AfterCommitResponseLoss
                }
                Some(
                    AuthPlannedRotationSourceMutationTestFault::DeferredForeignKeyCommitFailure,
                ) => CommitFault::DeferredForeignKeyCommitFailure,
            }
        }
        #[cfg(not(test))]
        {
            CommitFault::None
        }
    };

    ensure_operation_available(operation_poisoned)?;
    let poison = Arc::clone(operation_poisoned);
    let mutation = KeyTransitionSourceMutation { expectation };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _panic_guard = WorkerPanicPoisonGuard::new(Arc::clone(&poison));
        ensure_operation_available(&poison)?;
        execute_blocking(location, &poison, &mutation, &fault)
    }))
    .unwrap_or(Err(AuthRecordsError::ExecutorFailed));
    if result.is_err() {
        poison.store(true, Ordering::Release);
    }

    result.map(|run| match run {
        MutationRun::ExpectedNoCommit(PlannedRotationExpectedNoCommit::AlreadyCommitted) => {
            AuthPlannedRotationSourceMutationOutcome::AlreadyCommitted
        }
        MutationRun::ExpectedNoCommit(PlannedRotationExpectedNoCommit::PreconditionChanged) => {
            AuthPlannedRotationSourceMutationOutcome::PreconditionChanged
        }
        MutationRun::CommitResolved(execution) => match execution.disposition {
            MutationDisposition::Committed => AuthPlannedRotationSourceMutationOutcome::Committed,
            MutationDisposition::NotCommitted => {
                AuthPlannedRotationSourceMutationOutcome::ConfirmedNotCommitted
            }
        },
    })
}

pub(super) fn commit_retire_source(
    location: &StoreLocation,
    operation_poisoned: &Arc<AtomicBool>,
    expectation: RetireSourceExpectation<'_>,
    #[cfg(test)] test_fault: Option<AuthPlannedRotationSourceMutationTestFault>,
) -> Result<AuthPlannedRotationSourceMutationOutcome, AuthRecordsError> {
    let fault = {
        #[cfg(test)]
        {
            match test_fault {
                None => CommitFault::None,
                Some(AuthPlannedRotationSourceMutationTestFault::AfterCommitResponseLoss) => {
                    CommitFault::AfterCommitResponseLoss
                }
                Some(
                    AuthPlannedRotationSourceMutationTestFault::DeferredForeignKeyCommitFailure,
                ) => CommitFault::DeferredForeignKeyCommitFailure,
            }
        }
        #[cfg(not(test))]
        {
            CommitFault::None
        }
    };

    ensure_operation_available(operation_poisoned)?;
    let poison = Arc::clone(operation_poisoned);
    let mutation = KeyTransitionSourceMutation { expectation };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _panic_guard = WorkerPanicPoisonGuard::new(Arc::clone(&poison));
        ensure_operation_available(&poison)?;
        execute_blocking(location, &poison, &mutation, &fault)
    }))
    .unwrap_or(Err(AuthRecordsError::ExecutorFailed));
    if result.is_err() {
        poison.store(true, Ordering::Release);
    }

    result.map(|run| match run {
        MutationRun::ExpectedNoCommit(PlannedRotationExpectedNoCommit::AlreadyCommitted) => {
            AuthPlannedRotationSourceMutationOutcome::AlreadyCommitted
        }
        MutationRun::ExpectedNoCommit(PlannedRotationExpectedNoCommit::PreconditionChanged) => {
            AuthPlannedRotationSourceMutationOutcome::PreconditionChanged
        }
        MutationRun::CommitResolved(execution) => match execution.disposition {
            MutationDisposition::Committed => AuthPlannedRotationSourceMutationOutcome::Committed,
            MutationDisposition::NotCommitted => {
                AuthPlannedRotationSourceMutationOutcome::ConfirmedNotCommitted
            }
        },
    })
}

struct KeyTransitionFinalLifecycleMutation<E> {
    expectation: E,
}

impl<E> AuthMutation for KeyTransitionFinalLifecycleMutation<E>
where
    E: KeyTransitionSourceExpectation,
{
    type ExpectedNoCommit = PlannedRotationExpectedNoCommit;

    fn apply(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<ApplyDecision<Self::ExpectedNoCommit>, AuthRecordsError> {
        validate_store_contract_row(transaction, StoreKind::Conversation)?;
        validate_current_migration_history(
            transaction,
            StoreKind::Conversation,
            migrations_for_kind(StoreKind::Conversation),
        )?;
        validate_auth_table_inventory(transaction)?;

        let lifecycle = read_auth_lifecycle_observation(transaction)?;
        let inspection =
            read_planned_rotation_source_match(transaction, lifecycle, Some(self.expectation))?;
        match planned_rotation_lifecycle_stage(lifecycle, self.expectation) {
            Some(PlannedRotationLifecycleStage::PostSource)
                if inspection.source_match == AuthPlannedRotationSourceMatch::Exact => {}
            Some(PlannedRotationLifecycleStage::Final)
                if inspection.source_match == AuthPlannedRotationSourceMatch::Exact =>
            {
                return Ok(ApplyDecision::ExpectedNoCommit(
                    PlannedRotationExpectedNoCommit::AlreadyCommitted,
                ));
            }
            _ => {
                return Ok(ApplyDecision::ExpectedNoCommit(
                    PlannedRotationExpectedNoCommit::PreconditionChanged,
                ));
            }
        }

        let changed = transaction.execute(
            "UPDATE auth_key_lifecycle
             SET state = 'active',
                 state_revision = ?1,
                 transition_kind = NULL,
                 transition_id = NULL
             WHERE singleton = 1
               AND state = 'transitioning'
               AND state_revision = ?2
               AND expected_kid = ?3
               AND transition_kind = ?4
               AND transition_id = ?5
               AND keyring_version = ?6
               AND updated_at_micros = ?7",
            params![
                self.expectation.final_lifecycle_revision(),
                self.expectation.transitioning_lifecycle_revision(),
                self.expectation.result_kid(),
                self.expectation.transition_kind().as_str(),
                self.expectation.transition_id().as_slice(),
                self.expectation.result_keyring_version(),
                self.expectation.source_at_micros(),
            ],
        )?;
        if changed == 0 {
            return self.classify_expected_no_commit(transaction);
        }
        expect_mutation_cardinality(changed, 1)?;

        let lifecycle = read_auth_lifecycle_observation(transaction)?;
        let inspection =
            read_planned_rotation_source_match(transaction, lifecycle, Some(self.expectation))?;
        if planned_rotation_lifecycle_stage(lifecycle, self.expectation)
            != Some(PlannedRotationLifecycleStage::Final)
            || inspection.source_match != AuthPlannedRotationSourceMatch::Exact
        {
            return Err(AuthRecordsError::Store(StoreError::AuthControlPlaneCorrupt));
        }

        Ok(ApplyDecision::Commit)
    }

    fn classify(
        &self,
        committed_view: &mut RawConnection,
    ) -> Result<MutationPostcondition, AuthRecordsError> {
        let observation =
            inspect_auth_key_transition_snapshot(committed_view, Some(self.expectation))?;
        Ok(
            match (
                planned_rotation_lifecycle_stage(observation.lifecycle, self.expectation),
                observation.source,
            ) {
                (
                    Some(PlannedRotationLifecycleStage::Final),
                    AuthPlannedRotationSourceMatch::Exact,
                ) => MutationPostcondition::Committed,
                (
                    Some(PlannedRotationLifecycleStage::PostSource),
                    AuthPlannedRotationSourceMatch::Exact,
                ) => MutationPostcondition::NotCommitted,
                _ => MutationPostcondition::Ambiguous,
            },
        )
    }
}

impl<E> KeyTransitionFinalLifecycleMutation<E>
where
    E: KeyTransitionSourceExpectation,
{
    fn classify_expected_no_commit(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<ApplyDecision<PlannedRotationExpectedNoCommit>, AuthRecordsError> {
        let lifecycle = read_auth_lifecycle_observation(transaction)?;
        let inspection =
            read_planned_rotation_source_match(transaction, lifecycle, Some(self.expectation))?;
        let outcome = match (
            planned_rotation_lifecycle_stage(lifecycle, self.expectation),
            inspection.source_match,
        ) {
            (Some(PlannedRotationLifecycleStage::Final), AuthPlannedRotationSourceMatch::Exact) => {
                PlannedRotationExpectedNoCommit::AlreadyCommitted
            }
            _ => PlannedRotationExpectedNoCommit::PreconditionChanged,
        };
        Ok(ApplyDecision::ExpectedNoCommit(outcome))
    }
}

pub(super) fn commit_planned_rotation_final_lifecycle(
    location: &StoreLocation,
    operation_poisoned: &Arc<AtomicBool>,
    expectation: PlannedRotationSourceExpectation<'_>,
    #[cfg(test)] test_fault: Option<AuthPlannedRotationFinalLifecycleMutationTestFault>,
) -> Result<AuthPlannedRotationFinalLifecycleMutationOutcome, AuthRecordsError> {
    let fault = {
        #[cfg(test)]
        {
            match test_fault {
                None => CommitFault::None,
                Some(
                    AuthPlannedRotationFinalLifecycleMutationTestFault::AfterCommitResponseLoss,
                ) => CommitFault::AfterCommitResponseLoss,
                Some(
                    AuthPlannedRotationFinalLifecycleMutationTestFault::DeferredForeignKeyCommitFailure,
                ) => CommitFault::DeferredForeignKeyCommitFailure,
            }
        }
        #[cfg(not(test))]
        {
            CommitFault::None
        }
    };

    ensure_operation_available(operation_poisoned)?;
    let poison = Arc::clone(operation_poisoned);
    let mutation = KeyTransitionFinalLifecycleMutation { expectation };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _panic_guard = WorkerPanicPoisonGuard::new(Arc::clone(&poison));
        ensure_operation_available(&poison)?;
        execute_blocking(location, &poison, &mutation, &fault)
    }))
    .unwrap_or(Err(AuthRecordsError::ExecutorFailed));
    if result.is_err() {
        poison.store(true, Ordering::Release);
    }

    result.map(|run| match run {
        MutationRun::ExpectedNoCommit(PlannedRotationExpectedNoCommit::AlreadyCommitted) => {
            AuthPlannedRotationFinalLifecycleMutationOutcome::AlreadyCommitted
        }
        MutationRun::ExpectedNoCommit(PlannedRotationExpectedNoCommit::PreconditionChanged) => {
            AuthPlannedRotationFinalLifecycleMutationOutcome::PreconditionChanged
        }
        MutationRun::CommitResolved(execution) => match execution.disposition {
            MutationDisposition::Committed => {
                AuthPlannedRotationFinalLifecycleMutationOutcome::Committed
            }
            MutationDisposition::NotCommitted => {
                AuthPlannedRotationFinalLifecycleMutationOutcome::ConfirmedNotCommitted
            }
        },
    })
}

pub(super) fn commit_retire_final_lifecycle(
    location: &StoreLocation,
    operation_poisoned: &Arc<AtomicBool>,
    expectation: RetireSourceExpectation<'_>,
    #[cfg(test)] test_fault: Option<AuthPlannedRotationFinalLifecycleMutationTestFault>,
) -> Result<AuthPlannedRotationFinalLifecycleMutationOutcome, AuthRecordsError> {
    let fault = {
        #[cfg(test)]
        {
            match test_fault {
                None => CommitFault::None,
                Some(
                    AuthPlannedRotationFinalLifecycleMutationTestFault::AfterCommitResponseLoss,
                ) => CommitFault::AfterCommitResponseLoss,
                Some(
                    AuthPlannedRotationFinalLifecycleMutationTestFault::DeferredForeignKeyCommitFailure,
                ) => CommitFault::DeferredForeignKeyCommitFailure,
            }
        }
        #[cfg(not(test))]
        {
            CommitFault::None
        }
    };

    ensure_operation_available(operation_poisoned)?;
    let poison = Arc::clone(operation_poisoned);
    let mutation = KeyTransitionFinalLifecycleMutation { expectation };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _panic_guard = WorkerPanicPoisonGuard::new(Arc::clone(&poison));
        ensure_operation_available(&poison)?;
        execute_blocking(location, &poison, &mutation, &fault)
    }))
    .unwrap_or(Err(AuthRecordsError::ExecutorFailed));
    if result.is_err() {
        poison.store(true, Ordering::Release);
    }

    result.map(|run| match run {
        MutationRun::ExpectedNoCommit(PlannedRotationExpectedNoCommit::AlreadyCommitted) => {
            AuthPlannedRotationFinalLifecycleMutationOutcome::AlreadyCommitted
        }
        MutationRun::ExpectedNoCommit(PlannedRotationExpectedNoCommit::PreconditionChanged) => {
            AuthPlannedRotationFinalLifecycleMutationOutcome::PreconditionChanged
        }
        MutationRun::CommitResolved(execution) => match execution.disposition {
            MutationDisposition::Committed => {
                AuthPlannedRotationFinalLifecycleMutationOutcome::Committed
            }
            MutationDisposition::NotCommitted => {
                AuthPlannedRotationFinalLifecycleMutationOutcome::ConfirmedNotCommitted
            }
        },
    })
}

const AUTH_TABLES: [&str; 12] = [
    "auth_key_lifecycle",
    "auth_accounts",
    "auth_password_credentials",
    "auth_recovery_credentials",
    "auth_authenticator_throttles",
    "auth_login_control",
    "auth_login_attempt_markers",
    "auth_login_attempt_outcomes",
    "auth_sessions",
    "auth_refresh_families",
    "auth_refresh_tokens",
    "auth_audit",
];

const AUTH_NON_LIFECYCLE_ROWS_PRESENT_SQL: &str = "
    SELECT
        EXISTS(SELECT 1 FROM auth_accounts)
        OR EXISTS(SELECT 1 FROM auth_password_credentials)
        OR EXISTS(SELECT 1 FROM auth_recovery_credentials)
        OR EXISTS(SELECT 1 FROM auth_authenticator_throttles)
        OR EXISTS(SELECT 1 FROM auth_login_control)
        OR EXISTS(SELECT 1 FROM auth_login_attempt_markers)
        OR EXISTS(SELECT 1 FROM auth_login_attempt_outcomes)
        OR EXISTS(SELECT 1 FROM auth_sessions)
        OR EXISTS(SELECT 1 FROM auth_refresh_families)
        OR EXISTS(SELECT 1 FROM auth_refresh_tokens)
        OR EXISTS(SELECT 1 FROM auth_audit)
        OR EXISTS(SELECT 1 FROM sqlite_sequence WHERE name = 'auth_audit')
";

pub(super) fn inspect_auth_lifecycle(
    location: &StoreLocation,
) -> Result<AuthDatabaseLifecycleObservation, StoreError> {
    let mut reader = open_existing_store_connection(
        location,
        StoreKind::Conversation,
        ExistingConnectionAccess::ReadOnly,
    )?;
    let snapshot = inspect_auth_lifecycle_snapshot(&mut reader);
    reader.flush_prepared_statement_cache();
    let close = reader.close();
    let result = match (snapshot, close) {
        (Ok(state), Ok(())) => Ok(state),
        (Err(error), Ok(())) => Err(error),
        (snapshot, Err((_reader, close_error))) => Err(StoreError::LifecycleCleanup {
            kind: StoreKind::Conversation,
            operation: "authentication initialization inspection",
            primary_error: if snapshot.is_ok() {
                "snapshot inspection completed".to_owned()
            } else {
                "snapshot inspection failed".to_owned()
            },
            cleanup_error: close_error.to_string(),
        }),
    };
    let location_validation =
        validate_store_location(location, "auth initialization inspection readback");
    match (result, location_validation) {
        (Ok(state), Ok(())) => Ok(state),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

pub(super) fn inspect_auth_reconciliation(
    location: &StoreLocation,
    expectation: Option<InitializationSourceExpectation<'_>>,
) -> Result<AuthDatabaseReconciliationObservation, StoreError> {
    let mut reader = open_existing_store_connection(
        location,
        StoreKind::Conversation,
        ExistingConnectionAccess::ReadOnly,
    )?;
    let snapshot = inspect_auth_reconciliation_snapshot(&mut reader, expectation);
    reader.flush_prepared_statement_cache();
    let close = reader.close();
    let result = match (snapshot, close) {
        (Ok(state), Ok(())) => Ok(state),
        (Err(error), Ok(())) => Err(error),
        (snapshot, Err((_reader, close_error))) => Err(StoreError::LifecycleCleanup {
            kind: StoreKind::Conversation,
            operation: "authentication reconciliation inspection",
            primary_error: if snapshot.is_ok() {
                "snapshot inspection completed".to_owned()
            } else {
                "snapshot inspection failed".to_owned()
            },
            cleanup_error: close_error.to_string(),
        }),
    };
    let location_validation =
        validate_store_location(location, "auth reconciliation inspection readback");
    match (result, location_validation) {
        (Ok(state), Ok(())) => Ok(state),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

pub(super) fn inspect_auth_planned_rotation(
    location: &StoreLocation,
    expectation: Option<PlannedRotationSourceExpectation<'_>>,
) -> Result<AuthPlannedRotationDatabaseObservation, StoreError> {
    inspect_auth_key_transition(
        location,
        expectation,
        "authentication planned rotation inspection",
    )
}

pub(super) fn inspect_auth_retire(
    location: &StoreLocation,
    expectation: Option<RetireSourceExpectation<'_>>,
) -> Result<AuthPlannedRotationDatabaseObservation, StoreError> {
    inspect_auth_key_transition(location, expectation, "authentication retire inspection")
}

fn inspect_auth_key_transition<E>(
    location: &StoreLocation,
    expectation: Option<E>,
    operation: &'static str,
) -> Result<AuthPlannedRotationDatabaseObservation, StoreError>
where
    E: KeyTransitionSourceExpectation,
{
    let mut reader = open_existing_store_connection(
        location,
        StoreKind::Conversation,
        ExistingConnectionAccess::ReadOnly,
    )?;
    let snapshot = inspect_auth_key_transition_snapshot(&mut reader, expectation);
    reader.flush_prepared_statement_cache();
    let close = reader.close();
    let result = match (snapshot, close) {
        (Ok(state), Ok(())) => Ok(state),
        (Err(error), Ok(())) => Err(error),
        (snapshot, Err((_reader, close_error))) => Err(StoreError::LifecycleCleanup {
            kind: StoreKind::Conversation,
            operation,
            primary_error: if snapshot.is_ok() {
                "snapshot inspection completed".to_owned()
            } else {
                "snapshot inspection failed".to_owned()
            },
            cleanup_error: close_error.to_string(),
        }),
    };
    let location_validation = validate_store_location(location, operation);
    match (result, location_validation) {
        (Ok(state), Ok(())) => Ok(state),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

fn inspect_auth_key_transition_snapshot<E>(
    reader: &mut RawConnection,
    expectation: Option<E>,
) -> Result<AuthPlannedRotationDatabaseObservation, StoreError>
where
    E: KeyTransitionSourceExpectation,
{
    let transaction = reader.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let inspection = (|| {
        validate_store_contract_row(&transaction, StoreKind::Conversation)?;
        validate_current_migration_history(
            &transaction,
            StoreKind::Conversation,
            migrations_for_kind(StoreKind::Conversation),
        )?;
        validate_auth_table_inventory(&transaction)?;
        let lifecycle = read_auth_lifecycle_observation(&transaction)?;
        let (source, source_fingerprint) = match lifecycle {
            AuthDatabaseLifecycleObservation::Active(_)
            | AuthDatabaseLifecycleObservation::Transitioning(_)
                if expectation.is_some()
                    || matches!(lifecycle, AuthDatabaseLifecycleObservation::Active(_)) =>
            {
                let inspection =
                    read_planned_rotation_source_match(&transaction, lifecycle, expectation)?;
                (inspection.source_match, Some(inspection.fingerprint))
            }
            _ => (AuthPlannedRotationSourceMatch::NotApplicable, None),
        };
        validate_store_contract_row(&transaction, StoreKind::Conversation)?;
        validate_current_migration_history(
            &transaction,
            StoreKind::Conversation,
            migrations_for_kind(StoreKind::Conversation),
        )?;
        Ok(AuthPlannedRotationDatabaseObservation {
            lifecycle,
            source,
            source_fingerprint,
        })
    })();
    let rollback = transaction.rollback();
    match (inspection, rollback) {
        (Ok(state), Ok(())) => Ok(state),
        (Err(error), Ok(())) => Err(error),
        (_, Err(error)) => Err(StoreError::Sqlite(error)),
    }
}

fn inspect_auth_reconciliation_snapshot(
    reader: &mut RawConnection,
    expectation: Option<InitializationSourceExpectation<'_>>,
) -> Result<AuthDatabaseReconciliationObservation, StoreError> {
    let transaction = reader.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let inspection = (|| {
        validate_store_contract_row(&transaction, StoreKind::Conversation)?;
        validate_current_migration_history(
            &transaction,
            StoreKind::Conversation,
            migrations_for_kind(StoreKind::Conversation),
        )?;
        validate_auth_table_inventory(&transaction)?;
        let lifecycle = read_auth_lifecycle_observation(&transaction)?;
        let (source, source_fingerprint) = match lifecycle {
            AuthDatabaseLifecycleObservation::Initializing(facts) => {
                let inspection =
                    read_initialization_source_match(&transaction, facts.into(), expectation)?;
                (inspection.source_match, Some(inspection.fingerprint))
            }
            AuthDatabaseLifecycleObservation::Active(facts)
                if expectation.is_some()
                    && facts.state_revision == 2
                    && facts.keyring_version.get() == 1 =>
            {
                let inspection =
                    read_initialization_source_match(&transaction, facts.into(), expectation)?;
                (inspection.source_match, Some(inspection.fingerprint))
            }
            _ => (AuthInitializationSourceMatch::NotApplicable, None),
        };
        validate_store_contract_row(&transaction, StoreKind::Conversation)?;
        validate_current_migration_history(
            &transaction,
            StoreKind::Conversation,
            migrations_for_kind(StoreKind::Conversation),
        )?;
        Ok(AuthDatabaseReconciliationObservation {
            lifecycle,
            source,
            source_fingerprint,
        })
    })();
    let rollback = transaction.rollback();
    match (inspection, rollback) {
        (Ok(state), Ok(())) => Ok(state),
        (Err(error), Ok(())) => Err(error),
        (_, Err(error)) => Err(StoreError::Sqlite(error)),
    }
}

fn inspect_auth_lifecycle_snapshot(
    reader: &mut RawConnection,
) -> Result<AuthDatabaseLifecycleObservation, StoreError> {
    let transaction = reader.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let inspection = (|| {
        validate_store_contract_row(&transaction, StoreKind::Conversation)?;
        validate_current_migration_history(
            &transaction,
            StoreKind::Conversation,
            migrations_for_kind(StoreKind::Conversation),
        )?;
        validate_auth_table_inventory(&transaction)?;
        let state = read_auth_lifecycle_observation(&transaction)?;
        validate_store_contract_row(&transaction, StoreKind::Conversation)?;
        validate_current_migration_history(
            &transaction,
            StoreKind::Conversation,
            migrations_for_kind(StoreKind::Conversation),
        )?;
        Ok(state)
    })();
    let rollback = transaction.rollback();
    match (inspection, rollback) {
        (Ok(state), Ok(())) => Ok(state),
        (Err(error), Ok(())) => Err(error),
        (_, Err(error)) => Err(StoreError::Sqlite(error)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlannedRotationLifecycleStage {
    PreSource,
    PostSource,
    Final,
}

fn planned_rotation_lifecycle_stage<E>(
    lifecycle: AuthDatabaseLifecycleObservation,
    expectation: E,
) -> Option<PlannedRotationLifecycleStage>
where
    E: KeyTransitionSourceExpectation,
{
    match lifecycle {
        AuthDatabaseLifecycleObservation::Active(facts)
            if expectation.matches_active_lifecycle(
                facts.state_revision,
                facts.expected_kid,
                facts.keyring_version,
                facts.updated_at_micros,
            ) =>
        {
            Some(PlannedRotationLifecycleStage::PreSource)
        }
        AuthDatabaseLifecycleObservation::Transitioning(facts)
            if expectation.matches_transitioning_lifecycle(
                facts.state_revision,
                facts.kind,
                facts.transition_id,
                facts.expected_kid,
                facts.keyring_version,
                facts.updated_at_micros,
            ) =>
        {
            Some(PlannedRotationLifecycleStage::PostSource)
        }
        AuthDatabaseLifecycleObservation::Active(facts)
            if expectation.matches_final_active_lifecycle(
                facts.state_revision,
                facts.expected_kid,
                facts.keyring_version,
                facts.updated_at_micros,
            ) =>
        {
            Some(PlannedRotationLifecycleStage::Final)
        }
        _ => None,
    }
}

struct PlannedRotationSourceInspection {
    source_match: AuthPlannedRotationSourceMatch,
    fingerprint: AuthPlannedRotationSourceFingerprint,
}

const PLANNED_ROTATION_SOURCE_FINGERPRINT_DOMAIN: &[u8] =
    b"pov.auth.planned-rotation-source-snapshot.v1\0";

fn read_planned_rotation_source_match<E>(
    transaction: &Transaction<'_>,
    lifecycle: AuthDatabaseLifecycleObservation,
    expectation: Option<E>,
) -> Result<PlannedRotationSourceInspection, StoreError>
where
    E: KeyTransitionSourceExpectation,
{
    let mut hasher = Sha256::new();
    hasher.update(PLANNED_ROTATION_SOURCE_FINGERPRINT_DOMAIN);

    let account = {
        let mut statement = transaction.prepare(
            "SELECT
                singleton, owner_id, login_id, account_state, credential_version,
                account_revision, created_at_micros, updated_at_micros
             FROM auth_accounts",
        )?;
        let mut rows = statement.query([])?;
        let Some(row) = rows.next()? else {
            return Err(StoreError::AuthControlPlaneCorrupt);
        };
        let value = (
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, i64>(7)?,
        );
        if rows.next()?.is_some() {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
        value
    };
    let (
        account_singleton,
        owner_id,
        login_id,
        account_state,
        credential_version,
        account_revision,
        account_created_at,
        account_updated_at,
    ) = account;
    if account_singleton != 1
        || !InitializationSourceExpectation::is_canonical_owner_id(&owner_id)
        || !InitializationSourceExpectation::is_canonical_login_id(login_id.as_bytes())
        || !matches!(account_state.as_str(), "enabled" | "disabled")
        || credential_version <= 0
        || account_revision <= 0
        || account_created_at < 0
        || account_updated_at < account_created_at
    {
        return Err(StoreError::AuthControlPlaneCorrupt);
    }
    for (label, value) in [
        (b"account.singleton".as_slice(), account_singleton),
        (b"account.credential_version".as_slice(), credential_version),
        (b"account.revision".as_slice(), account_revision),
        (b"account.created_at".as_slice(), account_created_at),
        (b"account.updated_at".as_slice(), account_updated_at),
    ] {
        update_initialization_source_integer(&mut hasher, label, value);
    }
    update_initialization_source_blob(&mut hasher, b"account.owner_id", &owner_id);
    update_initialization_source_text(&mut hasher, b"account.login_id", login_id.as_bytes());
    update_initialization_source_text(&mut hasher, b"account.state", account_state.as_bytes());

    let password = {
        let mut statement = transaction.prepare(
            "SELECT
                singleton, owner_id, verifier_phc, authenticator_state,
                credential_revision, blocklist_version, created_at_micros,
                updated_at_micros
             FROM auth_password_credentials",
        )?;
        let mut rows = statement.query([])?;
        let Some(row) = rows.next()? else {
            return Err(StoreError::AuthControlPlaneCorrupt);
        };
        let value = (
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, i64>(7)?,
        );
        if rows.next()?.is_some() {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
        value
    };
    let (
        password_singleton,
        password_owner,
        password_verifier,
        password_state,
        password_revision,
        legacy_policy,
        password_created_at,
        password_updated_at,
    ) = password;
    if password_singleton != 1
        || password_owner != owner_id
        || !InitializationSourceExpectation::is_canonical_verifier(password_verifier.as_bytes())
        || !matches!(password_state.as_str(), "enabled" | "disabled")
        || password_revision <= 0
        || !InitializationSourceExpectation::is_canonical_legacy_policy_provenance(
            legacy_policy.as_bytes(),
        )
        || password_created_at < 0
        || password_updated_at < password_created_at
    {
        return Err(StoreError::AuthControlPlaneCorrupt);
    }
    for (label, value) in [
        (b"password.singleton".as_slice(), password_singleton),
        (b"password.revision".as_slice(), password_revision),
        (b"password.created_at".as_slice(), password_created_at),
        (b"password.updated_at".as_slice(), password_updated_at),
    ] {
        update_initialization_source_integer(&mut hasher, label, value);
    }
    update_initialization_source_blob(&mut hasher, b"password.owner_id", &password_owner);
    update_initialization_source_text(
        &mut hasher,
        b"password.verifier",
        password_verifier.as_bytes(),
    );
    update_initialization_source_text(&mut hasher, b"password.state", password_state.as_bytes());
    update_initialization_source_text(
        &mut hasher,
        b"password.legacy_policy",
        legacy_policy.as_bytes(),
    );

    let recovery = {
        let mut statement = transaction.prepare(
            "SELECT
                singleton, owner_id, verifier_phc, credential_revision,
                created_at_micros, updated_at_micros
             FROM auth_recovery_credentials",
        )?;
        let mut rows = statement.query([])?;
        let Some(row) = rows.next()? else {
            return Err(StoreError::AuthControlPlaneCorrupt);
        };
        let value = (
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
        );
        if rows.next()?.is_some() {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
        value
    };
    let (
        recovery_singleton,
        recovery_owner,
        recovery_verifier,
        recovery_revision,
        recovery_created_at,
        recovery_updated_at,
    ) = recovery;
    if recovery_singleton != 1
        || recovery_owner != owner_id
        || !InitializationSourceExpectation::is_canonical_verifier(recovery_verifier.as_bytes())
        || !InitializationSourceExpectation::verifiers_have_independent_salts(
            password_verifier.as_bytes(),
            recovery_verifier.as_bytes(),
        )
        || recovery_revision <= 0
        || recovery_created_at < 0
        || recovery_updated_at < recovery_created_at
    {
        return Err(StoreError::AuthControlPlaneCorrupt);
    }
    for (label, value) in [
        (b"recovery.singleton".as_slice(), recovery_singleton),
        (b"recovery.revision".as_slice(), recovery_revision),
        (b"recovery.created_at".as_slice(), recovery_created_at),
        (b"recovery.updated_at".as_slice(), recovery_updated_at),
    ] {
        update_initialization_source_integer(&mut hasher, label, value);
    }
    update_initialization_source_blob(&mut hasher, b"recovery.owner_id", &recovery_owner);
    update_initialization_source_text(
        &mut hasher,
        b"recovery.verifier",
        recovery_verifier.as_bytes(),
    );

    let audit = if let Some(expectation) = expectation {
        let mut statement = transaction.prepare(
            "SELECT owner_id, action, profile, session_id, attempt_id, happened_at_micros
             FROM auth_audit
             WHERE audit_id = ?1",
        )?;
        let mut rows = statement.query([expectation.audit_id().as_slice()])?;
        let value = rows
            .next()?
            .map(|row| {
                Ok::<_, rusqlite::Error>((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .transpose()?;
        if rows.next()?.is_some() {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
        value
    } else {
        None
    };

    let common_source_matches = expectation.is_some_and(|expectation| {
        expectation.matches_owner_id(&owner_id)
            && expectation.credential_version() == credential_version
            && expectation.account_revision() == account_revision
            && expectation.password_credential_revision() == password_revision
            && expectation.recovery_credential_revision() == recovery_revision
    });
    let source_match = match expectation {
        None if matches!(lifecycle, AuthDatabaseLifecycleObservation::Active(_)) => {
            AuthPlannedRotationSourceMatch::Canonical
        }
        Some(expectation) => {
            let lifecycle_stage = planned_rotation_lifecycle_stage(lifecycle, expectation);
            let audit_matches = match lifecycle_stage {
                Some(PlannedRotationLifecycleStage::PreSource) => audit.is_none(),
                Some(
                    PlannedRotationLifecycleStage::PostSource
                    | PlannedRotationLifecycleStage::Final,
                ) => audit.is_some_and(
                    |(audit_owner, action, profile, session_id, attempt_id, happened_at)| {
                        expectation.matches_owner_id(&audit_owner)
                            && action == expectation.audit_action()
                            && profile.is_none()
                            && session_id.is_none()
                            && attempt_id.is_none()
                            && happened_at == expectation.source_at_micros()
                    },
                ),
                None => false,
            };
            if common_source_matches && audit_matches {
                AuthPlannedRotationSourceMatch::Exact
            } else {
                AuthPlannedRotationSourceMatch::Mismatch
            }
        }
        None => AuthPlannedRotationSourceMatch::NotApplicable,
    };
    Ok(PlannedRotationSourceInspection {
        source_match,
        fingerprint: AuthPlannedRotationSourceFingerprint::from_bytes(hasher.finalize().into()),
    })
}

struct InitializationSourceInspection {
    source_match: AuthInitializationSourceMatch,
    fingerprint: AuthInitializationSourceFingerprint,
}

#[derive(Clone, Copy)]
struct InitializationSourceLifecycleFacts {
    transition_id: Option<PersistedLifecycleTransitionId>,
    expected_kid: PersistedLifecycleKeyId,
    keyring_version: PersistedLifecycleKeyringVersion,
    updated_at_micros: PersistedLifecycleTimestamp,
}

impl From<AuthInitializingLifecycleFacts> for InitializationSourceLifecycleFacts {
    fn from(facts: AuthInitializingLifecycleFacts) -> Self {
        Self {
            transition_id: Some(facts.transition_id),
            expected_kid: facts.expected_kid,
            keyring_version: facts.keyring_version,
            updated_at_micros: facts.updated_at_micros,
        }
    }
}

impl From<AuthActiveLifecycleFacts> for InitializationSourceLifecycleFacts {
    fn from(facts: AuthActiveLifecycleFacts) -> Self {
        Self {
            transition_id: None,
            expected_kid: facts.expected_kid,
            keyring_version: facts.keyring_version,
            updated_at_micros: facts.updated_at_micros,
        }
    }
}

impl InitializationSourceLifecycleFacts {
    fn matches_expectation(self, expectation: InitializationSourceExpectation<'_>) -> bool {
        match self.transition_id {
            Some(transition_id) => expectation.matches_lifecycle(
                transition_id,
                self.expected_kid,
                self.keyring_version,
                self.updated_at_micros,
            ),
            None => expectation.matches_active_lifecycle(
                self.expected_kid,
                self.keyring_version,
                self.updated_at_micros,
            ),
        }
    }
}

struct InitializationSourceShape {
    row_counts: [i64; 11],
    sequence_count: i64,
    sequence_is_integer: bool,
    sequence_value: Option<i64>,
}

const INITIALIZATION_SOURCE_FINGERPRINT_DOMAIN: &[u8] =
    b"pov.auth.initialization-source-snapshot.v1\0";

fn update_initialization_source_fingerprint(
    hasher: &mut Sha256,
    label: &[u8],
    value_type: u8,
    value: &[u8],
) {
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update([value_type]);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn update_initialization_source_integer(hasher: &mut Sha256, label: &[u8], value: i64) {
    update_initialization_source_fingerprint(hasher, label, b'i', &value.to_be_bytes());
}

fn update_initialization_source_text(hasher: &mut Sha256, label: &[u8], value: &[u8]) {
    update_initialization_source_fingerprint(hasher, label, b't', value);
}

fn update_initialization_source_blob(hasher: &mut Sha256, label: &[u8], value: &[u8]) {
    update_initialization_source_fingerprint(hasher, label, b'b', value);
}

fn update_initialization_source_null(hasher: &mut Sha256, label: &[u8]) {
    update_initialization_source_fingerprint(hasher, label, b'n', &[]);
}

fn read_initialization_source_match(
    transaction: &Transaction<'_>,
    lifecycle: InitializationSourceLifecycleFacts,
    expectation: Option<InitializationSourceExpectation<'_>>,
) -> Result<InitializationSourceInspection, StoreError> {
    let mut metadata_match =
        expectation.is_some_and(|expectation| lifecycle.matches_expectation(expectation));

    let shape = transaction.query_row(
        "SELECT
            (SELECT count(*) FROM auth_accounts),
            (SELECT count(*) FROM auth_password_credentials),
            (SELECT count(*) FROM auth_recovery_credentials),
            (SELECT count(*) FROM auth_authenticator_throttles),
            (SELECT count(*) FROM auth_login_control),
            (SELECT count(*) FROM auth_login_attempt_markers),
            (SELECT count(*) FROM auth_login_attempt_outcomes),
            (SELECT count(*) FROM auth_sessions),
            (SELECT count(*) FROM auth_refresh_families),
            (SELECT count(*) FROM auth_refresh_tokens),
            (SELECT count(*) FROM auth_audit),
            (
                SELECT count(*) FROM sqlite_sequence
                WHERE name = 'auth_audit'
            ),
            (
                SELECT typeof(seq) FROM sqlite_sequence
                WHERE name = 'auth_audit'
            ),
            (
                SELECT seq FROM sqlite_sequence
                WHERE name = 'auth_audit'
            )",
        [],
        |row| {
            Ok(InitializationSourceShape {
                row_counts: [
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ],
                sequence_count: row.get(11)?,
                sequence_is_integer: matches!(
                    row.get_ref(12)?,
                    ValueRef::Text(value) if value == b"integer"
                ),
                sequence_value: match row.get_ref(13)? {
                    ValueRef::Integer(value) => Some(value),
                    _ => None,
                },
            })
        },
    )?;
    if shape.row_counts != [1, 1, 1, 2, 1, 0, 0, 0, 0, 0, 1]
        || shape.sequence_count != 1
        || !shape.sequence_is_integer
        || shape.sequence_value != Some(1)
    {
        return Err(StoreError::AuthControlPlaneCorrupt);
    }
    let mut source_fingerprint = Sha256::new();
    source_fingerprint.update(INITIALIZATION_SOURCE_FINGERPRINT_DOMAIN);
    for (label, value) in [
        (b"auth_accounts.count".as_slice(), shape.row_counts[0]),
        (
            b"auth_password_credentials.count".as_slice(),
            shape.row_counts[1],
        ),
        (
            b"auth_recovery_credentials.count".as_slice(),
            shape.row_counts[2],
        ),
        (
            b"auth_authenticator_throttles.count".as_slice(),
            shape.row_counts[3],
        ),
        (b"auth_login_control.count".as_slice(), shape.row_counts[4]),
        (
            b"auth_login_attempt_markers.count".as_slice(),
            shape.row_counts[5],
        ),
        (
            b"auth_login_attempt_outcomes.count".as_slice(),
            shape.row_counts[6],
        ),
        (b"auth_sessions.count".as_slice(), shape.row_counts[7]),
        (
            b"auth_refresh_families.count".as_slice(),
            shape.row_counts[8],
        ),
        (b"auth_refresh_tokens.count".as_slice(), shape.row_counts[9]),
        (b"auth_audit.count".as_slice(), shape.row_counts[10]),
        (
            b"sqlite_sequence.auth_audit.count".as_slice(),
            shape.sequence_count,
        ),
    ] {
        update_initialization_source_integer(&mut source_fingerprint, label, value);
    }
    update_initialization_source_text(
        &mut source_fingerprint,
        b"sqlite_sequence.auth_audit.seq.type",
        b"integer",
    );
    update_initialization_source_integer(
        &mut source_fingerprint,
        b"sqlite_sequence.auth_audit.seq",
        shape
            .sequence_value
            .ok_or(StoreError::AuthControlPlaneCorrupt)?,
    );

    let account_owner: [u8; 16];
    {
        let mut statement = transaction.prepare(
            "SELECT
                owner_id,
                login_id,
                account_state,
                credential_version,
                account_revision,
                created_at_micros,
                updated_at_micros
             FROM auth_accounts
             WHERE singleton = 1",
        )?;
        let mut rows = statement.query([])?;
        let row = rows.next()?.ok_or(StoreError::AuthControlPlaneCorrupt)?;
        let owner_id = borrowed_blob(row, 0)?;
        let login_id = borrowed_text(row, 1)?;
        let account_state = borrowed_text(row, 2)?;
        let credential_version = row.get::<_, i64>(3)?;
        let account_revision = row.get::<_, i64>(4)?;
        let created_at_micros = row.get::<_, i64>(5)?;
        let updated_at_micros = row.get::<_, i64>(6)?;
        if !InitializationSourceExpectation::is_canonical_owner_id(owner_id)
            || !InitializationSourceExpectation::is_canonical_login_id(login_id)
        {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
        account_owner = owner_id
            .try_into()
            .map_err(|_| StoreError::AuthControlPlaneCorrupt)?;
        if account_state != b"enabled" {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
        if credential_version != 1
            || account_revision != 1
            || !lifecycle.updated_at_micros.matches_i64(created_at_micros)
            || !lifecycle.updated_at_micros.matches_i64(updated_at_micros)
        {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
        update_initialization_source_blob(
            &mut source_fingerprint,
            b"auth_accounts.owner_id",
            owner_id,
        );
        update_initialization_source_text(
            &mut source_fingerprint,
            b"auth_accounts.login_id",
            login_id,
        );
        update_initialization_source_text(
            &mut source_fingerprint,
            b"auth_accounts.account_state",
            account_state,
        );
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_accounts.credential_version",
            credential_version,
        );
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_accounts.account_revision",
            account_revision,
        );
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_accounts.created_at_micros",
            created_at_micros,
        );
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_accounts.updated_at_micros",
            updated_at_micros,
        );
        if let Some(expectation) = expectation {
            metadata_match &=
                expectation.matches_owner_id(owner_id) && expectation.matches_login_id(login_id);
        }
        if rows.next()?.is_some() {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
    }

    {
        let mut statement = transaction.prepare(
            "SELECT
                owner_id,
                verifier_phc,
                authenticator_state,
                credential_revision,
                blocklist_version,
                created_at_micros,
                updated_at_micros,
                (
                    SELECT verifier_phc
                    FROM auth_recovery_credentials
                    WHERE singleton = 1
                )
             FROM auth_password_credentials
             WHERE singleton = 1",
        )?;
        let mut rows = statement.query([])?;
        let row = rows.next()?.ok_or(StoreError::AuthControlPlaneCorrupt)?;
        let owner_id = borrowed_blob(row, 0)?;
        let verifier = borrowed_text(row, 1)?;
        let authenticator_state = borrowed_text(row, 2)?;
        let credential_revision = row.get::<_, i64>(3)?;
        let legacy_policy_provenance = borrowed_text(row, 4)?;
        let created_at_micros = row.get::<_, i64>(5)?;
        let updated_at_micros = row.get::<_, i64>(6)?;
        let recovery_verifier = borrowed_text(row, 7)?;
        if !InitializationSourceExpectation::is_canonical_owner_id(owner_id)
            || !InitializationSourceExpectation::is_canonical_verifier(verifier)
            || !InitializationSourceExpectation::is_canonical_legacy_policy_provenance(
                legacy_policy_provenance,
            )
            || !InitializationSourceExpectation::is_canonical_verifier(recovery_verifier)
            || !InitializationSourceExpectation::verifiers_have_independent_salts(
                verifier,
                recovery_verifier,
            )
        {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
        if owner_id != account_owner
            || authenticator_state != b"enabled"
            || credential_revision != 1
            || !lifecycle.updated_at_micros.matches_i64(created_at_micros)
            || !lifecycle.updated_at_micros.matches_i64(updated_at_micros)
        {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
        update_initialization_source_blob(
            &mut source_fingerprint,
            b"auth_password_credentials.owner_id",
            owner_id,
        );
        update_initialization_source_text(
            &mut source_fingerprint,
            b"auth_password_credentials.verifier_phc",
            verifier,
        );
        update_initialization_source_text(
            &mut source_fingerprint,
            b"auth_password_credentials.authenticator_state",
            authenticator_state,
        );
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_password_credentials.credential_revision",
            credential_revision,
        );
        update_initialization_source_text(
            &mut source_fingerprint,
            b"auth_password_credentials.blocklist_version",
            legacy_policy_provenance,
        );
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_password_credentials.created_at_micros",
            created_at_micros,
        );
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_password_credentials.updated_at_micros",
            updated_at_micros,
        );
        if let Some(expectation) = expectation {
            metadata_match &= expectation.matches_owner_id(owner_id)
                && expectation.matches_password_phc(verifier)
                && expectation.matches_legacy_policy_provenance(legacy_policy_provenance);
        }
        if rows.next()?.is_some() {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
    }

    {
        let mut statement = transaction.prepare(
            "SELECT
                owner_id,
                verifier_phc,
                credential_revision,
                created_at_micros,
                updated_at_micros
             FROM auth_recovery_credentials
             WHERE singleton = 1",
        )?;
        let mut rows = statement.query([])?;
        let row = rows.next()?.ok_or(StoreError::AuthControlPlaneCorrupt)?;
        let owner_id = borrowed_blob(row, 0)?;
        let verifier = borrowed_text(row, 1)?;
        let credential_revision = row.get::<_, i64>(2)?;
        let created_at_micros = row.get::<_, i64>(3)?;
        let updated_at_micros = row.get::<_, i64>(4)?;
        if !InitializationSourceExpectation::is_canonical_owner_id(owner_id)
            || !InitializationSourceExpectation::is_canonical_verifier(verifier)
        {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
        if owner_id != account_owner
            || credential_revision != 1
            || !lifecycle.updated_at_micros.matches_i64(created_at_micros)
            || !lifecycle.updated_at_micros.matches_i64(updated_at_micros)
        {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
        update_initialization_source_blob(
            &mut source_fingerprint,
            b"auth_recovery_credentials.owner_id",
            owner_id,
        );
        update_initialization_source_text(
            &mut source_fingerprint,
            b"auth_recovery_credentials.verifier_phc",
            verifier,
        );
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_recovery_credentials.credential_revision",
            credential_revision,
        );
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_recovery_credentials.created_at_micros",
            created_at_micros,
        );
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_recovery_credentials.updated_at_micros",
            updated_at_micros,
        );
        if let Some(expectation) = expectation {
            metadata_match &= expectation.matches_owner_id(owner_id)
                && expectation.matches_recovery_phc(verifier);
        }
        if rows.next()?.is_some() {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
    }

    {
        let mut statement = transaction.prepare(
            "SELECT
                owner_id,
                authenticator,
                failure_count,
                next_allowed_at_micros,
                throttle_revision,
                updated_at_micros
             FROM auth_authenticator_throttles
             ORDER BY authenticator",
        )?;
        let mut rows = statement.query([])?;
        for expected_authenticator in [b"password".as_slice(), b"recovery".as_slice()] {
            let row = rows.next()?.ok_or(StoreError::AuthControlPlaneCorrupt)?;
            let owner_id = borrowed_blob(row, 0)?;
            let authenticator = borrowed_text(row, 1)?;
            let failure_count = row.get::<_, i64>(2)?;
            let next_allowed_at_micros = row.get::<_, i64>(3)?;
            let throttle_revision = row.get::<_, i64>(4)?;
            let updated_at_micros = row.get::<_, i64>(5)?;
            if !InitializationSourceExpectation::is_canonical_owner_id(owner_id) {
                return Err(StoreError::AuthControlPlaneCorrupt);
            }
            if owner_id != account_owner
                || authenticator != expected_authenticator
                || failure_count != 0
                || next_allowed_at_micros != 0
                || throttle_revision != 1
                || !lifecycle.updated_at_micros.matches_i64(updated_at_micros)
            {
                return Err(StoreError::AuthControlPlaneCorrupt);
            }
            update_initialization_source_blob(
                &mut source_fingerprint,
                b"auth_authenticator_throttles.owner_id",
                owner_id,
            );
            update_initialization_source_text(
                &mut source_fingerprint,
                b"auth_authenticator_throttles.authenticator",
                authenticator,
            );
            update_initialization_source_integer(
                &mut source_fingerprint,
                b"auth_authenticator_throttles.failure_count",
                failure_count,
            );
            update_initialization_source_integer(
                &mut source_fingerprint,
                b"auth_authenticator_throttles.next_allowed_at_micros",
                next_allowed_at_micros,
            );
            update_initialization_source_integer(
                &mut source_fingerprint,
                b"auth_authenticator_throttles.throttle_revision",
                throttle_revision,
            );
            update_initialization_source_integer(
                &mut source_fingerprint,
                b"auth_authenticator_throttles.updated_at_micros",
                updated_at_micros,
            );
            if let Some(expectation) = expectation {
                metadata_match &= expectation.matches_owner_id(owner_id);
            }
        }
        if rows.next()?.is_some() {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
    }

    {
        let mut statement = transaction.prepare(
            "SELECT
                owner_id,
                admission_revision,
                clock_floor_micros,
                control_revision,
                created_at_micros,
                updated_at_micros
             FROM auth_login_control
             WHERE singleton = 1",
        )?;
        let mut rows = statement.query([])?;
        let row = rows.next()?.ok_or(StoreError::AuthControlPlaneCorrupt)?;
        let owner_id = borrowed_blob(row, 0)?;
        let admission_revision = row.get::<_, i64>(1)?;
        let clock_floor_micros = row.get::<_, i64>(2)?;
        let control_revision = row.get::<_, i64>(3)?;
        let created_at_micros = row.get::<_, i64>(4)?;
        let updated_at_micros = row.get::<_, i64>(5)?;
        if !InitializationSourceExpectation::is_canonical_owner_id(owner_id) {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
        if owner_id != account_owner
            || admission_revision != 1
            || !lifecycle.updated_at_micros.matches_i64(clock_floor_micros)
            || control_revision != 1
            || !lifecycle.updated_at_micros.matches_i64(created_at_micros)
            || !lifecycle.updated_at_micros.matches_i64(updated_at_micros)
        {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
        update_initialization_source_blob(
            &mut source_fingerprint,
            b"auth_login_control.owner_id",
            owner_id,
        );
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_login_control.admission_revision",
            admission_revision,
        );
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_login_control.clock_floor_micros",
            clock_floor_micros,
        );
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_login_control.control_revision",
            control_revision,
        );
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_login_control.created_at_micros",
            created_at_micros,
        );
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_login_control.updated_at_micros",
            updated_at_micros,
        );
        if let Some(expectation) = expectation {
            metadata_match &= expectation.matches_owner_id(owner_id);
        }
        if rows.next()?.is_some() {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
    }

    {
        let mut statement = transaction.prepare(
            "SELECT
                audit_sequence,
                owner_id,
                audit_id,
                action,
                profile,
                session_id,
                attempt_id,
                happened_at_micros
             FROM auth_audit",
        )?;
        let mut rows = statement.query([])?;
        let row = rows.next()?.ok_or(StoreError::AuthControlPlaneCorrupt)?;
        let audit_sequence = row.get::<_, i64>(0)?;
        let owner_id = borrowed_blob(row, 1)?;
        let audit_id = borrowed_blob(row, 2)?;
        let action = borrowed_text(row, 3)?;
        let profile_is_null = matches!(row.get_ref(4)?, ValueRef::Null);
        let session_id_is_null = matches!(row.get_ref(5)?, ValueRef::Null);
        let attempt_id_is_null = matches!(row.get_ref(6)?, ValueRef::Null);
        let happened_at_micros = row.get::<_, i64>(7)?;
        if !InitializationSourceExpectation::is_canonical_owner_id(owner_id)
            || !InitializationSourceExpectation::is_canonical_audit_id(audit_id)
        {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
        if audit_sequence != 1
            || owner_id != account_owner
            || action != b"auth_initialized"
            || !profile_is_null
            || !session_id_is_null
            || !attempt_id_is_null
            || !lifecycle.updated_at_micros.matches_i64(happened_at_micros)
        {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_audit.audit_sequence",
            audit_sequence,
        );
        update_initialization_source_blob(
            &mut source_fingerprint,
            b"auth_audit.owner_id",
            owner_id,
        );
        update_initialization_source_blob(
            &mut source_fingerprint,
            b"auth_audit.audit_id",
            audit_id,
        );
        update_initialization_source_text(&mut source_fingerprint, b"auth_audit.action", action);
        update_initialization_source_null(&mut source_fingerprint, b"auth_audit.profile");
        update_initialization_source_null(&mut source_fingerprint, b"auth_audit.session_id");
        update_initialization_source_null(&mut source_fingerprint, b"auth_audit.attempt_id");
        update_initialization_source_integer(
            &mut source_fingerprint,
            b"auth_audit.happened_at_micros",
            happened_at_micros,
        );
        if let Some(expectation) = expectation {
            metadata_match &=
                expectation.matches_owner_id(owner_id) && expectation.matches_audit_id(audit_id);
        }
        if rows.next()?.is_some() {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
    }

    Ok(InitializationSourceInspection {
        source_match: if metadata_match {
            AuthInitializationSourceMatch::Exact
        } else {
            AuthInitializationSourceMatch::Mismatch
        },
        fingerprint: AuthInitializationSourceFingerprint::from_bytes(
            source_fingerprint.finalize().into(),
        ),
    })
}

fn borrowed_blob<'row>(row: &'row Row<'_>, index: usize) -> Result<&'row [u8], StoreError> {
    match row.get_ref(index)? {
        ValueRef::Blob(value) => Ok(value),
        _ => Err(StoreError::AuthControlPlaneCorrupt),
    }
}

fn borrowed_text<'row>(row: &'row Row<'_>, index: usize) -> Result<&'row [u8], StoreError> {
    match row.get_ref(index)? {
        ValueRef::Text(value) => Ok(value),
        _ => Err(StoreError::AuthControlPlaneCorrupt),
    }
}

fn validate_auth_table_inventory(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    let auth_table_count: i64 = transaction.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name GLOB 'auth_*'",
        [],
        |row| row.get(0),
    )?;
    if auth_table_count != AUTH_TABLES.len() as i64 {
        return Err(StoreError::AuthControlPlaneCorrupt);
    }
    for table in AUTH_TABLES {
        let present: i64 = transaction.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )?;
        if present != 1 {
            return Err(StoreError::AuthControlPlaneCorrupt);
        }
    }
    Ok(())
}

fn read_auth_lifecycle_observation(
    transaction: &Transaction<'_>,
) -> Result<AuthDatabaseLifecycleObservation, StoreError> {
    let mut statement = transaction.prepare(
        "SELECT
            singleton,
            state,
            state_revision,
            expected_kid,
            transition_kind,
            transition_id,
            keyring_version,
            updated_at_micros
         FROM auth_key_lifecycle",
    )?;
    let mut rows = statement.query([])?;
    let Some(row) = rows.next()? else {
        return Err(StoreError::AuthControlPlaneCorrupt);
    };
    let singleton = row.get::<_, i64>(0)?;
    let state = row.get::<_, String>(1)?;
    let state_revision = row.get::<_, i64>(2)?;
    let expected_kid = row.get::<_, Option<String>>(3)?;
    let transition_kind = row.get::<_, Option<String>>(4)?;
    let transition_id = row.get::<_, Option<Vec<u8>>>(5)?;
    let keyring_version = row.get::<_, Option<i64>>(6)?;
    let updated_at_micros = row.get::<_, i64>(7)?;
    if rows.next()?.is_some() || singleton != 1 {
        return Err(StoreError::AuthControlPlaneCorrupt);
    }
    drop(rows);
    drop(statement);

    match state.as_str() {
        "uninitialized" => {
            let non_lifecycle_rows_present: bool =
                transaction.query_row(AUTH_NON_LIFECYCLE_ROWS_PRESENT_SQL, [], |row| row.get(0))?;
            if state_revision == 0
                && expected_kid.is_none()
                && transition_kind.is_none()
                && transition_id.is_none()
                && keyring_version.is_none()
                && updated_at_micros == 0
                && !non_lifecycle_rows_present
            {
                Ok(AuthDatabaseLifecycleObservation::CleanUninitialized)
            } else {
                Err(StoreError::AuthControlPlaneCorrupt)
            }
        }
        "initializing" => {
            let expected_kid = parse_lifecycle_kid(expected_kid)?;
            let transition_kind = parse_transition_kind(transition_kind)?;
            let transition_id = parse_transition_id(transition_id)?;
            let keyring_version = parse_keyring_version(keyring_version)?;
            let updated_at_micros = parse_lifecycle_timestamp(updated_at_micros)?;
            if state_revision != 1
                || transition_kind != TransitionKind::Initialize
                || keyring_version.get() != 1
            {
                return Err(StoreError::AuthControlPlaneCorrupt);
            }
            Ok(AuthDatabaseLifecycleObservation::Initializing(
                AuthInitializingLifecycleFacts {
                    state_revision: 1,
                    transition_id,
                    expected_kid,
                    keyring_version,
                    updated_at_micros,
                },
            ))
        }
        "active" => {
            if transition_kind.is_some() || transition_id.is_some() {
                return Err(StoreError::AuthControlPlaneCorrupt);
            }
            let state_revision =
                u64::try_from(state_revision).map_err(|_| StoreError::AuthControlPlaneCorrupt)?;
            let expected_kid = parse_lifecycle_kid(expected_kid)?;
            let keyring_version = parse_keyring_version(keyring_version)?;
            let updated_at_micros = parse_lifecycle_timestamp(updated_at_micros)?;
            let expected_revision = keyring_version
                .get()
                .checked_mul(2)
                .filter(|revision| *revision <= i64::MAX as u64)
                .ok_or(StoreError::AuthControlPlaneCorrupt)?;
            if state_revision != expected_revision {
                return Err(StoreError::AuthControlPlaneCorrupt);
            }
            Ok(AuthDatabaseLifecycleObservation::Active(
                AuthActiveLifecycleFacts {
                    state_revision,
                    expected_kid,
                    keyring_version,
                    updated_at_micros,
                },
            ))
        }
        "transitioning" => {
            let state_revision =
                u64::try_from(state_revision).map_err(|_| StoreError::AuthControlPlaneCorrupt)?;
            let expected_kid = parse_lifecycle_kid(expected_kid)?;
            let transition_kind = parse_transition_kind(transition_kind)?;
            let transition_id = parse_transition_id(transition_id)?;
            let keyring_version = parse_keyring_version(keyring_version)?;
            let updated_at_micros = parse_lifecycle_timestamp(updated_at_micros)?;
            let expected_revision = keyring_version
                .get()
                .checked_mul(2)
                .and_then(|revision| revision.checked_sub(1))
                .filter(|revision| *revision <= i64::MAX as u64)
                .ok_or(StoreError::AuthControlPlaneCorrupt)?;
            if transition_kind == TransitionKind::Initialize || state_revision != expected_revision
            {
                return Err(StoreError::AuthControlPlaneCorrupt);
            }
            Ok(AuthDatabaseLifecycleObservation::Transitioning(
                AuthTransitioningLifecycleFacts {
                    state_revision,
                    kind: transition_kind,
                    transition_id,
                    expected_kid,
                    keyring_version,
                    updated_at_micros,
                },
            ))
        }
        _ => Err(StoreError::AuthControlPlaneCorrupt),
    }
}

fn parse_lifecycle_kid(value: Option<String>) -> Result<PersistedLifecycleKeyId, StoreError> {
    value
        .as_deref()
        .and_then(PersistedLifecycleKeyId::parse)
        .ok_or(StoreError::AuthControlPlaneCorrupt)
}

fn parse_transition_kind(value: Option<String>) -> Result<TransitionKind, StoreError> {
    value
        .as_deref()
        .and_then(TransitionKind::parse_persisted)
        .ok_or(StoreError::AuthControlPlaneCorrupt)
}

fn parse_transition_id(
    value: Option<Vec<u8>>,
) -> Result<PersistedLifecycleTransitionId, StoreError> {
    value
        .as_deref()
        .and_then(PersistedLifecycleTransitionId::parse)
        .ok_or(StoreError::AuthControlPlaneCorrupt)
}

fn parse_keyring_version(
    value: Option<i64>,
) -> Result<PersistedLifecycleKeyringVersion, StoreError> {
    value
        .and_then(PersistedLifecycleKeyringVersion::parse)
        .ok_or(StoreError::AuthControlPlaneCorrupt)
}

fn parse_lifecycle_timestamp(value: i64) -> Result<PersistedLifecycleTimestamp, StoreError> {
    PersistedLifecycleTimestamp::parse(value).ok_or(StoreError::AuthControlPlaneCorrupt)
}

#[cfg(test)]
#[derive(Clone)]
struct OperationGate {
    reached: Arc<std::sync::Barrier>,
    resume: Arc<std::sync::Barrier>,
    completed: Arc<std::sync::Barrier>,
}

#[cfg(test)]
impl OperationGate {
    fn new() -> Self {
        Self {
            reached: Arc::new(std::sync::Barrier::new(2)),
            resume: Arc::new(std::sync::Barrier::new(2)),
            completed: Arc::new(std::sync::Barrier::new(2)),
        }
    }

    fn pause(&self) {
        self.reached.wait();
        self.resume.wait();
    }

    fn wait_until_paused(&self) {
        self.reached.wait();
    }

    fn resume(&self) {
        self.resume.wait();
    }

    fn complete(&self) {
        self.completed.wait();
    }

    fn wait_until_complete(&self) {
        self.completed.wait();
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{
        convert::Infallible,
        sync::atomic::{AtomicUsize, Ordering as AtomicOrdering},
    };

    use tempfile::tempdir;
    use tokio_rusqlite::rusqlite::params;
    #[cfg(unix)]
    use uuid::Uuid;

    use super::*;
    #[cfg(unix)]
    use crate::auth::{
        AuditId, AuthOwnerId, AuthTimestampMicros, Keyring, PlannedRotationMetadataInput,
        PlannedRotationPreparationV1, SourceTimestampMicros, TransitionId,
    };
    #[cfg(unix)]
    use crate::storage::AuthConversationStoreBinding;
    use crate::storage::{BUSY_TIMEOUT_MILLIS, StoreSet, read_report, validate_store_report};

    const TEST_OWNER: [u8; 16] = [0x11; 16];
    const TEST_TRANSITION: [u8; 16] = [
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x42, 0x22, 0x82, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22,
    ];
    const OTHER_TRANSITION: [u8; 16] = [
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x43, 0x33, 0x83, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33,
    ];
    const TEST_KID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const OTHER_KID: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
    const NONCANONICAL_KID: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    fn with_initialization_source_seed<R>(
        transition: [u8; 16],
        login_id: &'static str,
        signing_seed: [u8; 32],
        run: impl FnOnce(InitializationSourceSeed<'_>) -> R,
    ) -> R {
        InitializationSourceSeed::with_test_metadata(
            transition,
            login_id.as_bytes(),
            signing_seed,
            run,
        )
    }

    #[derive(Debug, Eq, PartialEq)]
    struct LifecycleRow {
        state: String,
        state_revision: i64,
        expected_kid: Option<String>,
        transition_kind: Option<String>,
        transition_id: Option<Vec<u8>>,
        keyring_version: Option<i64>,
    }

    struct LifecycleMutation;

    impl AuthMutation for LifecycleMutation {
        type ExpectedNoCommit = Infallible;

        fn apply(
            &self,
            transaction: &Transaction<'_>,
        ) -> Result<ApplyDecision<Self::ExpectedNoCommit>, AuthRecordsError> {
            let changed = transaction.execute(
                "UPDATE auth_key_lifecycle
                 SET state = 'initializing',
                     state_revision = 1,
                     expected_kid = ?1,
                     transition_kind = 'initialize',
                     transition_id = ?2,
                     keyring_version = 1,
                     updated_at_micros = 1
                 WHERE singleton = 1
                   AND state = 'uninitialized'
                   AND state_revision = 0",
                params![TEST_KID, TEST_TRANSITION.as_slice()],
            )?;
            if changed != 1 {
                return Err(AuthRecordsError::UnexpectedMutationCardinality);
            }
            Ok(ApplyDecision::Commit)
        }

        fn classify(
            &self,
            committed_view: &mut RawConnection,
        ) -> Result<MutationPostcondition, AuthRecordsError> {
            let row = committed_view.query_row(
                "SELECT state,
                            state_revision,
                            expected_kid,
                            transition_kind,
                            transition_id,
                            keyring_version
                     FROM auth_key_lifecycle
                     WHERE singleton = 1",
                [],
                |row| {
                    Ok(LifecycleRow {
                        state: row.get(0)?,
                        state_revision: row.get(1)?,
                        expected_kid: row.get(2)?,
                        transition_kind: row.get(3)?,
                        transition_id: row.get(4)?,
                        keyring_version: row.get(5)?,
                    })
                },
            )?;
            if row
                == (LifecycleRow {
                    state: "initializing".to_owned(),
                    state_revision: 1,
                    expected_kid: Some(TEST_KID.to_owned()),
                    transition_kind: Some("initialize".to_owned()),
                    transition_id: Some(TEST_TRANSITION.to_vec()),
                    keyring_version: Some(1),
                })
            {
                return Ok(MutationPostcondition::Committed);
            }
            if row
                == (LifecycleRow {
                    state: "uninitialized".to_owned(),
                    state_revision: 0,
                    expected_kid: None,
                    transition_kind: None,
                    transition_id: None,
                    keyring_version: None,
                })
            {
                return Ok(MutationPostcondition::NotCommitted);
            }
            Ok(MutationPostcondition::Ambiguous)
        }
    }

    struct DeferredForeignKeyMutation;

    impl AuthMutation for DeferredForeignKeyMutation {
        type ExpectedNoCommit = Infallible;

        fn apply(
            &self,
            transaction: &Transaction<'_>,
        ) -> Result<ApplyDecision<Self::ExpectedNoCommit>, AuthRecordsError> {
            transaction.pragma_update(None, "defer_foreign_keys", "ON")?;
            transaction.execute(
                "INSERT INTO auth_password_credentials(
                    singleton,
                    owner_id,
                    verifier_phc,
                    authenticator_state,
                    credential_revision,
                    blocklist_version,
                    created_at_micros,
                    updated_at_micros
                 ) VALUES (1, ?1, 'synthetic-phc', 'enabled', 1, 'synthetic-v1', 1, 1)",
                [TEST_OWNER.as_slice()],
            )?;
            Ok(ApplyDecision::Commit)
        }

        fn classify(
            &self,
            committed_view: &mut RawConnection,
        ) -> Result<MutationPostcondition, AuthRecordsError> {
            let count: i64 = committed_view.query_row(
                "SELECT count(*) FROM auth_password_credentials WHERE singleton = 1",
                [],
                |row| row.get(0),
            )?;
            match count {
                0 => Ok(MutationPostcondition::NotCommitted),
                1 => Ok(MutationPostcondition::Committed),
                _ => Ok(MutationPostcondition::Ambiguous),
            }
        }
    }

    struct AmbiguousMutation;

    impl AuthMutation for AmbiguousMutation {
        type ExpectedNoCommit = Infallible;

        fn apply(
            &self,
            _transaction: &Transaction<'_>,
        ) -> Result<ApplyDecision<Self::ExpectedNoCommit>, AuthRecordsError> {
            Ok(ApplyDecision::Commit)
        }

        fn classify(
            &self,
            _committed_view: &mut RawConnection,
        ) -> Result<MutationPostcondition, AuthRecordsError> {
            Ok(MutationPostcondition::Ambiguous)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ExpectedLifecycleNoCommit {
        AlreadyApplied,
        PreconditionChanged,
    }

    struct ExpectedLifecycleCasMutation {
        target_kid: &'static str,
        target_transition: [u8; 16],
        classifier_calls: Arc<AtomicUsize>,
    }

    impl ExpectedLifecycleCasMutation {
        fn new(
            target_kid: &'static str,
            target_transition: [u8; 16],
            classifier_calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                target_kid,
                target_transition,
                classifier_calls,
            }
        }
    }

    impl AuthMutation for ExpectedLifecycleCasMutation {
        type ExpectedNoCommit = ExpectedLifecycleNoCommit;

        fn apply(
            &self,
            transaction: &Transaction<'_>,
        ) -> Result<ApplyDecision<Self::ExpectedNoCommit>, AuthRecordsError> {
            let changed = transaction.execute(
                "UPDATE auth_key_lifecycle
                 SET state = 'initializing',
                     state_revision = 1,
                     expected_kid = ?1,
                     transition_kind = 'initialize',
                     transition_id = ?2,
                     keyring_version = 1,
                     updated_at_micros = 1
                 WHERE singleton = 1
                   AND state = 'uninitialized'
                   AND state_revision = 0",
                params![self.target_kid, self.target_transition.as_slice()],
            )?;
            match changed {
                1 => Ok(ApplyDecision::Commit),
                0 => {
                    let row = read_lifecycle_row(transaction)?;
                    let outcome = if row
                        == expected_initializing_row(self.target_kid, self.target_transition)
                    {
                        ExpectedLifecycleNoCommit::AlreadyApplied
                    } else {
                        ExpectedLifecycleNoCommit::PreconditionChanged
                    };
                    Ok(ApplyDecision::ExpectedNoCommit(outcome))
                }
                _ => Err(AuthRecordsError::UnexpectedMutationCardinality),
            }
        }

        fn classify(
            &self,
            _committed_view: &mut RawConnection,
        ) -> Result<MutationPostcondition, AuthRecordsError> {
            self.classifier_calls.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(MutationPostcondition::Ambiguous)
        }
    }

    struct ExpectedNoCommitWithHistoryDriftMutation {
        classifier_calls: Arc<AtomicUsize>,
    }

    impl AuthMutation for ExpectedNoCommitWithHistoryDriftMutation {
        type ExpectedNoCommit = ExpectedLifecycleNoCommit;

        fn apply(
            &self,
            transaction: &Transaction<'_>,
        ) -> Result<ApplyDecision<Self::ExpectedNoCommit>, AuthRecordsError> {
            transaction.execute(
                "UPDATE _pov_migrations
                 SET migration_sql = '-- synthetic expected-no-commit drift'
                 WHERE namespace = 'sqlite/conversation' AND version = 4",
                [],
            )?;
            Ok(ApplyDecision::ExpectedNoCommit(
                ExpectedLifecycleNoCommit::PreconditionChanged,
            ))
        }

        fn classify(
            &self,
            _committed_view: &mut RawConnection,
        ) -> Result<MutationPostcondition, AuthRecordsError> {
            self.classifier_calls.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(MutationPostcondition::Ambiguous)
        }
    }

    struct ExpectedNoCommitWithProvisionalWriteMutation {
        classifier_calls: Arc<AtomicUsize>,
    }

    impl AuthMutation for ExpectedNoCommitWithProvisionalWriteMutation {
        type ExpectedNoCommit = ExpectedLifecycleNoCommit;

        fn apply(
            &self,
            transaction: &Transaction<'_>,
        ) -> Result<ApplyDecision<Self::ExpectedNoCommit>, AuthRecordsError> {
            transaction.execute(
                "UPDATE auth_key_lifecycle
                 SET state = 'initializing',
                     state_revision = 1,
                     expected_kid = ?1,
                     transition_kind = 'initialize',
                     transition_id = ?2,
                     keyring_version = 1,
                     updated_at_micros = 1
                 WHERE singleton = 1
                   AND state = 'uninitialized'
                   AND state_revision = 0",
                params![TEST_KID, TEST_TRANSITION.as_slice()],
            )?;
            Ok(ApplyDecision::ExpectedNoCommit(
                ExpectedLifecycleNoCommit::PreconditionChanged,
            ))
        }

        fn classify(
            &self,
            _committed_view: &mut RawConnection,
        ) -> Result<MutationPostcondition, AuthRecordsError> {
            self.classifier_calls.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(MutationPostcondition::Ambiguous)
        }
    }

    fn read_lifecycle_row(connection: &RawConnection) -> Result<LifecycleRow, AuthRecordsError> {
        connection
            .query_row(
                "SELECT state,
                        state_revision,
                        expected_kid,
                        transition_kind,
                        transition_id,
                        keyring_version
                 FROM auth_key_lifecycle
                 WHERE singleton = 1",
                [],
                |row| {
                    Ok(LifecycleRow {
                        state: row.get(0)?,
                        state_revision: row.get(1)?,
                        expected_kid: row.get(2)?,
                        transition_kind: row.get(3)?,
                        transition_id: row.get(4)?,
                        keyring_version: row.get(5)?,
                    })
                },
            )
            .map_err(AuthRecordsError::from)
    }

    fn expected_initializing_row(kid: &str, transition: [u8; 16]) -> LifecycleRow {
        LifecycleRow {
            state: "initializing".to_owned(),
            state_revision: 1,
            expected_kid: Some(kid.to_owned()),
            transition_kind: Some("initialize".to_owned()),
            transition_id: Some(transition.to_vec()),
            keyring_version: Some(1),
        }
    }

    fn expect_commit_execution(run: MutationRun<Infallible>) -> MutationExecution {
        match run {
            MutationRun::CommitResolved(execution) => execution,
            MutationRun::ExpectedNoCommit(never) => match never {},
        }
    }

    #[cfg(unix)]
    fn with_planned_rotation_fixture<R>(
        binding: &AuthConversationStoreBinding,
        run: impl FnOnce(&PlannedRotationPreparationV1) -> R,
    ) -> R {
        const INITIAL_KEY_SEED: [u8; 32] = [0x91; 32];
        const INITIAL_SOURCE_AT: u64 = 1_700_000_000_000_001;
        const PLANNED_TRANSITION: [u8; 16] = [
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x46, 0x66, 0x86, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66,
        ];
        const PLANNED_AUDIT: [u8; 16] = [
            0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x47, 0x77, 0x87, 0x77, 0x77, 0x77, 0x77, 0x77,
            0x77, 0x77,
        ];
        const OWNER_ID: [u8; 16] = [
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x84, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44,
        ];

        with_initialization_source_seed(
            TEST_TRANSITION,
            "owner",
            INITIAL_KEY_SEED,
            |initialization| {
                assert_eq!(
                    binding
                        .commit_initialization_source(initialization)
                        .expect("initialization source commit"),
                    AuthInitializationSourceMutationOutcome::Committed
                );
                assert_eq!(
                    binding
                        .commit_initialization_final_lifecycle(initialization.expectation())
                        .expect("initialization final lifecycle"),
                    AuthInitializationFinalLifecycleMutationOutcome::Committed
                );
            },
        );

        let current = Keyring::from_test_seeds(1, INITIAL_SOURCE_AT - 1, INITIAL_KEY_SEED, None)
            .expect("current planned keyring");
        let preparation = PlannedRotationPreparationV1::from_current_keyring(
            PlannedRotationMetadataInput {
                transition_id: TransitionId::from_uuid(Uuid::from_bytes(PLANNED_TRANSITION))
                    .expect("planned transition"),
                owner_id: AuthOwnerId::from_uuid(Uuid::from_bytes(OWNER_ID))
                    .expect("planned owner"),
                audit_id: AuditId::from_uuid(Uuid::from_bytes(PLANNED_AUDIT))
                    .expect("planned audit"),
                key_activated_at_micros: AuthTimestampMicros::new(INITIAL_SOURCE_AT + 10)
                    .expect("planned activation"),
                source_at_micros: SourceTimestampMicros::new(INITIAL_SOURCE_AT + 11)
                    .expect("planned source timestamp"),
                expected_lifecycle_revision: 2,
                expected_lifecycle_updated_at_micros: SourceTimestampMicros::new(INITIAL_SOURCE_AT)
                    .expect("active lifecycle timestamp"),
                credential_version: 1,
                account_revision: 1,
                password_credential_revision: 1,
                recovery_credential_revision: 1,
            },
            &current,
        )
        .expect("planned preparation");
        run(&preparation)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn clean_initialization_snapshot_survives_explicit_reopen() {
        let directory = tempdir().expect("temporary store directory");
        let store_root = directory.path().join("stores");
        let stores = StoreSet::open(&store_root).await.expect("stores open");
        let binding = stores
            .conversation
            .auth_maintenance_binding()
            .expect("auth binding");
        assert_eq!(
            binding
                .inspect_auth_lifecycle()
                .expect("clean initialization snapshot"),
            AuthDatabaseLifecycleObservation::CleanUninitialized
        );
        stores.close().await.expect("stores close");

        let reopened = StoreSet::open(&store_root).await.expect("stores reopen");
        assert_eq!(
            reopened
                .conversation
                .auth_maintenance_binding()
                .expect("reopened auth binding")
                .inspect_auth_lifecycle()
                .expect("reopened clean snapshot"),
            AuthDatabaseLifecycleObservation::CleanUninitialized
        );
        reopened.close().await.expect("reopened stores close");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn planned_rotation_source_and_final_lifecycle_are_exact_replayable_and_redacted() {
        let directory = tempdir().expect("temporary store directory");
        let store_root = directory.path().join("stores");
        let stores = StoreSet::open(&store_root).await.expect("stores open");
        let binding = stores
            .conversation
            .auth_maintenance_binding()
            .expect("auth binding");

        with_planned_rotation_fixture(&binding, |preparation| {
            let expectation = preparation.source_expectation();
            let pre_source = binding
                .inspect_auth_planned_rotation(Some(expectation))
                .expect("planned pre-source observation");
            assert_eq!(pre_source.source, AuthPlannedRotationSourceMatch::Exact);
            assert!(matches!(
                planned_rotation_lifecycle_stage(pre_source.lifecycle, expectation),
                Some(PlannedRotationLifecycleStage::PreSource)
            ));

            let source = binding
                .commit_planned_rotation_source(expectation)
                .expect("planned source commit");
            assert_eq!(source, AuthPlannedRotationSourceMutationOutcome::Committed);
            assert_eq!(
                format!("{source:?}"),
                "AuthPlannedRotationSourceMutationOutcome::Committed"
            );
            let post_source = binding
                .inspect_auth_planned_rotation(Some(expectation))
                .expect("planned post-source observation");
            assert_eq!(post_source.source, AuthPlannedRotationSourceMatch::Exact);
            assert!(matches!(
                planned_rotation_lifecycle_stage(post_source.lifecycle, expectation),
                Some(PlannedRotationLifecycleStage::PostSource)
            ));
            assert_eq!(
                binding
                    .commit_planned_rotation_source(expectation)
                    .expect("planned source replay"),
                AuthPlannedRotationSourceMutationOutcome::AlreadyCommitted
            );

            let final_lifecycle = binding
                .commit_planned_rotation_final_lifecycle(expectation)
                .expect("planned final lifecycle");
            assert_eq!(
                final_lifecycle,
                AuthPlannedRotationFinalLifecycleMutationOutcome::Committed
            );
            assert_eq!(
                format!("{final_lifecycle:?}"),
                "AuthPlannedRotationFinalLifecycleMutationOutcome::Committed"
            );
            let final_observation = binding
                .inspect_auth_planned_rotation(Some(expectation))
                .expect("planned final observation");
            assert_eq!(
                final_observation.source,
                AuthPlannedRotationSourceMatch::Exact
            );
            assert!(matches!(
                planned_rotation_lifecycle_stage(final_observation.lifecycle, expectation),
                Some(PlannedRotationLifecycleStage::Final)
            ));
            assert_eq!(
                binding
                    .commit_planned_rotation_final_lifecycle(expectation)
                    .expect("planned final replay"),
                AuthPlannedRotationFinalLifecycleMutationOutcome::AlreadyCommitted
            );
        });

        stores.close().await.expect("stores close");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn planned_rotation_source_and_final_lifecycle_resolve_commit_uncertainty() {
        for final_lifecycle in [false, true] {
            let directory = tempdir().expect("temporary store directory");
            let stores = StoreSet::open(directory.path().join("stores"))
                .await
                .expect("stores open");
            let binding = stores
                .conversation
                .auth_maintenance_binding()
                .expect("auth binding");

            with_planned_rotation_fixture(&binding, |preparation| {
                let expectation = preparation.source_expectation();
                let source = binding
                    .commit_planned_rotation_source_with_test_fault(
                        expectation,
                        AuthPlannedRotationSourceMutationTestFault::AfterCommitResponseLoss,
                    )
                    .expect("planned source response-loss classification");
                assert_eq!(source, AuthPlannedRotationSourceMutationOutcome::Committed);

                if final_lifecycle {
                    let final_outcome = binding
                        .commit_planned_rotation_final_lifecycle_with_test_fault(
                            expectation,
                            AuthPlannedRotationFinalLifecycleMutationTestFault::AfterCommitResponseLoss,
                        )
                        .expect("planned final response-loss classification");
                    assert_eq!(
                        final_outcome,
                        AuthPlannedRotationFinalLifecycleMutationOutcome::Committed
                    );
                }
            });

            stores.close().await.expect("stores close");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn planned_rotation_failed_commits_are_freshly_classified_as_not_committed() {
        for final_lifecycle in [false, true] {
            let directory = tempdir().expect("temporary store directory");
            let stores = StoreSet::open(directory.path().join("stores"))
                .await
                .expect("stores open");
            let binding = stores
                .conversation
                .auth_maintenance_binding()
                .expect("auth binding");

            with_planned_rotation_fixture(&binding, |preparation| {
                let expectation = preparation.source_expectation();
                if final_lifecycle {
                    assert_eq!(
                        binding
                            .commit_planned_rotation_source(expectation)
                            .expect("planned source commit"),
                        AuthPlannedRotationSourceMutationOutcome::Committed
                    );
                    assert_eq!(
                        binding
                            .commit_planned_rotation_final_lifecycle_with_test_fault(
                                expectation,
                                AuthPlannedRotationFinalLifecycleMutationTestFault::DeferredForeignKeyCommitFailure,
                            )
                            .expect("planned final failed-commit classification"),
                        AuthPlannedRotationFinalLifecycleMutationOutcome::ConfirmedNotCommitted
                    );
                    let observation = binding
                        .inspect_auth_planned_rotation(Some(expectation))
                        .expect("planned post-source remains");
                    assert_eq!(
                        planned_rotation_lifecycle_stage(observation.lifecycle, expectation),
                        Some(PlannedRotationLifecycleStage::PostSource)
                    );
                } else {
                    assert_eq!(
                        binding
                            .commit_planned_rotation_source_with_test_fault(
                                expectation,
                                AuthPlannedRotationSourceMutationTestFault::DeferredForeignKeyCommitFailure,
                            )
                            .expect("planned source failed-commit classification"),
                        AuthPlannedRotationSourceMutationOutcome::ConfirmedNotCommitted
                    );
                    let observation = binding
                        .inspect_auth_planned_rotation(Some(expectation))
                        .expect("planned pre-source remains");
                    assert_eq!(
                        planned_rotation_lifecycle_stage(observation.lifecycle, expectation),
                        Some(PlannedRotationLifecycleStage::PreSource)
                    );
                }
            });

            stores.close().await.expect("stores close");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn initialization_final_lifecycle_commit_is_exact_replayable_and_redacted() {
        let directory = tempdir().expect("temporary store directory");
        let store_root = directory.path().join("stores");
        let database = store_root.join(StoreKind::Conversation.file_name());
        let stores = StoreSet::open(&store_root).await.expect("stores open");
        let binding = stores
            .conversation
            .auth_maintenance_binding()
            .expect("auth binding");
        with_initialization_source_seed(TEST_TRANSITION, "owner_01", [0x31; 32], |seed| {
            assert_eq!(
                binding
                    .commit_initialization_source(seed)
                    .expect("initialization source commit"),
                AuthInitializationSourceMutationOutcome::Committed
            );

            let expectation = seed.expectation();
            let committed = binding
                .commit_initialization_final_lifecycle(expectation)
                .expect("initialization final lifecycle commit");
            assert_eq!(
                committed,
                AuthInitializationFinalLifecycleMutationOutcome::Committed
            );
            let active = binding
                .inspect_auth_reconciliation(Some(expectation))
                .expect("active initialization source readback");
            let AuthDatabaseLifecycleObservation::Active(active_facts) = active.lifecycle else {
                panic!("expected exact active initialization lifecycle");
            };
            assert_eq!(active_facts.state_revision, 2);
            assert_eq!(active_facts.keyring_version.get(), 1);
            assert_eq!(
                active_facts.expected_kid,
                PersistedLifecycleKeyId::parse(expectation.result_kid())
                    .expect("canonical final KID")
            );
            assert!(
                active_facts
                    .updated_at_micros
                    .matches_i64(expectation.source_at_micros())
            );
            assert_eq!(active.source, AuthInitializationSourceMatch::Exact);
            assert!(active.source_fingerprint.is_some());

            let reader = RawConnection::open(&database).expect("final lifecycle reader");
            let lifecycle = reader
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
                            row.get::<_, String>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, Option<Vec<u8>>>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    },
                )
                .expect("final lifecycle row");
            assert_eq!(
                lifecycle,
                (
                    "active".to_owned(),
                    2,
                    expectation.result_kid().to_owned(),
                    None,
                    None,
                    1,
                    expectation.source_at_micros(),
                )
            );
            assert_eq!(
                reader
                    .query_row("SELECT count(*) FROM auth_audit", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .expect("initialization audit count"),
                1
            );

            let replay = binding
                .commit_initialization_final_lifecycle(expectation)
                .expect("initialization final lifecycle replay");
            assert_eq!(
                replay,
                AuthInitializationFinalLifecycleMutationOutcome::AlreadyCommitted
            );
            assert_eq!(
                format!("{committed:?} {replay:?} {expectation:?}"),
                "AuthInitializationFinalLifecycleMutationOutcome::Committed \
                     AuthInitializationFinalLifecycleMutationOutcome::AlreadyCommitted \
                     InitializationSourceExpectation([REDACTED])"
            );
        });
        stores
            .conversation
            .report()
            .await
            .expect("final lifecycle commit keeps store healthy");
        stores.close().await.expect("stores close");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn initialization_final_lifecycle_mismatch_is_typed_without_mutation() {
        let directory = tempdir().expect("temporary store directory");
        let store_root = directory.path().join("stores");
        let stores = StoreSet::open(&store_root).await.expect("stores open");
        let binding = stores
            .conversation
            .auth_maintenance_binding()
            .expect("auth binding");
        with_initialization_source_seed(
            TEST_TRANSITION,
            "owner_01",
            [0x31; 32],
            |committed_seed| {
                binding
                    .commit_initialization_source(committed_seed)
                    .expect("initialization source commit");
                with_initialization_source_seed(
                    OTHER_TRANSITION,
                    "owner_02",
                    [0x32; 32],
                    |other_seed| {
                        assert_eq!(
                            binding
                                .commit_initialization_final_lifecycle(other_seed.expectation())
                                .expect("typed final lifecycle mismatch"),
                            AuthInitializationFinalLifecycleMutationOutcome::PreconditionChanged
                        );
                    },
                );

                let readback = binding
                    .inspect_auth_reconciliation(Some(committed_seed.expectation()))
                    .expect("initializing source readback");
                assert!(matches!(
                    readback.lifecycle,
                    AuthDatabaseLifecycleObservation::Initializing(_)
                ));
                assert_eq!(readback.source, AuthInitializationSourceMatch::Exact);
                assert_eq!(
                    binding
                        .commit_initialization_final_lifecycle(committed_seed.expectation())
                        .expect("exact final lifecycle retry"),
                    AuthInitializationFinalLifecycleMutationOutcome::Committed
                );
            },
        );
        stores
            .conversation
            .report()
            .await
            .expect("typed mismatch keeps store healthy");
        stores.close().await.expect("stores close");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn initialization_final_lifecycle_resolves_response_loss_and_failed_commit() {
        let directory = tempdir().expect("temporary store directory");

        let response_loss_root = directory.path().join("response-loss-stores");
        let response_loss_stores = StoreSet::open(&response_loss_root)
            .await
            .expect("response-loss stores open");
        let response_loss_binding = response_loss_stores
            .conversation
            .auth_maintenance_binding()
            .expect("response-loss auth binding");
        with_initialization_source_seed(
            TEST_TRANSITION,
            "owner_01",
            [0x31; 32],
            |response_loss_seed| {
                response_loss_binding
                    .commit_initialization_source(response_loss_seed)
                    .expect("response-loss source commit");
                assert_eq!(
                    response_loss_binding
                        .commit_initialization_final_lifecycle_with_test_fault(
                            response_loss_seed.expectation(),
                            AuthInitializationFinalLifecycleMutationTestFault::AfterCommitResponseLoss,
                        )
                        .expect("response-loss committed-view classification"),
                    AuthInitializationFinalLifecycleMutationOutcome::Committed
                );
                assert!(matches!(
                    response_loss_binding
                        .inspect_auth_reconciliation(Some(response_loss_seed.expectation()))
                        .expect("response-loss active readback")
                        .lifecycle,
                    AuthDatabaseLifecycleObservation::Active(_)
                ));
            },
        );
        response_loss_stores
            .conversation
            .report()
            .await
            .expect("response-loss classification keeps store healthy");
        response_loss_stores
            .close()
            .await
            .expect("response-loss stores close");

        let failed_root = directory.path().join("failed-commit-stores");
        let failed_stores = StoreSet::open(&failed_root)
            .await
            .expect("failed-commit stores open");
        let failed_binding = failed_stores
            .conversation
            .auth_maintenance_binding()
            .expect("failed-commit auth binding");
        with_initialization_source_seed(TEST_TRANSITION, "owner_01", [0x31; 32], |failed_seed| {
            failed_binding
                .commit_initialization_source(failed_seed)
                .expect("failed-commit source commit");
            assert_eq!(
                    failed_binding
                        .commit_initialization_final_lifecycle_with_test_fault(
                            failed_seed.expectation(),
                            AuthInitializationFinalLifecycleMutationTestFault::DeferredForeignKeyCommitFailure,
                        )
                        .expect("confirmed final lifecycle no-commit"),
                    AuthInitializationFinalLifecycleMutationOutcome::ConfirmedNotCommitted
                );
            let prior = failed_binding
                .inspect_auth_reconciliation(Some(failed_seed.expectation()))
                .expect("confirmed prior initializing source");
            assert!(matches!(
                prior.lifecycle,
                AuthDatabaseLifecycleObservation::Initializing(_)
            ));
            assert_eq!(prior.source, AuthInitializationSourceMatch::Exact);
            assert_eq!(
                failed_binding
                    .commit_initialization_final_lifecycle(failed_seed.expectation())
                    .expect("final lifecycle retry"),
                AuthInitializationFinalLifecycleMutationOutcome::Committed
            );
        });
        failed_stores
            .conversation
            .report()
            .await
            .expect("failed-commit classification keeps store healthy");
        failed_stores
            .close()
            .await
            .expect("failed-commit stores close");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lifecycle_observations_are_typed_redacted_and_survive_reopen() {
        let directory = tempdir().expect("temporary store directory");
        let store_root = directory.path().join("stores");
        let database = store_root.join(StoreKind::Conversation.file_name());
        let stores = StoreSet::open(&store_root).await.expect("stores open");
        let writer = RawConnection::open(&database).expect("synthetic lifecycle writer");
        writer
            .execute(
                "UPDATE auth_key_lifecycle
                 SET state = 'initializing',
                     state_revision = 1,
                     expected_kid = ?1,
                     transition_kind = 'initialize',
                     transition_id = ?2,
                     keyring_version = 1,
                     updated_at_micros = 11
                 WHERE singleton = 1",
                params![TEST_KID, TEST_TRANSITION],
            )
            .expect("initializing lifecycle");

        let initializing = stores
            .conversation
            .auth_maintenance_binding()
            .expect("auth binding")
            .inspect_auth_lifecycle()
            .expect("initializing observation");
        let AuthDatabaseLifecycleObservation::Initializing(initializing_facts) = initializing
        else {
            panic!("expected initializing facts");
        };
        assert_eq!(initializing_facts.state_revision, 1);
        assert_eq!(
            initializing_facts.transition_id,
            PersistedLifecycleTransitionId::parse(&TEST_TRANSITION).expect("canonical transition")
        );
        assert_eq!(
            initializing_facts.expected_kid,
            PersistedLifecycleKeyId::parse(TEST_KID).expect("canonical KID")
        );
        assert_eq!(initializing_facts.keyring_version.get(), 1);
        assert_eq!(
            format!("{initializing:?}"),
            "AuthDatabaseLifecycleObservation::Initializing([REDACTED])"
        );
        assert!(!format!("{initializing:?}").contains(TEST_KID));

        writer
            .execute(
                "UPDATE auth_key_lifecycle
                 SET state = 'active',
                     state_revision = 2,
                     transition_kind = NULL,
                     transition_id = NULL,
                     updated_at_micros = 12
                 WHERE singleton = 1",
                [],
            )
            .expect("active lifecycle");
        let active = stores
            .conversation
            .auth_maintenance_binding()
            .expect("active binding")
            .inspect_auth_lifecycle()
            .expect("active observation");
        let AuthDatabaseLifecycleObservation::Active(active_facts) = active else {
            panic!("expected active facts");
        };
        assert_eq!(active_facts.state_revision, 2);
        assert_eq!(active_facts.keyring_version.get(), 1);
        assert_eq!(
            format!("{active:?}"),
            "AuthDatabaseLifecycleObservation::Active([REDACTED])"
        );
        drop(writer);
        stores.close().await.expect("stores close");

        let reopened = StoreSet::open(&store_root).await.expect("stores reopen");
        assert!(matches!(
            reopened
                .conversation
                .auth_maintenance_binding()
                .expect("reopened auth binding")
                .inspect_auth_lifecycle()
                .expect("reopened active observation"),
            AuthDatabaseLifecycleObservation::Active(_)
        ));
        reopened.close().await.expect("reopened stores close");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn every_non_initialization_transition_kind_has_typed_facts() {
        for kind in [
            TransitionKind::Planned,
            TransitionKind::Retire,
            TransitionKind::Compromise,
            TransitionKind::Loss,
        ] {
            let directory = tempdir().expect("temporary store directory");
            let store_root = directory.path().join("stores");
            let database = store_root.join(StoreKind::Conversation.file_name());
            let stores = StoreSet::open(&store_root).await.expect("stores open");
            let writer = RawConnection::open(&database).expect("synthetic lifecycle writer");
            writer
                .execute(
                    "UPDATE auth_key_lifecycle
                     SET state = 'initializing',
                         state_revision = 1,
                         expected_kid = ?1,
                         transition_kind = 'initialize',
                         transition_id = ?2,
                         keyring_version = 1,
                         updated_at_micros = 1
                     WHERE singleton = 1",
                    params![TEST_KID, TEST_TRANSITION],
                )
                .expect("initializing lifecycle");
            writer
                .execute(
                    "UPDATE auth_key_lifecycle
                     SET state = 'active',
                         state_revision = 2,
                         transition_kind = NULL,
                         transition_id = NULL,
                         updated_at_micros = 2
                     WHERE singleton = 1",
                    [],
                )
                .expect("active lifecycle");
            let next_kid = if kind == TransitionKind::Retire {
                TEST_KID
            } else {
                OTHER_KID
            };
            writer
                .execute(
                    "UPDATE auth_key_lifecycle
                     SET state = 'transitioning',
                         state_revision = 3,
                         expected_kid = ?1,
                         transition_kind = ?2,
                         transition_id = ?3,
                         keyring_version = 2,
                         updated_at_micros = 3
                     WHERE singleton = 1",
                    params![next_kid, kind.as_str(), OTHER_TRANSITION],
                )
                .expect("transitioning lifecycle");
            drop(writer);

            let observation = stores
                .conversation
                .auth_maintenance_binding()
                .expect("auth binding")
                .inspect_auth_lifecycle()
                .expect("transitioning observation");
            let AuthDatabaseLifecycleObservation::Transitioning(facts) = observation else {
                panic!("expected transitioning facts");
            };
            assert_eq!(facts.kind, kind);
            assert_eq!(facts.state_revision, 3);
            assert_eq!(facts.keyring_version.get(), 2);
            assert_eq!(
                format!("{observation:?}"),
                "AuthDatabaseLifecycleObservation::Transitioning([REDACTED])"
            );
            assert!(!format!("{observation:?}").contains(next_kid));
            stores.close().await.expect("stores close");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn noncanonical_kid_and_non_v4_transition_poison_shared_operations() {
        for (kid, transition) in [(NONCANONICAL_KID, TEST_TRANSITION), (TEST_KID, [0x11; 16])] {
            let directory = tempdir().expect("temporary store directory");
            let store_root = directory.path().join("stores");
            let database = store_root.join(StoreKind::Conversation.file_name());
            let stores = StoreSet::open(&store_root).await.expect("stores open");
            let writer = RawConnection::open(database).expect("synthetic lifecycle writer");
            writer
                .execute(
                    "UPDATE auth_key_lifecycle
                     SET state = 'initializing',
                         state_revision = 1,
                         expected_kid = ?1,
                         transition_kind = 'initialize',
                         transition_id = ?2,
                         keyring_version = 1,
                         updated_at_micros = 1
                     WHERE singleton = 1",
                    params![kid, transition],
                )
                .expect("schema-valid but noncanonical lifecycle");
            drop(writer);

            assert!(matches!(
                stores
                    .conversation
                    .auth_maintenance_binding()
                    .expect("auth binding")
                    .inspect_auth_lifecycle(),
                Err(StoreError::AuthControlPlaneCorrupt)
            ));
            assert!(matches!(
                stores.conversation.report().await,
                Err(StoreError::OperationPoisoned {
                    kind: StoreKind::Conversation
                })
            ));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn revision_version_overflow_timestamp_and_null_mismatches_are_corrupt() {
        struct InvalidLifecycle<'a> {
            state: &'a str,
            revision: i64,
            kid: Option<&'a str>,
            kind: Option<&'a str>,
            transition: Option<&'a [u8]>,
            version: Option<i64>,
            updated_at: i64,
        }

        for invalid in [
            InvalidLifecycle {
                state: "active",
                revision: 4,
                kid: Some(TEST_KID),
                kind: None,
                transition: None,
                version: Some(1),
                updated_at: 1,
            },
            InvalidLifecycle {
                state: "active",
                revision: 2,
                kid: Some(TEST_KID),
                kind: None,
                transition: None,
                version: Some(i64::MAX),
                updated_at: 1,
            },
            InvalidLifecycle {
                state: "active",
                revision: 2,
                kid: Some(TEST_KID),
                kind: None,
                transition: None,
                version: Some(1),
                updated_at: 0,
            },
            InvalidLifecycle {
                state: "initializing",
                revision: 1,
                kid: Some(TEST_KID),
                kind: Some("initialize"),
                transition: None,
                version: Some(1),
                updated_at: 1,
            },
            InvalidLifecycle {
                state: "transitioning",
                revision: 3,
                kid: Some(OTHER_KID),
                kind: Some("initialize"),
                transition: Some(&OTHER_TRANSITION),
                version: Some(2),
                updated_at: 1,
            },
        ] {
            let directory = tempdir().expect("temporary store directory");
            let store_root = directory.path().join("stores");
            let database = store_root.join(StoreKind::Conversation.file_name());
            let stores = StoreSet::open(&store_root).await.expect("stores open");
            let writer = RawConnection::open(&database).expect("synthetic lifecycle writer");
            writer
                .execute_batch(
                    "DROP TRIGGER auth_key_lifecycle_guard_update;
                     PRAGMA ignore_check_constraints = ON;",
                )
                .expect("enable synthetic corruption");
            writer
                .execute(
                    "UPDATE auth_key_lifecycle
                     SET state = ?1,
                         state_revision = ?2,
                         expected_kid = ?3,
                         transition_kind = ?4,
                         transition_id = ?5,
                         keyring_version = ?6,
                         updated_at_micros = ?7
                     WHERE singleton = 1",
                    params![
                        invalid.state,
                        invalid.revision,
                        invalid.kid,
                        invalid.kind,
                        invalid.transition,
                        invalid.version,
                        invalid.updated_at
                    ],
                )
                .expect("write synthetic invalid lifecycle");
            drop(writer);

            let mut reader = RawConnection::open(database).expect("synthetic lifecycle reader");
            let transaction = reader
                .transaction_with_behavior(TransactionBehavior::Deferred)
                .expect("synthetic read transaction");
            assert!(matches!(
                read_auth_lifecycle_observation(&transaction),
                Err(StoreError::AuthControlPlaneCorrupt)
            ));
            transaction.rollback().expect("rollback synthetic reader");
            stores.close().await.expect("stores close");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unknown_auth_table_is_corruption_and_poisons_shared_operations() {
        let directory = tempdir().expect("temporary store directory");
        let store_root = directory.path().join("stores");
        let stores = StoreSet::open(&store_root).await.expect("stores open");
        let writer = RawConnection::open(store_root.join(StoreKind::Conversation.file_name()))
            .expect("synthetic schema writer");
        writer
            .execute_batch("CREATE TABLE auth_shadow(id INTEGER PRIMARY KEY) STRICT;")
            .expect("unknown auth table");
        drop(writer);

        let error = stores
            .conversation
            .auth_maintenance_binding()
            .expect("auth binding")
            .inspect_auth_lifecycle()
            .unwrap_err();
        assert!(matches!(error, StoreError::AuthControlPlaneCorrupt));
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn audit_sequence_residue_is_inconsistent_with_clean_uninitialized_state() {
        let directory = tempdir().expect("temporary store directory");
        let store_root = directory.path().join("stores");
        let stores = StoreSet::open(&store_root).await.expect("stores open");
        let writer = RawConnection::open(store_root.join(StoreKind::Conversation.file_name()))
            .expect("synthetic sequence writer");
        writer
            .execute(
                "INSERT INTO sqlite_sequence(name, seq) VALUES ('auth_audit', 1)",
                [],
            )
            .expect("synthetic audit sequence residue");
        drop(writer);

        assert!(matches!(
            stores
                .conversation
                .auth_maintenance_binding()
                .expect("auth binding")
                .inspect_auth_lifecycle(),
            Err(StoreError::AuthControlPlaneCorrupt)
        ));
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn missing_lifecycle_singleton_is_corruption_and_poisons_shared_operations() {
        let directory = tempdir().expect("temporary store directory");
        let store_root = directory.path().join("stores");
        let stores = StoreSet::open(&store_root).await.expect("stores open");
        let writer = RawConnection::open(store_root.join(StoreKind::Conversation.file_name()))
            .expect("synthetic lifecycle writer");
        writer
            .execute_batch(
                "DROP TRIGGER auth_key_lifecycle_reject_delete;
                 DELETE FROM auth_key_lifecycle;",
            )
            .expect("remove lifecycle singleton through synthetic corruption");
        drop(writer);

        assert!(matches!(
            stores
                .conversation
                .auth_maintenance_binding()
                .expect("auth binding")
                .inspect_auth_lifecycle(),
            Err(StoreError::AuthControlPlaneCorrupt)
        ));
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
    }

    #[tokio::test]
    async fn failed_commit_with_active_transaction_is_rolled_back_and_read_as_no_commit() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let executor = AuthMutationExecutor::new(&stores.conversation);

        let execution = expect_commit_execution(
            executor
                .execute(DeferredForeignKeyMutation, CommitFault::None)
                .await
                .expect("failed commit should resolve from fresh committed view"),
        );

        assert_eq!(execution.disposition, MutationDisposition::NotCommitted);
        assert_eq!(execution.observation, CommitObservation::Uncertain);
        assert!(execution.rolled_back_active_transaction);
        assert!(!executor.operation_poisoned.load(Ordering::Acquire));
        stores
            .conversation
            .report()
            .await
            .expect("store remains healthy");
    }

    #[tokio::test]
    async fn committed_response_loss_is_classified_from_fresh_view() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let executor = AuthMutationExecutor::new(&stores.conversation);

        let execution = expect_commit_execution(
            executor
                .execute(LifecycleMutation, CommitFault::AfterCommitResponseLoss)
                .await
                .expect("fresh readback should recover committed mutation"),
        );

        assert_eq!(execution.disposition, MutationDisposition::Committed);
        assert_eq!(execution.observation, CommitObservation::Uncertain);
        assert!(!execution.rolled_back_active_transaction);
        assert!(!executor.operation_poisoned.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn expected_cas_miss_rolls_back_without_readback_or_poison() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let executor = AuthMutationExecutor::new(&stores.conversation);
        let classifier_calls = Arc::new(AtomicUsize::new(0));

        let provisional_write = executor
            .execute(
                ExpectedNoCommitWithProvisionalWriteMutation {
                    classifier_calls: Arc::clone(&classifier_calls),
                },
                CommitFault::None,
            )
            .await
            .expect("provisional expected-no-commit write");
        assert!(matches!(
            provisional_write,
            MutationRun::ExpectedNoCommit(ExpectedLifecycleNoCommit::PreconditionChanged)
        ));
        let mut precommit_view = open_existing_store_connection(
            &executor.location,
            StoreKind::Conversation,
            ExistingConnectionAccess::ReadOnly,
        )
        .expect("precommit state read");
        assert_eq!(
            LifecycleMutation
                .classify(&mut precommit_view)
                .expect("rolled-back provisional state"),
            MutationPostcondition::NotCommitted
        );
        close_committed_view(precommit_view).expect("precommit state closes");

        expect_commit_execution(
            executor
                .execute(LifecycleMutation, CommitFault::None)
                .await
                .expect("initial lifecycle mutation"),
        );

        let already_applied = executor
            .execute(
                ExpectedLifecycleCasMutation::new(
                    TEST_KID,
                    TEST_TRANSITION,
                    Arc::clone(&classifier_calls),
                ),
                CommitFault::None,
            )
            .await
            .expect("already-applied CAS outcome");
        assert!(matches!(
            already_applied,
            MutationRun::ExpectedNoCommit(ExpectedLifecycleNoCommit::AlreadyApplied)
        ));

        let precondition_changed = executor
            .execute(
                ExpectedLifecycleCasMutation::new(
                    OTHER_KID,
                    OTHER_TRANSITION,
                    Arc::clone(&classifier_calls),
                ),
                CommitFault::None,
            )
            .await
            .expect("changed-precondition CAS outcome");
        assert!(matches!(
            precondition_changed,
            MutationRun::ExpectedNoCommit(ExpectedLifecycleNoCommit::PreconditionChanged)
        ));

        assert_eq!(classifier_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(!executor.operation_poisoned.load(Ordering::Acquire));
        stores
            .conversation
            .report()
            .await
            .expect("expected no-commit keeps store healthy");

        let committed_view = open_existing_store_connection(
            &executor.location,
            StoreKind::Conversation,
            ExistingConnectionAccess::ReadOnly,
        )
        .expect("fresh state read");
        assert_eq!(
            read_lifecycle_row(&committed_view).expect("lifecycle row"),
            expected_initializing_row(TEST_KID, TEST_TRANSITION)
        );
        close_committed_view(committed_view).expect("fresh state closes");
    }

    #[tokio::test]
    async fn expected_no_commit_still_revalidates_migration_history() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let executor = AuthMutationExecutor::new(&stores.conversation);
        let classifier_calls = Arc::new(AtomicUsize::new(0));

        assert!(
            executor
                .execute(
                    ExpectedNoCommitWithHistoryDriftMutation {
                        classifier_calls: Arc::clone(&classifier_calls),
                    },
                    CommitFault::None,
                )
                .await
                .is_err()
        );
        assert_eq!(classifier_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(executor.operation_poisoned.load(Ordering::Acquire));
        let committed_view = open_existing_store_connection(
            &executor.location,
            StoreKind::Conversation,
            ExistingConnectionAccess::ReadOnly,
        )
        .expect("expected-no-commit history drift rolled back");
        close_committed_view(committed_view).expect("committed view closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn expected_no_commit_close_failure_poisons_without_returning_domain_outcome() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let executor = AuthMutationExecutor::new(&stores.conversation);
        expect_commit_execution(
            executor
                .execute(LifecycleMutation, CommitFault::None)
                .await
                .expect("initial lifecycle mutation"),
        );
        let classifier_calls = Arc::new(AtomicUsize::new(0));

        assert!(matches!(
            executor
                .execute(
                    ExpectedLifecycleCasMutation::new(
                        TEST_KID,
                        TEST_TRANSITION,
                        Arc::clone(&classifier_calls),
                    ),
                    CommitFault::LeakStatementBeforeWriterClose,
                )
                .await,
            Err(AuthRecordsError::WriterCloseFailed)
        ));
        assert_eq!(classifier_calls.load(AtomicOrdering::SeqCst), 0);
        assert!(executor.operation_poisoned.load(Ordering::Acquire));
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
    }

    #[tokio::test]
    async fn missing_store_path_is_not_recreated_and_poisons_shared_operations() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let executor = AuthMutationExecutor::new(&stores.conversation);
        let path = executor.location.path.clone();
        let preserved = directory.path().join("preserved-conversation.sqlite3");
        stores.close().await.expect("stores close");
        std::fs::rename(&path, &preserved).expect("preserve original database");

        assert!(
            executor
                .execute(LifecycleMutation, CommitFault::None)
                .await
                .is_err()
        );
        assert!(!path.exists());
        assert!(preserved.exists());
        assert!(executor.operation_poisoned.load(Ordering::Acquire));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn replaced_store_identity_is_rejected_before_mutation() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let executor = AuthMutationExecutor::new(&stores.conversation);
        let path = executor.location.path.clone();
        let preserved = directory.path().join("preserved-conversation.sqlite3");
        stores.close().await.expect("stores close");
        std::fs::rename(&path, &preserved).expect("preserve original database");
        std::fs::copy(&preserved, &path).expect("replacement database");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("replacement owner-only mode");

        let result = executor.execute(LifecycleMutation, CommitFault::None).await;

        assert!(matches!(
            result,
            Err(AuthRecordsError::Store(
                StoreError::FilesystemIdentityChanged { .. }
            ))
        ));
        assert!(executor.operation_poisoned.load(Ordering::Acquire));
        assert_eq!(
            std::fs::metadata(&path)
                .expect("replacement metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn fresh_connections_keep_policy_history_and_private_cache_isolation() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let location = Arc::clone(&stores.conversation.location);
        let mut writer = open_existing_store_connection(
            &location,
            StoreKind::Conversation,
            ExistingConnectionAccess::ReadWrite,
        )
        .expect("fresh writer");
        let report = read_report(&writer, StoreKind::Conversation).expect("writer report");
        validate_store_report(&report).expect("writer policy");
        assert_eq!(report.applied_migrations.len(), 6);
        assert_eq!(report.busy_timeout_millis, BUSY_TIMEOUT_MILLIS);

        let transaction = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("writer transaction");
        transaction
            .execute(
                "UPDATE auth_key_lifecycle
                 SET state = 'initializing',
                     state_revision = 1,
                     expected_kid = ?1,
                     transition_kind = 'initialize',
                     transition_id = ?2,
                     keyring_version = 1,
                     updated_at_micros = 1
                 WHERE singleton = 1",
                params![TEST_KID, TEST_TRANSITION.as_slice()],
            )
            .expect("uncommitted mutation");

        let reader = open_existing_store_connection(
            &location,
            StoreKind::Conversation,
            ExistingConnectionAccess::ReadOnly,
        )
        .expect("private-cache reader");
        reader
            .pragma_update(None, "read_uncommitted", "ON")
            .expect("reader dirty-read probe");
        let visible_state: String = reader
            .query_row(
                "SELECT state FROM auth_key_lifecycle WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("reader state");
        assert_eq!(visible_state, "uninitialized");

        close_committed_view(reader).expect("reader closes");
        transaction.rollback().expect("writer rolls back");
        close_after_precommit_error(writer).expect("writer closes");
    }

    #[tokio::test]
    async fn migration_history_failure_poisons_shared_operations() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let executor = AuthMutationExecutor::new(&stores.conversation);
        stores
            .conversation
            .connection
            .call(|connection| {
                connection.execute(
                    "UPDATE _pov_migrations
                     SET migration_sql = '-- synthetic drift'
                     WHERE namespace = 'sqlite/conversation' AND version = 4",
                    [],
                )?;
                Ok::<_, StoreError>(())
            })
            .await
            .expect("synthetic migration drift");

        assert!(
            executor
                .execute(LifecycleMutation, CommitFault::None)
                .await
                .is_err()
        );
        assert!(executor.operation_poisoned.load(Ordering::Acquire));
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
    }

    #[tokio::test]
    async fn ambiguous_committed_view_poisons_shared_operations() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let executor = AuthMutationExecutor::new(&stores.conversation);

        assert!(matches!(
            executor.execute(AmbiguousMutation, CommitFault::None).await,
            Err(AuthRecordsError::AmbiguousCommittedView)
        ));
        assert!(executor.operation_poisoned.load(Ordering::Acquire));
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
    }

    #[tokio::test]
    async fn poisoned_executor_rejects_without_starting_a_mutation() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let executor = AuthMutationExecutor::new(&stores.conversation);
        executor.operation_poisoned.store(true, Ordering::Release);

        assert!(matches!(
            executor.execute(LifecycleMutation, CommitFault::None).await,
            Err(AuthRecordsError::Store(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            }))
        ));

        let mut committed_view = open_existing_store_connection(
            &executor.location,
            StoreKind::Conversation,
            ExistingConnectionAccess::ReadOnly,
        )
        .expect("fresh committed view");
        assert_eq!(
            LifecycleMutation
                .classify(&mut committed_view)
                .expect("classify state"),
            MutationPostcondition::NotCommitted
        );
        close_committed_view(committed_view).expect("committed view closes");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn queued_worker_rechecks_poison_before_mutation() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let executor = AuthMutationExecutor::new(&stores.conversation);
        let task_executor = executor.clone();
        let gate = OperationGate::new();
        let task_gate = gate.clone();
        let task = tokio::spawn(async move {
            task_executor
                .execute(
                    LifecycleMutation,
                    CommitFault::PauseBeforePoisonCheck(task_gate),
                )
                .await
        });

        gate.wait_until_paused();
        executor.operation_poisoned.store(true, Ordering::Release);
        gate.resume();
        gate.wait_until_complete();

        assert!(matches!(
            task.await.expect("executor task joins"),
            Err(AuthRecordsError::Store(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            }))
        ));
        let mut committed_view = open_existing_store_connection(
            &executor.location,
            StoreKind::Conversation,
            ExistingConnectionAccess::ReadOnly,
        )
        .expect("fresh committed view");
        assert_eq!(
            LifecycleMutation
                .classify(&mut committed_view)
                .expect("classify state"),
            MutationPostcondition::NotCommitted
        );
        close_committed_view(committed_view).expect("committed view closes");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn caller_abort_cannot_hide_worker_panic_or_allow_a_retry() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let executor = AuthMutationExecutor::new(&stores.conversation);
        let task_executor = executor.clone();
        let gate = OperationGate::new();
        let task_gate = gate.clone();
        let task = tokio::spawn(async move {
            task_executor
                .execute(
                    LifecycleMutation,
                    CommitFault::PanicBeforeExecute(task_gate),
                )
                .await
        });

        gate.wait_until_paused();
        task.abort();
        gate.resume();
        gate.wait_until_complete();
        let _ = task.await;

        assert!(executor.operation_poisoned.load(Ordering::Acquire));
        assert!(matches!(
            executor.execute(LifecycleMutation, CommitFault::None).await,
            Err(AuthRecordsError::Store(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            }))
        ));
        let mut committed_view = open_existing_store_connection(
            &executor.location,
            StoreKind::Conversation,
            ExistingConnectionAccess::ReadOnly,
        )
        .expect("fresh committed view");
        assert_eq!(
            LifecycleMutation
                .classify(&mut committed_view)
                .expect("classify state"),
            MutationPostcondition::NotCommitted
        );
        close_committed_view(committed_view).expect("committed view closes");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn writer_close_failure_prevents_readback_and_poisons_shared_operations() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let executor = AuthMutationExecutor::new(&stores.conversation);

        assert!(matches!(
            executor
                .execute(
                    LifecycleMutation,
                    CommitFault::LeakStatementBeforeWriterClose,
                )
                .await,
            Err(AuthRecordsError::WriterCloseFailed)
        ));
        assert!(executor.operation_poisoned.load(Ordering::Acquire));
        assert!(matches!(
            stores.conversation.report().await,
            Err(StoreError::OperationPoisoned {
                kind: StoreKind::Conversation
            })
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn caller_drop_does_not_interrupt_writer_quiescence_and_readback() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let executor = AuthMutationExecutor::new(&stores.conversation);
        let task_executor = executor.clone();
        let gate = OperationGate::new();
        let task_gate = gate.clone();
        let task = tokio::spawn(async move {
            task_executor
                .execute(
                    LifecycleMutation,
                    CommitFault::PauseAfterCommitBeforeQuiesce(task_gate),
                )
                .await
        });

        gate.wait_until_paused();
        task.abort();
        gate.resume();
        gate.wait_until_complete();
        let _ = task.await;

        assert!(!executor.operation_poisoned.load(Ordering::Acquire));
        let mut committed_view = open_existing_store_connection(
            &executor.location,
            StoreKind::Conversation,
            ExistingConnectionAccess::ReadOnly,
        )
        .expect("post-abort committed view");
        assert_eq!(
            LifecycleMutation
                .classify(&mut committed_view)
                .expect("classify committed state"),
            MutationPostcondition::Committed
        );
        close_committed_view(committed_view).expect("committed view closes");
    }

    #[test]
    fn store_location_debug_redacts_path_and_identity() {
        let directory = tempdir().expect("temporary store directory");
        let root = crate::storage::prepare_store_root(&directory.path().join("stores"))
            .expect("secure root");
        crate::storage::reserve_owner_only_file(
            &root.join(StoreKind::Conversation.file_name()),
            StoreKind::Conversation,
            "synthetic location",
        )
        .expect("synthetic database");
        let location = crate::storage::capture_store_location(
            &root.join(StoreKind::Conversation.file_name()),
            "synthetic location",
        )
        .expect("store location");
        let debug = format!("{location:?}");

        assert_eq!(
            debug,
            "StoreLocation { path: \"[REDACTED]\", identity: \"[REDACTED]\" }"
        );
        assert!(!debug.contains(root.to_string_lossy().as_ref()));
    }
}
