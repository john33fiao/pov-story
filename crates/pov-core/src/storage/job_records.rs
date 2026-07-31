use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio_rusqlite::{
    Error as ExecutorError,
    rusqlite::{
        self, Connection as RawConnection, OptionalExtension, Row, Transaction,
        TransactionBehavior, params,
    },
};
use uuid::Uuid;

use crate::{
    conversation::{IdempotencyKey, OutboxId},
    identity::{CorrelationId, Revision, VerifiedAuthContext},
    job::{
        ClaimResult, EnqueueFingerprint, EnqueueReceipt, JOB_EVENT_PAGE_SIZE, JobAttemptId,
        JobAttemptSnapshot, JobAttemptState, JobEvent, JobEventCursor, JobEventId, JobEventKind,
        JobEventPage, JobFailureKind, JobId, JobKind, JobLease, JobLeaseToken,
        JobMutationFingerprint, JobOutcome, JobOwnerMutationOperation, JobPriority, JobQueueError,
        JobQueueFault, JobSnapshot, JobState, JobTimestampMicros, JobTransitionReceipt,
        PreparedEnqueue, PreparedJobOwnerMutation, RecoveryResolution, RecoveryTicket,
        SequencedJobEvent, duration_micros,
    },
};

use super::{ConversationStore, SqliteStore};

#[cfg(test)]
use crate::job::{JobEnqueueKey, JobMutationKey};

const ENQUEUE_OPERATION: &str = "enqueue_conversation_job_v1";

struct JobRow {
    job_id: Vec<u8>,
    source_outbox_id: Vec<u8>,
    job_kind: String,
    priority: i64,
    state: String,
    state_revision: i64,
    attempts_started: i64,
    max_attempts: i64,
    enqueued_at_micros: i64,
    ready_at_micros: i64,
    first_started_at_micros: Option<i64>,
    terminal_at_micros: Option<i64>,
    queue_wait_micros: i64,
    execution_micros: i64,
    correlation_id: Vec<u8>,
}

struct AttemptRow {
    attempt_id: Vec<u8>,
    job_id: Vec<u8>,
    attempt_number: i64,
    state: String,
    leased_at_micros: i64,
    started_at_micros: Option<i64>,
    lease_expires_at_micros: i64,
    attempt_deadline_at_micros: i64,
    finished_at_micros: Option<i64>,
    retry_at_micros: Option<i64>,
    queue_wait_micros: Option<i64>,
    execution_micros: Option<i64>,
    failure_kind: Option<String>,
}

struct EventRow {
    event_id: Vec<u8>,
    job_id: Vec<u8>,
    job_revision: i64,
    event_kind: String,
    state: String,
    attempt_id: Option<Vec<u8>>,
    happened_at_micros: i64,
    queue_wait_micros: Option<i64>,
    execution_micros: Option<i64>,
    failure_kind: Option<String>,
    correlation_id: Vec<u8>,
}

struct EnqueueLinkageRow {
    outbox_correlation_id: Vec<u8>,
    event_correlation_id: Vec<u8>,
    attempt_id: Option<Vec<u8>>,
    queue_wait_micros: Option<i64>,
    execution_micros: Option<i64>,
    failure_kind: Option<String>,
}

struct ControlRow {
    status: String,
    lease_generation: i64,
    owner_id: Option<Vec<u8>>,
    job_id: Option<Vec<u8>>,
    attempt_id: Option<Vec<u8>>,
    attempt_number: Option<i64>,
    lease_token: Option<Vec<u8>>,
    lease_expires_at_micros: Option<i64>,
    attempt_deadline_at_micros: Option<i64>,
}

struct ActiveControl {
    status: String,
    generation: u64,
    owner_id: Vec<u8>,
    job_id: JobId,
    attempt_id: JobAttemptId,
    attempt_number: u16,
    token: JobLeaseToken,
    lease_expires_at: JobTimestampMicros,
    attempt_deadline_at: JobTimestampMicros,
}

struct InternalJob {
    snapshot: JobSnapshot,
    cancel_requested: bool,
    attempt_timeout_micros: u64,
    retry_base_micros: u64,
    result_idempotency_key: IdempotencyKey,
}

struct StoredAttemptCapability {
    owner_id: Vec<u8>,
    state: JobAttemptState,
    completion_kind: Option<String>,
    failure_kind: Option<String>,
}

pub(crate) async fn enqueue(
    store: &SqliteStore<ConversationStore>,
    prepared: PreparedEnqueue,
    now: JobTimestampMicros,
    fault: JobQueueFault,
) -> Result<EnqueueReceipt, JobQueueError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_not_poisoned(&poison)?;
            let transaction = begin_immediate(connection)?;
            let result = enqueue_in_transaction(&transaction, &prepared, now, fault);
            let (job_id, replayed) = match result {
                Ok(result) => {
                    commit_or_poison(transaction, &poison)?;
                    ensure_autocommit(connection, &poison)?;
                    result
                }
                Err(error) => {
                    rollback_or_poison(transaction, &poison)?;
                    ensure_autocommit(connection, &poison)?;
                    return Err(error);
                }
            };
            read_enqueue_receipt(connection, &prepared, job_id, replayed)
        })
        .await
        .map_err(map_executor_error)
}

fn enqueue_in_transaction(
    transaction: &Transaction<'_>,
    prepared: &PreparedEnqueue,
    now: JobTimestampMicros,
    fault: JobQueueFault,
) -> Result<(JobId, bool), JobQueueError> {
    let owner_id = prepared.auth.owner_id().as_uuid();
    let existing: Option<(Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT request_fingerprint, job_id
             FROM conversation_job_enqueue_idempotency
             WHERE owner_id = ?1 AND idempotency_key = ?2",
            params![
                owner_id.as_bytes().as_slice(),
                prepared
                    .command
                    .idempotency_key
                    .as_uuid()
                    .as_bytes()
                    .as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(backend)?;
    if let Some((fingerprint, job_id)) = existing {
        if decode_fingerprint(&fingerprint)? != prepared.fingerprint {
            return Err(JobQueueError::IdempotencyConflict);
        }
        return Ok((decode_job_id(&job_id)?, true));
    }

    let duplicate_source: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM conversation_jobs
                WHERE owner_id = ?1
                  AND source_outbox_id = ?2
                  AND job_kind = ?3
            )",
            params![
                owner_id.as_bytes().as_slice(),
                prepared
                    .command
                    .source_outbox_id
                    .as_uuid()
                    .as_bytes()
                    .as_slice(),
                prepared.command.kind.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(backend)?;
    if duplicate_source {
        return Err(JobQueueError::IdempotencyConflict);
    }

    let outbox: Option<(Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT owner_id, correlation_id
             FROM conversation_outbox
             WHERE owner_id = ?1 AND outbox_id = ?2",
            params![
                owner_id.as_bytes().as_slice(),
                prepared
                    .command
                    .source_outbox_id
                    .as_uuid()
                    .as_bytes()
                    .as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(backend)?;
    let Some((stored_owner_id, correlation_id)) = outbox else {
        return Err(JobQueueError::NotFound);
    };
    if stored_owner_id.as_slice() != owner_id.as_bytes() {
        return Err(JobQueueError::CorruptStoredState);
    }
    let correlation_id = decode_correlation_id(&correlation_id)?;

    observe_clock(transaction, now)?;
    let job_id = JobId::new();
    let result_idempotency_key = IdempotencyKey::new();
    let attempt_timeout_micros =
        duration_micros(prepared.attempt_timeout).ok_or(JobQueueError::TimeOverflow)?;
    let retry_base_micros =
        duration_micros(prepared.retry_base).ok_or(JobQueueError::TimeOverflow)?;
    let now_i64 = timestamp_i64(now)?;
    transaction
        .execute(
            "INSERT INTO conversation_jobs(
                owner_id,
                job_id,
                source_outbox_id,
                job_kind,
                priority,
                state,
                state_revision,
                max_attempts,
                attempts_started,
                attempt_timeout_micros,
                retry_base_micros,
                result_idempotency_key,
                cancel_requested,
                enqueued_at_micros,
                ready_at_micros,
                first_started_at_micros,
                terminal_at_micros,
                queue_wait_micros,
                execution_micros,
                correlation_id,
                updated_at_micros
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, 'queued', 1, ?6, 0, ?7, ?8, ?9, 0,
                ?10, ?10, NULL, NULL, 0, 0, ?11, ?10
             )",
            params![
                stored_owner_id,
                job_id.as_uuid().as_bytes().as_slice(),
                prepared
                    .command
                    .source_outbox_id
                    .as_uuid()
                    .as_bytes()
                    .as_slice(),
                prepared.command.kind.as_str(),
                prepared.priority.as_i64(),
                i64::from(prepared.max_attempts),
                micros_i64(attempt_timeout_micros)?,
                micros_i64(retry_base_micros)?,
                result_idempotency_key.as_uuid().as_bytes().as_slice(),
                now_i64,
                correlation_id.as_uuid().as_bytes().as_slice()
            ],
        )
        .map_err(backend)?;

    #[cfg(test)]
    if matches!(fault, JobQueueFault::BeforeEnqueueLedger) {
        return Err(JobQueueError::InjectedFailure);
    }
    let _ = fault;

    transaction
        .execute(
            "INSERT INTO conversation_job_enqueue_idempotency(
                owner_id,
                idempotency_key,
                operation,
                request_fingerprint,
                job_id,
                source_outbox_id,
                job_kind,
                created_at_micros
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                owner_id.as_bytes().as_slice(),
                prepared
                    .command
                    .idempotency_key
                    .as_uuid()
                    .as_bytes()
                    .as_slice(),
                ENQUEUE_OPERATION,
                prepared.fingerprint.as_bytes().as_slice(),
                job_id.as_uuid().as_bytes().as_slice(),
                prepared
                    .command
                    .source_outbox_id
                    .as_uuid()
                    .as_bytes()
                    .as_slice(),
                prepared.command.kind.as_str(),
                now_i64
            ],
        )
        .map_err(backend)?;

    insert_event(
        transaction,
        &stored_owner_id,
        job_id,
        Revision::INITIAL,
        JobEventKind::Enqueued,
        JobState::Queued,
        None,
        now,
        None,
        None,
        None,
        correlation_id,
    )?;
    Ok((job_id, false))
}

fn read_enqueue_receipt(
    connection: &RawConnection,
    prepared: &PreparedEnqueue,
    job_id: JobId,
    replayed: bool,
) -> Result<EnqueueReceipt, JobQueueError> {
    let owner_id = prepared.auth.owner_id().as_uuid();
    let (fingerprint, mapped_job_id, operation, mapped_source, mapped_kind): (
        Vec<u8>,
        Vec<u8>,
        String,
        Vec<u8>,
        String,
    ) = connection
        .query_row(
            "SELECT request_fingerprint, job_id, operation, source_outbox_id, job_kind
             FROM conversation_job_enqueue_idempotency
             WHERE owner_id = ?1 AND idempotency_key = ?2",
            params![
                owner_id.as_bytes().as_slice(),
                prepared
                    .command
                    .idempotency_key
                    .as_uuid()
                    .as_bytes()
                    .as_slice()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(backend)?;
    if decode_fingerprint(&fingerprint)? != prepared.fingerprint
        || decode_job_id(&mapped_job_id)? != job_id
        || operation != ENQUEUE_OPERATION
        || decode_outbox_id(&mapped_source)? != prepared.command.source_outbox_id
        || mapped_kind != prepared.command.kind.as_str()
    {
        return Err(JobQueueError::CorruptStoredState);
    }
    let internal = read_internal_job(connection, owner_id.as_bytes(), job_id)?;
    let job = &internal.snapshot;
    if job.source_outbox_id != prepared.command.source_outbox_id
        || job.kind != prepared.command.kind
        || job.priority != prepared.priority
        || job.max_attempts != prepared.max_attempts
        || internal.attempt_timeout_micros
            != duration_micros(prepared.attempt_timeout).ok_or(JobQueueError::TimeOverflow)?
        || internal.retry_base_micros
            != duration_micros(prepared.retry_base).ok_or(JobQueueError::TimeOverflow)?
    {
        return Err(JobQueueError::CorruptStoredState);
    }
    let linkage: EnqueueLinkageRow = connection
        .query_row(
            "SELECT
                outbox.correlation_id,
                event.correlation_id,
                event.attempt_id,
                event.queue_wait_micros,
                event.execution_micros,
                event.failure_kind
             FROM conversation_outbox AS outbox
             JOIN conversation_job_events AS event
               ON event.owner_id = outbox.owner_id
              AND event.job_id = ?3
              AND event.job_revision = 1
              AND event.event_kind = 'enqueued'
              AND event.state = 'queued'
             WHERE outbox.owner_id = ?1
               AND outbox.outbox_id = ?2",
            params![
                owner_id.as_bytes().as_slice(),
                prepared
                    .command
                    .source_outbox_id
                    .as_uuid()
                    .as_bytes()
                    .as_slice(),
                job_id.as_uuid().as_bytes().as_slice()
            ],
            |row| {
                Ok(EnqueueLinkageRow {
                    outbox_correlation_id: row.get(0)?,
                    event_correlation_id: row.get(1)?,
                    attempt_id: row.get(2)?,
                    queue_wait_micros: row.get(3)?,
                    execution_micros: row.get(4)?,
                    failure_kind: row.get(5)?,
                })
            },
        )
        .map_err(backend)?;
    if decode_correlation_id(&linkage.outbox_correlation_id)? != job.correlation_id
        || decode_correlation_id(&linkage.event_correlation_id)? != job.correlation_id
        || linkage.attempt_id.is_some()
        || linkage.queue_wait_micros.is_some()
        || linkage.execution_micros.is_some()
        || linkage.failure_kind.is_some()
    {
        return Err(JobQueueError::CorruptStoredState);
    }
    Ok(EnqueueReceipt {
        job: internal.snapshot,
        replayed,
    })
}

pub(crate) async fn read_job(
    store: &SqliteStore<ConversationStore>,
    auth: VerifiedAuthContext,
    job_id: JobId,
) -> Result<JobSnapshot, JobQueueError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_not_poisoned(&poison)?;
            read_job_snapshot(connection, auth.owner_id().as_uuid().as_bytes(), job_id)
        })
        .await
        .map_err(map_executor_error)
}

pub(crate) async fn read_job_by_source(
    store: &SqliteStore<ConversationStore>,
    auth: VerifiedAuthContext,
    source_outbox_id: OutboxId,
    kind: JobKind,
) -> Result<JobSnapshot, JobQueueError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_not_poisoned(&poison)?;
            let row = connection
                .query_row(
                    "SELECT
                        job_id,
                        source_outbox_id,
                        job_kind,
                        priority,
                        state,
                        state_revision,
                        attempts_started,
                        max_attempts,
                        enqueued_at_micros,
                        ready_at_micros,
                        first_started_at_micros,
                        terminal_at_micros,
                        queue_wait_micros,
                        execution_micros,
                        correlation_id
                     FROM conversation_jobs
                     WHERE owner_id = ?1
                       AND source_outbox_id = ?2
                       AND job_kind = ?3",
                    params![
                        auth.owner_id().as_uuid().as_bytes().as_slice(),
                        source_outbox_id.as_uuid().as_bytes().as_slice(),
                        kind.as_str()
                    ],
                    decode_job_row,
                )
                .optional()
                .map_err(backend)?
                .ok_or(JobQueueError::NotFound)?;
            job_from_row(row)
        })
        .await
        .map_err(map_executor_error)
}

pub(crate) async fn read_attempts(
    store: &SqliteStore<ConversationStore>,
    auth: VerifiedAuthContext,
    job_id: JobId,
) -> Result<Vec<JobAttemptSnapshot>, JobQueueError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_not_poisoned(&poison)?;
            let owner_id = auth.owner_id().as_uuid();
            ensure_job_exists(connection, owner_id.as_bytes(), job_id)?;
            let mut statement = connection
                .prepare(
                    "SELECT
                        attempt_id,
                        job_id,
                        attempt_number,
                        state,
                        leased_at_micros,
                        started_at_micros,
                        lease_expires_at_micros,
                        attempt_deadline_at_micros,
                        finished_at_micros,
                        retry_at_micros,
                        queue_wait_micros,
                        execution_micros,
                        failure_kind
                     FROM conversation_job_attempts
                     WHERE owner_id = ?1 AND job_id = ?2
                     ORDER BY attempt_number",
                )
                .map_err(backend)?;
            let rows = statement
                .query_map(
                    params![
                        owner_id.as_bytes().as_slice(),
                        job_id.as_uuid().as_bytes().as_slice()
                    ],
                    decode_attempt_row,
                )
                .map_err(backend)?;
            rows.map(|row| row.map_err(backend).and_then(attempt_from_row))
                .collect()
        })
        .await
        .map_err(map_executor_error)
}

pub(crate) async fn read_events(
    store: &SqliteStore<ConversationStore>,
    auth: VerifiedAuthContext,
    job_id: JobId,
) -> Result<Vec<JobEvent>, JobQueueError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_not_poisoned(&poison)?;
            let owner_id = auth.owner_id().as_uuid();
            ensure_job_exists(connection, owner_id.as_bytes(), job_id)?;
            let mut statement = connection
                .prepare(
                    "SELECT
                        event_id,
                        job_id,
                        job_revision,
                        event_kind,
                        state,
                        attempt_id,
                        happened_at_micros,
                        queue_wait_micros,
                        execution_micros,
                        failure_kind,
                        correlation_id
                     FROM conversation_job_events
                     WHERE owner_id = ?1 AND job_id = ?2
                     ORDER BY job_revision",
                )
                .map_err(backend)?;
            let rows = statement
                .query_map(
                    params![
                        owner_id.as_bytes().as_slice(),
                        job_id.as_uuid().as_bytes().as_slice()
                    ],
                    decode_event_row,
                )
                .map_err(backend)?;
            rows.map(|row| row.map_err(backend).and_then(event_from_row))
                .collect()
        })
        .await
        .map_err(map_executor_error)
}

pub(crate) async fn read_event_page(
    store: &SqliteStore<ConversationStore>,
    auth: VerifiedAuthContext,
    after: JobEventCursor,
) -> Result<JobEventPage, JobQueueError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_not_poisoned(&poison)?;
            let owner_id = auth.owner_id().as_uuid();
            let after_i64 = i64::try_from(after.get()).map_err(|_| JobQueueError::InvalidCursor)?;
            if after != JobEventCursor::START {
                let owned: i64 = connection
                    .query_row(
                        "SELECT EXISTS(
                            SELECT 1
                            FROM conversation_job_events
                            WHERE owner_id = ?1 AND event_sequence = ?2
                        )",
                        params![owner_id.as_bytes().as_slice(), after_i64],
                        |row| row.get(0),
                    )
                    .map_err(backend)?;
                if owned != 1 {
                    return Err(JobQueueError::InvalidCursor);
                }
            }
            let mut statement = connection
                .prepare(
                    "SELECT
                        event_sequence,
                        event_id,
                        job_id,
                        job_revision,
                        event_kind,
                        state,
                        attempt_id,
                        happened_at_micros,
                        queue_wait_micros,
                        execution_micros,
                        failure_kind,
                        correlation_id
                     FROM conversation_job_events
                     WHERE owner_id = ?1 AND event_sequence > ?2
                     ORDER BY event_sequence
                     LIMIT ?3",
                )
                .map_err(backend)?;
            let rows = statement
                .query_map(
                    params![
                        owner_id.as_bytes().as_slice(),
                        after_i64,
                        i64::try_from(JOB_EVENT_PAGE_SIZE + 1)
                            .map_err(|_| JobQueueError::CorruptStoredState)?
                    ],
                    |row| Ok((row.get::<_, i64>(0)?, decode_event_row_at(row, 1)?)),
                )
                .map_err(backend)?;
            let mut events = rows
                .map(|row| {
                    let (sequence, event) = row.map_err(backend)?;
                    let cursor = u64::try_from(sequence)
                        .ok()
                        .and_then(JobEventCursor::new)
                        .ok_or(JobQueueError::CorruptStoredState)?;
                    Ok(SequencedJobEvent {
                        cursor,
                        event: event_from_row(event)?,
                    })
                })
                .collect::<Result<Vec<_>, JobQueueError>>()?;
            let has_more = events.len() > JOB_EVENT_PAGE_SIZE;
            if has_more {
                events.pop();
            }
            let next_cursor = events.last().map_or(after, SequencedJobEvent::cursor);
            Ok(JobEventPage {
                events,
                next_cursor,
                has_more,
            })
        })
        .await
        .map_err(map_executor_error)
}

pub(crate) async fn claim_next(
    store: &SqliteStore<ConversationStore>,
    now: JobTimestampMicros,
    fault: JobQueueFault,
) -> Result<ClaimResult, JobQueueError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_not_poisoned(&poison)?;
            let transaction = begin_immediate(connection)?;
            let result = claim_in_transaction(&transaction, now);
            let claimed = match result {
                Ok(result) => {
                    commit_or_poison(transaction, &poison)?;
                    ensure_autocommit(connection, &poison)?;
                    result
                }
                Err(error) => {
                    rollback_or_poison(transaction, &poison)?;
                    ensure_autocommit(connection, &poison)?;
                    return Err(error);
                }
            };

            #[cfg(test)]
            if matches!(fault, JobQueueFault::AfterClaimCommitBeforeReadback)
                && matches!(claimed, ClaimResult::Leased(_))
            {
                return Err(JobQueueError::InjectedFailure);
            }
            let _ = fault;

            match claimed {
                ClaimResult::Leased(lease) => {
                    Ok(ClaimResult::Leased(read_active_lease(connection, &lease)?))
                }
                ClaimResult::RecoveryRequired(ticket) => Ok(ClaimResult::RecoveryRequired(
                    read_recovery_ticket(connection, &ticket)?,
                )),
                ClaimResult::Idle => Ok(ClaimResult::Idle),
            }
        })
        .await
        .map_err(map_executor_error)
}

fn claim_in_transaction(
    transaction: &Transaction<'_>,
    now: JobTimestampMicros,
) -> Result<ClaimResult, JobQueueError> {
    observe_clock(transaction, now)?;
    let control = read_control(transaction)?;
    if control.status == "recovery_required" {
        return Ok(ClaimResult::RecoveryRequired(recovery_ticket_from_control(
            &control,
        )?));
    }
    if control.status == "leased" {
        let active = active_control_from_row(&control)?;
        if now < active.lease_expires_at {
            return Ok(ClaimResult::Idle);
        }
        let attempt_state = read_attempt_state(
            transaction,
            &active.owner_id,
            active.job_id,
            active.attempt_id,
        )?;
        match attempt_state {
            JobAttemptState::Leased => {
                expire_unstarted_attempt(transaction, &active, now)?;
            }
            JobAttemptState::Running | JobAttemptState::CancelRequested => {
                return mark_recovery_required(transaction, &active, attempt_state, now);
            }
            JobAttemptState::RecoveryRequired => {
                return Ok(ClaimResult::RecoveryRequired(RecoveryTicket {
                    job_id: active.job_id,
                    attempt_id: active.attempt_id,
                    attempt_number: active.attempt_number,
                    generation: active.generation,
                    token: active.token,
                }));
            }
            _ => return Err(JobQueueError::CorruptStoredState),
        }
    } else if control.status != "idle" {
        return Err(JobQueueError::CorruptStoredState);
    }

    let candidate: Option<(Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT owner_id, job_id
             FROM conversation_jobs
             WHERE state IN ('queued', 'retry_scheduled')
               AND ready_at_micros <= ?1
             ORDER BY priority DESC, enqueue_sequence ASC
             LIMIT 1",
            params![timestamp_i64(now)?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(backend)?;
    let Some((owner_id, job_id)) = candidate else {
        return Ok(ClaimResult::Idle);
    };
    let job_id = decode_job_id(&job_id)?;
    let job = read_internal_job(transaction, &owner_id, job_id)?;
    if !matches!(
        job.snapshot.state,
        JobState::Queued | JobState::RetryScheduled
    ) || job.snapshot.ready_at > now
        || job.cancel_requested
    {
        return Err(JobQueueError::CorruptStoredState);
    }
    let attempt_number = job
        .snapshot
        .attempts_started
        .checked_add(1)
        .ok_or(JobQueueError::CorruptStoredState)?;
    if attempt_number > job.snapshot.max_attempts {
        return Err(JobQueueError::CorruptStoredState);
    }
    let attempt_id = JobAttemptId::new();
    let token = JobLeaseToken::new();
    let generation = u64::try_from(control.lease_generation)
        .ok()
        .and_then(|value| value.checked_add(1))
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(JobQueueError::TimeOverflow)?;
    let attempt_deadline_at = now
        .checked_add(Duration::from_micros(job.attempt_timeout_micros))
        .ok_or(JobQueueError::TimeOverflow)?;
    let lease_expires_at = now
        .checked_add(job.snapshot.kind.lease_duration())
        .ok_or(JobQueueError::TimeOverflow)?
        .min(attempt_deadline_at);
    if lease_expires_at <= now {
        return Err(JobQueueError::TimeOverflow);
    }
    let next_revision = job
        .snapshot
        .revision
        .checked_next()
        .ok_or(JobQueueError::CorruptStoredState)?;

    transaction
        .execute(
            "INSERT INTO conversation_job_attempts(
                owner_id,
                job_id,
                attempt_id,
                attempt_number,
                lease_generation,
                lease_token,
                state,
                completion_kind,
                leased_at_micros,
                started_at_micros,
                lease_expires_at_micros,
                attempt_deadline_at_micros,
                finished_at_micros,
                retry_at_micros,
                queue_wait_micros,
                execution_micros,
                failure_kind
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, 'leased', NULL, ?7, NULL, ?8, ?9,
                NULL, NULL, NULL, NULL, NULL
             )",
            params![
                owner_id,
                job_id.as_uuid().as_bytes().as_slice(),
                attempt_id.as_uuid().as_bytes().as_slice(),
                i64::from(attempt_number),
                micros_i64(generation)?,
                token.as_uuid().as_bytes().as_slice(),
                timestamp_i64(now)?,
                timestamp_i64(lease_expires_at)?,
                timestamp_i64(attempt_deadline_at)?
            ],
        )
        .map_err(backend)?;
    let updated = transaction
        .execute(
            "UPDATE conversation_jobs
             SET state = 'leased',
                 state_revision = ?3,
                 attempts_started = ?4,
                 updated_at_micros = ?5
             WHERE owner_id = ?1
               AND job_id = ?2
               AND state_revision = ?6
               AND state IN ('queued', 'retry_scheduled')
               AND cancel_requested = 0",
            params![
                owner_id,
                job_id.as_uuid().as_bytes().as_slice(),
                revision_i64(next_revision)?,
                i64::from(attempt_number),
                timestamp_i64(now)?,
                revision_i64(job.snapshot.revision)?
            ],
        )
        .map_err(backend)?;
    if updated != 1 {
        return Err(JobQueueError::CorruptStoredState);
    }
    set_control_active(
        transaction,
        &ActiveControl {
            status: "leased".to_owned(),
            generation,
            owner_id: owner_id.clone(),
            job_id,
            attempt_id,
            attempt_number,
            token,
            lease_expires_at,
            attempt_deadline_at,
        },
    )?;
    insert_event(
        transaction,
        &owner_id,
        job_id,
        next_revision,
        JobEventKind::Leased,
        JobState::Leased,
        Some(attempt_id),
        now,
        None,
        None,
        None,
        job.snapshot.correlation_id,
    )?;

    Ok(ClaimResult::Leased(JobLease {
        job_id,
        attempt_id,
        attempt_number,
        source_outbox_id: job.snapshot.source_outbox_id,
        kind: job.snapshot.kind,
        result_idempotency_key: job.result_idempotency_key,
        generation,
        token,
        state: JobAttemptState::Leased,
        lease_expires_at,
        attempt_deadline_at,
    }))
}

fn expire_unstarted_attempt(
    transaction: &Transaction<'_>,
    active: &ActiveControl,
    now: JobTimestampMicros,
) -> Result<(), JobQueueError> {
    let job = read_internal_job(transaction, &active.owner_id, active.job_id)?;
    if job.snapshot.state != JobState::Leased {
        return Err(JobQueueError::CorruptStoredState);
    }
    let can_retry = job.snapshot.attempts_started < job.snapshot.max_attempts;
    let retry_at = if can_retry {
        Some(retry_at(&job, active.attempt_number, now)?)
    } else {
        None
    };
    let next_state = if can_retry {
        JobState::RetryScheduled
    } else {
        JobState::Failed
    };
    let next_revision = job
        .snapshot
        .revision
        .checked_next()
        .ok_or(JobQueueError::CorruptStoredState)?;

    let updated_attempt = transaction
        .execute(
            "UPDATE conversation_job_attempts
             SET state = 'lease_expired',
                 completion_kind = 'lease_expired_unstarted',
                 finished_at_micros = ?5,
                 retry_at_micros = ?6,
                 failure_kind = 'lease_expired'
             WHERE owner_id = ?1
               AND job_id = ?2
               AND attempt_id = ?3
               AND lease_token = ?4
               AND state = 'leased'",
            params![
                active.owner_id,
                active.job_id.as_uuid().as_bytes().as_slice(),
                active.attempt_id.as_uuid().as_bytes().as_slice(),
                active.token.as_uuid().as_bytes().as_slice(),
                timestamp_i64(now)?,
                retry_at.map(timestamp_i64).transpose()?
            ],
        )
        .map_err(backend)?;
    if updated_attempt != 1 {
        return Err(JobQueueError::CorruptStoredState);
    }
    let updated_job = transaction
        .execute(
            "UPDATE conversation_jobs
             SET state = ?3,
                 state_revision = ?4,
                 ready_at_micros = COALESCE(?5, ready_at_micros),
                 terminal_at_micros = CASE WHEN ?3 = 'failed' THEN ?6 ELSE NULL END,
                 updated_at_micros = ?6
             WHERE owner_id = ?1
               AND job_id = ?2
               AND state = 'leased'
               AND state_revision = ?7",
            params![
                active.owner_id,
                active.job_id.as_uuid().as_bytes().as_slice(),
                next_state.as_str(),
                revision_i64(next_revision)?,
                retry_at.map(timestamp_i64).transpose()?,
                timestamp_i64(now)?,
                revision_i64(job.snapshot.revision)?
            ],
        )
        .map_err(backend)?;
    if updated_job != 1 {
        return Err(JobQueueError::CorruptStoredState);
    }
    clear_control(transaction, active.generation)?;
    insert_event(
        transaction,
        &active.owner_id,
        active.job_id,
        next_revision,
        JobEventKind::LeaseExpired,
        next_state,
        Some(active.attempt_id),
        now,
        None,
        None,
        Some(JobFailureKind::LeaseExpired),
        job.snapshot.correlation_id,
    )
}

fn mark_recovery_required(
    transaction: &Transaction<'_>,
    active: &ActiveControl,
    attempt_state: JobAttemptState,
    now: JobTimestampMicros,
) -> Result<ClaimResult, JobQueueError> {
    let job = read_internal_job(transaction, &active.owner_id, active.job_id)?;
    let expected_job_state = match attempt_state {
        JobAttemptState::Running => JobState::Running,
        JobAttemptState::CancelRequested => JobState::CancelRequested,
        _ => return Err(JobQueueError::CorruptStoredState),
    };
    if job.snapshot.state != expected_job_state {
        return Err(JobQueueError::CorruptStoredState);
    }
    let attempt = read_attempt_snapshot(
        transaction,
        &active.owner_id,
        active.job_id,
        active.attempt_id,
    )?;
    let started_at = attempt
        .started_at
        .ok_or(JobQueueError::CorruptStoredState)?;
    let bounded_execution = active
        .lease_expires_at
        .checked_duration_since(started_at)
        .ok_or(JobQueueError::CorruptStoredState)?;
    let next_revision = job
        .snapshot
        .revision
        .checked_next()
        .ok_or(JobQueueError::CorruptStoredState)?;

    let updated_attempt = transaction
        .execute(
            "UPDATE conversation_job_attempts
             SET state = 'recovery_required',
                 execution_micros = ?5,
                 failure_kind = 'cleanup_uncertain'
             WHERE owner_id = ?1
               AND job_id = ?2
               AND attempt_id = ?3
               AND lease_token = ?4
               AND state = ?6",
            params![
                active.owner_id,
                active.job_id.as_uuid().as_bytes().as_slice(),
                active.attempt_id.as_uuid().as_bytes().as_slice(),
                active.token.as_uuid().as_bytes().as_slice(),
                micros_i64(bounded_execution)?,
                attempt_state.as_str()
            ],
        )
        .map_err(backend)?;
    if updated_attempt != 1 {
        return Err(JobQueueError::CorruptStoredState);
    }
    let updated_job = transaction
        .execute(
            "UPDATE conversation_jobs
             SET state = 'recovery_required',
                 state_revision = ?3,
                 execution_micros = execution_micros + ?7,
                 updated_at_micros = ?4
             WHERE owner_id = ?1
               AND job_id = ?2
               AND state = ?5
               AND state_revision = ?6",
            params![
                active.owner_id,
                active.job_id.as_uuid().as_bytes().as_slice(),
                revision_i64(next_revision)?,
                timestamp_i64(now)?,
                expected_job_state.as_str(),
                revision_i64(job.snapshot.revision)?,
                micros_i64(bounded_execution)?
            ],
        )
        .map_err(backend)?;
    if updated_job != 1 {
        return Err(JobQueueError::CorruptStoredState);
    }
    set_control_status(transaction, "recovery_required", active.generation)?;
    insert_event(
        transaction,
        &active.owner_id,
        active.job_id,
        next_revision,
        JobEventKind::RecoveryRequired,
        JobState::RecoveryRequired,
        Some(active.attempt_id),
        now,
        None,
        Some(bounded_execution),
        Some(JobFailureKind::CleanupUncertain),
        job.snapshot.correlation_id,
    )?;
    Ok(ClaimResult::RecoveryRequired(RecoveryTicket {
        job_id: active.job_id,
        attempt_id: active.attempt_id,
        attempt_number: active.attempt_number,
        generation: active.generation,
        token: active.token,
    }))
}

pub(crate) async fn mark_running(
    store: &SqliteStore<ConversationStore>,
    lease: JobLease,
    now: JobTimestampMicros,
) -> Result<JobLease, JobQueueError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_not_poisoned(&poison)?;
            let transaction = begin_immediate(connection)?;
            let result = mark_running_in_transaction(&transaction, &lease, now);
            match result {
                Ok(()) => {
                    commit_or_poison(transaction, &poison)?;
                    ensure_autocommit(connection, &poison)?;
                }
                Err(error) => {
                    rollback_or_poison(transaction, &poison)?;
                    ensure_autocommit(connection, &poison)?;
                    return Err(error);
                }
            }
            read_active_lease(connection, &lease)
        })
        .await
        .map_err(map_executor_error)
}

fn mark_running_in_transaction(
    transaction: &Transaction<'_>,
    lease: &JobLease,
    now: JobTimestampMicros,
) -> Result<(), JobQueueError> {
    observe_clock(transaction, now)?;
    let active = validate_active_lease(transaction, lease, now)?;
    let attempt_state = read_attempt_state(
        transaction,
        &active.owner_id,
        active.job_id,
        active.attempt_id,
    )?;
    if attempt_state == JobAttemptState::Running {
        return Ok(());
    }
    if attempt_state != JobAttemptState::Leased {
        return Err(JobQueueError::InvalidTransition);
    }
    let job = read_internal_job(transaction, &active.owner_id, active.job_id)?;
    if job.snapshot.state != JobState::Leased {
        return Err(JobQueueError::CorruptStoredState);
    }
    let queue_wait = now
        .checked_duration_since(job.snapshot.ready_at)
        .ok_or(JobQueueError::ClockRegression)?;
    let next_revision = job
        .snapshot
        .revision
        .checked_next()
        .ok_or(JobQueueError::CorruptStoredState)?;
    let updated_attempt = transaction
        .execute(
            "UPDATE conversation_job_attempts
             SET state = 'running',
                 started_at_micros = ?5,
                 queue_wait_micros = ?6
             WHERE owner_id = ?1
               AND job_id = ?2
               AND attempt_id = ?3
               AND lease_token = ?4
               AND state = 'leased'",
            params![
                active.owner_id,
                active.job_id.as_uuid().as_bytes().as_slice(),
                active.attempt_id.as_uuid().as_bytes().as_slice(),
                active.token.as_uuid().as_bytes().as_slice(),
                timestamp_i64(now)?,
                micros_i64(queue_wait)?
            ],
        )
        .map_err(backend)?;
    if updated_attempt != 1 {
        return Err(JobQueueError::CorruptStoredState);
    }
    let updated_job = transaction
        .execute(
            "UPDATE conversation_jobs
             SET state = 'running',
                 state_revision = ?3,
                 first_started_at_micros = COALESCE(first_started_at_micros, ?4),
                 queue_wait_micros = queue_wait_micros + ?5,
                 updated_at_micros = ?4
             WHERE owner_id = ?1
               AND job_id = ?2
               AND state = 'leased'
               AND state_revision = ?6",
            params![
                active.owner_id,
                active.job_id.as_uuid().as_bytes().as_slice(),
                revision_i64(next_revision)?,
                timestamp_i64(now)?,
                micros_i64(queue_wait)?,
                revision_i64(job.snapshot.revision)?
            ],
        )
        .map_err(backend)?;
    if updated_job != 1 {
        return Err(JobQueueError::CorruptStoredState);
    }
    insert_event(
        transaction,
        &active.owner_id,
        active.job_id,
        next_revision,
        JobEventKind::Started,
        JobState::Running,
        Some(active.attempt_id),
        now,
        Some(queue_wait),
        None,
        None,
        job.snapshot.correlation_id,
    )
}

pub(crate) async fn renew(
    store: &SqliteStore<ConversationStore>,
    lease: JobLease,
    now: JobTimestampMicros,
) -> Result<JobLease, JobQueueError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_not_poisoned(&poison)?;
            let transaction = begin_immediate(connection)?;
            let result = renew_in_transaction(&transaction, &lease, now);
            match result {
                Ok(()) => {
                    commit_or_poison(transaction, &poison)?;
                    ensure_autocommit(connection, &poison)?;
                }
                Err(error) => {
                    rollback_or_poison(transaction, &poison)?;
                    ensure_autocommit(connection, &poison)?;
                    return Err(error);
                }
            }
            read_active_lease(connection, &lease)
        })
        .await
        .map_err(map_executor_error)
}

fn renew_in_transaction(
    transaction: &Transaction<'_>,
    lease: &JobLease,
    now: JobTimestampMicros,
) -> Result<(), JobQueueError> {
    observe_clock(transaction, now)?;
    let active = validate_active_lease(transaction, lease, now)?;
    let attempt_state = read_attempt_state(
        transaction,
        &active.owner_id,
        active.job_id,
        active.attempt_id,
    )?;
    if !matches!(
        attempt_state,
        JobAttemptState::Leased | JobAttemptState::Running | JobAttemptState::CancelRequested
    ) {
        return Err(JobQueueError::InvalidTransition);
    }
    let job = read_internal_job(transaction, &active.owner_id, active.job_id)?;
    let requested = now
        .checked_add(job.snapshot.kind.lease_duration())
        .ok_or(JobQueueError::TimeOverflow)?
        .min(active.attempt_deadline_at);
    if requested <= now {
        return Err(JobQueueError::LeaseExpired);
    }
    if requested <= active.lease_expires_at {
        return Ok(());
    }
    let updated_attempt = transaction
        .execute(
            "UPDATE conversation_job_attempts
             SET lease_expires_at_micros = ?5
             WHERE owner_id = ?1
               AND job_id = ?2
               AND attempt_id = ?3
               AND lease_token = ?4
               AND state IN ('leased', 'running', 'cancel_requested')
               AND lease_expires_at_micros = ?6",
            params![
                active.owner_id,
                active.job_id.as_uuid().as_bytes().as_slice(),
                active.attempt_id.as_uuid().as_bytes().as_slice(),
                active.token.as_uuid().as_bytes().as_slice(),
                timestamp_i64(requested)?,
                timestamp_i64(active.lease_expires_at)?
            ],
        )
        .map_err(backend)?;
    if updated_attempt != 1 {
        return Err(JobQueueError::StaleLease);
    }
    let updated_control = transaction
        .execute(
            "UPDATE conversation_job_queue_control
             SET lease_expires_at_micros = ?2
             WHERE control_id = 1
               AND status = 'leased'
               AND lease_generation = ?1
               AND lease_token = ?3
               AND lease_expires_at_micros = ?4",
            params![
                micros_i64(active.generation)?,
                timestamp_i64(requested)?,
                active.token.as_uuid().as_bytes().as_slice(),
                timestamp_i64(active.lease_expires_at)?
            ],
        )
        .map_err(backend)?;
    if updated_control != 1 {
        return Err(JobQueueError::StaleLease);
    }
    Ok(())
}

struct FinishResult {
    owner_id: Vec<u8>,
    job_id: JobId,
    replayed: bool,
}

struct OwnerMutationResult {
    owner_id: Vec<u8>,
    job_id: JobId,
    result_revision: Revision,
    replayed: bool,
}

pub(crate) async fn finish(
    store: &SqliteStore<ConversationStore>,
    lease: JobLease,
    outcome: JobOutcome,
    now: JobTimestampMicros,
) -> Result<JobTransitionReceipt, JobQueueError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_not_poisoned(&poison)?;
            let transaction = begin_immediate(connection)?;
            let result = finish_in_transaction(&transaction, &lease, outcome, now);
            let result = match result {
                Ok(result) => {
                    commit_or_poison(transaction, &poison)?;
                    ensure_autocommit(connection, &poison)?;
                    result
                }
                Err(error) => {
                    rollback_or_poison(transaction, &poison)?;
                    ensure_autocommit(connection, &poison)?;
                    return Err(error);
                }
            };
            let job = read_job_snapshot(connection, &result.owner_id, result.job_id)?;
            Ok(JobTransitionReceipt {
                job,
                replayed: result.replayed,
            })
        })
        .await
        .map_err(map_executor_error)
}

fn finish_in_transaction(
    transaction: &Transaction<'_>,
    lease: &JobLease,
    outcome: JobOutcome,
    now: JobTimestampMicros,
) -> Result<FinishResult, JobQueueError> {
    let stored_attempt = find_attempt_by_capability(transaction, lease)?;
    if let Some(stored) = stored_attempt {
        if is_terminal_attempt_state(stored.state) {
            let (requested_completion, requested_failure) = completion_signature(outcome);
            if stored.completion_kind.as_deref() == Some(requested_completion)
                && decode_optional_failure(stored.failure_kind.as_deref())? == requested_failure
            {
                return Ok(FinishResult {
                    owner_id: stored.owner_id,
                    job_id: lease.job_id,
                    replayed: true,
                });
            }
            return Err(JobQueueError::StaleLease);
        }
    } else {
        return Err(JobQueueError::StaleLease);
    }

    observe_clock(transaction, now)?;
    let active = validate_active_lease(transaction, lease, now)?;
    let attempt = read_attempt_snapshot(
        transaction,
        &active.owner_id,
        active.job_id,
        active.attempt_id,
    )?;
    if !matches!(
        attempt.state,
        JobAttemptState::Running | JobAttemptState::CancelRequested
    ) {
        return Err(JobQueueError::InvalidTransition);
    }
    let job = read_internal_job(transaction, &active.owner_id, active.job_id)?;
    if !matches!(
        job.snapshot.state,
        JobState::Running | JobState::CancelRequested
    ) {
        return Err(JobQueueError::CorruptStoredState);
    }
    if outcome == JobOutcome::WaitingConfirmation
        && job.snapshot.attempts_started >= job.snapshot.max_attempts
    {
        return Err(JobQueueError::InvalidTransition);
    }
    let cancel_requested =
        attempt.state == JobAttemptState::CancelRequested || job.cancel_requested;
    if cancel_requested && outcome != JobOutcome::Cancelled {
        return Err(JobQueueError::InvalidTransition);
    }
    if outcome == JobOutcome::Cancelled && !cancel_requested {
        return Err(JobQueueError::InvalidTransition);
    }
    let started_at = attempt
        .started_at
        .ok_or(JobQueueError::CorruptStoredState)?;
    let execution = now
        .checked_duration_since(started_at)
        .ok_or(JobQueueError::ClockRegression)?;
    let (completion_kind, requested_failure) = completion_signature(outcome);
    let next_revision = job
        .snapshot
        .revision
        .checked_next()
        .ok_or(JobQueueError::CorruptStoredState)?;

    let (attempt_state, job_state, event_kind, retry_at, stored_failure, terminal_at) =
        match outcome {
            JobOutcome::Succeeded => (
                JobAttemptState::Succeeded,
                JobState::Succeeded,
                JobEventKind::Succeeded,
                None,
                None,
                Some(now),
            ),
            JobOutcome::PermanentFailure(failure) => (
                JobAttemptState::Failed,
                JobState::Failed,
                JobEventKind::Failed,
                None,
                Some(failure),
                Some(now),
            ),
            JobOutcome::RetryableFailure(failure) => {
                if job.snapshot.attempts_started < job.snapshot.max_attempts {
                    (
                        JobAttemptState::RetryScheduled,
                        JobState::RetryScheduled,
                        JobEventKind::RetryScheduled,
                        Some(retry_at(&job, active.attempt_number, now)?),
                        Some(failure),
                        None,
                    )
                } else {
                    (
                        JobAttemptState::Failed,
                        JobState::Failed,
                        JobEventKind::Failed,
                        None,
                        Some(failure),
                        Some(now),
                    )
                }
            }
            JobOutcome::WaitingConfirmation => (
                JobAttemptState::WaitingConfirmation,
                JobState::WaitingConfirmation,
                JobEventKind::WaitingConfirmation,
                None,
                None,
                None,
            ),
            JobOutcome::Cancelled => (
                JobAttemptState::Cancelled,
                JobState::Cancelled,
                JobEventKind::Cancelled,
                None,
                None,
                Some(now),
            ),
        };
    if requested_failure != stored_failure {
        return Err(JobQueueError::CorruptStoredState);
    }

    let updated_attempt = transaction
        .execute(
            "UPDATE conversation_job_attempts
             SET state = ?5,
                 completion_kind = ?6,
                 finished_at_micros = ?7,
                 retry_at_micros = ?8,
                 execution_micros = ?9,
                 failure_kind = ?10
             WHERE owner_id = ?1
               AND job_id = ?2
               AND attempt_id = ?3
               AND lease_token = ?4
               AND state IN ('running', 'cancel_requested')",
            params![
                active.owner_id,
                active.job_id.as_uuid().as_bytes().as_slice(),
                active.attempt_id.as_uuid().as_bytes().as_slice(),
                active.token.as_uuid().as_bytes().as_slice(),
                attempt_state.as_str(),
                completion_kind,
                timestamp_i64(now)?,
                retry_at.map(timestamp_i64).transpose()?,
                micros_i64(execution)?,
                stored_failure.map(JobFailureKind::as_str)
            ],
        )
        .map_err(backend)?;
    if updated_attempt != 1 {
        return Err(JobQueueError::StaleLease);
    }
    let updated_job = transaction
        .execute(
            "UPDATE conversation_jobs
             SET state = ?3,
                 state_revision = ?4,
                 ready_at_micros = COALESCE(?5, ready_at_micros),
                 terminal_at_micros = ?6,
                 execution_micros = execution_micros + ?7,
                 updated_at_micros = ?8
             WHERE owner_id = ?1
               AND job_id = ?2
               AND state IN ('running', 'cancel_requested')
               AND state_revision = ?9",
            params![
                active.owner_id,
                active.job_id.as_uuid().as_bytes().as_slice(),
                job_state.as_str(),
                revision_i64(next_revision)?,
                retry_at.map(timestamp_i64).transpose()?,
                terminal_at.map(timestamp_i64).transpose()?,
                micros_i64(execution)?,
                timestamp_i64(now)?,
                revision_i64(job.snapshot.revision)?
            ],
        )
        .map_err(backend)?;
    if updated_job != 1 {
        return Err(JobQueueError::CorruptStoredState);
    }
    clear_control(transaction, active.generation)?;
    insert_event(
        transaction,
        &active.owner_id,
        active.job_id,
        next_revision,
        event_kind,
        job_state,
        Some(active.attempt_id),
        now,
        None,
        Some(execution),
        stored_failure,
        job.snapshot.correlation_id,
    )?;
    Ok(FinishResult {
        owner_id: active.owner_id,
        job_id: active.job_id,
        replayed: false,
    })
}

pub(crate) async fn request_cancel(
    store: &SqliteStore<ConversationStore>,
    prepared: PreparedJobOwnerMutation,
    now: JobTimestampMicros,
) -> Result<JobTransitionReceipt, JobQueueError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_not_poisoned(&poison)?;
            let transaction = begin_immediate(connection)?;
            let result = request_cancel_in_transaction(&transaction, &prepared, now);
            let result = match result {
                Ok(result) => {
                    commit_or_poison(transaction, &poison)?;
                    ensure_autocommit(connection, &poison)?;
                    result
                }
                Err(error) => {
                    rollback_or_poison(transaction, &poison)?;
                    ensure_autocommit(connection, &poison)?;
                    return Err(error);
                }
            };
            read_owner_mutation_receipt(connection, &prepared, result)
        })
        .await
        .map_err(map_executor_error)
}

fn request_cancel_in_transaction(
    transaction: &Transaction<'_>,
    prepared: &PreparedJobOwnerMutation,
    now: JobTimestampMicros,
) -> Result<OwnerMutationResult, JobQueueError> {
    if prepared.operation != JobOwnerMutationOperation::Cancel {
        return Err(JobQueueError::CorruptStoredState);
    }
    if let Some(replayed) = find_owner_mutation_replay(transaction, prepared)? {
        return Ok(replayed);
    }
    let owner_uuid = prepared.auth.owner_id().as_uuid();
    let owner_id = owner_uuid.as_bytes();
    let job_id = prepared.job_id;
    let job = read_internal_job(transaction, owner_id, job_id)?;
    if job.snapshot.revision != prepared.expected_revision {
        return Err(JobQueueError::RevisionConflict);
    }
    if job.cancel_requested
        || matches!(
            job.snapshot.state,
            JobState::CancelRequested
                | JobState::Cancelled
                | JobState::Succeeded
                | JobState::Failed
        )
    {
        return Err(JobQueueError::InvalidTransition);
    }
    observe_clock(transaction, now)?;
    let next_revision = job
        .snapshot
        .revision
        .checked_next()
        .ok_or(JobQueueError::CorruptStoredState)?;
    let mut attempt_id = None;
    let (next_state, terminal_at) = match job.snapshot.state {
        JobState::Queued | JobState::RetryScheduled | JobState::WaitingConfirmation => {
            (JobState::Cancelled, Some(now))
        }
        JobState::Leased => {
            let control = active_control_from_row(&read_control(transaction)?)?;
            if control.job_id != job_id || control.owner_id != owner_id {
                return Err(JobQueueError::CorruptStoredState);
            }
            let updated = transaction
                .execute(
                    "UPDATE conversation_job_attempts
                     SET state = 'cancelled',
                         completion_kind = 'owner_cancel_before_start',
                         finished_at_micros = ?5
                     WHERE owner_id = ?1
                       AND job_id = ?2
                       AND attempt_id = ?3
                       AND lease_token = ?4
                       AND state = 'leased'",
                    params![
                        owner_id,
                        job_id.as_uuid().as_bytes().as_slice(),
                        control.attempt_id.as_uuid().as_bytes().as_slice(),
                        control.token.as_uuid().as_bytes().as_slice(),
                        timestamp_i64(now)?
                    ],
                )
                .map_err(backend)?;
            if updated != 1 {
                return Err(JobQueueError::CorruptStoredState);
            }
            attempt_id = Some(control.attempt_id);
            clear_control(transaction, control.generation)?;
            (JobState::Cancelled, Some(now))
        }
        JobState::Running => {
            let control = active_control_from_row(&read_control(transaction)?)?;
            if control.job_id != job_id || control.owner_id != owner_id {
                return Err(JobQueueError::CorruptStoredState);
            }
            let updated = transaction
                .execute(
                    "UPDATE conversation_job_attempts
                     SET state = 'cancel_requested'
                     WHERE owner_id = ?1
                       AND job_id = ?2
                       AND attempt_id = ?3
                       AND lease_token = ?4
                       AND state = 'running'",
                    params![
                        owner_id,
                        job_id.as_uuid().as_bytes().as_slice(),
                        control.attempt_id.as_uuid().as_bytes().as_slice(),
                        control.token.as_uuid().as_bytes().as_slice()
                    ],
                )
                .map_err(backend)?;
            if updated != 1 {
                return Err(JobQueueError::CorruptStoredState);
            }
            attempt_id = Some(control.attempt_id);
            (JobState::CancelRequested, None)
        }
        JobState::RecoveryRequired => {
            let control = active_control_from_row(&read_control(transaction)?)?;
            if control.status != "recovery_required"
                || control.job_id != job_id
                || control.owner_id != owner_id
            {
                return Err(JobQueueError::CorruptStoredState);
            }
            attempt_id = Some(control.attempt_id);
            (JobState::RecoveryRequired, None)
        }
        JobState::CancelRequested | JobState::Cancelled => unreachable!(),
        JobState::Succeeded | JobState::Failed => unreachable!(),
    };
    let updated_job = transaction
        .execute(
            "UPDATE conversation_jobs
             SET state = ?3,
                 state_revision = ?4,
                 cancel_requested = 1,
                 terminal_at_micros = ?5,
                 updated_at_micros = ?6
             WHERE owner_id = ?1
               AND job_id = ?2
               AND state_revision = ?7",
            params![
                owner_id,
                job_id.as_uuid().as_bytes().as_slice(),
                next_state.as_str(),
                revision_i64(next_revision)?,
                terminal_at.map(timestamp_i64).transpose()?,
                timestamp_i64(now)?,
                revision_i64(job.snapshot.revision)?
            ],
        )
        .map_err(backend)?;
    if updated_job != 1 {
        return Err(JobQueueError::CorruptStoredState);
    }
    let event_kind = if next_state == JobState::Cancelled {
        JobEventKind::Cancelled
    } else {
        JobEventKind::CancelRequested
    };
    insert_event(
        transaction,
        owner_id,
        job_id,
        next_revision,
        event_kind,
        next_state,
        attempt_id,
        now,
        None,
        None,
        None,
        job.snapshot.correlation_id,
    )?;
    insert_owner_mutation_ledger(transaction, prepared, next_revision, now)?;
    Ok(OwnerMutationResult {
        owner_id: owner_id.to_vec(),
        job_id,
        result_revision: next_revision,
        replayed: false,
    })
}

pub(crate) async fn resume_after_confirmation(
    store: &SqliteStore<ConversationStore>,
    prepared: PreparedJobOwnerMutation,
    now: JobTimestampMicros,
) -> Result<JobTransitionReceipt, JobQueueError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_not_poisoned(&poison)?;
            let transaction = begin_immediate(connection)?;
            let result = resume_in_transaction(&transaction, &prepared, now);
            let result = match result {
                Ok(result) => {
                    commit_or_poison(transaction, &poison)?;
                    ensure_autocommit(connection, &poison)?;
                    result
                }
                Err(error) => {
                    rollback_or_poison(transaction, &poison)?;
                    ensure_autocommit(connection, &poison)?;
                    return Err(error);
                }
            };
            read_owner_mutation_receipt(connection, &prepared, result)
        })
        .await
        .map_err(map_executor_error)
}

fn resume_in_transaction(
    transaction: &Transaction<'_>,
    prepared: &PreparedJobOwnerMutation,
    now: JobTimestampMicros,
) -> Result<OwnerMutationResult, JobQueueError> {
    if prepared.operation != JobOwnerMutationOperation::Resume {
        return Err(JobQueueError::CorruptStoredState);
    }
    if let Some(replayed) = find_owner_mutation_replay(transaction, prepared)? {
        return Ok(replayed);
    }
    let owner_uuid = prepared.auth.owner_id().as_uuid();
    let owner_id = owner_uuid.as_bytes();
    let job_id = prepared.job_id;
    let job = read_internal_job(transaction, owner_id, job_id)?;
    if job.snapshot.revision != prepared.expected_revision {
        return Err(JobQueueError::RevisionConflict);
    }
    if job.snapshot.state != JobState::WaitingConfirmation {
        return Err(JobQueueError::InvalidTransition);
    }
    observe_clock(transaction, now)?;
    let next_revision = job
        .snapshot
        .revision
        .checked_next()
        .ok_or(JobQueueError::CorruptStoredState)?;
    let updated = transaction
        .execute(
            "UPDATE conversation_jobs
             SET state = 'queued',
                 state_revision = ?3,
                 ready_at_micros = ?4,
                 cancel_requested = 0,
                 updated_at_micros = ?4
             WHERE owner_id = ?1
               AND job_id = ?2
               AND state = 'waiting_confirmation'
               AND state_revision = ?5",
            params![
                owner_id,
                job_id.as_uuid().as_bytes().as_slice(),
                revision_i64(next_revision)?,
                timestamp_i64(now)?,
                revision_i64(job.snapshot.revision)?
            ],
        )
        .map_err(backend)?;
    if updated != 1 {
        return Err(JobQueueError::RevisionConflict);
    }
    insert_event(
        transaction,
        owner_id,
        job_id,
        next_revision,
        JobEventKind::ConfirmationResumed,
        JobState::Queued,
        None,
        now,
        None,
        None,
        None,
        job.snapshot.correlation_id,
    )?;
    insert_owner_mutation_ledger(transaction, prepared, next_revision, now)?;
    Ok(OwnerMutationResult {
        owner_id: owner_id.to_vec(),
        job_id,
        result_revision: next_revision,
        replayed: false,
    })
}

fn find_owner_mutation_replay(
    transaction: &Transaction<'_>,
    prepared: &PreparedJobOwnerMutation,
) -> Result<Option<OwnerMutationResult>, JobQueueError> {
    let owner_id = prepared.auth.owner_id().as_uuid();
    let stored: Option<(Vec<u8>, String, Vec<u8>, i64)> = transaction
        .query_row(
            "SELECT request_fingerprint, operation, job_id, result_revision
             FROM conversation_job_owner_mutation_idempotency
             WHERE owner_id = ?1 AND idempotency_key = ?2",
            params![
                owner_id.as_bytes().as_slice(),
                prepared.idempotency_key.as_uuid().as_bytes().as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(backend)?;
    let Some((fingerprint, operation, job_id, result_revision)) = stored else {
        return Ok(None);
    };
    if decode_mutation_fingerprint(&fingerprint)? != prepared.fingerprint
        || operation != prepared.operation.as_str()
        || decode_job_id(&job_id)? != prepared.job_id
    {
        return Err(JobQueueError::IdempotencyConflict);
    }
    Ok(Some(OwnerMutationResult {
        owner_id: owner_id.as_bytes().to_vec(),
        job_id: prepared.job_id,
        result_revision: decode_revision(result_revision)?,
        replayed: true,
    }))
}

fn insert_owner_mutation_ledger(
    transaction: &Transaction<'_>,
    prepared: &PreparedJobOwnerMutation,
    result_revision: Revision,
    now: JobTimestampMicros,
) -> Result<(), JobQueueError> {
    transaction
        .execute(
            "INSERT INTO conversation_job_owner_mutation_idempotency(
                owner_id,
                idempotency_key,
                operation,
                request_fingerprint,
                job_id,
                result_revision,
                created_at_micros
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                prepared.auth.owner_id().as_uuid().as_bytes().as_slice(),
                prepared.idempotency_key.as_uuid().as_bytes().as_slice(),
                prepared.operation.as_str(),
                prepared.fingerprint.as_bytes().as_slice(),
                prepared.job_id.as_uuid().as_bytes().as_slice(),
                revision_i64(result_revision)?,
                timestamp_i64(now)?
            ],
        )
        .map_err(backend)?;
    Ok(())
}

fn read_owner_mutation_receipt(
    connection: &RawConnection,
    prepared: &PreparedJobOwnerMutation,
    result: OwnerMutationResult,
) -> Result<JobTransitionReceipt, JobQueueError> {
    let owner_id = prepared.auth.owner_id().as_uuid();
    if result.owner_id.as_slice() != owner_id.as_bytes() || result.job_id != prepared.job_id {
        return Err(JobQueueError::CorruptStoredState);
    }
    let stored: (Vec<u8>, String, Vec<u8>, i64) = connection
        .query_row(
            "SELECT request_fingerprint, operation, job_id, result_revision
             FROM conversation_job_owner_mutation_idempotency
             WHERE owner_id = ?1 AND idempotency_key = ?2",
            params![
                owner_id.as_bytes().as_slice(),
                prepared.idempotency_key.as_uuid().as_bytes().as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(backend)?;
    if decode_mutation_fingerprint(&stored.0)? != prepared.fingerprint
        || stored.1 != prepared.operation.as_str()
        || decode_job_id(&stored.2)? != result.job_id
        || decode_revision(stored.3)? != result.result_revision
    {
        return Err(JobQueueError::CorruptStoredState);
    }
    let job = read_job_snapshot(connection, owner_id.as_bytes(), result.job_id)?;
    if job.revision().get() < result.result_revision.get() {
        return Err(JobQueueError::CorruptStoredState);
    }
    let event_kind: String = connection
        .query_row(
            "SELECT event_kind
             FROM conversation_job_events
             WHERE owner_id = ?1
               AND job_id = ?2
               AND job_revision = ?3",
            params![
                owner_id.as_bytes().as_slice(),
                result.job_id.as_uuid().as_bytes().as_slice(),
                revision_i64(result.result_revision)?
            ],
            |row| row.get(0),
        )
        .map_err(backend)?;
    let event_matches = match prepared.operation {
        JobOwnerMutationOperation::Cancel => {
            matches!(event_kind.as_str(), "cancel_requested" | "cancelled")
        }
        JobOwnerMutationOperation::Resume => event_kind == "confirmation_resumed",
    };
    if !event_matches {
        return Err(JobQueueError::CorruptStoredState);
    }
    Ok(JobTransitionReceipt {
        job,
        replayed: result.replayed,
    })
}

pub(crate) async fn resolve_recovery(
    store: &SqliteStore<ConversationStore>,
    ticket: RecoveryTicket,
    resolution: RecoveryResolution,
    now: JobTimestampMicros,
) -> Result<JobTransitionReceipt, JobQueueError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_not_poisoned(&poison)?;
            let transaction = begin_immediate(connection)?;
            let result = resolve_recovery_in_transaction(&transaction, &ticket, resolution, now);
            let result = match result {
                Ok(result) => {
                    commit_or_poison(transaction, &poison)?;
                    ensure_autocommit(connection, &poison)?;
                    result
                }
                Err(error) => {
                    rollback_or_poison(transaction, &poison)?;
                    ensure_autocommit(connection, &poison)?;
                    return Err(error);
                }
            };
            let job = read_job_snapshot(connection, &result.owner_id, result.job_id)?;
            Ok(JobTransitionReceipt {
                job,
                replayed: result.replayed,
            })
        })
        .await
        .map_err(map_executor_error)
}

fn resolve_recovery_in_transaction(
    transaction: &Transaction<'_>,
    ticket: &RecoveryTicket,
    resolution: RecoveryResolution,
    now: JobTimestampMicros,
) -> Result<FinishResult, JobQueueError> {
    let stored: Option<(Vec<u8>, String, Option<String>)> = transaction
        .query_row(
            "SELECT owner_id, state, completion_kind
             FROM conversation_job_attempts
             WHERE job_id = ?1
               AND attempt_id = ?2
               AND attempt_number = ?3
               AND lease_generation = ?4
               AND lease_token = ?5",
            params![
                ticket.job_id.as_uuid().as_bytes().as_slice(),
                ticket.attempt_id.as_uuid().as_bytes().as_slice(),
                i64::from(ticket.attempt_number),
                micros_i64(ticket.generation)?,
                ticket.token.as_uuid().as_bytes().as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(backend)?;
    let Some((owner_id, state, completion_kind)) = stored else {
        return Err(JobQueueError::StaleLease);
    };
    let state = JobAttemptState::from_str(&state).ok_or(JobQueueError::CorruptStoredState)?;
    if is_terminal_attempt_state(state) {
        let matches_resolution = match resolution {
            RecoveryResolution::ConfirmedStoppedRetry => matches!(
                completion_kind.as_deref(),
                Some("recovery_retry" | "recovery_retry_exhausted")
            ),
            RecoveryResolution::ConfirmedStoppedFail => {
                completion_kind.as_deref() == Some("recovery_fail")
            }
        };
        if matches_resolution || completion_kind.as_deref() == Some("recovery_cancelled") {
            return Ok(FinishResult {
                owner_id,
                job_id: ticket.job_id,
                replayed: true,
            });
        }
        return Err(JobQueueError::StaleLease);
    }
    if state != JobAttemptState::RecoveryRequired {
        return Err(JobQueueError::StaleLease);
    }

    observe_clock(transaction, now)?;
    let control = active_control_from_row(&read_control(transaction)?)?;
    if control.status != "recovery_required"
        || control.job_id != ticket.job_id
        || control.attempt_id != ticket.attempt_id
        || control.attempt_number != ticket.attempt_number
        || control.generation != ticket.generation
        || control.token != ticket.token
        || control.owner_id != owner_id
    {
        return Err(JobQueueError::StaleLease);
    }
    let job = read_internal_job(transaction, &owner_id, ticket.job_id)?;
    if job.snapshot.state != JobState::RecoveryRequired {
        return Err(JobQueueError::CorruptStoredState);
    }
    let retry_allowed = !job.cancel_requested
        && resolution == RecoveryResolution::ConfirmedStoppedRetry
        && job.snapshot.attempts_started < job.snapshot.max_attempts;
    let (attempt_state, job_state, completion_kind, retry_at, failure, terminal_at) =
        if job.cancel_requested {
            (
                JobAttemptState::Cancelled,
                JobState::Cancelled,
                "recovery_cancelled",
                None,
                None,
                Some(now),
            )
        } else if retry_allowed {
            (
                JobAttemptState::LeaseExpired,
                JobState::RetryScheduled,
                "recovery_retry",
                Some(retry_at(&job, ticket.attempt_number, now)?),
                Some(JobFailureKind::LeaseExpired),
                None,
            )
        } else if resolution == RecoveryResolution::ConfirmedStoppedRetry {
            (
                JobAttemptState::Failed,
                JobState::Failed,
                "recovery_retry_exhausted",
                None,
                Some(JobFailureKind::LeaseExpired),
                Some(now),
            )
        } else {
            (
                JobAttemptState::Failed,
                JobState::Failed,
                "recovery_fail",
                None,
                Some(JobFailureKind::CleanupUncertain),
                Some(now),
            )
        };
    let next_revision = job
        .snapshot
        .revision
        .checked_next()
        .ok_or(JobQueueError::CorruptStoredState)?;
    let updated_attempt = transaction
        .execute(
            "UPDATE conversation_job_attempts
             SET state = ?5,
                 completion_kind = ?6,
                 finished_at_micros = ?7,
                 retry_at_micros = ?8,
                 failure_kind = ?9
             WHERE owner_id = ?1
               AND job_id = ?2
               AND attempt_id = ?3
               AND lease_token = ?4
               AND state = 'recovery_required'",
            params![
                owner_id,
                ticket.job_id.as_uuid().as_bytes().as_slice(),
                ticket.attempt_id.as_uuid().as_bytes().as_slice(),
                ticket.token.as_uuid().as_bytes().as_slice(),
                attempt_state.as_str(),
                completion_kind,
                timestamp_i64(now)?,
                retry_at.map(timestamp_i64).transpose()?,
                failure.map(JobFailureKind::as_str)
            ],
        )
        .map_err(backend)?;
    if updated_attempt != 1 {
        return Err(JobQueueError::StaleLease);
    }
    let updated_job = transaction
        .execute(
            "UPDATE conversation_jobs
             SET state = ?3,
                 state_revision = ?4,
                 ready_at_micros = COALESCE(?5, ready_at_micros),
                 terminal_at_micros = ?6,
                 updated_at_micros = ?7
             WHERE owner_id = ?1
               AND job_id = ?2
               AND state = 'recovery_required'
               AND state_revision = ?8",
            params![
                owner_id,
                ticket.job_id.as_uuid().as_bytes().as_slice(),
                job_state.as_str(),
                revision_i64(next_revision)?,
                retry_at.map(timestamp_i64).transpose()?,
                terminal_at.map(timestamp_i64).transpose()?,
                timestamp_i64(now)?,
                revision_i64(job.snapshot.revision)?
            ],
        )
        .map_err(backend)?;
    if updated_job != 1 {
        return Err(JobQueueError::CorruptStoredState);
    }
    clear_control(transaction, ticket.generation)?;
    insert_event(
        transaction,
        &owner_id,
        ticket.job_id,
        next_revision,
        JobEventKind::RecoveryResolved,
        job_state,
        Some(ticket.attempt_id),
        now,
        None,
        read_attempt_snapshot(transaction, &owner_id, ticket.job_id, ticket.attempt_id)?
            .execution_micros,
        failure,
        job.snapshot.correlation_id,
    )?;
    Ok(FinishResult {
        owner_id,
        job_id: ticket.job_id,
        replayed: false,
    })
}

fn read_job_snapshot(
    connection: &RawConnection,
    owner_id: &[u8],
    job_id: JobId,
) -> Result<JobSnapshot, JobQueueError> {
    let row = connection
        .query_row(
            "SELECT
                job_id,
                source_outbox_id,
                job_kind,
                priority,
                state,
                state_revision,
                attempts_started,
                max_attempts,
                enqueued_at_micros,
                ready_at_micros,
                first_started_at_micros,
                terminal_at_micros,
                queue_wait_micros,
                execution_micros,
                correlation_id
             FROM conversation_jobs
             WHERE owner_id = ?1 AND job_id = ?2",
            params![owner_id, job_id.as_uuid().as_bytes().as_slice()],
            decode_job_row,
        )
        .optional()
        .map_err(backend)?
        .ok_or(JobQueueError::NotFound)?;
    job_from_row(row)
}

fn read_internal_job(
    connection: &RawConnection,
    owner_id: &[u8],
    job_id: JobId,
) -> Result<InternalJob, JobQueueError> {
    let row: Option<(JobRow, bool, i64, i64, Vec<u8>)> = connection
        .query_row(
            "SELECT
                job_id,
                source_outbox_id,
                job_kind,
                priority,
                state,
                state_revision,
                attempts_started,
                max_attempts,
                enqueued_at_micros,
                ready_at_micros,
                first_started_at_micros,
                terminal_at_micros,
                queue_wait_micros,
                execution_micros,
                correlation_id,
                cancel_requested,
                attempt_timeout_micros,
                retry_base_micros,
                result_idempotency_key
             FROM conversation_jobs
             WHERE owner_id = ?1 AND job_id = ?2",
            params![owner_id, job_id.as_uuid().as_bytes().as_slice()],
            |row| {
                Ok((
                    JobRow {
                        job_id: row.get(0)?,
                        source_outbox_id: row.get(1)?,
                        job_kind: row.get(2)?,
                        priority: row.get(3)?,
                        state: row.get(4)?,
                        state_revision: row.get(5)?,
                        attempts_started: row.get(6)?,
                        max_attempts: row.get(7)?,
                        enqueued_at_micros: row.get(8)?,
                        ready_at_micros: row.get(9)?,
                        first_started_at_micros: row.get(10)?,
                        terminal_at_micros: row.get(11)?,
                        queue_wait_micros: row.get(12)?,
                        execution_micros: row.get(13)?,
                        correlation_id: row.get(14)?,
                    },
                    row.get(15)?,
                    row.get(16)?,
                    row.get(17)?,
                    row.get(18)?,
                ))
            },
        )
        .optional()
        .map_err(backend)?;
    let Some((
        row,
        cancel_requested,
        attempt_timeout_micros,
        retry_base_micros,
        result_idempotency_key,
    )) = row
    else {
        return Err(JobQueueError::NotFound);
    };
    Ok(InternalJob {
        snapshot: job_from_row(row)?,
        cancel_requested,
        attempt_timeout_micros: decode_nonnegative_u64(attempt_timeout_micros)?,
        retry_base_micros: decode_nonnegative_u64(retry_base_micros)?,
        result_idempotency_key: decode_idempotency_key(&result_idempotency_key)?,
    })
}

fn ensure_job_exists(
    connection: &RawConnection,
    owner_id: &[u8],
    job_id: JobId,
) -> Result<(), JobQueueError> {
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM conversation_jobs
                WHERE owner_id = ?1 AND job_id = ?2
            )",
            params![owner_id, job_id.as_uuid().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(backend)?;
    if exists {
        Ok(())
    } else {
        Err(JobQueueError::NotFound)
    }
}

fn read_attempt_snapshot(
    connection: &RawConnection,
    owner_id: &[u8],
    job_id: JobId,
    attempt_id: JobAttemptId,
) -> Result<JobAttemptSnapshot, JobQueueError> {
    let row = connection
        .query_row(
            "SELECT
                attempt_id,
                job_id,
                attempt_number,
                state,
                leased_at_micros,
                started_at_micros,
                lease_expires_at_micros,
                attempt_deadline_at_micros,
                finished_at_micros,
                retry_at_micros,
                queue_wait_micros,
                execution_micros,
                failure_kind
             FROM conversation_job_attempts
             WHERE owner_id = ?1 AND job_id = ?2 AND attempt_id = ?3",
            params![
                owner_id,
                job_id.as_uuid().as_bytes().as_slice(),
                attempt_id.as_uuid().as_bytes().as_slice()
            ],
            decode_attempt_row,
        )
        .optional()
        .map_err(backend)?
        .ok_or(JobQueueError::NotFound)?;
    attempt_from_row(row)
}

fn read_attempt_state(
    connection: &RawConnection,
    owner_id: &[u8],
    job_id: JobId,
    attempt_id: JobAttemptId,
) -> Result<JobAttemptState, JobQueueError> {
    let state: String = connection
        .query_row(
            "SELECT state
             FROM conversation_job_attempts
             WHERE owner_id = ?1 AND job_id = ?2 AND attempt_id = ?3",
            params![
                owner_id,
                job_id.as_uuid().as_bytes().as_slice(),
                attempt_id.as_uuid().as_bytes().as_slice()
            ],
            |row| row.get(0),
        )
        .map_err(backend)?;
    JobAttemptState::from_str(&state).ok_or(JobQueueError::CorruptStoredState)
}

fn read_control(connection: &RawConnection) -> Result<ControlRow, JobQueueError> {
    connection
        .query_row(
            "SELECT
                status,
                lease_generation,
                owner_id,
                job_id,
                attempt_id,
                attempt_number,
                lease_token,
                lease_expires_at_micros,
                attempt_deadline_at_micros
             FROM conversation_job_queue_control
             WHERE control_id = 1",
            [],
            |row| {
                Ok(ControlRow {
                    status: row.get(0)?,
                    lease_generation: row.get(1)?,
                    owner_id: row.get(2)?,
                    job_id: row.get(3)?,
                    attempt_id: row.get(4)?,
                    attempt_number: row.get(5)?,
                    lease_token: row.get(6)?,
                    lease_expires_at_micros: row.get(7)?,
                    attempt_deadline_at_micros: row.get(8)?,
                })
            },
        )
        .map_err(backend)
}

fn active_control_from_row(row: &ControlRow) -> Result<ActiveControl, JobQueueError> {
    if !matches!(row.status.as_str(), "leased" | "recovery_required") {
        return Err(JobQueueError::CorruptStoredState);
    }
    let generation = u64::try_from(row.lease_generation)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(JobQueueError::CorruptStoredState)?;
    let owner_id = row
        .owner_id
        .clone()
        .filter(|value| value.len() == 16)
        .ok_or(JobQueueError::CorruptStoredState)?;
    Ok(ActiveControl {
        status: row.status.clone(),
        generation,
        owner_id,
        job_id: decode_job_id(
            row.job_id
                .as_deref()
                .ok_or(JobQueueError::CorruptStoredState)?,
        )?,
        attempt_id: decode_attempt_id(
            row.attempt_id
                .as_deref()
                .ok_or(JobQueueError::CorruptStoredState)?,
        )?,
        attempt_number: decode_positive_u16(
            row.attempt_number
                .ok_or(JobQueueError::CorruptStoredState)?,
        )?,
        token: decode_lease_token(
            row.lease_token
                .as_deref()
                .ok_or(JobQueueError::CorruptStoredState)?,
        )?,
        lease_expires_at: decode_timestamp(
            row.lease_expires_at_micros
                .ok_or(JobQueueError::CorruptStoredState)?,
        )?,
        attempt_deadline_at: decode_timestamp(
            row.attempt_deadline_at_micros
                .ok_or(JobQueueError::CorruptStoredState)?,
        )?,
    })
}

fn recovery_ticket_from_control(row: &ControlRow) -> Result<RecoveryTicket, JobQueueError> {
    let active = active_control_from_row(row)?;
    if active.status != "recovery_required" {
        return Err(JobQueueError::CorruptStoredState);
    }
    Ok(RecoveryTicket {
        job_id: active.job_id,
        attempt_id: active.attempt_id,
        attempt_number: active.attempt_number,
        generation: active.generation,
        token: active.token,
    })
}

fn validate_active_lease(
    connection: &RawConnection,
    lease: &JobLease,
    now: JobTimestampMicros,
) -> Result<ActiveControl, JobQueueError> {
    let active = active_control_from_row(&read_control(connection)?)?;
    if active.status != "leased"
        || active.job_id != lease.job_id
        || active.attempt_id != lease.attempt_id
        || active.attempt_number != lease.attempt_number
        || active.generation != lease.generation
        || active.token != lease.token
    {
        return Err(JobQueueError::StaleLease);
    }
    if now >= active.lease_expires_at || now >= active.attempt_deadline_at {
        return Err(JobQueueError::LeaseExpired);
    }
    Ok(active)
}

fn read_active_lease(
    connection: &RawConnection,
    expected: &JobLease,
) -> Result<JobLease, JobQueueError> {
    let active = active_control_from_row(&read_control(connection)?)?;
    if active.status != "leased"
        || active.job_id != expected.job_id
        || active.attempt_id != expected.attempt_id
        || active.attempt_number != expected.attempt_number
        || active.generation != expected.generation
        || active.token != expected.token
    {
        return Err(JobQueueError::CorruptStoredState);
    }
    let attempt = read_attempt_snapshot(
        connection,
        &active.owner_id,
        active.job_id,
        active.attempt_id,
    )?;
    if !matches!(
        attempt.state,
        JobAttemptState::Leased | JobAttemptState::Running | JobAttemptState::CancelRequested
    ) || attempt.lease_expires_at != active.lease_expires_at
        || attempt.attempt_deadline_at != active.attempt_deadline_at
    {
        return Err(JobQueueError::CorruptStoredState);
    }
    let job = read_internal_job(connection, &active.owner_id, active.job_id)?;
    let expected_job_state = match attempt.state {
        JobAttemptState::Leased => JobState::Leased,
        JobAttemptState::Running => JobState::Running,
        JobAttemptState::CancelRequested => JobState::CancelRequested,
        _ => return Err(JobQueueError::CorruptStoredState),
    };
    if job.snapshot.state != expected_job_state
        || job.snapshot.attempts_started != active.attempt_number
    {
        return Err(JobQueueError::CorruptStoredState);
    }
    Ok(JobLease {
        job_id: active.job_id,
        attempt_id: active.attempt_id,
        attempt_number: active.attempt_number,
        source_outbox_id: job.snapshot.source_outbox_id,
        kind: job.snapshot.kind,
        result_idempotency_key: job.result_idempotency_key,
        generation: active.generation,
        token: active.token,
        state: attempt.state,
        lease_expires_at: active.lease_expires_at,
        attempt_deadline_at: active.attempt_deadline_at,
    })
}

fn read_recovery_ticket(
    connection: &RawConnection,
    expected: &RecoveryTicket,
) -> Result<RecoveryTicket, JobQueueError> {
    let actual = recovery_ticket_from_control(&read_control(connection)?)?;
    if actual != *expected {
        return Err(JobQueueError::CorruptStoredState);
    }
    let control = active_control_from_row(&read_control(connection)?)?;
    let attempt = read_attempt_snapshot(
        connection,
        &control.owner_id,
        actual.job_id,
        actual.attempt_id,
    )?;
    let job = read_internal_job(connection, &control.owner_id, actual.job_id)?;
    if attempt.state != JobAttemptState::RecoveryRequired
        || attempt.attempt_number != actual.attempt_number
        || job.snapshot.state != JobState::RecoveryRequired
        || job.snapshot.attempts_started != actual.attempt_number
    {
        return Err(JobQueueError::CorruptStoredState);
    }
    Ok(actual)
}

fn find_attempt_by_capability(
    connection: &RawConnection,
    lease: &JobLease,
) -> Result<Option<StoredAttemptCapability>, JobQueueError> {
    let row = connection
        .query_row(
            "SELECT owner_id, state, completion_kind, failure_kind
             FROM conversation_job_attempts
             WHERE job_id = ?1
               AND attempt_id = ?2
               AND attempt_number = ?3
               AND lease_generation = ?4
               AND lease_token = ?5",
            params![
                lease.job_id.as_uuid().as_bytes().as_slice(),
                lease.attempt_id.as_uuid().as_bytes().as_slice(),
                i64::from(lease.attempt_number),
                micros_i64(lease.generation)?,
                lease.token.as_uuid().as_bytes().as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(backend)?;
    row.map(|(owner_id, state, completion_kind, failure_kind)| {
        let state = JobAttemptState::from_str(&state).ok_or(JobQueueError::CorruptStoredState)?;
        Ok(StoredAttemptCapability {
            owner_id,
            state,
            completion_kind,
            failure_kind,
        })
    })
    .transpose()
}

fn set_control_active(
    transaction: &Transaction<'_>,
    active: &ActiveControl,
) -> Result<(), JobQueueError> {
    let previous_generation = active
        .generation
        .checked_sub(1)
        .ok_or(JobQueueError::CorruptStoredState)?;
    let updated = transaction
        .execute(
            "UPDATE conversation_job_queue_control
             SET status = ?2,
                 lease_generation = ?3,
                 owner_id = ?4,
                 job_id = ?5,
                 attempt_id = ?6,
                 attempt_number = ?7,
                 lease_token = ?8,
                 lease_expires_at_micros = ?9,
                 attempt_deadline_at_micros = ?10
             WHERE control_id = 1
               AND status = 'idle'
               AND lease_generation = ?1",
            params![
                micros_i64(previous_generation)?,
                active.status,
                micros_i64(active.generation)?,
                active.owner_id,
                active.job_id.as_uuid().as_bytes().as_slice(),
                active.attempt_id.as_uuid().as_bytes().as_slice(),
                i64::from(active.attempt_number),
                active.token.as_uuid().as_bytes().as_slice(),
                timestamp_i64(active.lease_expires_at)?,
                timestamp_i64(active.attempt_deadline_at)?
            ],
        )
        .map_err(backend)?;
    if updated == 1 {
        Ok(())
    } else {
        Err(JobQueueError::CorruptStoredState)
    }
}

fn clear_control(transaction: &Transaction<'_>, generation: u64) -> Result<(), JobQueueError> {
    let updated = transaction
        .execute(
            "UPDATE conversation_job_queue_control
             SET status = 'idle',
                 owner_id = NULL,
                 job_id = NULL,
                 attempt_id = NULL,
                 attempt_number = NULL,
                 lease_token = NULL,
                 lease_expires_at_micros = NULL,
                 attempt_deadline_at_micros = NULL
             WHERE control_id = 1
               AND status IN ('leased', 'recovery_required')
               AND lease_generation = ?1",
            params![micros_i64(generation)?],
        )
        .map_err(backend)?;
    if updated == 1 {
        Ok(())
    } else {
        Err(JobQueueError::StaleLease)
    }
}

fn set_control_status(
    transaction: &Transaction<'_>,
    status: &str,
    generation: u64,
) -> Result<(), JobQueueError> {
    let updated = transaction
        .execute(
            "UPDATE conversation_job_queue_control
             SET status = ?2
             WHERE control_id = 1
               AND status = 'leased'
               AND lease_generation = ?1",
            params![micros_i64(generation)?, status],
        )
        .map_err(backend)?;
    if updated == 1 {
        Ok(())
    } else {
        Err(JobQueueError::StaleLease)
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_event(
    transaction: &Transaction<'_>,
    owner_id: &[u8],
    job_id: JobId,
    revision: Revision,
    event_kind: JobEventKind,
    state: JobState,
    attempt_id: Option<JobAttemptId>,
    happened_at: JobTimestampMicros,
    queue_wait_micros: Option<u64>,
    execution_micros: Option<u64>,
    failure: Option<JobFailureKind>,
    correlation_id: CorrelationId,
) -> Result<(), JobQueueError> {
    let event_id = JobEventId::new();
    let attempt_id = attempt_id.map(|value| value.as_uuid().as_bytes().to_vec());
    transaction
        .execute(
            "INSERT INTO conversation_job_events(
                owner_id,
                event_id,
                job_id,
                job_revision,
                event_kind,
                state,
                attempt_id,
                happened_at_micros,
                queue_wait_micros,
                execution_micros,
                failure_kind,
                correlation_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                owner_id,
                event_id.as_uuid().as_bytes().as_slice(),
                job_id.as_uuid().as_bytes().as_slice(),
                revision_i64(revision)?,
                event_kind.as_str(),
                state.as_str(),
                attempt_id,
                timestamp_i64(happened_at)?,
                queue_wait_micros.map(micros_i64).transpose()?,
                execution_micros.map(micros_i64).transpose()?,
                failure.map(JobFailureKind::as_str),
                correlation_id.as_uuid().as_bytes().as_slice()
            ],
        )
        .map_err(backend)?;
    Ok(())
}

fn observe_clock(
    transaction: &Transaction<'_>,
    now: JobTimestampMicros,
) -> Result<(), JobQueueError> {
    let last: i64 = transaction
        .query_row(
            "SELECT last_observed_at_micros
             FROM conversation_job_queue_control
             WHERE control_id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(backend)?;
    let last = decode_timestamp(last)?;
    if now < last {
        return Err(JobQueueError::ClockRegression);
    }
    let updated = transaction
        .execute(
            "UPDATE conversation_job_queue_control
             SET last_observed_at_micros = ?1
             WHERE control_id = 1 AND last_observed_at_micros <= ?1",
            params![timestamp_i64(now)?],
        )
        .map_err(backend)?;
    if updated == 1 {
        Ok(())
    } else {
        Err(JobQueueError::ClockRegression)
    }
}

fn retry_at(
    job: &InternalJob,
    completed_attempt: u16,
    now: JobTimestampMicros,
) -> Result<JobTimestampMicros, JobQueueError> {
    let exponent = u32::from(completed_attempt.saturating_sub(1));
    let multiplier = 1_u64
        .checked_shl(exponent)
        .ok_or(JobQueueError::TimeOverflow)?;
    let delay = job
        .retry_base_micros
        .checked_mul(multiplier)
        .ok_or(JobQueueError::TimeOverflow)?;
    now.checked_add(Duration::from_micros(delay))
        .ok_or(JobQueueError::TimeOverflow)
}

fn completion_signature(outcome: JobOutcome) -> (&'static str, Option<JobFailureKind>) {
    match outcome {
        JobOutcome::Succeeded => ("succeeded", None),
        JobOutcome::RetryableFailure(failure) => ("retryable_failure", Some(failure)),
        JobOutcome::PermanentFailure(failure) => ("permanent_failure", Some(failure)),
        JobOutcome::WaitingConfirmation => ("waiting_confirmation", None),
        JobOutcome::Cancelled => ("cancelled", None),
    }
}

fn is_terminal_attempt_state(state: JobAttemptState) -> bool {
    matches!(
        state,
        JobAttemptState::RetryScheduled
            | JobAttemptState::WaitingConfirmation
            | JobAttemptState::Succeeded
            | JobAttemptState::Failed
            | JobAttemptState::Cancelled
            | JobAttemptState::LeaseExpired
    )
}

fn decode_optional_failure(value: Option<&str>) -> Result<Option<JobFailureKind>, JobQueueError> {
    value
        .map(|value| JobFailureKind::from_str(value).ok_or(JobQueueError::CorruptStoredState))
        .transpose()
}

fn decode_job_row(row: &Row<'_>) -> rusqlite::Result<JobRow> {
    Ok(JobRow {
        job_id: row.get(0)?,
        source_outbox_id: row.get(1)?,
        job_kind: row.get(2)?,
        priority: row.get(3)?,
        state: row.get(4)?,
        state_revision: row.get(5)?,
        attempts_started: row.get(6)?,
        max_attempts: row.get(7)?,
        enqueued_at_micros: row.get(8)?,
        ready_at_micros: row.get(9)?,
        first_started_at_micros: row.get(10)?,
        terminal_at_micros: row.get(11)?,
        queue_wait_micros: row.get(12)?,
        execution_micros: row.get(13)?,
        correlation_id: row.get(14)?,
    })
}

fn job_from_row(row: JobRow) -> Result<JobSnapshot, JobQueueError> {
    Ok(JobSnapshot {
        id: decode_job_id(&row.job_id)?,
        source_outbox_id: decode_outbox_id(&row.source_outbox_id)?,
        kind: JobKind::from_str(&row.job_kind).ok_or(JobQueueError::CorruptStoredState)?,
        priority: JobPriority::from_i64(row.priority).ok_or(JobQueueError::CorruptStoredState)?,
        state: JobState::from_str(&row.state).ok_or(JobQueueError::CorruptStoredState)?,
        revision: decode_revision(row.state_revision)?,
        attempts_started: decode_nonnegative_u16(row.attempts_started)?,
        max_attempts: decode_positive_u16(row.max_attempts)?,
        enqueued_at: decode_timestamp(row.enqueued_at_micros)?,
        ready_at: decode_timestamp(row.ready_at_micros)?,
        first_started_at: row
            .first_started_at_micros
            .map(decode_timestamp)
            .transpose()?,
        terminal_at: row.terminal_at_micros.map(decode_timestamp).transpose()?,
        queue_wait_micros: decode_nonnegative_u64(row.queue_wait_micros)?,
        execution_micros: decode_nonnegative_u64(row.execution_micros)?,
        correlation_id: decode_correlation_id(&row.correlation_id)?,
    })
}

fn decode_attempt_row(row: &Row<'_>) -> rusqlite::Result<AttemptRow> {
    Ok(AttemptRow {
        attempt_id: row.get(0)?,
        job_id: row.get(1)?,
        attempt_number: row.get(2)?,
        state: row.get(3)?,
        leased_at_micros: row.get(4)?,
        started_at_micros: row.get(5)?,
        lease_expires_at_micros: row.get(6)?,
        attempt_deadline_at_micros: row.get(7)?,
        finished_at_micros: row.get(8)?,
        retry_at_micros: row.get(9)?,
        queue_wait_micros: row.get(10)?,
        execution_micros: row.get(11)?,
        failure_kind: row.get(12)?,
    })
}

fn attempt_from_row(row: AttemptRow) -> Result<JobAttemptSnapshot, JobQueueError> {
    Ok(JobAttemptSnapshot {
        id: decode_attempt_id(&row.attempt_id)?,
        job_id: decode_job_id(&row.job_id)?,
        attempt_number: decode_positive_u16(row.attempt_number)?,
        state: JobAttemptState::from_str(&row.state).ok_or(JobQueueError::CorruptStoredState)?,
        leased_at: decode_timestamp(row.leased_at_micros)?,
        started_at: row.started_at_micros.map(decode_timestamp).transpose()?,
        lease_expires_at: decode_timestamp(row.lease_expires_at_micros)?,
        attempt_deadline_at: decode_timestamp(row.attempt_deadline_at_micros)?,
        finished_at: row.finished_at_micros.map(decode_timestamp).transpose()?,
        retry_at: row.retry_at_micros.map(decode_timestamp).transpose()?,
        queue_wait_micros: row
            .queue_wait_micros
            .map(decode_nonnegative_u64)
            .transpose()?,
        execution_micros: row
            .execution_micros
            .map(decode_nonnegative_u64)
            .transpose()?,
        failure: row
            .failure_kind
            .as_deref()
            .map(|value| JobFailureKind::from_str(value).ok_or(JobQueueError::CorruptStoredState))
            .transpose()?,
    })
}

fn decode_event_row(row: &Row<'_>) -> rusqlite::Result<EventRow> {
    decode_event_row_at(row, 0)
}

fn decode_event_row_at(row: &Row<'_>, offset: usize) -> rusqlite::Result<EventRow> {
    Ok(EventRow {
        event_id: row.get(offset)?,
        job_id: row.get(offset + 1)?,
        job_revision: row.get(offset + 2)?,
        event_kind: row.get(offset + 3)?,
        state: row.get(offset + 4)?,
        attempt_id: row.get(offset + 5)?,
        happened_at_micros: row.get(offset + 6)?,
        queue_wait_micros: row.get(offset + 7)?,
        execution_micros: row.get(offset + 8)?,
        failure_kind: row.get(offset + 9)?,
        correlation_id: row.get(offset + 10)?,
    })
}

fn event_from_row(row: EventRow) -> Result<JobEvent, JobQueueError> {
    Ok(JobEvent {
        id: decode_event_id(&row.event_id)?,
        job_id: decode_job_id(&row.job_id)?,
        job_revision: decode_revision(row.job_revision)?,
        kind: JobEventKind::from_str(&row.event_kind).ok_or(JobQueueError::CorruptStoredState)?,
        state: JobState::from_str(&row.state).ok_or(JobQueueError::CorruptStoredState)?,
        attempt_id: row
            .attempt_id
            .as_deref()
            .map(decode_attempt_id)
            .transpose()?,
        happened_at: decode_timestamp(row.happened_at_micros)?,
        queue_wait_micros: row
            .queue_wait_micros
            .map(decode_nonnegative_u64)
            .transpose()?,
        execution_micros: row
            .execution_micros
            .map(decode_nonnegative_u64)
            .transpose()?,
        failure: row
            .failure_kind
            .as_deref()
            .map(|value| JobFailureKind::from_str(value).ok_or(JobQueueError::CorruptStoredState))
            .transpose()?,
        correlation_id: decode_correlation_id(&row.correlation_id)?,
    })
}

#[cfg(test)]
pub(crate) struct GuardedRecordIds {
    pub(crate) job_id: JobId,
    pub(crate) attempt_id: JobAttemptId,
    pub(crate) event_id: JobEventId,
    pub(crate) enqueue_key: JobEnqueueKey,
    pub(crate) mutation_key: JobMutationKey,
}

#[cfg(test)]
pub(crate) async fn test_guarded_records_reject_mutation(
    store: &SqliteStore<ConversationStore>,
    auth: VerifiedAuthContext,
    ids: GuardedRecordIds,
) -> Result<(), JobQueueError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_not_poisoned(&poison)?;
            let owner_id = auth.owner_id().as_uuid();
            let denied = [
                connection.execute(
                    "UPDATE conversation_jobs
                     SET state_revision = state_revision
                     WHERE owner_id = ?1 AND job_id = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        ids.job_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "DELETE FROM conversation_jobs
                     WHERE owner_id = ?1 AND job_id = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        ids.job_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "INSERT OR REPLACE INTO conversation_jobs
                     SELECT * FROM conversation_jobs
                     WHERE owner_id = ?1 AND job_id = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        ids.job_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "UPDATE conversation_job_enqueue_idempotency
                     SET request_fingerprint = request_fingerprint
                     WHERE owner_id = ?1 AND idempotency_key = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        ids.enqueue_key.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "DELETE FROM conversation_job_enqueue_idempotency
                     WHERE owner_id = ?1 AND idempotency_key = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        ids.enqueue_key.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "INSERT OR REPLACE INTO conversation_job_enqueue_idempotency
                     SELECT * FROM conversation_job_enqueue_idempotency
                     WHERE owner_id = ?1 AND idempotency_key = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        ids.enqueue_key.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "UPDATE conversation_job_owner_mutation_idempotency
                     SET request_fingerprint = request_fingerprint
                     WHERE owner_id = ?1 AND idempotency_key = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        ids.mutation_key.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "DELETE FROM conversation_job_owner_mutation_idempotency
                     WHERE owner_id = ?1 AND idempotency_key = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        ids.mutation_key.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "INSERT OR REPLACE INTO conversation_job_owner_mutation_idempotency
                     SELECT * FROM conversation_job_owner_mutation_idempotency
                     WHERE owner_id = ?1 AND idempotency_key = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        ids.mutation_key.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "UPDATE conversation_job_attempts
                     SET lease_token = zeroblob(16)
                     WHERE owner_id = ?1 AND job_id = ?2 AND attempt_id = ?3",
                    params![
                        owner_id.as_bytes().as_slice(),
                        ids.job_id.as_uuid().as_bytes().as_slice(),
                        ids.attempt_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "DELETE FROM conversation_job_attempts
                     WHERE owner_id = ?1 AND job_id = ?2 AND attempt_id = ?3",
                    params![
                        owner_id.as_bytes().as_slice(),
                        ids.job_id.as_uuid().as_bytes().as_slice(),
                        ids.attempt_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "INSERT OR REPLACE INTO conversation_job_attempts
                     SELECT * FROM conversation_job_attempts
                     WHERE owner_id = ?1 AND job_id = ?2 AND attempt_id = ?3",
                    params![
                        owner_id.as_bytes().as_slice(),
                        ids.job_id.as_uuid().as_bytes().as_slice(),
                        ids.attempt_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "UPDATE conversation_job_events
                     SET event_kind = event_kind
                     WHERE owner_id = ?1 AND event_id = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        ids.event_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "DELETE FROM conversation_job_events
                     WHERE owner_id = ?1 AND event_id = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        ids.event_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "INSERT OR REPLACE INTO conversation_job_events
                     SELECT * FROM conversation_job_events
                     WHERE owner_id = ?1 AND event_id = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        ids.event_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "UPDATE conversation_job_queue_control
                     SET lease_generation = lease_generation + 2
                     WHERE control_id = 1",
                    [],
                ),
                connection.execute(
                    "DELETE FROM conversation_job_queue_control WHERE control_id = 1",
                    [],
                ),
                connection.execute(
                    "INSERT OR REPLACE INTO conversation_job_queue_control
                     SELECT * FROM conversation_job_queue_control
                     WHERE control_id = 1",
                    [],
                ),
            ];
            if denied.iter().any(Result::is_ok) || !connection.is_autocommit() {
                return Err(JobQueueError::CorruptStoredState);
            }
            Ok(())
        })
        .await
        .map_err(map_executor_error)
}

#[cfg(test)]
pub(crate) async fn test_final_attempt_waiting_transition_is_guarded(
    store: &SqliteStore<ConversationStore>,
    auth: VerifiedAuthContext,
    job_id: JobId,
    now: JobTimestampMicros,
) -> Result<(), JobQueueError> {
    ensure_store_healthy(store)?;
    store
        .connection
        .call(move |connection| {
            let rejected = connection.execute(
                "UPDATE conversation_jobs
                 SET state = 'waiting_confirmation',
                     state_revision = state_revision + 1,
                     updated_at_micros = ?3
                 WHERE owner_id = ?1
                   AND job_id = ?2
                   AND state = 'running'
                   AND attempts_started = max_attempts",
                params![
                    auth.owner_id().as_uuid().as_bytes().as_slice(),
                    job_id.as_uuid().as_bytes().as_slice(),
                    timestamp_i64(now)?
                ],
            );
            if rejected.is_ok() || !connection.is_autocommit() {
                return Err(JobQueueError::CorruptStoredState);
            }
            Ok(())
        })
        .await
        .map_err(map_executor_error)
}

fn begin_immediate(connection: &mut RawConnection) -> Result<Transaction<'_>, JobQueueError> {
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(backend)
}

fn commit_or_poison(
    transaction: Transaction<'_>,
    poison: &AtomicBool,
) -> Result<(), JobQueueError> {
    if transaction.commit().is_err() {
        poison.store(true, Ordering::Release);
        return Err(JobQueueError::BackendFailure);
    }
    Ok(())
}

fn rollback_or_poison(
    transaction: Transaction<'_>,
    poison: &AtomicBool,
) -> Result<(), JobQueueError> {
    if transaction.rollback().is_err() {
        poison.store(true, Ordering::Release);
        return Err(JobQueueError::BackendFailure);
    }
    Ok(())
}

fn ensure_autocommit(
    connection: &mut RawConnection,
    poison: &AtomicBool,
) -> Result<(), JobQueueError> {
    if !connection.is_autocommit() {
        restore_or_poison(connection, poison);
        return Err(JobQueueError::BackendFailure);
    }
    Ok(())
}

fn restore_or_poison(connection: &mut RawConnection, poison: &AtomicBool) {
    if !connection.is_autocommit() && connection.execute_batch("ROLLBACK").is_err() {
        poison.store(true, Ordering::Release);
    }
    if !connection.is_autocommit() {
        poison.store(true, Ordering::Release);
    }
}

fn ensure_store_healthy(store: &SqliteStore<ConversationStore>) -> Result<(), JobQueueError> {
    ensure_not_poisoned(&store.operation_poisoned)
}

fn ensure_not_poisoned(poison: &AtomicBool) -> Result<(), JobQueueError> {
    if poison.load(Ordering::Acquire) {
        Err(JobQueueError::BackendFailure)
    } else {
        Ok(())
    }
}

fn map_executor_error(error: ExecutorError<JobQueueError>) -> JobQueueError {
    match error {
        ExecutorError::Error(error) => error,
        ExecutorError::ConnectionClosed | ExecutorError::Close(_) => JobQueueError::BackendFailure,
        _ => JobQueueError::BackendFailure,
    }
}

fn backend(_error: rusqlite::Error) -> JobQueueError {
    JobQueueError::BackendFailure
}

fn decode_uuid(value: &[u8]) -> Result<Uuid, JobQueueError> {
    if value.len() != 16 {
        return Err(JobQueueError::CorruptStoredState);
    }
    Uuid::from_slice(value).map_err(|_| JobQueueError::CorruptStoredState)
}

fn decode_job_id(value: &[u8]) -> Result<JobId, JobQueueError> {
    JobId::from_uuid(decode_uuid(value)?).ok_or(JobQueueError::CorruptStoredState)
}

fn decode_attempt_id(value: &[u8]) -> Result<JobAttemptId, JobQueueError> {
    JobAttemptId::from_uuid(decode_uuid(value)?).ok_or(JobQueueError::CorruptStoredState)
}

fn decode_event_id(value: &[u8]) -> Result<JobEventId, JobQueueError> {
    JobEventId::from_uuid(decode_uuid(value)?).ok_or(JobQueueError::CorruptStoredState)
}

fn decode_outbox_id(value: &[u8]) -> Result<OutboxId, JobQueueError> {
    OutboxId::from_uuid(decode_uuid(value)?).ok_or(JobQueueError::CorruptStoredState)
}

fn decode_idempotency_key(value: &[u8]) -> Result<IdempotencyKey, JobQueueError> {
    IdempotencyKey::from_uuid(decode_uuid(value)?).ok_or(JobQueueError::CorruptStoredState)
}

fn decode_correlation_id(value: &[u8]) -> Result<CorrelationId, JobQueueError> {
    CorrelationId::from_uuid(decode_uuid(value)?).ok_or(JobQueueError::CorruptStoredState)
}

fn decode_lease_token(value: &[u8]) -> Result<JobLeaseToken, JobQueueError> {
    JobLeaseToken::from_uuid(decode_uuid(value)?).ok_or(JobQueueError::CorruptStoredState)
}

fn decode_fingerprint(value: &[u8]) -> Result<EnqueueFingerprint, JobQueueError> {
    let value: [u8; 32] = value
        .try_into()
        .map_err(|_| JobQueueError::CorruptStoredState)?;
    Ok(EnqueueFingerprint::from_bytes(value))
}

fn decode_mutation_fingerprint(value: &[u8]) -> Result<JobMutationFingerprint, JobQueueError> {
    let value: [u8; 32] = value
        .try_into()
        .map_err(|_| JobQueueError::CorruptStoredState)?;
    Ok(JobMutationFingerprint::from_bytes(value))
}

fn decode_revision(value: i64) -> Result<Revision, JobQueueError> {
    u64::try_from(value)
        .ok()
        .and_then(Revision::new)
        .ok_or(JobQueueError::CorruptStoredState)
}

fn decode_timestamp(value: i64) -> Result<JobTimestampMicros, JobQueueError> {
    u64::try_from(value)
        .ok()
        .and_then(JobTimestampMicros::new)
        .ok_or(JobQueueError::CorruptStoredState)
}

fn decode_nonnegative_u64(value: i64) -> Result<u64, JobQueueError> {
    u64::try_from(value).map_err(|_| JobQueueError::CorruptStoredState)
}

fn decode_nonnegative_u16(value: i64) -> Result<u16, JobQueueError> {
    u16::try_from(value).map_err(|_| JobQueueError::CorruptStoredState)
}

fn decode_positive_u16(value: i64) -> Result<u16, JobQueueError> {
    u16::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(JobQueueError::CorruptStoredState)
}

fn timestamp_i64(value: JobTimestampMicros) -> Result<i64, JobQueueError> {
    i64::try_from(value.get()).map_err(|_| JobQueueError::TimeOverflow)
}

fn micros_i64(value: u64) -> Result<i64, JobQueueError> {
    i64::try_from(value).map_err(|_| JobQueueError::TimeOverflow)
}

fn revision_i64(value: Revision) -> Result<i64, JobQueueError> {
    i64::try_from(value.get()).map_err(|_| JobQueueError::CorruptStoredState)
}
