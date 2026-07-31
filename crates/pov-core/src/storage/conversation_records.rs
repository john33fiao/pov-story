use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::Digest;
use tokio_rusqlite::{
    Error as ExecutorError,
    rusqlite::{self, OptionalExtension, Transaction, TransactionBehavior, params},
};
use uuid::Uuid;

use crate::{
    conversation::{
        AppendReceipt, AuditId, ContentHash, ConversationAudit, ConversationError,
        ConversationEvent, ConversationEventId, ConversationEventKind, ConversationId,
        ConversationRecord, ConversationTimeline, IdempotencyKey, IdempotencyResult, OutboxEvent,
        OutboxId, PreparedAppend, RequestFingerprint, conversation_source, event_source,
    },
    identity::{CorrelationId, Revision, VerifiedAuthContext},
};

use super::{ConversationAppendFault, ConversationStore, SqliteStore};

const APPEND_OPERATION: &str = "append_user_event_v1";
const OUTBOX_TOPIC: &str = "conversation.user-appended.v1";
const AUDIT_ACTION: &str = "conversation.user-appended.v1";

struct WriteOutcome {
    replayed: bool,
    correlation_id: CorrelationId,
}

struct ReceiptRow {
    current_revision: i64,
    event_id: Vec<u8>,
    conversation_id: Vec<u8>,
    conversation_revision: i64,
    event_kind: String,
    content: String,
    content_bytes: i64,
    content_sha256: Vec<u8>,
    correlation_id: Vec<u8>,
    request_fingerprint: Vec<u8>,
    operation: String,
    expected_revision: Option<i64>,
    outbox_id: Vec<u8>,
    source_revision: i64,
    outbox_content_sha256: Vec<u8>,
    outbox_correlation_id: Vec<u8>,
    topic: String,
    audit_id: Vec<u8>,
    audit_correlation_id: Vec<u8>,
    action: String,
}

struct EventRow {
    conversation_id: Vec<u8>,
    conversation_revision: i64,
    event_kind: String,
    content: String,
    content_bytes: i64,
    content_sha256: Vec<u8>,
    correlation_id: Vec<u8>,
}

struct OutboxRow {
    event_id: Vec<u8>,
    conversation_id: Vec<u8>,
    conversation_revision: i64,
    source_revision: i64,
    content_sha256: Vec<u8>,
    correlation_id: Vec<u8>,
    topic: String,
}

struct AuditRow {
    event_id: Vec<u8>,
    conversation_id: Vec<u8>,
    conversation_revision: i64,
    correlation_id: Vec<u8>,
    action: String,
}

struct IdempotencyRow {
    event_id: Vec<u8>,
    conversation_id: Vec<u8>,
    conversation_revision: i64,
    correlation_id: Vec<u8>,
}

pub(crate) async fn append(
    store: &SqliteStore<ConversationStore>,
    prepared: PreparedAppend,
    fault: ConversationAppendFault,
) -> Result<AppendReceipt, ConversationError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            if poison.load(Ordering::Acquire) {
                return Err(ConversationError::BackendFailure);
            }

            #[cfg(test)]
            if let ConversationAppendFault::PauseBeforeUncertainTransaction(gate) = &fault {
                gate.pause();
                connection
                    .execute_batch("BEGIN IMMEDIATE")
                    .map_err(|_| ConversationError::BackendFailure)?;
                poison.store(true, Ordering::Release);
                return Err(ConversationError::InjectedFailure);
            }

            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| ConversationError::BackendFailure)?;
            let write_result = append_in_transaction(&transaction, &prepared, &fault);
            let outcome = match write_result {
                Ok(outcome) => {
                    if transaction.commit().is_err() {
                        restore_or_poison(connection, &poison);
                        return Err(ConversationError::BackendFailure);
                    }
                    if !connection.is_autocommit() {
                        restore_or_poison(connection, &poison);
                        return Err(ConversationError::BackendFailure);
                    }
                    outcome
                }
                Err(error) => {
                    if transaction.rollback().is_err() {
                        poison.store(true, Ordering::Release);
                        return Err(ConversationError::BackendFailure);
                    }
                    if !connection.is_autocommit() {
                        restore_or_poison(connection, &poison);
                        return Err(ConversationError::BackendFailure);
                    }
                    return Err(error);
                }
            };

            #[cfg(test)]
            if let ConversationAppendFault::PauseAfterCommitBeforeReadback(gate) = &fault {
                gate.pause();
            }

            #[cfg(test)]
            if matches!(&fault, ConversationAppendFault::AfterCommitBeforeReadback) {
                return Err(ConversationError::InjectedFailure);
            }

            readback_receipt(connection, &prepared, outcome)
        })
        .await
        .map_err(map_executor_error)
}

fn append_in_transaction(
    transaction: &Transaction<'_>,
    prepared: &PreparedAppend,
    fault: &ConversationAppendFault,
) -> Result<WriteOutcome, ConversationError> {
    let _ = fault;
    let owner_id = prepared.auth.owner_id().as_uuid();
    let command = &prepared.command;
    let existing: Option<(Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT request_fingerprint, correlation_id
             FROM conversation_append_idempotency
             WHERE owner_id = ?1 AND idempotency_key = ?2",
            params![
                owner_id.as_bytes().as_slice(),
                command.idempotency_key.as_uuid().as_bytes().as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(backend)?;

    if let Some((fingerprint, correlation_id)) = existing {
        if decode_fingerprint(&fingerprint)? != prepared.fingerprint {
            return Err(ConversationError::IdempotencyConflict);
        }
        return Ok(WriteOutcome {
            replayed: true,
            correlation_id: decode_correlation_id(&correlation_id)?,
        });
    }

    let now = timestamp_micros()?;
    let conversation_revision = match command.expected_revision {
        None => {
            let exists: bool = transaction
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1
                        FROM conversations
                        WHERE owner_id = ?1 AND conversation_id = ?2
                    )",
                    params![
                        owner_id.as_bytes().as_slice(),
                        command.conversation_id.as_uuid().as_bytes().as_slice()
                    ],
                    |row| row.get(0),
                )
                .map_err(backend)?;
            if exists {
                return Err(ConversationError::RevisionConflict);
            }
            transaction
                .execute(
                    "INSERT INTO conversations(
                        owner_id,
                        conversation_id,
                        current_revision,
                        created_at_micros,
                        updated_at_micros
                     ) VALUES (?1, ?2, 1, ?3, ?3)",
                    params![
                        owner_id.as_bytes().as_slice(),
                        command.conversation_id.as_uuid().as_bytes().as_slice(),
                        now
                    ],
                )
                .map_err(backend)?;
            Revision::INITIAL
        }
        Some(expected) => {
            let next = expected
                .checked_next()
                .ok_or(ConversationError::RevisionExhausted)?;
            let updated = transaction
                .execute(
                    "UPDATE conversations
                     SET current_revision = ?3, updated_at_micros = ?4
                     WHERE owner_id = ?1
                       AND conversation_id = ?2
                       AND current_revision = ?5",
                    params![
                        owner_id.as_bytes().as_slice(),
                        command.conversation_id.as_uuid().as_bytes().as_slice(),
                        revision_i64(next)?,
                        now,
                        revision_i64(expected)?
                    ],
                )
                .map_err(backend)?;
            if updated != 1 {
                return Err(ConversationError::RevisionConflict);
            }
            next
        }
    };

    let event_id = ConversationEventId::new();
    let outbox_id = OutboxId::new();
    let audit_id = AuditId::new();
    let correlation_id = CorrelationId::new();
    let event_kind = ConversationEventKind::UserText.as_str();
    let conversation_revision_i64 = revision_i64(conversation_revision)?;

    transaction
        .execute(
            "INSERT INTO conversation_events(
                owner_id,
                event_id,
                conversation_id,
                conversation_revision,
                event_kind,
                content,
                content_bytes,
                content_sha256,
                correlation_id,
                created_at_micros
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                owner_id.as_bytes().as_slice(),
                event_id.as_uuid().as_bytes().as_slice(),
                command.conversation_id.as_uuid().as_bytes().as_slice(),
                conversation_revision_i64,
                event_kind,
                command.content,
                content_len_i64(&command.content)?,
                prepared.content_hash.as_bytes().as_slice(),
                correlation_id.as_uuid().as_bytes().as_slice(),
                now
            ],
        )
        .map_err(backend)?;

    #[cfg(test)]
    if matches!(fault, ConversationAppendFault::BeforeOutboxInsert) {
        return Err(ConversationError::InjectedFailure);
    }

    transaction
        .execute(
            "INSERT INTO conversation_outbox(
                owner_id,
                outbox_id,
                event_id,
                conversation_id,
                conversation_revision,
                source_revision,
                event_kind,
                topic,
                content_sha256,
                correlation_id,
                created_at_micros
             ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, ?9, ?10)",
            params![
                owner_id.as_bytes().as_slice(),
                outbox_id.as_uuid().as_bytes().as_slice(),
                event_id.as_uuid().as_bytes().as_slice(),
                command.conversation_id.as_uuid().as_bytes().as_slice(),
                conversation_revision_i64,
                event_kind,
                OUTBOX_TOPIC,
                prepared.content_hash.as_bytes().as_slice(),
                correlation_id.as_uuid().as_bytes().as_slice(),
                now
            ],
        )
        .map_err(backend)?;

    transaction
        .execute(
            "INSERT INTO conversation_audit(
                owner_id,
                audit_id,
                event_id,
                conversation_id,
                conversation_revision,
                event_kind,
                action,
                correlation_id,
                created_at_micros
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                owner_id.as_bytes().as_slice(),
                audit_id.as_uuid().as_bytes().as_slice(),
                event_id.as_uuid().as_bytes().as_slice(),
                command.conversation_id.as_uuid().as_bytes().as_slice(),
                conversation_revision_i64,
                event_kind,
                AUDIT_ACTION,
                correlation_id.as_uuid().as_bytes().as_slice(),
                now
            ],
        )
        .map_err(backend)?;

    transaction
        .execute(
            "INSERT INTO conversation_append_idempotency(
                owner_id,
                idempotency_key,
                operation,
                request_fingerprint,
                conversation_id,
                expected_revision,
                event_id,
                conversation_revision,
                event_kind,
                correlation_id,
                created_at_micros
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                owner_id.as_bytes().as_slice(),
                command.idempotency_key.as_uuid().as_bytes().as_slice(),
                APPEND_OPERATION,
                prepared.fingerprint.as_bytes().as_slice(),
                command.conversation_id.as_uuid().as_bytes().as_slice(),
                command.expected_revision.map(revision_i64).transpose()?,
                event_id.as_uuid().as_bytes().as_slice(),
                conversation_revision_i64,
                event_kind,
                correlation_id.as_uuid().as_bytes().as_slice(),
                now
            ],
        )
        .map_err(backend)?;

    Ok(WriteOutcome {
        replayed: false,
        correlation_id,
    })
}

fn readback_receipt(
    connection: &rusqlite::Connection,
    prepared: &PreparedAppend,
    outcome: WriteOutcome,
) -> Result<AppendReceipt, ConversationError> {
    let owner_id = prepared.auth.owner_id().as_uuid();
    let command = &prepared.command;
    let row: ReceiptRow = connection
        .query_row(
            "SELECT
                c.current_revision,
                e.event_id,
                e.conversation_id,
                e.conversation_revision,
                e.event_kind,
                e.content,
                e.content_bytes,
                e.content_sha256,
                e.correlation_id,
                i.request_fingerprint,
                i.operation,
                i.expected_revision,
                o.outbox_id,
                o.source_revision,
                o.content_sha256,
                o.correlation_id,
                o.topic,
                a.audit_id,
                a.correlation_id,
                a.action
             FROM conversation_append_idempotency AS i
             JOIN conversation_events AS e
               ON e.owner_id = i.owner_id
              AND e.event_id = i.event_id
              AND e.conversation_id = i.conversation_id
              AND e.conversation_revision = i.conversation_revision
              AND e.event_kind = i.event_kind
              AND e.correlation_id = i.correlation_id
             JOIN conversations AS c
               ON c.owner_id = e.owner_id
              AND c.conversation_id = e.conversation_id
             JOIN conversation_outbox AS o
               ON o.owner_id = e.owner_id
              AND o.event_id = e.event_id
              AND o.conversation_id = e.conversation_id
              AND o.conversation_revision = e.conversation_revision
              AND o.event_kind = e.event_kind
              AND o.correlation_id = e.correlation_id
              AND o.content_sha256 = e.content_sha256
             JOIN conversation_audit AS a
               ON a.owner_id = e.owner_id
              AND a.event_id = e.event_id
              AND a.conversation_id = e.conversation_id
              AND a.conversation_revision = e.conversation_revision
              AND a.event_kind = e.event_kind
              AND a.correlation_id = e.correlation_id
             WHERE i.owner_id = ?1 AND i.idempotency_key = ?2",
            params![
                owner_id.as_bytes().as_slice(),
                command.idempotency_key.as_uuid().as_bytes().as_slice()
            ],
            |row| {
                Ok(ReceiptRow {
                    current_revision: row.get(0)?,
                    event_id: row.get(1)?,
                    conversation_id: row.get(2)?,
                    conversation_revision: row.get(3)?,
                    event_kind: row.get(4)?,
                    content: row.get(5)?,
                    content_bytes: row.get(6)?,
                    content_sha256: row.get(7)?,
                    correlation_id: row.get(8)?,
                    request_fingerprint: row.get(9)?,
                    operation: row.get(10)?,
                    expected_revision: row.get(11)?,
                    outbox_id: row.get(12)?,
                    source_revision: row.get(13)?,
                    outbox_content_sha256: row.get(14)?,
                    outbox_correlation_id: row.get(15)?,
                    topic: row.get(16)?,
                    audit_id: row.get(17)?,
                    audit_correlation_id: row.get(18)?,
                    action: row.get(19)?,
                })
            },
        )
        .optional()
        .map_err(backend)?
        .ok_or(ConversationError::CorruptStoredState)?;

    let conversation_id = decode_conversation_id(&row.conversation_id)?;
    let event_id = decode_event_id(&row.event_id)?;
    let outbox_id = decode_outbox_id(&row.outbox_id)?;
    let audit_id = decode_audit_id(&row.audit_id)?;
    let conversation_revision = decode_revision(row.conversation_revision)?;
    let current_revision = decode_revision(row.current_revision)?;
    let event_kind = ConversationEventKind::from_str(&row.event_kind)
        .ok_or(ConversationError::CorruptStoredState)?;
    let content_hash = decode_content_hash(&row.content_sha256)?;
    let correlation_id = decode_correlation_id(&row.correlation_id)?;

    let current_contains_event = current_revision.get() >= conversation_revision.get();
    let content_bytes =
        usize::try_from(row.content_bytes).map_err(|_| ConversationError::CorruptStoredState)?;
    let actual_content_hash =
        ContentHash::from_bytes(sha2::Sha256::digest(row.content.as_bytes()).into());
    let stored_expected_revision = row.expected_revision.map(decode_revision).transpose()?;
    if conversation_id != command.conversation_id
        || event_kind != ConversationEventKind::UserText
        || row.content.as_bytes() != command.content.as_bytes()
        || content_bytes != row.content.len()
        || content_hash != prepared.content_hash
        || actual_content_hash != content_hash
        || decode_fingerprint(&row.request_fingerprint)? != prepared.fingerprint
        || row.operation != APPEND_OPERATION
        || stored_expected_revision != command.expected_revision
        || correlation_id != outcome.correlation_id
        || row.source_revision != 1
        || decode_content_hash(&row.outbox_content_sha256)? != content_hash
        || decode_correlation_id(&row.outbox_correlation_id)? != correlation_id
        || row.topic != OUTBOX_TOPIC
        || decode_correlation_id(&row.audit_correlation_id)? != correlation_id
        || row.action != AUDIT_ACTION
        || !current_contains_event
    {
        return Err(ConversationError::CorruptStoredState);
    }

    let source = event_source(&prepared.auth, event_id)?;
    Ok(AppendReceipt {
        event: ConversationEvent {
            id: event_id,
            conversation_id,
            conversation_revision,
            source,
            kind: event_kind,
            content: row.content,
            content_hash,
            correlation_id,
        },
        outbox: OutboxEvent {
            id: outbox_id,
            event_id,
            conversation_id,
            conversation_revision,
            source,
            content_hash,
            correlation_id,
        },
        audit: ConversationAudit {
            id: audit_id,
            event_id,
            conversation_id,
            conversation_revision,
            correlation_id,
        },
        replayed: outcome.replayed,
    })
}

pub(crate) async fn read_conversation(
    store: &SqliteStore<ConversationStore>,
    auth: VerifiedAuthContext,
    id: ConversationId,
) -> Result<ConversationRecord, ConversationError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_connection_healthy(&poison)?;
            let revision: Option<i64> = connection
                .query_row(
                    "SELECT current_revision
                     FROM conversations
                     WHERE owner_id = ?1 AND conversation_id = ?2",
                    params![
                        auth.owner_id().as_uuid().as_bytes().as_slice(),
                        id.as_uuid().as_bytes().as_slice()
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(backend)?;
            let revision = revision.ok_or(ConversationError::NotFound)?;
            Ok(ConversationRecord {
                id,
                source: conversation_source(&auth, id, decode_revision(revision)?)?,
            })
        })
        .await
        .map_err(map_executor_error)
}

pub(crate) async fn list_conversations(
    store: &SqliteStore<ConversationStore>,
    auth: VerifiedAuthContext,
) -> Result<Vec<ConversationRecord>, ConversationError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_connection_healthy(&poison)?;
            let mut statement = connection
                .prepare(
                    "SELECT conversation_id, current_revision
                     FROM conversations
                     WHERE owner_id = ?1
                     ORDER BY updated_at_micros DESC, conversation_id ASC",
                )
                .map_err(backend)?;
            let rows = statement
                .query_map(
                    params![auth.owner_id().as_uuid().as_bytes().as_slice()],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
                )
                .map_err(backend)?;
            let mut conversations = Vec::new();
            for row in rows {
                let (conversation_id, revision) = row.map_err(backend)?;
                let conversation_id = decode_conversation_id(&conversation_id)?;
                conversations.push(ConversationRecord {
                    id: conversation_id,
                    source: conversation_source(
                        &auth,
                        conversation_id,
                        decode_revision(revision)?,
                    )?,
                });
            }
            Ok(conversations)
        })
        .await
        .map_err(map_executor_error)
}

pub(crate) async fn read_timeline(
    store: &SqliteStore<ConversationStore>,
    auth: VerifiedAuthContext,
    id: ConversationId,
) -> Result<ConversationTimeline, ConversationError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_connection_healthy(&poison)?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Deferred)
                .map_err(backend)?;
            let revision: Option<i64> = transaction
                .query_row(
                    "SELECT current_revision
                     FROM conversations
                     WHERE owner_id = ?1 AND conversation_id = ?2",
                    params![
                        auth.owner_id().as_uuid().as_bytes().as_slice(),
                        id.as_uuid().as_bytes().as_slice()
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(backend)?;
            let revision = revision.ok_or(ConversationError::NotFound)?;
            let mut statement = transaction
                .prepare(
                    "SELECT
                        event_id,
                        conversation_id,
                        conversation_revision,
                        event_kind,
                        content,
                        content_bytes,
                        content_sha256,
                        correlation_id
                     FROM conversation_events
                     WHERE owner_id = ?1 AND conversation_id = ?2
                     ORDER BY conversation_revision ASC",
                )
                .map_err(backend)?;
            let rows = statement
                .query_map(
                    params![
                        auth.owner_id().as_uuid().as_bytes().as_slice(),
                        id.as_uuid().as_bytes().as_slice()
                    ],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            EventRow {
                                conversation_id: row.get(1)?,
                                conversation_revision: row.get(2)?,
                                event_kind: row.get(3)?,
                                content: row.get(4)?,
                                content_bytes: row.get(5)?,
                                content_sha256: row.get(6)?,
                                correlation_id: row.get(7)?,
                            },
                        ))
                    },
                )
                .map_err(backend)?;
            let mut events = Vec::new();
            for row in rows {
                let (event_id, row) = row.map_err(backend)?;
                events.push(decode_event(&auth, decode_event_id(&event_id)?, row)?);
            }
            drop(statement);
            transaction.commit().map_err(backend)?;

            let revision = decode_revision(revision)?;
            if events.is_empty()
                || events.last().map(ConversationEvent::conversation_revision) != Some(revision)
                || events.iter().any(|event| event.conversation_id() != id)
            {
                return Err(ConversationError::CorruptStoredState);
            }
            Ok(ConversationTimeline {
                conversation: ConversationRecord {
                    id,
                    source: conversation_source(&auth, id, revision)?,
                },
                events,
            })
        })
        .await
        .map_err(map_executor_error)
}

pub(crate) async fn read_event(
    store: &SqliteStore<ConversationStore>,
    auth: VerifiedAuthContext,
    id: ConversationEventId,
) -> Result<ConversationEvent, ConversationError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_connection_healthy(&poison)?;
            let row: Option<EventRow> = connection
                .query_row(
                    "SELECT
                            conversation_id,
                            conversation_revision,
                            event_kind,
                            content,
                            content_bytes,
                            content_sha256,
                            correlation_id
                         FROM conversation_events
                         WHERE owner_id = ?1 AND event_id = ?2",
                    params![
                        auth.owner_id().as_uuid().as_bytes().as_slice(),
                        id.as_uuid().as_bytes().as_slice()
                    ],
                    |row| {
                        Ok(EventRow {
                            conversation_id: row.get(0)?,
                            conversation_revision: row.get(1)?,
                            event_kind: row.get(2)?,
                            content: row.get(3)?,
                            content_bytes: row.get(4)?,
                            content_sha256: row.get(5)?,
                            correlation_id: row.get(6)?,
                        })
                    },
                )
                .optional()
                .map_err(backend)?;
            let row = row.ok_or(ConversationError::NotFound)?;
            decode_event(&auth, id, row)
        })
        .await
        .map_err(map_executor_error)
}

fn decode_event(
    auth: &VerifiedAuthContext,
    id: ConversationEventId,
    row: EventRow,
) -> Result<ConversationEvent, ConversationError> {
    let content_hash = decode_content_hash(&row.content_sha256)?;
    let actual_hash = ContentHash::from_bytes(sha2::Sha256::digest(row.content.as_bytes()).into());
    if usize::try_from(row.content_bytes).map_err(|_| ConversationError::CorruptStoredState)?
        != row.content.len()
        || actual_hash != content_hash
    {
        return Err(ConversationError::CorruptStoredState);
    }
    Ok(ConversationEvent {
        id,
        conversation_id: decode_conversation_id(&row.conversation_id)?,
        conversation_revision: decode_revision(row.conversation_revision)?,
        source: event_source(auth, id)?,
        kind: ConversationEventKind::from_str(&row.event_kind)
            .ok_or(ConversationError::CorruptStoredState)?,
        content: row.content,
        content_hash,
        correlation_id: decode_correlation_id(&row.correlation_id)?,
    })
}

pub(crate) async fn read_outbox(
    store: &SqliteStore<ConversationStore>,
    auth: VerifiedAuthContext,
    id: OutboxId,
) -> Result<OutboxEvent, ConversationError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_connection_healthy(&poison)?;
            let row: Option<OutboxRow> = connection
                .query_row(
                    "SELECT
                            o.event_id,
                            o.conversation_id,
                            o.conversation_revision,
                            o.source_revision,
                            o.content_sha256,
                            o.correlation_id,
                            o.topic
                         FROM conversation_outbox AS o
                         JOIN conversation_events AS e
                           ON e.owner_id = o.owner_id
                          AND e.event_id = o.event_id
                          AND e.conversation_id = o.conversation_id
                          AND e.conversation_revision = o.conversation_revision
                          AND e.event_kind = o.event_kind
                          AND e.correlation_id = o.correlation_id
                          AND e.content_sha256 = o.content_sha256
                         WHERE o.owner_id = ?1 AND o.outbox_id = ?2",
                    params![
                        auth.owner_id().as_uuid().as_bytes().as_slice(),
                        id.as_uuid().as_bytes().as_slice()
                    ],
                    |row| {
                        Ok(OutboxRow {
                            event_id: row.get(0)?,
                            conversation_id: row.get(1)?,
                            conversation_revision: row.get(2)?,
                            source_revision: row.get(3)?,
                            content_sha256: row.get(4)?,
                            correlation_id: row.get(5)?,
                            topic: row.get(6)?,
                        })
                    },
                )
                .optional()
                .map_err(backend)?;
            let row = row.ok_or(ConversationError::NotFound)?;
            if row.source_revision != 1 || row.topic != OUTBOX_TOPIC {
                return Err(ConversationError::CorruptStoredState);
            }
            let event_id = decode_event_id(&row.event_id)?;
            Ok(OutboxEvent {
                id,
                event_id,
                conversation_id: decode_conversation_id(&row.conversation_id)?,
                conversation_revision: decode_revision(row.conversation_revision)?,
                source: event_source(&auth, event_id)?,
                content_hash: decode_content_hash(&row.content_sha256)?,
                correlation_id: decode_correlation_id(&row.correlation_id)?,
            })
        })
        .await
        .map_err(map_executor_error)
}

pub(crate) async fn read_audit(
    store: &SqliteStore<ConversationStore>,
    auth: VerifiedAuthContext,
    id: AuditId,
) -> Result<ConversationAudit, ConversationError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_connection_healthy(&poison)?;
            let row: Option<AuditRow> = connection
                .query_row(
                    "SELECT
                        a.event_id,
                        a.conversation_id,
                        a.conversation_revision,
                        a.correlation_id,
                        a.action
                     FROM conversation_audit AS a
                     JOIN conversation_events AS e
                       ON e.owner_id = a.owner_id
                      AND e.event_id = a.event_id
                      AND e.conversation_id = a.conversation_id
                      AND e.conversation_revision = a.conversation_revision
                      AND e.event_kind = a.event_kind
                      AND e.correlation_id = a.correlation_id
                     WHERE a.owner_id = ?1 AND a.audit_id = ?2",
                    params![
                        auth.owner_id().as_uuid().as_bytes().as_slice(),
                        id.as_uuid().as_bytes().as_slice()
                    ],
                    |row| {
                        Ok(AuditRow {
                            event_id: row.get(0)?,
                            conversation_id: row.get(1)?,
                            conversation_revision: row.get(2)?,
                            correlation_id: row.get(3)?,
                            action: row.get(4)?,
                        })
                    },
                )
                .optional()
                .map_err(backend)?;
            let row = row.ok_or(ConversationError::NotFound)?;
            if row.action != AUDIT_ACTION {
                return Err(ConversationError::CorruptStoredState);
            }
            Ok(ConversationAudit {
                id,
                event_id: decode_event_id(&row.event_id)?,
                conversation_id: decode_conversation_id(&row.conversation_id)?,
                conversation_revision: decode_revision(row.conversation_revision)?,
                correlation_id: decode_correlation_id(&row.correlation_id)?,
            })
        })
        .await
        .map_err(map_executor_error)
}

pub(crate) async fn read_idempotency_result(
    store: &SqliteStore<ConversationStore>,
    auth: VerifiedAuthContext,
    key: IdempotencyKey,
) -> Result<IdempotencyResult, ConversationError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_connection_healthy(&poison)?;
            let row: Option<IdempotencyRow> = connection
                .query_row(
                    "SELECT
                        i.event_id,
                        i.conversation_id,
                        i.conversation_revision,
                        i.correlation_id
                     FROM conversation_append_idempotency AS i
                     JOIN conversation_events AS e
                       ON e.owner_id = i.owner_id
                      AND e.event_id = i.event_id
                      AND e.conversation_id = i.conversation_id
                      AND e.conversation_revision = i.conversation_revision
                      AND e.event_kind = i.event_kind
                      AND e.correlation_id = i.correlation_id
                     WHERE i.owner_id = ?1 AND i.idempotency_key = ?2",
                    params![
                        auth.owner_id().as_uuid().as_bytes().as_slice(),
                        key.as_uuid().as_bytes().as_slice()
                    ],
                    |row| {
                        Ok(IdempotencyRow {
                            event_id: row.get(0)?,
                            conversation_id: row.get(1)?,
                            conversation_revision: row.get(2)?,
                            correlation_id: row.get(3)?,
                        })
                    },
                )
                .optional()
                .map_err(backend)?;
            let row = row.ok_or(ConversationError::NotFound)?;
            Ok(IdempotencyResult {
                event_id: decode_event_id(&row.event_id)?,
                conversation_id: decode_conversation_id(&row.conversation_id)?,
                conversation_revision: decode_revision(row.conversation_revision)?,
                correlation_id: decode_correlation_id(&row.correlation_id)?,
            })
        })
        .await
        .map_err(map_executor_error)
}

#[cfg(test)]
pub(crate) async fn test_row_counts(
    store: &SqliteStore<ConversationStore>,
    auth: VerifiedAuthContext,
) -> Result<(usize, usize, usize, usize, usize), ConversationError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_connection_healthy(&poison)?;
            let owner_id = auth.owner_id().as_uuid();
            let count = |table: &'static str| -> Result<usize, ConversationError> {
                let sql = format!("SELECT count(*) FROM {table} WHERE owner_id = ?1");
                connection
                    .query_row(&sql, [owner_id.as_bytes().as_slice()], |row| row.get(0))
                    .map_err(backend)
            };
            Ok((
                count("conversations")?,
                count("conversation_events")?,
                count("conversation_outbox")?,
                count("conversation_audit")?,
                count("conversation_append_idempotency")?,
            ))
        })
        .await
        .map_err(map_executor_error)
}

#[cfg(test)]
pub(crate) async fn test_immutable_records_reject_mutation(
    store: &SqliteStore<ConversationStore>,
    auth: VerifiedAuthContext,
    conversation_id: ConversationId,
    event_id: ConversationEventId,
    outbox_id: OutboxId,
    audit_id: AuditId,
    key: IdempotencyKey,
) -> Result<(), ConversationError> {
    ensure_store_healthy(store)?;
    let poison = Arc::clone(&store.operation_poisoned);
    store
        .connection
        .call(move |connection| {
            ensure_connection_healthy(&poison)?;
            let owner_id = auth.owner_id().as_uuid();
            let denied = [
                connection.execute(
                    "UPDATE conversations
                     SET current_revision = current_revision
                     WHERE owner_id = ?1 AND conversation_id = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        conversation_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "DELETE FROM conversations
                     WHERE owner_id = ?1 AND conversation_id = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        conversation_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "UPDATE conversation_events
                     SET content = content
                     WHERE owner_id = ?1 AND event_id = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        event_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "DELETE FROM conversation_events
                     WHERE owner_id = ?1 AND event_id = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        event_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "UPDATE conversation_append_idempotency
                     SET request_fingerprint = request_fingerprint
                     WHERE owner_id = ?1 AND idempotency_key = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        key.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "DELETE FROM conversation_append_idempotency
                     WHERE owner_id = ?1 AND idempotency_key = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        key.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "INSERT OR REPLACE INTO conversation_append_idempotency
                     SELECT *
                     FROM conversation_append_idempotency
                     WHERE owner_id = ?1 AND idempotency_key = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        key.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "UPDATE conversation_outbox
                     SET topic = topic
                     WHERE owner_id = ?1 AND outbox_id = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        outbox_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "DELETE FROM conversation_outbox
                     WHERE owner_id = ?1 AND outbox_id = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        outbox_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "INSERT OR REPLACE INTO conversation_outbox
                     SELECT *
                     FROM conversation_outbox
                     WHERE owner_id = ?1 AND outbox_id = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        outbox_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "UPDATE conversation_audit
                     SET action = action
                     WHERE owner_id = ?1 AND audit_id = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        audit_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "DELETE FROM conversation_audit
                     WHERE owner_id = ?1 AND audit_id = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        audit_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
                connection.execute(
                    "INSERT OR REPLACE INTO conversation_audit
                     SELECT *
                     FROM conversation_audit
                     WHERE owner_id = ?1 AND audit_id = ?2",
                    params![
                        owner_id.as_bytes().as_slice(),
                        audit_id.as_uuid().as_bytes().as_slice()
                    ],
                ),
            ];
            if denied.iter().any(Result::is_ok) || !connection.is_autocommit() {
                return Err(ConversationError::CorruptStoredState);
            }
            Ok(())
        })
        .await
        .map_err(map_executor_error)
}

#[cfg(test)]
pub(crate) async fn test_connection_is_autocommit(
    store: &SqliteStore<ConversationStore>,
) -> Result<bool, ConversationError> {
    ensure_store_healthy(store)?;
    store
        .connection
        .call(|connection| Ok::<_, ConversationError>(connection.is_autocommit()))
        .await
        .map_err(map_executor_error)
}

fn ensure_store_healthy(store: &SqliteStore<ConversationStore>) -> Result<(), ConversationError> {
    ensure_connection_healthy(&store.operation_poisoned)
}

fn ensure_connection_healthy(poison: &AtomicBool) -> Result<(), ConversationError> {
    if poison.load(Ordering::Acquire) {
        Err(ConversationError::BackendFailure)
    } else {
        Ok(())
    }
}

fn restore_or_poison(connection: &rusqlite::Connection, poison: &AtomicBool) {
    if !connection.is_autocommit() {
        let _ = connection.execute_batch("ROLLBACK");
    }
    if !connection.is_autocommit() {
        poison.store(true, Ordering::Release);
    }
}

fn backend(_: rusqlite::Error) -> ConversationError {
    ConversationError::BackendFailure
}

fn map_executor_error(error: ExecutorError<ConversationError>) -> ConversationError {
    match error {
        ExecutorError::Error(error) => error,
        ExecutorError::ConnectionClosed | ExecutorError::Close(_) => {
            ConversationError::BackendFailure
        }
        _ => ConversationError::BackendFailure,
    }
}

fn timestamp_micros() -> Result<i64, ConversationError> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ConversationError::BackendFailure)?
        .as_micros();
    i64::try_from(micros).map_err(|_| ConversationError::BackendFailure)
}

fn revision_i64(revision: Revision) -> Result<i64, ConversationError> {
    i64::try_from(revision.get()).map_err(|_| ConversationError::CorruptStoredState)
}

fn content_len_i64(content: &str) -> Result<i64, ConversationError> {
    i64::try_from(content.len()).map_err(|_| ConversationError::ContentTooLarge)
}

fn decode_revision(value: i64) -> Result<Revision, ConversationError> {
    let value = u64::try_from(value).map_err(|_| ConversationError::CorruptStoredState)?;
    Revision::new(value).ok_or(ConversationError::CorruptStoredState)
}

fn decode_uuid(bytes: &[u8]) -> Result<Uuid, ConversationError> {
    Uuid::from_slice(bytes).map_err(|_| ConversationError::CorruptStoredState)
}

fn decode_conversation_id(bytes: &[u8]) -> Result<ConversationId, ConversationError> {
    ConversationId::from_uuid(decode_uuid(bytes)?).ok_or(ConversationError::CorruptStoredState)
}

fn decode_event_id(bytes: &[u8]) -> Result<ConversationEventId, ConversationError> {
    ConversationEventId::from_uuid(decode_uuid(bytes)?).ok_or(ConversationError::CorruptStoredState)
}

fn decode_outbox_id(bytes: &[u8]) -> Result<OutboxId, ConversationError> {
    OutboxId::from_uuid(decode_uuid(bytes)?).ok_or(ConversationError::CorruptStoredState)
}

fn decode_audit_id(bytes: &[u8]) -> Result<AuditId, ConversationError> {
    AuditId::from_uuid(decode_uuid(bytes)?).ok_or(ConversationError::CorruptStoredState)
}

fn decode_correlation_id(bytes: &[u8]) -> Result<CorrelationId, ConversationError> {
    CorrelationId::from_uuid(decode_uuid(bytes)?).ok_or(ConversationError::CorruptStoredState)
}

fn decode_content_hash(bytes: &[u8]) -> Result<ContentHash, ConversationError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ConversationError::CorruptStoredState)?;
    Ok(ContentHash::from_bytes(bytes))
}

fn decode_fingerprint(bytes: &[u8]) -> Result<RequestFingerprint, ConversationError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ConversationError::CorruptStoredState)?;
    Ok(RequestFingerprint::from_bytes(bytes))
}
