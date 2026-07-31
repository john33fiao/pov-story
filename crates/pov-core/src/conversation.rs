use std::{error::Error, fmt};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    identity::{
        CorrelationId, OwnerId, Revision, SourceDomain, SourceId, SourceIdentity, SourceRevision,
        VerifiedAuthContext,
    },
    storage::{self, ConversationAppendFault, ConversationStore, SqliteStore},
};

pub const MAX_USER_EVENT_CONTENT_BYTES: usize = 64 * 1024;

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Option<Self> {
                if matches!(value.get_version(), Some(uuid::Version::Random))
                    && matches!(value.get_variant(), uuid::Variant::RFC4122)
                {
                    Some(Self(value))
                } else {
                    None
                }
            }

            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

opaque_id!(ConversationId);
opaque_id!(ConversationEventId);
opaque_id!(OutboxId);
opaque_id!(AuditId);

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdempotencyKey(Uuid);

impl IdempotencyKey {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Option<Self> {
        if matches!(value.get_version(), Some(uuid::Version::Random))
            && matches!(value.get_variant(), uuid::Variant::RFC4122)
        {
            Some(Self(value))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for IdempotencyKey {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdempotencyKey(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContentHash(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct RequestFingerprint([u8; 32]);

impl RequestFingerprint {
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for RequestFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestFingerprint(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AppendUserEvent {
    pub conversation_id: ConversationId,
    pub expected_revision: Option<Revision>,
    pub idempotency_key: IdempotencyKey,
    pub content: String,
}

impl fmt::Debug for AppendUserEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppendUserEvent")
            .field("conversation_id", &self.conversation_id)
            .field("expected_revision", &self.expected_revision)
            .field("idempotency_key", &"<redacted>")
            .field("content", &"<redacted>")
            .field("content_bytes", &self.content.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationEventKind {
    UserText,
    AssistantText,
    ToolCall,
    ToolResult,
}

impl ConversationEventKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserText => "user_text",
            Self::AssistantText => "assistant_text",
            Self::ToolCall => "tool_call",
            Self::ToolResult => "tool_result",
        }
    }

    pub(crate) fn from_str(value: &str) -> Option<Self> {
        match value {
            "user_text" => Some(Self::UserText),
            "assistant_text" => Some(Self::AssistantText),
            "tool_call" => Some(Self::ToolCall),
            "tool_result" => Some(Self::ToolResult),
            _ => None,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConversationRecord {
    pub(crate) id: ConversationId,
    pub(crate) source: SourceRevision,
}

impl ConversationRecord {
    #[must_use]
    pub const fn id(&self) -> ConversationId {
        self.id
    }

    #[must_use]
    pub const fn source(&self) -> SourceRevision {
        self.source
    }
}

impl fmt::Debug for ConversationRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConversationRecord")
            .field("id", &self.id)
            .field("revision", &self.source.revision())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConversationTimeline {
    pub(crate) conversation: ConversationRecord,
    pub(crate) events: Vec<ConversationEvent>,
}

impl ConversationTimeline {
    #[must_use]
    pub const fn conversation(&self) -> &ConversationRecord {
        &self.conversation
    }

    #[must_use]
    pub fn events(&self) -> &[ConversationEvent] {
        &self.events
    }
}

impl fmt::Debug for ConversationTimeline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConversationTimeline")
            .field("conversation", &self.conversation)
            .field("events", &self.events)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConversationEvent {
    pub(crate) id: ConversationEventId,
    pub(crate) conversation_id: ConversationId,
    pub(crate) conversation_revision: Revision,
    pub(crate) source: SourceRevision,
    pub(crate) kind: ConversationEventKind,
    pub(crate) content: String,
    pub(crate) content_hash: ContentHash,
    pub(crate) correlation_id: CorrelationId,
}

impl ConversationEvent {
    #[must_use]
    pub const fn id(&self) -> ConversationEventId {
        self.id
    }

    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    #[must_use]
    pub const fn conversation_revision(&self) -> Revision {
        self.conversation_revision
    }

    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.conversation_revision.get()
    }

    #[must_use]
    pub const fn source(&self) -> SourceRevision {
        self.source
    }

    #[must_use]
    pub const fn kind(&self) -> ConversationEventKind {
        self.kind
    }

    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    #[must_use]
    pub const fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    #[must_use]
    pub const fn correlation_id(&self) -> CorrelationId {
        self.correlation_id
    }
}

impl fmt::Debug for ConversationEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConversationEvent")
            .field("id", &self.id)
            .field("conversation_id", &self.conversation_id)
            .field("conversation_revision", &self.conversation_revision)
            .field("source", &self.source)
            .field("kind", &self.kind)
            .field("content", &"<redacted>")
            .field("content_bytes", &self.content.len())
            .field("content_hash", &self.content_hash)
            .field("correlation_id", &self.correlation_id)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OutboxEvent {
    pub(crate) id: OutboxId,
    pub(crate) event_id: ConversationEventId,
    pub(crate) conversation_id: ConversationId,
    pub(crate) conversation_revision: Revision,
    pub(crate) source: SourceRevision,
    pub(crate) content_hash: ContentHash,
    pub(crate) correlation_id: CorrelationId,
}

impl OutboxEvent {
    #[must_use]
    pub const fn id(&self) -> OutboxId {
        self.id
    }

    #[must_use]
    pub const fn event_id(&self) -> ConversationEventId {
        self.event_id
    }

    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    #[must_use]
    pub const fn conversation_revision(&self) -> Revision {
        self.conversation_revision
    }

    #[must_use]
    pub const fn source(&self) -> SourceRevision {
        self.source
    }

    #[must_use]
    pub const fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    #[must_use]
    pub const fn correlation_id(&self) -> CorrelationId {
        self.correlation_id
    }
}

impl fmt::Debug for OutboxEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboxEvent")
            .field("id", &self.id)
            .field("event_id", &self.event_id)
            .field("conversation_id", &self.conversation_id)
            .field("conversation_revision", &self.conversation_revision)
            .field("source", &self.source)
            .field("content_hash", &self.content_hash)
            .field("correlation_id", &self.correlation_id)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationAudit {
    pub(crate) id: AuditId,
    pub(crate) event_id: ConversationEventId,
    pub(crate) conversation_id: ConversationId,
    pub(crate) conversation_revision: Revision,
    pub(crate) correlation_id: CorrelationId,
}

impl ConversationAudit {
    #[must_use]
    pub const fn id(&self) -> AuditId {
        self.id
    }

    #[must_use]
    pub const fn event_id(&self) -> ConversationEventId {
        self.event_id
    }

    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    #[must_use]
    pub const fn conversation_revision(&self) -> Revision {
        self.conversation_revision
    }

    #[must_use]
    pub const fn correlation_id(&self) -> CorrelationId {
        self.correlation_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyResult {
    pub(crate) event_id: ConversationEventId,
    pub(crate) conversation_id: ConversationId,
    pub(crate) conversation_revision: Revision,
    pub(crate) correlation_id: CorrelationId,
}

impl IdempotencyResult {
    #[must_use]
    pub const fn event_id(&self) -> ConversationEventId {
        self.event_id
    }

    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    #[must_use]
    pub const fn conversation_revision(&self) -> Revision {
        self.conversation_revision
    }

    #[must_use]
    pub const fn correlation_id(&self) -> CorrelationId {
        self.correlation_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppendReceipt {
    pub event: ConversationEvent,
    pub outbox: OutboxEvent,
    pub audit: ConversationAudit,
    pub replayed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationError {
    EmptyContent,
    ContentTooLarge,
    NotFound,
    IdempotencyConflict,
    RevisionConflict,
    RevisionExhausted,
    CorruptStoredState,
    BackendFailure,
    #[cfg(test)]
    InjectedFailure,
}

impl fmt::Display for ConversationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyContent => "conversation content is empty",
            Self::ContentTooLarge => "conversation content exceeds the byte limit",
            Self::NotFound => "conversation record was not found",
            Self::IdempotencyConflict => "idempotency key conflicts with another request",
            Self::RevisionConflict => "conversation revision conflict",
            Self::RevisionExhausted => "conversation revision is exhausted",
            Self::CorruptStoredState => "conversation postcondition failed",
            Self::BackendFailure => "conversation storage is unavailable",
            #[cfg(test)]
            Self::InjectedFailure => "injected conversation storage failure",
        })
    }
}

impl Error for ConversationError {}

#[derive(Clone)]
pub(crate) struct PreparedAppend {
    pub(crate) auth: VerifiedAuthContext,
    pub(crate) command: AppendUserEvent,
    pub(crate) content_hash: ContentHash,
    pub(crate) fingerprint: RequestFingerprint,
}

pub struct ConversationRepository<'a> {
    store: &'a SqliteStore<ConversationStore>,
}

impl fmt::Debug for ConversationRepository<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConversationRepository")
            .finish_non_exhaustive()
    }
}

impl<'a> ConversationRepository<'a> {
    #[must_use]
    pub const fn new(store: &'a SqliteStore<ConversationStore>) -> Self {
        Self { store }
    }

    pub async fn append_user_event(
        &self,
        auth: &VerifiedAuthContext,
        command: AppendUserEvent,
    ) -> Result<AppendReceipt, ConversationError> {
        let prepared = prepare_append(auth, command)?;
        storage::conversation_records::append(self.store, prepared, ConversationAppendFault::None)
            .await
    }

    pub async fn read_conversation(
        &self,
        auth: &VerifiedAuthContext,
        id: ConversationId,
    ) -> Result<ConversationRecord, ConversationError> {
        storage::conversation_records::read_conversation(self.store, auth.clone(), id).await
    }

    pub async fn list_conversations(
        &self,
        auth: &VerifiedAuthContext,
    ) -> Result<Vec<ConversationRecord>, ConversationError> {
        storage::conversation_records::list_conversations(self.store, auth.clone()).await
    }

    pub async fn read_timeline(
        &self,
        auth: &VerifiedAuthContext,
        id: ConversationId,
    ) -> Result<ConversationTimeline, ConversationError> {
        storage::conversation_records::read_timeline(self.store, auth.clone(), id).await
    }

    pub async fn read_event(
        &self,
        auth: &VerifiedAuthContext,
        id: ConversationEventId,
    ) -> Result<ConversationEvent, ConversationError> {
        storage::conversation_records::read_event(self.store, auth.clone(), id).await
    }

    pub async fn read_outbox(
        &self,
        auth: &VerifiedAuthContext,
        id: OutboxId,
    ) -> Result<OutboxEvent, ConversationError> {
        storage::conversation_records::read_outbox(self.store, auth.clone(), id).await
    }

    pub async fn read_audit(
        &self,
        auth: &VerifiedAuthContext,
        id: AuditId,
    ) -> Result<ConversationAudit, ConversationError> {
        storage::conversation_records::read_audit(self.store, auth.clone(), id).await
    }

    pub async fn read_idempotency_result(
        &self,
        auth: &VerifiedAuthContext,
        key: IdempotencyKey,
    ) -> Result<IdempotencyResult, ConversationError> {
        storage::conversation_records::read_idempotency_result(self.store, auth.clone(), key).await
    }

    #[cfg(test)]
    async fn append_user_event_with_fault(
        &self,
        auth: &VerifiedAuthContext,
        command: AppendUserEvent,
        fault: ConversationAppendFault,
    ) -> Result<AppendReceipt, ConversationError> {
        let prepared = prepare_append(auth, command)?;
        storage::conversation_records::append(self.store, prepared, fault).await
    }

    #[cfg(test)]
    async fn test_row_counts(
        &self,
        auth: &VerifiedAuthContext,
    ) -> Result<(usize, usize, usize, usize, usize), ConversationError> {
        storage::conversation_records::test_row_counts(self.store, auth.clone()).await
    }

    #[cfg(test)]
    async fn test_connection_is_autocommit(&self) -> Result<bool, ConversationError> {
        storage::conversation_records::test_connection_is_autocommit(self.store).await
    }

    #[cfg(test)]
    async fn test_immutable_records_reject_mutation(
        &self,
        auth: &VerifiedAuthContext,
        receipt: &AppendReceipt,
        key: IdempotencyKey,
    ) -> Result<(), ConversationError> {
        storage::conversation_records::test_immutable_records_reject_mutation(
            self.store,
            auth.clone(),
            receipt.event.conversation_id(),
            receipt.event.id(),
            receipt.outbox.id(),
            receipt.audit.id(),
            key,
        )
        .await
    }
}

fn prepare_append(
    auth: &VerifiedAuthContext,
    command: AppendUserEvent,
) -> Result<PreparedAppend, ConversationError> {
    if command.content.is_empty() {
        return Err(ConversationError::EmptyContent);
    }
    if command.content.len() > MAX_USER_EVENT_CONTENT_BYTES {
        return Err(ConversationError::ContentTooLarge);
    }

    let content_hash = ContentHash(Sha256::digest(command.content.as_bytes()).into());
    let fingerprint = request_fingerprint(auth.owner_id(), &command);
    Ok(PreparedAppend {
        auth: auth.clone(),
        command,
        content_hash,
        fingerprint,
    })
}

fn request_fingerprint(owner_id: OwnerId, command: &AppendUserEvent) -> RequestFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(b"POV_CONVERSATION_APPEND_REQUEST");
    hasher.update([0, 1]);
    update_fingerprint_field(&mut hasher, b"owner", owner_id.as_uuid().as_bytes());
    update_fingerprint_field(
        &mut hasher,
        b"conversation",
        command.conversation_id.as_uuid().as_bytes(),
    );
    match command.expected_revision {
        Some(revision) => {
            update_fingerprint_field(&mut hasher, b"expected-kind", b"exact");
            update_fingerprint_field(
                &mut hasher,
                b"expected-revision",
                &revision.get().to_be_bytes(),
            );
        }
        None => update_fingerprint_field(&mut hasher, b"expected-kind", b"absent"),
    }
    update_fingerprint_field(
        &mut hasher,
        b"event-kind",
        ConversationEventKind::UserText.as_str().as_bytes(),
    );
    update_fingerprint_field(&mut hasher, b"content", command.content.as_bytes());
    RequestFingerprint(hasher.finalize().into())
}

fn update_fingerprint_field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

pub(crate) fn source_id_from_uuid(value: Uuid) -> Result<SourceId, ConversationError> {
    SourceId::from_uuid(value).ok_or(ConversationError::CorruptStoredState)
}

pub(crate) fn event_source(
    auth: &VerifiedAuthContext,
    event_id: ConversationEventId,
) -> Result<SourceRevision, ConversationError> {
    let source_id = source_id_from_uuid(event_id.as_uuid())?;
    Ok(auth.bind_source(
        SourceIdentity::from_parts(SourceDomain::Conversation, source_id),
        Revision::INITIAL,
    ))
}

pub(crate) fn conversation_source(
    auth: &VerifiedAuthContext,
    conversation_id: ConversationId,
    revision: Revision,
) -> Result<SourceRevision, ConversationError> {
    let source_id = source_id_from_uuid(conversation_id.as_uuid())?;
    Ok(auth.bind_source(
        SourceIdentity::from_parts(SourceDomain::Conversation, source_id),
        revision,
    ))
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;
    use uuid::Uuid;

    use crate::{
        identity::{Revision, VerifiedAuthContext},
        storage::{
            BackupHook, ConversationAppendFault, ConversationOperationGate, StoreError, StoreSet,
        },
    };

    use super::{
        AppendUserEvent, ConversationError, ConversationId, ConversationRepository, IdempotencyKey,
        MAX_USER_EVENT_CONTENT_BYTES, request_fingerprint,
    };

    fn command(
        conversation_id: ConversationId,
        idempotency_key: IdempotencyKey,
        expected_revision: Option<Revision>,
        content: &str,
    ) -> AppendUserEvent {
        AppendUserEvent {
            conversation_id,
            idempotency_key,
            expected_revision,
            content: content.to_owned(),
        }
    }

    #[tokio::test]
    async fn concurrent_retry_across_connections_returns_one_durable_event_and_outbox() {
        let directory = tempdir().expect("temporary store directory");
        let root = directory.path().join("stores");
        let left_stores = StoreSet::open(&root).await.expect("left stores open");
        let right_stores = StoreSet::open(&root).await.expect("right stores open");
        let left_repository = ConversationRepository::new(&left_stores.conversation);
        let right_repository = ConversationRepository::new(&right_stores.conversation);
        let owner = VerifiedAuthContext::synthetic(1);
        let append = command(
            ConversationId::new(),
            IdempotencyKey::new(),
            None,
            "synthetic private note",
        );

        let (left, right) = tokio::join!(
            left_repository.append_user_event(&owner, append.clone()),
            right_repository.append_user_event(&owner, append),
        );
        let left = left.expect("left append");
        let right = right.expect("right append");

        assert_eq!(left.event.source(), right.event.source());
        assert_eq!(left.outbox.id(), right.outbox.id());
        assert_eq!(left.audit.id(), right.audit.id());
        assert_ne!(left.replayed, right.replayed);
        assert_eq!(
            left_repository
                .test_row_counts(&owner)
                .await
                .expect("row counts"),
            (1, 1, 1, 1, 1)
        );
    }

    #[tokio::test]
    async fn reused_key_with_a_different_payload_conflicts_without_mutation() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let repository = ConversationRepository::new(&stores.conversation);
        let owner = VerifiedAuthContext::synthetic(1);
        let conversation_id = ConversationId::new();
        let idempotency_key = IdempotencyKey::new();

        let original = repository
            .append_user_event(
                &owner,
                command(conversation_id, idempotency_key, None, "original"),
            )
            .await
            .expect("original append");

        assert_eq!(
            repository
                .append_user_event(
                    &owner,
                    command(conversation_id, idempotency_key, None, "forged replacement",),
                )
                .await,
            Err(ConversationError::IdempotencyConflict)
        );
        assert_eq!(
            repository
                .read_event(&owner, original.event.id())
                .await
                .expect("original remains")
                .content(),
            "original"
        );
        assert_eq!(
            repository
                .test_row_counts(&owner)
                .await
                .expect("row counts"),
            (1, 1, 1, 1, 1)
        );
    }

    #[tokio::test]
    async fn every_read_surface_fails_closed_across_owners() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let repository = ConversationRepository::new(&stores.conversation);
        let owner = VerifiedAuthContext::synthetic(1);
        let other_owner = VerifiedAuthContext::synthetic(2);
        let append = command(
            ConversationId::new(),
            IdempotencyKey::new(),
            None,
            "owner one",
        );
        let receipt = repository
            .append_user_event(&owner, append.clone())
            .await
            .expect("owner append");

        assert_eq!(
            repository
                .read_conversation(&other_owner, append.conversation_id)
                .await,
            Err(ConversationError::NotFound)
        );
        assert_eq!(
            repository
                .read_event(&other_owner, receipt.event.id())
                .await,
            Err(ConversationError::NotFound)
        );
        assert_eq!(
            repository
                .read_outbox(&other_owner, receipt.outbox.id())
                .await,
            Err(ConversationError::NotFound)
        );
        assert_eq!(
            repository
                .read_audit(&other_owner, receipt.audit.id())
                .await,
            Err(ConversationError::NotFound)
        );
        assert_eq!(
            repository
                .read_idempotency_result(&other_owner, append.idempotency_key)
                .await,
            Err(ConversationError::NotFound)
        );

        let other_receipt = repository
            .append_user_event(&other_owner, append)
            .await
            .expect("same public IDs are independently owner scoped");
        assert_ne!(receipt.event.source(), other_receipt.event.source());
        assert_eq!(
            repository
                .test_row_counts(&owner)
                .await
                .expect("owner row counts"),
            (1, 1, 1, 1, 1)
        );
        assert_eq!(
            repository
                .test_row_counts(&other_owner)
                .await
                .expect("other owner row counts"),
            (1, 1, 1, 1, 1)
        );
    }

    #[tokio::test]
    async fn list_and_timeline_are_owner_scoped_and_revision_ordered() {
        let directory = tempfile::tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let repository = ConversationRepository::new(&stores.conversation);
        let owner = VerifiedAuthContext::synthetic(41);
        let other_owner = VerifiedAuthContext::synthetic(42);
        let conversation_id = ConversationId::new();

        let first = repository
            .append_user_event(
                &owner,
                command(
                    conversation_id,
                    IdempotencyKey::new(),
                    None,
                    "first stored event",
                ),
            )
            .await
            .expect("first append");
        repository
            .append_user_event(
                &owner,
                command(
                    conversation_id,
                    IdempotencyKey::new(),
                    Some(first.event.conversation_revision()),
                    "second stored event",
                ),
            )
            .await
            .expect("second append");

        let conversations = repository
            .list_conversations(&owner)
            .await
            .expect("owner list");
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].id(), conversation_id);
        assert_eq!(conversations[0].source().revision().get(), 2);

        let timeline = repository
            .read_timeline(&owner, conversation_id)
            .await
            .expect("owner timeline");
        assert_eq!(timeline.conversation().id(), conversation_id);
        assert_eq!(timeline.conversation().source().revision().get(), 2);
        assert_eq!(
            timeline
                .events()
                .iter()
                .map(|event| event.content())
                .collect::<Vec<_>>(),
            ["first stored event", "second stored event"]
        );
        assert_eq!(
            timeline
                .events()
                .iter()
                .map(|event| event.ordinal())
                .collect::<Vec<_>>(),
            [1, 2]
        );

        assert!(
            repository
                .list_conversations(&other_owner)
                .await
                .expect("other owner list")
                .is_empty()
        );
        assert_eq!(
            repository
                .read_timeline(&other_owner, conversation_id)
                .await,
            Err(ConversationError::NotFound)
        );

        stores.close().await.expect("stores close");
    }

    #[tokio::test]
    async fn injected_outbox_failure_rolls_back_the_whole_source_transaction() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let repository = ConversationRepository::new(&stores.conversation);
        let owner = VerifiedAuthContext::synthetic(1);
        let append = command(
            ConversationId::new(),
            IdempotencyKey::new(),
            None,
            "atomic append",
        );

        assert_eq!(
            repository
                .append_user_event_with_fault(
                    &owner,
                    append.clone(),
                    ConversationAppendFault::BeforeOutboxInsert,
                )
                .await,
            Err(ConversationError::InjectedFailure)
        );
        assert_eq!(
            repository
                .test_row_counts(&owner)
                .await
                .expect("rolled back counts"),
            (0, 0, 0, 0, 0)
        );

        let receipt = repository
            .append_user_event(&owner, append)
            .await
            .expect("retry after rollback");
        assert!(!receipt.replayed);
        assert_eq!(receipt.event.ordinal(), 1);
        assert!(
            repository
                .test_connection_is_autocommit()
                .await
                .expect("connection state")
        );
    }

    #[tokio::test]
    async fn reopen_preserves_receipt_and_actual_byte_hashes() {
        let directory = tempdir().expect("temporary store directory");
        let root = directory.path().join("stores");
        let stores = StoreSet::open(&root).await.expect("stores open");
        let owner = VerifiedAuthContext::synthetic(1);
        let append = command(
            ConversationId::new(),
            IdempotencyKey::new(),
            None,
            "persisted synthetic text",
        );
        let receipt = ConversationRepository::new(&stores.conversation)
            .append_user_event(&owner, append.clone())
            .await
            .expect("append");
        stores.close().await.expect("stores close");

        let reopened = StoreSet::open(&root).await.expect("stores reopen");
        let repository = ConversationRepository::new(&reopened.conversation);
        let replayed = repository
            .append_user_event(&owner, append.clone())
            .await
            .expect("replay after reopen");
        let event = repository
            .read_event(&owner, receipt.event.id())
            .await
            .expect("event after reopen");
        let outbox = repository
            .read_outbox(&owner, receipt.outbox.id())
            .await
            .expect("outbox after reopen");
        let idempotency = repository
            .read_idempotency_result(&owner, append.idempotency_key)
            .await
            .expect("idempotency result after reopen");

        assert!(replayed.replayed);
        assert_eq!(replayed.event.source(), receipt.event.source());
        assert_eq!(event.correlation_id(), receipt.event.correlation_id());
        assert_eq!(outbox.source(), event.source());
        assert_eq!(idempotency.event_id(), event.id());
        let expected_hash: [u8; 32] = Sha256::digest(append.content.as_bytes()).into();
        assert_eq!(event.content_hash().as_bytes(), &expected_hash);
        assert_eq!(
            repository
                .test_row_counts(&owner)
                .await
                .expect("persisted counts"),
            (1, 1, 1, 1, 1)
        );
    }

    #[tokio::test]
    async fn validation_rejects_empty_and_oversized_content_without_mutation() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let repository = ConversationRepository::new(&stores.conversation);
        let owner = VerifiedAuthContext::synthetic(1);

        assert_eq!(
            repository
                .append_user_event(
                    &owner,
                    command(ConversationId::new(), IdempotencyKey::new(), None, ""),
                )
                .await,
            Err(ConversationError::EmptyContent)
        );
        assert_eq!(
            repository
                .append_user_event(
                    &owner,
                    command(
                        ConversationId::new(),
                        IdempotencyKey::new(),
                        None,
                        &"x".repeat(MAX_USER_EVENT_CONTENT_BYTES + 1),
                    ),
                )
                .await,
            Err(ConversationError::ContentTooLarge)
        );
        assert_eq!(
            repository
                .test_row_counts(&owner)
                .await
                .expect("row counts"),
            (0, 0, 0, 0, 0)
        );
    }

    #[tokio::test]
    async fn exact_utf8_bytes_round_trip_without_sql_interpretation() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let repository = ConversationRepository::new(&stores.conversation);
        let owner = VerifiedAuthContext::synthetic(1);
        let content = " \n'; DROP TABLE conversation_events; --\0🦀 ";
        let receipt = repository
            .append_user_event(
                &owner,
                command(ConversationId::new(), IdempotencyKey::new(), None, content),
            )
            .await
            .expect("append");
        let stored = repository
            .read_event(&owner, receipt.event.id())
            .await
            .expect("read exact event");

        assert_eq!(stored.content().as_bytes(), content.as_bytes());
        assert_eq!(
            repository
                .test_row_counts(&owner)
                .await
                .expect("row counts"),
            (1, 1, 1, 1, 1)
        );
    }

    #[tokio::test]
    async fn expected_revision_allows_only_one_concurrent_next_append() {
        let directory = tempdir().expect("temporary store directory");
        let root = directory.path().join("stores");
        let left_stores = StoreSet::open(&root).await.expect("left stores open");
        let right_stores = StoreSet::open(&root).await.expect("right stores open");
        let left_repository = ConversationRepository::new(&left_stores.conversation);
        let right_repository = ConversationRepository::new(&right_stores.conversation);
        let owner = VerifiedAuthContext::synthetic(1);
        let conversation_id = ConversationId::new();
        let first = left_repository
            .append_user_event(
                &owner,
                command(conversation_id, IdempotencyKey::new(), None, "first"),
            )
            .await
            .expect("first append");
        let expected_revision = Some(first.event.conversation_revision());

        let (left, right) = tokio::join!(
            left_repository.append_user_event(
                &owner,
                command(
                    conversation_id,
                    IdempotencyKey::new(),
                    expected_revision,
                    "left",
                ),
            ),
            right_repository.append_user_event(
                &owner,
                command(
                    conversation_id,
                    IdempotencyKey::new(),
                    expected_revision,
                    "right",
                ),
            ),
        );

        assert_eq!(
            [left.is_ok(), right.is_ok()]
                .into_iter()
                .filter(|success| *success)
                .count(),
            1
        );
        assert_eq!(
            [left, right]
                .into_iter()
                .filter(|result| matches!(result, Err(ConversationError::RevisionConflict)))
                .count(),
            1
        );
        assert_eq!(
            left_repository
                .test_row_counts(&owner)
                .await
                .expect("row counts"),
            (1, 2, 2, 2, 2)
        );
    }

    #[tokio::test]
    async fn post_commit_readback_accepts_a_later_committed_revision() {
        let directory = tempdir().expect("temporary store directory");
        let root = directory.path().join("stores");
        let first_stores = StoreSet::open(&root).await.expect("first stores open");
        let second_stores = StoreSet::open(&root).await.expect("second stores open");
        let first_repository = ConversationRepository::new(&first_stores.conversation);
        let second_repository = ConversationRepository::new(&second_stores.conversation);
        let owner = VerifiedAuthContext::synthetic(1);
        let conversation_id = ConversationId::new();
        let gate = ConversationOperationGate::new();

        let first_append = first_repository.append_user_event_with_fault(
            &owner,
            command(conversation_id, IdempotencyKey::new(), None, "first"),
            ConversationAppendFault::PauseAfterCommitBeforeReadback(gate.clone()),
        );
        let advance_before_readback = async {
            let reached = gate.clone();
            tokio::task::spawn_blocking(move || reached.wait_until_paused())
                .await
                .expect("readback gate reached");
            let result = second_repository
                .append_user_event(
                    &owner,
                    command(
                        conversation_id,
                        IdempotencyKey::new(),
                        Some(Revision::INITIAL),
                        "second",
                    ),
                )
                .await;
            let resume = gate.clone();
            tokio::task::spawn_blocking(move || resume.resume())
                .await
                .expect("readback gate resumed");
            result
        };

        let (first, second) = tokio::join!(first_append, advance_before_readback);
        let first = first.expect("first append survives later revision");
        let second = second.expect("second append");

        assert_eq!(first.event.conversation_revision(), Revision::INITIAL);
        assert_eq!(
            second.event.conversation_revision(),
            Revision::new(2).expect("revision two")
        );
        assert_eq!(
            first_repository
                .test_row_counts(&owner)
                .await
                .expect("row counts"),
            (1, 2, 2, 2, 2)
        );
    }

    #[tokio::test]
    async fn old_idempotent_retry_precedes_newer_revision_validation() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let repository = ConversationRepository::new(&stores.conversation);
        let owner = VerifiedAuthContext::synthetic(1);
        let conversation_id = ConversationId::new();
        let first_command = command(conversation_id, IdempotencyKey::new(), None, "first");
        let first = repository
            .append_user_event(&owner, first_command.clone())
            .await
            .expect("first append");
        repository
            .append_user_event(
                &owner,
                command(
                    conversation_id,
                    IdempotencyKey::new(),
                    Some(first.event.conversation_revision()),
                    "second",
                ),
            )
            .await
            .expect("second append");

        let replayed = repository
            .append_user_event(&owner, first_command)
            .await
            .expect("old append replay");

        assert!(replayed.replayed);
        assert_eq!(replayed.event.id(), first.event.id());
        assert_eq!(replayed.event.source(), first.event.source());
        assert_eq!(
            repository
                .test_row_counts(&owner)
                .await
                .expect("row counts"),
            (1, 2, 2, 2, 2)
        );
    }

    #[test]
    fn append_debug_output_redacts_private_content_and_idempotency_key() {
        let command = command(
            ConversationId::new(),
            IdempotencyKey::new(),
            None,
            "never print this private text",
        );
        let key = command.idempotency_key.as_uuid().to_string();
        let rendered = format!("{command:?}");

        assert!(!rendered.contains("never print this private text"));
        assert!(!rendered.contains(&key));
    }

    #[tokio::test]
    async fn same_key_with_changed_target_or_expected_revision_conflicts() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let repository = ConversationRepository::new(&stores.conversation);
        let owner = VerifiedAuthContext::synthetic(1);
        let conversation_id = ConversationId::new();
        let key = IdempotencyKey::new();
        repository
            .append_user_event(
                &owner,
                command(conversation_id, key, None, "same exact content"),
            )
            .await
            .expect("original append");

        assert_eq!(
            repository
                .append_user_event(
                    &owner,
                    command(ConversationId::new(), key, None, "same exact content"),
                )
                .await,
            Err(ConversationError::IdempotencyConflict)
        );
        assert_eq!(
            repository
                .append_user_event(
                    &owner,
                    command(
                        conversation_id,
                        key,
                        Some(Revision::INITIAL),
                        "same exact content",
                    ),
                )
                .await,
            Err(ConversationError::IdempotencyConflict)
        );
        assert_eq!(
            repository
                .test_row_counts(&owner)
                .await
                .expect("row counts"),
            (1, 1, 1, 1, 1)
        );
    }

    #[tokio::test]
    async fn response_loss_after_commit_recovers_through_same_key_retry() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let repository = ConversationRepository::new(&stores.conversation);
        let owner = VerifiedAuthContext::synthetic(1);
        let append = command(
            ConversationId::new(),
            IdempotencyKey::new(),
            None,
            "committed before response loss",
        );

        assert_eq!(
            repository
                .append_user_event_with_fault(
                    &owner,
                    append.clone(),
                    ConversationAppendFault::AfterCommitBeforeReadback,
                )
                .await,
            Err(ConversationError::InjectedFailure)
        );
        let replayed = repository
            .append_user_event(&owner, append)
            .await
            .expect("retry recovers committed receipt");

        assert!(replayed.replayed);
        assert_eq!(
            repository
                .test_row_counts(&owner)
                .await
                .expect("row counts"),
            (1, 1, 1, 1, 1)
        );
    }

    #[tokio::test]
    async fn queued_store_operations_recheck_poison_until_reopened() {
        let directory = tempdir().expect("temporary store directory");
        let root = directory.path().join("stores");
        let stores = StoreSet::open(&root).await.expect("stores open");
        let repository = ConversationRepository::new(&stores.conversation);
        let owner = VerifiedAuthContext::synthetic(1);
        let gate = ConversationOperationGate::new();
        let backup = root.join("must-not-exist.backup");
        let append = command(
            ConversationId::new(),
            IdempotencyKey::new(),
            None,
            "must not reach a dirty writer",
        );

        let uncertain_append = repository.append_user_event_with_fault(
            &owner,
            append.clone(),
            ConversationAppendFault::PauseBeforeUncertainTransaction(gate.clone()),
        );
        let queued_operations = async {
            let reached = gate.clone();
            tokio::task::spawn_blocking(move || reached.wait_until_paused())
                .await
                .expect("uncertain gate reached");
            let report = stores.conversation.report();
            let backup_future = stores.conversation.backup_to_new_file(&backup);
            let release = async {
                tokio::task::yield_now().await;
                tokio::task::yield_now().await;
                let resume = gate.clone();
                tokio::task::spawn_blocking(move || resume.resume())
                    .await
                    .expect("uncertain gate resumed");
            };
            let (report, backup_result, ()) = tokio::join!(report, backup_future, release);
            (report, backup_result)
        };
        let (append_result, (report_result, backup_result)) =
            tokio::join!(uncertain_append, queued_operations);

        assert_eq!(append_result, Err(ConversationError::InjectedFailure));
        assert!(matches!(
            report_result,
            Err(StoreError::OperationPoisoned {
                kind: crate::storage::StoreKind::Conversation
            })
        ));
        assert!(matches!(
            backup_result,
            Err(StoreError::OperationPoisoned {
                kind: crate::storage::StoreKind::Conversation
            })
        ));
        assert!(!backup.exists());
        assert_eq!(
            repository.append_user_event(&owner, append).await,
            Err(ConversationError::BackendFailure)
        );
        stores.close().await.expect("poisoned stores close");

        let reopened = StoreSet::open(&root).await.expect("stores reopen");
        assert_eq!(
            ConversationRepository::new(&reopened.conversation)
                .test_row_counts(&owner)
                .await
                .expect("reopened counts"),
            (0, 0, 0, 0, 0)
        );
    }

    #[tokio::test]
    async fn append_only_tables_reject_update_delete_and_replace() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let repository = ConversationRepository::new(&stores.conversation);
        let owner = VerifiedAuthContext::synthetic(1);
        let key = IdempotencyKey::new();
        let receipt = repository
            .append_user_event(
                &owner,
                command(ConversationId::new(), key, None, "immutable"),
            )
            .await
            .expect("append");

        repository
            .test_immutable_records_reject_mutation(&owner, &receipt, key)
            .await
            .expect("immutable records reject mutation");
        assert_eq!(
            repository
                .read_event(&owner, receipt.event.id())
                .await
                .expect("event remains")
                .content(),
            "immutable"
        );
    }

    #[tokio::test]
    async fn receipt_debug_output_redacts_content_digest_and_internal_sequence() {
        let directory = tempdir().expect("temporary store directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let repository = ConversationRepository::new(&stores.conversation);
        let owner = VerifiedAuthContext::synthetic(1);
        let key = IdempotencyKey::new();
        let receipt = repository
            .append_user_event(
                &owner,
                command(
                    ConversationId::new(),
                    key,
                    None,
                    "private low entropy content",
                ),
            )
            .await
            .expect("append");
        let rendered = format!("{receipt:?}");

        assert!(!rendered.contains("private low entropy content"));
        assert!(!rendered.contains(&key.as_uuid().to_string()));
        assert!(!rendered.contains("dispatch_sequence"));
        assert!(rendered.contains("ContentHash(<redacted>)"));
    }

    #[test]
    fn request_fingerprint_has_a_stable_domain_separated_vector() {
        let owner = VerifiedAuthContext::synthetic(1);
        let conversation_id = ConversationId::from_uuid(
            Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                .expect("fixed v4 conversation ID"),
        )
        .expect("valid conversation ID");
        let command = command(
            conversation_id,
            IdempotencyKey::new(),
            Revision::new(7),
            "\nexact 🦀",
        );

        assert_eq!(
            request_fingerprint(owner.owner_id(), &command).as_bytes(),
            &[
                39, 144, 191, 171, 34, 120, 57, 19, 168, 175, 102, 138, 145, 4, 191, 182, 238, 75,
                193, 168, 204, 167, 136, 42, 27, 8, 57, 45, 105, 106, 155, 150,
            ]
        );
    }
}
