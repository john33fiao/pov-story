use std::{
    error::Error,
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    conversation::{IdempotencyKey, OutboxId},
    identity::{CorrelationId, Revision, VerifiedAuthContext},
    storage::{self, ConversationStore, SqliteStore},
};

const CONVERSATION_RESPONSE_MAX_ATTEMPTS: u16 = 3;
const CONVERSATION_RESPONSE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const CONVERSATION_RESPONSE_LEASE_DURATION: Duration = Duration::from_secs(30);
const CONVERSATION_RESPONSE_RETRY_BASE: Duration = Duration::from_secs(1);
const MAX_DURABLE_MICROS: u64 = i64::MAX as u64;

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

opaque_id!(JobId);
opaque_id!(JobAttemptId);
opaque_id!(JobEventId);

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JobEnqueueKey(Uuid);

impl JobEnqueueKey {
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

impl Default for JobEnqueueKey {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for JobEnqueueKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Debug for JobEnqueueKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JobEnqueueKey(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JobMutationKey(Uuid);

impl JobMutationKey {
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

impl Default for JobMutationKey {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for JobMutationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Debug for JobMutationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JobMutationKey(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct JobLeaseToken(Uuid);

impl JobLeaseToken {
    pub(crate) fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub(crate) const fn from_uuid(value: Uuid) -> Option<Self> {
        if matches!(value.get_version(), Some(uuid::Version::Random))
            && matches!(value.get_variant(), uuid::Variant::RFC4122)
        {
            Some(Self(value))
        } else {
            None
        }
    }

    pub(crate) const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Debug for JobLeaseToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JobLeaseToken(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JobTimestampMicros(u64);

impl JobTimestampMicros {
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        if value <= MAX_DURABLE_MICROS {
            Some(Self(value))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) fn checked_add(self, duration: Duration) -> Option<Self> {
        let micros = u64::try_from(duration.as_micros()).ok()?;
        self.0.checked_add(micros).and_then(Self::new)
    }

    pub(crate) fn checked_duration_since(self, earlier: Self) -> Option<u64> {
        self.0.checked_sub(earlier.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JobKind {
    ConversationResponseV1,
}

impl JobKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ConversationResponseV1 => "conversation_response_v1",
        }
    }

    pub(crate) fn from_str(value: &str) -> Option<Self> {
        match value {
            "conversation_response_v1" => Some(Self::ConversationResponseV1),
            _ => None,
        }
    }

    pub(crate) const fn priority(self) -> JobPriority {
        match self {
            Self::ConversationResponseV1 => JobPriority::Normal,
        }
    }

    pub(crate) const fn max_attempts(self) -> u16 {
        match self {
            Self::ConversationResponseV1 => CONVERSATION_RESPONSE_MAX_ATTEMPTS,
        }
    }

    pub(crate) const fn attempt_timeout(self) -> Duration {
        match self {
            Self::ConversationResponseV1 => CONVERSATION_RESPONSE_ATTEMPT_TIMEOUT,
        }
    }

    pub(crate) const fn lease_duration(self) -> Duration {
        match self {
            Self::ConversationResponseV1 => CONVERSATION_RESPONSE_LEASE_DURATION,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JobPriority {
    Normal,
}

impl JobPriority {
    pub(crate) const fn as_i64(self) -> i64 {
        match self {
            Self::Normal => 0,
        }
    }

    pub(crate) const fn from_i64(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Normal),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JobState {
    Queued,
    Leased,
    Running,
    CancelRequested,
    RetryScheduled,
    WaitingConfirmation,
    RecoveryRequired,
    Succeeded,
    Failed,
    Cancelled,
}

impl JobState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Leased => "leased",
            Self::Running => "running",
            Self::CancelRequested => "cancel_requested",
            Self::RetryScheduled => "retry_scheduled",
            Self::WaitingConfirmation => "waiting_confirmation",
            Self::RecoveryRequired => "recovery_required",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub(crate) fn from_str(value: &str) -> Option<Self> {
        match value {
            "queued" => Some(Self::Queued),
            "leased" => Some(Self::Leased),
            "running" => Some(Self::Running),
            "cancel_requested" => Some(Self::CancelRequested),
            "retry_scheduled" => Some(Self::RetryScheduled),
            "waiting_confirmation" => Some(Self::WaitingConfirmation),
            "recovery_required" => Some(Self::RecoveryRequired),
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JobAttemptState {
    Leased,
    Running,
    CancelRequested,
    RetryScheduled,
    WaitingConfirmation,
    RecoveryRequired,
    Succeeded,
    Failed,
    Cancelled,
    LeaseExpired,
}

impl JobAttemptState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Leased => "leased",
            Self::Running => "running",
            Self::CancelRequested => "cancel_requested",
            Self::RetryScheduled => "retry_scheduled",
            Self::WaitingConfirmation => "waiting_confirmation",
            Self::RecoveryRequired => "recovery_required",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::LeaseExpired => "lease_expired",
        }
    }

    pub(crate) fn from_str(value: &str) -> Option<Self> {
        match value {
            "leased" => Some(Self::Leased),
            "running" => Some(Self::Running),
            "cancel_requested" => Some(Self::CancelRequested),
            "retry_scheduled" => Some(Self::RetryScheduled),
            "waiting_confirmation" => Some(Self::WaitingConfirmation),
            "recovery_required" => Some(Self::RecoveryRequired),
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            "lease_expired" => Some(Self::LeaseExpired),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JobEventKind {
    Enqueued,
    Leased,
    Started,
    CancelRequested,
    Cancelled,
    RetryScheduled,
    WaitingConfirmation,
    ConfirmationResumed,
    Succeeded,
    Failed,
    LeaseExpired,
    RecoveryRequired,
    RecoveryResolved,
}

impl JobEventKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Enqueued => "enqueued",
            Self::Leased => "leased",
            Self::Started => "started",
            Self::CancelRequested => "cancel_requested",
            Self::Cancelled => "cancelled",
            Self::RetryScheduled => "retry_scheduled",
            Self::WaitingConfirmation => "waiting_confirmation",
            Self::ConfirmationResumed => "confirmation_resumed",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::LeaseExpired => "lease_expired",
            Self::RecoveryRequired => "recovery_required",
            Self::RecoveryResolved => "recovery_resolved",
        }
    }

    pub(crate) fn from_str(value: &str) -> Option<Self> {
        match value {
            "enqueued" => Some(Self::Enqueued),
            "leased" => Some(Self::Leased),
            "started" => Some(Self::Started),
            "cancel_requested" => Some(Self::CancelRequested),
            "cancelled" => Some(Self::Cancelled),
            "retry_scheduled" => Some(Self::RetryScheduled),
            "waiting_confirmation" => Some(Self::WaitingConfirmation),
            "confirmation_resumed" => Some(Self::ConfirmationResumed),
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            "lease_expired" => Some(Self::LeaseExpired),
            "recovery_required" => Some(Self::RecoveryRequired),
            "recovery_resolved" => Some(Self::RecoveryResolved),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JobFailureKind {
    ProviderUnavailable,
    Timeout,
    ExecutionFailed,
    LeaseExpired,
    CleanupUncertain,
}

impl JobFailureKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderUnavailable => "provider_unavailable",
            Self::Timeout => "timeout",
            Self::ExecutionFailed => "execution_failed",
            Self::LeaseExpired => "lease_expired",
            Self::CleanupUncertain => "cleanup_uncertain",
        }
    }

    pub(crate) fn from_str(value: &str) -> Option<Self> {
        match value {
            "provider_unavailable" => Some(Self::ProviderUnavailable),
            "timeout" => Some(Self::Timeout),
            "execution_failed" => Some(Self::ExecutionFailed),
            "lease_expired" => Some(Self::LeaseExpired),
            "cleanup_uncertain" => Some(Self::CleanupUncertain),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobOutcome {
    Succeeded,
    RetryableFailure(JobFailureKind),
    PermanentFailure(JobFailureKind),
    WaitingConfirmation,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryResolution {
    ConfirmedStoppedRetry,
    ConfirmedStoppedFail,
}

#[derive(Clone, Eq, PartialEq)]
pub struct EnqueueJob {
    pub source_outbox_id: OutboxId,
    pub kind: JobKind,
    pub idempotency_key: JobEnqueueKey,
}

impl fmt::Debug for EnqueueJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnqueueJob")
            .field("source_outbox_id", &self.source_outbox_id)
            .field("kind", &self.kind)
            .field("idempotency_key", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CancelJob {
    pub job_id: JobId,
    pub expected_revision: Revision,
    pub idempotency_key: JobMutationKey,
}

impl fmt::Debug for CancelJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CancelJob")
            .field("job_id", &self.job_id)
            .field("expected_revision", &self.expected_revision)
            .field("idempotency_key", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ResumeJob {
    pub job_id: JobId,
    pub expected_revision: Revision,
    pub idempotency_key: JobMutationKey,
}

impl fmt::Debug for ResumeJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResumeJob")
            .field("job_id", &self.job_id)
            .field("expected_revision", &self.expected_revision)
            .field("idempotency_key", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobSnapshot {
    pub(crate) id: JobId,
    pub(crate) source_outbox_id: OutboxId,
    pub(crate) kind: JobKind,
    pub(crate) priority: JobPriority,
    pub(crate) state: JobState,
    pub(crate) revision: Revision,
    pub(crate) attempts_started: u16,
    pub(crate) max_attempts: u16,
    pub(crate) enqueued_at: JobTimestampMicros,
    pub(crate) ready_at: JobTimestampMicros,
    pub(crate) first_started_at: Option<JobTimestampMicros>,
    pub(crate) terminal_at: Option<JobTimestampMicros>,
    pub(crate) queue_wait_micros: u64,
    pub(crate) execution_micros: u64,
    pub(crate) correlation_id: CorrelationId,
}

impl JobSnapshot {
    #[must_use]
    pub const fn id(&self) -> JobId {
        self.id
    }

    #[must_use]
    pub const fn source_outbox_id(&self) -> OutboxId {
        self.source_outbox_id
    }

    #[must_use]
    pub const fn kind(&self) -> JobKind {
        self.kind
    }

    #[must_use]
    pub const fn priority(&self) -> JobPriority {
        self.priority
    }

    #[must_use]
    pub const fn state(&self) -> JobState {
        self.state
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn attempts_started(&self) -> u16 {
        self.attempts_started
    }

    #[must_use]
    pub const fn max_attempts(&self) -> u16 {
        self.max_attempts
    }

    #[must_use]
    pub const fn enqueued_at(&self) -> JobTimestampMicros {
        self.enqueued_at
    }

    #[must_use]
    pub const fn ready_at(&self) -> JobTimestampMicros {
        self.ready_at
    }

    #[must_use]
    pub const fn first_started_at(&self) -> Option<JobTimestampMicros> {
        self.first_started_at
    }

    #[must_use]
    pub const fn terminal_at(&self) -> Option<JobTimestampMicros> {
        self.terminal_at
    }

    #[must_use]
    pub const fn queue_wait_micros(&self) -> u64 {
        self.queue_wait_micros
    }

    #[must_use]
    pub const fn execution_micros(&self) -> u64 {
        self.execution_micros
    }

    #[must_use]
    pub const fn correlation_id(&self) -> CorrelationId {
        self.correlation_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobAttemptSnapshot {
    pub(crate) id: JobAttemptId,
    pub(crate) job_id: JobId,
    pub(crate) attempt_number: u16,
    pub(crate) state: JobAttemptState,
    pub(crate) leased_at: JobTimestampMicros,
    pub(crate) started_at: Option<JobTimestampMicros>,
    pub(crate) lease_expires_at: JobTimestampMicros,
    pub(crate) attempt_deadline_at: JobTimestampMicros,
    pub(crate) finished_at: Option<JobTimestampMicros>,
    pub(crate) retry_at: Option<JobTimestampMicros>,
    pub(crate) queue_wait_micros: Option<u64>,
    pub(crate) execution_micros: Option<u64>,
    pub(crate) failure: Option<JobFailureKind>,
}

impl JobAttemptSnapshot {
    #[must_use]
    pub const fn id(&self) -> JobAttemptId {
        self.id
    }

    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    #[must_use]
    pub const fn attempt_number(&self) -> u16 {
        self.attempt_number
    }

    #[must_use]
    pub const fn state(&self) -> JobAttemptState {
        self.state
    }

    #[must_use]
    pub const fn leased_at(&self) -> JobTimestampMicros {
        self.leased_at
    }

    #[must_use]
    pub const fn started_at(&self) -> Option<JobTimestampMicros> {
        self.started_at
    }

    #[must_use]
    pub const fn lease_expires_at(&self) -> JobTimestampMicros {
        self.lease_expires_at
    }

    #[must_use]
    pub const fn attempt_deadline_at(&self) -> JobTimestampMicros {
        self.attempt_deadline_at
    }

    #[must_use]
    pub const fn finished_at(&self) -> Option<JobTimestampMicros> {
        self.finished_at
    }

    #[must_use]
    pub const fn retry_at(&self) -> Option<JobTimestampMicros> {
        self.retry_at
    }

    #[must_use]
    pub const fn queue_wait_micros(&self) -> Option<u64> {
        self.queue_wait_micros
    }

    #[must_use]
    pub const fn execution_micros(&self) -> Option<u64> {
        self.execution_micros
    }

    #[must_use]
    pub const fn failure(&self) -> Option<JobFailureKind> {
        self.failure
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobEvent {
    pub(crate) id: JobEventId,
    pub(crate) job_id: JobId,
    pub(crate) job_revision: Revision,
    pub(crate) kind: JobEventKind,
    pub(crate) state: JobState,
    pub(crate) attempt_id: Option<JobAttemptId>,
    pub(crate) happened_at: JobTimestampMicros,
    pub(crate) queue_wait_micros: Option<u64>,
    pub(crate) execution_micros: Option<u64>,
    pub(crate) failure: Option<JobFailureKind>,
    pub(crate) correlation_id: CorrelationId,
}

impl JobEvent {
    #[must_use]
    pub const fn id(&self) -> JobEventId {
        self.id
    }

    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    #[must_use]
    pub const fn job_revision(&self) -> Revision {
        self.job_revision
    }

    #[must_use]
    pub const fn kind(&self) -> JobEventKind {
        self.kind
    }

    #[must_use]
    pub const fn state(&self) -> JobState {
        self.state
    }

    #[must_use]
    pub const fn attempt_id(&self) -> Option<JobAttemptId> {
        self.attempt_id
    }

    #[must_use]
    pub const fn happened_at(&self) -> JobTimestampMicros {
        self.happened_at
    }

    #[must_use]
    pub const fn queue_wait_micros(&self) -> Option<u64> {
        self.queue_wait_micros
    }

    #[must_use]
    pub const fn execution_micros(&self) -> Option<u64> {
        self.execution_micros
    }

    #[must_use]
    pub const fn failure(&self) -> Option<JobFailureKind> {
        self.failure
    }

    #[must_use]
    pub const fn correlation_id(&self) -> CorrelationId {
        self.correlation_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnqueueReceipt {
    pub job: JobSnapshot,
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobTransitionReceipt {
    pub job: JobSnapshot,
    pub replayed: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct JobLease {
    pub(crate) job_id: JobId,
    pub(crate) attempt_id: JobAttemptId,
    pub(crate) attempt_number: u16,
    pub(crate) source_outbox_id: OutboxId,
    pub(crate) kind: JobKind,
    pub(crate) result_idempotency_key: IdempotencyKey,
    pub(crate) generation: u64,
    pub(crate) token: JobLeaseToken,
    pub(crate) state: JobAttemptState,
    pub(crate) lease_expires_at: JobTimestampMicros,
    pub(crate) attempt_deadline_at: JobTimestampMicros,
}

impl JobLease {
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    #[must_use]
    pub const fn attempt_id(&self) -> JobAttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn attempt_number(&self) -> u16 {
        self.attempt_number
    }

    #[must_use]
    pub const fn source_outbox_id(&self) -> OutboxId {
        self.source_outbox_id
    }

    #[must_use]
    pub const fn kind(&self) -> JobKind {
        self.kind
    }

    #[must_use]
    pub const fn lease_expires_at(&self) -> JobTimestampMicros {
        self.lease_expires_at
    }

    #[must_use]
    pub const fn state(&self) -> JobAttemptState {
        self.state
    }

    #[must_use]
    pub const fn attempt_deadline_at(&self) -> JobTimestampMicros {
        self.attempt_deadline_at
    }
}

impl fmt::Debug for JobLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobLease")
            .field("job_id", &self.job_id)
            .field("attempt_id", &self.attempt_id)
            .field("attempt_number", &self.attempt_number)
            .field("kind", &self.kind)
            .field("state", &self.state)
            .field("lease_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryTicket {
    pub(crate) job_id: JobId,
    pub(crate) attempt_id: JobAttemptId,
    pub(crate) attempt_number: u16,
    pub(crate) generation: u64,
    pub(crate) token: JobLeaseToken,
}

impl RecoveryTicket {
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    #[must_use]
    pub const fn attempt_id(&self) -> JobAttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn attempt_number(&self) -> u16 {
        self.attempt_number
    }
}

impl fmt::Debug for RecoveryTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryTicket")
            .field("job_id", &self.job_id)
            .field("attempt_id", &self.attempt_id)
            .field("attempt_number", &self.attempt_number)
            .field("lease_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimResult {
    Idle,
    Leased(JobLease),
    RecoveryRequired(RecoveryTicket),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobQueueError {
    NotFound,
    IdempotencyConflict,
    RevisionConflict,
    InvalidTransition,
    StaleLease,
    LeaseExpired,
    RecoveryRequired,
    ClockRegression,
    TimeOverflow,
    CorruptStoredState,
    BackendFailure,
    #[cfg(test)]
    InjectedFailure,
}

impl fmt::Display for JobQueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "job queue record was not found",
            Self::IdempotencyConflict => "job operation idempotency conflict",
            Self::RevisionConflict => "job revision conflict",
            Self::InvalidTransition => "job state transition is not allowed",
            Self::StaleLease => "job lease is stale",
            Self::LeaseExpired => "job lease is expired",
            Self::RecoveryRequired => "job queue requires confirmed recovery",
            Self::ClockRegression => "job queue clock regressed",
            Self::TimeOverflow => "job queue time is out of range",
            Self::CorruptStoredState => "job queue postcondition failed",
            Self::BackendFailure => "job queue storage is unavailable",
            #[cfg(test)]
            Self::InjectedFailure => "injected job queue storage failure",
        })
    }
}

impl Error for JobQueueError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JobQueueFault {
    None,
    #[cfg(test)]
    BeforeEnqueueLedger,
    #[cfg(test)]
    AfterClaimCommitBeforeReadback,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct EnqueueFingerprint([u8; 32]);

impl EnqueueFingerprint {
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct JobMutationFingerprint([u8; 32]);

impl JobMutationFingerprint {
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl fmt::Debug for JobMutationFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JobMutationFingerprint(<redacted>)")
    }
}

impl fmt::Debug for EnqueueFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnqueueFingerprint(<redacted>)")
    }
}

#[derive(Clone)]
pub(crate) struct PreparedEnqueue {
    pub(crate) auth: VerifiedAuthContext,
    pub(crate) command: EnqueueJob,
    pub(crate) fingerprint: EnqueueFingerprint,
    pub(crate) priority: JobPriority,
    pub(crate) max_attempts: u16,
    pub(crate) attempt_timeout: Duration,
    pub(crate) retry_base: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JobOwnerMutationOperation {
    Cancel,
    Resume,
}

impl JobOwnerMutationOperation {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Cancel => "cancel_job_v1",
            Self::Resume => "resume_job_v1",
        }
    }
}

#[derive(Clone)]
pub(crate) struct PreparedJobOwnerMutation {
    pub(crate) auth: VerifiedAuthContext,
    pub(crate) job_id: JobId,
    pub(crate) expected_revision: Revision,
    pub(crate) idempotency_key: JobMutationKey,
    pub(crate) operation: JobOwnerMutationOperation,
    pub(crate) fingerprint: JobMutationFingerprint,
}

pub(crate) trait JobClock: Send + Sync {
    fn now(&self) -> Result<JobTimestampMicros, JobQueueError>;
}

#[derive(Debug)]
struct SystemJobClock;

impl JobClock for SystemJobClock {
    fn now(&self) -> Result<JobTimestampMicros, JobQueueError> {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JobQueueError::TimeOverflow)?
            .as_micros();
        let micros = u64::try_from(micros).map_err(|_| JobQueueError::TimeOverflow)?;
        JobTimestampMicros::new(micros).ok_or(JobQueueError::TimeOverflow)
    }
}

pub struct JobQueueRepository<'a> {
    store: &'a SqliteStore<ConversationStore>,
    clock: Arc<dyn JobClock>,
}

impl fmt::Debug for JobQueueRepository<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobQueueRepository")
            .finish_non_exhaustive()
    }
}

impl<'a> JobQueueRepository<'a> {
    #[must_use]
    pub fn new(store: &'a SqliteStore<ConversationStore>) -> Self {
        Self {
            store,
            clock: Arc::new(SystemJobClock),
        }
    }

    pub async fn enqueue(
        &self,
        auth: &VerifiedAuthContext,
        command: EnqueueJob,
    ) -> Result<EnqueueReceipt, JobQueueError> {
        let prepared = prepare_enqueue(auth, command);
        let now = self.clock.now()?;
        storage::job_records::enqueue(self.store, prepared, now, JobQueueFault::None).await
    }

    pub async fn read_job(
        &self,
        auth: &VerifiedAuthContext,
        job_id: JobId,
    ) -> Result<JobSnapshot, JobQueueError> {
        storage::job_records::read_job(self.store, auth.clone(), job_id).await
    }

    pub async fn read_job_by_source(
        &self,
        auth: &VerifiedAuthContext,
        source_outbox_id: OutboxId,
        kind: JobKind,
    ) -> Result<JobSnapshot, JobQueueError> {
        storage::job_records::read_job_by_source(self.store, auth.clone(), source_outbox_id, kind)
            .await
    }

    pub async fn read_attempts(
        &self,
        auth: &VerifiedAuthContext,
        job_id: JobId,
    ) -> Result<Vec<JobAttemptSnapshot>, JobQueueError> {
        storage::job_records::read_attempts(self.store, auth.clone(), job_id).await
    }

    pub async fn read_events(
        &self,
        auth: &VerifiedAuthContext,
        job_id: JobId,
    ) -> Result<Vec<JobEvent>, JobQueueError> {
        storage::job_records::read_events(self.store, auth.clone(), job_id).await
    }

    pub async fn request_cancel(
        &self,
        auth: &VerifiedAuthContext,
        command: CancelJob,
    ) -> Result<JobTransitionReceipt, JobQueueError> {
        let prepared = prepare_cancel(auth, command);
        let now = self.clock.now()?;
        storage::job_records::request_cancel(self.store, prepared, now).await
    }

    pub async fn resume_after_confirmation(
        &self,
        auth: &VerifiedAuthContext,
        command: ResumeJob,
    ) -> Result<JobTransitionReceipt, JobQueueError> {
        let prepared = prepare_resume(auth, command);
        let now = self.clock.now()?;
        storage::job_records::resume_after_confirmation(self.store, prepared, now).await
    }

    #[must_use]
    pub fn dispatcher(&self) -> JobDispatcher<'a> {
        JobDispatcher {
            store: self.store,
            clock: Arc::clone(&self.clock),
        }
    }

    #[cfg(test)]
    fn with_clock(store: &'a SqliteStore<ConversationStore>, clock: Arc<dyn JobClock>) -> Self {
        Self { store, clock }
    }

    #[cfg(test)]
    async fn enqueue_with_fault(
        &self,
        auth: &VerifiedAuthContext,
        command: EnqueueJob,
        fault: JobQueueFault,
    ) -> Result<EnqueueReceipt, JobQueueError> {
        let prepared = prepare_enqueue(auth, command);
        let now = self.clock.now()?;
        storage::job_records::enqueue(self.store, prepared, now, fault).await
    }
}

pub struct JobDispatcher<'a> {
    store: &'a SqliteStore<ConversationStore>,
    clock: Arc<dyn JobClock>,
}

impl fmt::Debug for JobDispatcher<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobDispatcher")
            .finish_non_exhaustive()
    }
}

impl JobDispatcher<'_> {
    pub async fn claim_next(&self) -> Result<ClaimResult, JobQueueError> {
        let now = self.clock.now()?;
        storage::job_records::claim_next(self.store, now, JobQueueFault::None).await
    }

    pub async fn mark_running(&self, lease: &JobLease) -> Result<JobLease, JobQueueError> {
        let now = self.clock.now()?;
        storage::job_records::mark_running(self.store, lease.clone(), now).await
    }

    pub async fn renew(&self, lease: &JobLease) -> Result<JobLease, JobQueueError> {
        let now = self.clock.now()?;
        storage::job_records::renew(self.store, lease.clone(), now).await
    }

    pub async fn finish(
        &self,
        lease: &JobLease,
        outcome: JobOutcome,
    ) -> Result<JobTransitionReceipt, JobQueueError> {
        let now = self.clock.now()?;
        storage::job_records::finish(self.store, lease.clone(), outcome, now).await
    }

    pub async fn resolve_recovery(
        &self,
        ticket: &RecoveryTicket,
        resolution: RecoveryResolution,
    ) -> Result<JobTransitionReceipt, JobQueueError> {
        let now = self.clock.now()?;
        storage::job_records::resolve_recovery(self.store, ticket.clone(), resolution, now).await
    }

    #[cfg(test)]
    async fn claim_next_with_fault(
        &self,
        fault: JobQueueFault,
    ) -> Result<ClaimResult, JobQueueError> {
        let now = self.clock.now()?;
        storage::job_records::claim_next(self.store, now, fault).await
    }
}

fn prepare_enqueue(auth: &VerifiedAuthContext, command: EnqueueJob) -> PreparedEnqueue {
    let kind = command.kind;
    PreparedEnqueue {
        auth: auth.clone(),
        fingerprint: enqueue_fingerprint(auth, &command),
        command,
        priority: kind.priority(),
        max_attempts: kind.max_attempts(),
        attempt_timeout: kind.attempt_timeout(),
        retry_base: CONVERSATION_RESPONSE_RETRY_BASE,
    }
}

fn prepare_cancel(auth: &VerifiedAuthContext, command: CancelJob) -> PreparedJobOwnerMutation {
    prepare_owner_mutation(
        auth,
        command.job_id,
        command.expected_revision,
        command.idempotency_key,
        JobOwnerMutationOperation::Cancel,
    )
}

fn prepare_resume(auth: &VerifiedAuthContext, command: ResumeJob) -> PreparedJobOwnerMutation {
    prepare_owner_mutation(
        auth,
        command.job_id,
        command.expected_revision,
        command.idempotency_key,
        JobOwnerMutationOperation::Resume,
    )
}

fn prepare_owner_mutation(
    auth: &VerifiedAuthContext,
    job_id: JobId,
    expected_revision: Revision,
    idempotency_key: JobMutationKey,
    operation: JobOwnerMutationOperation,
) -> PreparedJobOwnerMutation {
    let mut hasher = Sha256::new();
    hasher.update(b"POV_JOB_OWNER_MUTATION_REQUEST");
    hasher.update([0, 1]);
    update_fingerprint_field(&mut hasher, b"owner", auth.owner_id().as_uuid().as_bytes());
    update_fingerprint_field(&mut hasher, b"operation", operation.as_str().as_bytes());
    update_fingerprint_field(&mut hasher, b"job", job_id.as_uuid().as_bytes());
    update_fingerprint_field(
        &mut hasher,
        b"expected-revision",
        &expected_revision.get().to_be_bytes(),
    );
    PreparedJobOwnerMutation {
        auth: auth.clone(),
        job_id,
        expected_revision,
        idempotency_key,
        operation,
        fingerprint: JobMutationFingerprint(hasher.finalize().into()),
    }
}

fn enqueue_fingerprint(auth: &VerifiedAuthContext, command: &EnqueueJob) -> EnqueueFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(b"POV_JOB_ENQUEUE_REQUEST");
    hasher.update([0, 1]);
    update_fingerprint_field(&mut hasher, b"owner", auth.owner_id().as_uuid().as_bytes());
    update_fingerprint_field(
        &mut hasher,
        b"source-outbox",
        command.source_outbox_id.as_uuid().as_bytes(),
    );
    update_fingerprint_field(&mut hasher, b"job-kind", command.kind.as_str().as_bytes());
    update_fingerprint_field(
        &mut hasher,
        b"priority",
        &command.kind.priority().as_i64().to_be_bytes(),
    );
    update_fingerprint_field(
        &mut hasher,
        b"max-attempts",
        &command.kind.max_attempts().to_be_bytes(),
    );
    update_fingerprint_field(
        &mut hasher,
        b"attempt-timeout-micros",
        &duration_micros(command.kind.attempt_timeout())
            .unwrap_or(MAX_DURABLE_MICROS)
            .to_be_bytes(),
    );
    update_fingerprint_field(
        &mut hasher,
        b"retry-base-micros",
        &duration_micros(CONVERSATION_RESPONSE_RETRY_BASE)
            .unwrap_or(MAX_DURABLE_MICROS)
            .to_be_bytes(),
    );
    EnqueueFingerprint(hasher.finalize().into())
}

fn update_fingerprint_field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

pub(crate) fn duration_micros(duration: Duration) -> Option<u64> {
    u64::try_from(duration.as_micros())
        .ok()
        .filter(|value| *value <= MAX_DURABLE_MICROS)
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        process::{Command, Stdio},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };

    use tempfile::tempdir;

    use crate::{
        conversation::{
            AppendUserEvent, ConversationId, ConversationRepository, IdempotencyKey, OutboxId,
        },
        identity::{Revision, VerifiedAuthContext},
        storage::StoreSet,
    };

    use super::{
        CancelJob, ClaimResult, EnqueueFingerprint, EnqueueJob, JobAttemptState, JobClock,
        JobEnqueueKey, JobEventKind, JobFailureKind, JobKind, JobLease, JobLeaseToken,
        JobMutationKey, JobOutcome, JobQueueError, JobQueueFault, JobQueueRepository, JobState,
        JobTimestampMicros, RecoveryResolution, RecoveryTicket, ResumeJob,
    };

    const SECOND: u64 = 1_000_000;
    const START: u64 = 10 * SECOND;
    const MULTIPROCESS_ROOT_ENV: &str = "POV_JOB_QUEUE_TEST_ROOT";
    const MULTIPROCESS_START_ENV: &str = "POV_JOB_QUEUE_TEST_START";
    const MULTIPROCESS_RESULT_ENV: &str = "POV_JOB_QUEUE_TEST_RESULT";

    #[derive(Debug)]
    struct ManualClock {
        now_micros: AtomicU64,
    }

    impl ManualClock {
        fn new(now_micros: u64) -> Self {
            Self {
                now_micros: AtomicU64::new(now_micros),
            }
        }

        fn set(&self, now_micros: u64) {
            self.now_micros.store(now_micros, Ordering::SeqCst);
        }

        fn advance(&self, micros: u64) {
            self.now_micros.fetch_add(micros, Ordering::SeqCst);
        }
    }

    impl JobClock for ManualClock {
        fn now(&self) -> Result<JobTimestampMicros, JobQueueError> {
            JobTimestampMicros::new(self.now_micros.load(Ordering::SeqCst))
                .ok_or(JobQueueError::TimeOverflow)
        }
    }

    fn queue_with_clock<'a>(
        stores: &'a StoreSet,
        clock: &Arc<ManualClock>,
    ) -> JobQueueRepository<'a> {
        JobQueueRepository::with_clock(&stores.conversation, clock.clone())
    }

    fn enqueue_command(source_outbox_id: OutboxId, idempotency_key: JobEnqueueKey) -> EnqueueJob {
        EnqueueJob {
            source_outbox_id,
            kind: JobKind::ConversationResponseV1,
            idempotency_key,
        }
    }

    fn cancel_command(job_id: super::JobId, expected_revision: Revision) -> CancelJob {
        CancelJob {
            job_id,
            expected_revision,
            idempotency_key: JobMutationKey::new(),
        }
    }

    async fn append_outbox(
        stores: &StoreSet,
        owner: &VerifiedAuthContext,
        content: &str,
    ) -> OutboxId {
        ConversationRepository::new(&stores.conversation)
            .append_user_event(
                owner,
                AppendUserEvent {
                    conversation_id: ConversationId::new(),
                    expected_revision: None,
                    idempotency_key: IdempotencyKey::new(),
                    content: content.to_owned(),
                },
            )
            .await
            .expect("synthetic source append")
            .outbox
            .id()
    }

    async fn claim_lease(queue: &JobQueueRepository<'_>) -> JobLease {
        match queue
            .dispatcher()
            .claim_next()
            .await
            .expect("claim succeeds")
        {
            ClaimResult::Leased(lease) => lease,
            other => panic!("expected leased job, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn enqueue_replay_conflict_and_cross_owner_access_fail_closed() {
        let directory = tempdir().expect("temporary directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let clock = Arc::new(ManualClock::new(START));
        let queue = queue_with_clock(&stores, &clock);
        let owner = VerifiedAuthContext::synthetic(1);
        let other_owner = VerifiedAuthContext::synthetic(2);
        let first_outbox = append_outbox(&stores, &owner, "first source").await;
        let second_outbox = append_outbox(&stores, &owner, "second source").await;
        let key = JobEnqueueKey::new();
        let command = enqueue_command(first_outbox, key);

        let first = queue
            .enqueue(&owner, command.clone())
            .await
            .expect("first enqueue");
        let replay = queue
            .enqueue(&owner, command)
            .await
            .expect("enqueue replay");
        assert!(!first.replayed);
        assert!(replay.replayed);
        assert_eq!(first.job.id(), replay.job.id());
        assert_eq!(
            queue
                .enqueue(&owner, enqueue_command(second_outbox, key))
                .await,
            Err(JobQueueError::IdempotencyConflict)
        );
        assert_eq!(
            queue
                .enqueue(&owner, enqueue_command(first_outbox, JobEnqueueKey::new()))
                .await,
            Err(JobQueueError::IdempotencyConflict)
        );

        assert_eq!(
            queue
                .enqueue(&other_owner, enqueue_command(first_outbox, key))
                .await,
            Err(JobQueueError::NotFound)
        );
        assert_eq!(
            queue.read_job(&other_owner, first.job.id()).await,
            Err(JobQueueError::NotFound)
        );
        assert_eq!(
            queue.read_attempts(&other_owner, first.job.id()).await,
            Err(JobQueueError::NotFound)
        );
        assert_eq!(
            queue.read_events(&other_owner, first.job.id()).await,
            Err(JobQueueError::NotFound)
        );
        assert_eq!(
            queue
                .request_cancel(
                    &other_owner,
                    cancel_command(first.job.id(), first.job.revision()),
                )
                .await,
            Err(JobQueueError::NotFound)
        );
        let events = queue
            .read_events(&owner, first.job.id())
            .await
            .expect("owner events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind(), JobEventKind::Enqueued);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fifo_and_singleton_claim_hold_across_independent_store_handles() {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("stores");
        let left_stores = StoreSet::open(&root).await.expect("left stores open");
        let right_stores = StoreSet::open(&root).await.expect("right stores open");
        let clock = Arc::new(ManualClock::new(START));
        let left = queue_with_clock(&left_stores, &clock);
        let right = queue_with_clock(&right_stores, &clock);
        let owner = VerifiedAuthContext::synthetic(1);

        let mut jobs = Vec::new();
        for content in ["fifo one", "fifo two", "fifo three"] {
            let outbox = append_outbox(&left_stores, &owner, content).await;
            jobs.push(
                left.enqueue(&owner, enqueue_command(outbox, JobEnqueueKey::new()))
                    .await
                    .expect("enqueue fifo job")
                    .job,
            );
        }

        let left_dispatcher = left.dispatcher();
        let right_dispatcher = right.dispatcher();
        let (left_claim, right_claim) =
            tokio::join!(left_dispatcher.claim_next(), right_dispatcher.claim_next());
        let claims = [
            left_claim.expect("left claim"),
            right_claim.expect("right claim"),
        ];
        let first_lease = claims
            .iter()
            .find_map(|claim| match claim {
                ClaimResult::Leased(lease) => Some(lease.clone()),
                ClaimResult::Idle => None,
                ClaimResult::RecoveryRequired(_) => panic!("unexpected recovery"),
            })
            .expect("one claimant gets the singleton slot");
        assert_eq!(
            claims
                .iter()
                .filter(|claim| matches!(claim, ClaimResult::Leased(_)))
                .count(),
            1
        );
        assert_eq!(
            claims
                .iter()
                .filter(|claim| matches!(claim, ClaimResult::Idle))
                .count(),
            1
        );
        assert_eq!(first_lease.job_id(), jobs[0].id());

        let first = left
            .read_job(&owner, jobs[0].id())
            .await
            .expect("first leased job");
        left.request_cancel(&owner, cancel_command(first.id(), first.revision()))
            .await
            .expect("cancel first lease");
        let second_lease = claim_lease(&right).await;
        assert_eq!(second_lease.job_id(), jobs[1].id());
        let second = right
            .read_job(&owner, jobs[1].id())
            .await
            .expect("second leased job");
        right
            .request_cancel(&owner, cancel_command(second.id(), second.revision()))
            .await
            .expect("cancel second lease");
        let third_lease = claim_lease(&left).await;
        assert_eq!(third_lease.job_id(), jobs[2].id());
    }

    #[tokio::test]
    async fn singleton_claim_is_enforced_across_processes() {
        if let (Ok(root), Ok(start), Ok(result)) = (
            env::var(MULTIPROCESS_ROOT_ENV),
            env::var(MULTIPROCESS_START_ENV),
            env::var(MULTIPROCESS_RESULT_ENV),
        ) {
            for _ in 0..500 {
                if std::path::Path::new(&start).exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(
                std::path::Path::new(&start).exists(),
                "parent start barrier must appear"
            );
            let stores = StoreSet::open(root).await.expect("child stores open");
            let result_text = match JobQueueRepository::new(&stores.conversation)
                .dispatcher()
                .claim_next()
                .await
                .expect("child claim")
            {
                ClaimResult::Leased(_) => "leased",
                ClaimResult::Idle => "idle",
                ClaimResult::RecoveryRequired(_) => panic!("unexpected recovery"),
            };
            fs::write(result, result_text).expect("write child claim result");
            stores.close().await.expect("child stores close");
            return;
        }

        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("stores");
        let stores = StoreSet::open(&root).await.expect("parent stores open");
        let clock = Arc::new(ManualClock::new(START));
        let queue = queue_with_clock(&stores, &clock);
        let owner = VerifiedAuthContext::synthetic(1);
        for content in ["process one", "process two"] {
            let outbox = append_outbox(&stores, &owner, content).await;
            queue
                .enqueue(&owner, enqueue_command(outbox, JobEnqueueKey::new()))
                .await
                .expect("enqueue multiprocess job");
        }
        drop(queue);
        stores.close().await.expect("parent stores close");

        let start = directory.path().join("start");
        let left_result = directory.path().join("left-result");
        let right_result = directory.path().join("right-result");
        let executable = env::current_exe().expect("current test executable");
        let spawn_child = |result: &std::path::Path| {
            Command::new(&executable)
                .args([
                    "--exact",
                    "job::tests::singleton_claim_is_enforced_across_processes",
                    "--test-threads=1",
                    "--no-capture",
                ])
                .env(MULTIPROCESS_ROOT_ENV, &root)
                .env(MULTIPROCESS_START_ENV, &start)
                .env(MULTIPROCESS_RESULT_ENV, result)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn queue claimant")
        };
        let left = spawn_child(&left_result);
        let right = spawn_child(&right_result);
        fs::write(&start, b"go").expect("release child claimants");
        let left_output = left.wait_with_output().expect("left claimant output");
        let right_output = right.wait_with_output().expect("right claimant output");
        assert!(
            left_output.status.success(),
            "left claimant failed: {}",
            String::from_utf8_lossy(&left_output.stderr)
        );
        assert!(
            right_output.status.success(),
            "right claimant failed: {}",
            String::from_utf8_lossy(&right_output.stderr)
        );
        let results = [
            fs::read_to_string(left_result).expect("left result"),
            fs::read_to_string(right_result).expect("right result"),
        ];
        assert_eq!(
            results
                .iter()
                .filter(|result| result.as_str() == "leased")
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| result.as_str() == "idle")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn expired_unstarted_lease_retries_and_fences_the_old_capability() {
        let directory = tempdir().expect("temporary directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let clock = Arc::new(ManualClock::new(START));
        let queue = queue_with_clock(&stores, &clock);
        let dispatcher = queue.dispatcher();
        let owner = VerifiedAuthContext::synthetic(1);
        let outbox = append_outbox(&stores, &owner, "lease expiry").await;
        let job = queue
            .enqueue(&owner, enqueue_command(outbox, JobEnqueueKey::new()))
            .await
            .expect("enqueue")
            .job;
        let old_lease = claim_lease(&queue).await;

        clock.set(old_lease.lease_expires_at().get());
        assert_eq!(
            dispatcher.claim_next().await.expect("expiry recovery"),
            ClaimResult::Idle
        );
        let retrying = queue
            .read_job(&owner, job.id())
            .await
            .expect("retrying job");
        assert_eq!(retrying.state(), JobState::RetryScheduled);
        let attempts = queue
            .read_attempts(&owner, job.id())
            .await
            .expect("expired attempt");
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].state(), JobAttemptState::LeaseExpired);

        clock.advance(SECOND);
        let new_lease = claim_lease(&queue).await;
        assert_eq!(new_lease.job_id(), job.id());
        assert_eq!(new_lease.attempt_number(), 2);
        assert_eq!(
            new_lease.result_idempotency_key,
            old_lease.result_idempotency_key
        );
        assert_eq!(
            dispatcher.renew(&old_lease).await,
            Err(JobQueueError::StaleLease)
        );
        assert_eq!(
            dispatcher.mark_running(&old_lease).await,
            Err(JobQueueError::StaleLease)
        );
        assert_eq!(
            dispatcher.finish(&old_lease, JobOutcome::Succeeded).await,
            Err(JobQueueError::StaleLease)
        );
    }

    #[tokio::test]
    async fn running_expiry_halts_claims_until_explicit_recovery_resolution() {
        let directory = tempdir().expect("temporary directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let clock = Arc::new(ManualClock::new(START));
        let queue = queue_with_clock(&stores, &clock);
        let dispatcher = queue.dispatcher();
        let owner = VerifiedAuthContext::synthetic(1);
        let first_outbox = append_outbox(&stores, &owner, "running recovery").await;
        let second_outbox = append_outbox(&stores, &owner, "blocked follower").await;
        let first_job = queue
            .enqueue(&owner, enqueue_command(first_outbox, JobEnqueueKey::new()))
            .await
            .expect("enqueue first")
            .job;
        let second_job = queue
            .enqueue(&owner, enqueue_command(second_outbox, JobEnqueueKey::new()))
            .await
            .expect("enqueue second")
            .job;
        let lease = claim_lease(&queue).await;
        let running = dispatcher.mark_running(&lease).await.expect("mark running");

        clock.set(running.lease_expires_at().get());
        assert_eq!(
            dispatcher.renew(&running).await,
            Err(JobQueueError::LeaseExpired)
        );
        let ticket = match dispatcher
            .claim_next()
            .await
            .expect("detect expired running attempt")
        {
            ClaimResult::RecoveryRequired(ticket) => ticket,
            other => panic!("expected recovery ticket, got {other:?}"),
        };
        assert_eq!(ticket.job_id(), first_job.id());
        assert_eq!(
            dispatcher
                .claim_next()
                .await
                .expect("recovery stays halted"),
            ClaimResult::RecoveryRequired(ticket.clone())
        );
        assert_eq!(
            queue
                .read_job(&owner, second_job.id())
                .await
                .expect("follower remains queued")
                .state(),
            JobState::Queued
        );
        assert_eq!(
            dispatcher.finish(&running, JobOutcome::Succeeded).await,
            Err(JobQueueError::StaleLease)
        );

        let resolved = dispatcher
            .resolve_recovery(&ticket, RecoveryResolution::ConfirmedStoppedRetry)
            .await
            .expect("explicit recovery resolution");
        assert_eq!(resolved.job.state(), JobState::RetryScheduled);
        let replay = dispatcher
            .resolve_recovery(&ticket, RecoveryResolution::ConfirmedStoppedRetry)
            .await
            .expect("resolution replay");
        assert!(replay.replayed);
        clock.advance(SECOND);
        let retried = claim_lease(&queue).await;
        assert_eq!(retried.job_id(), first_job.id());
        assert_eq!(retried.attempt_number(), 2);
    }

    #[tokio::test]
    async fn cancellation_handles_queued_leased_running_and_waiting_states() {
        let directory = tempdir().expect("temporary directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let clock = Arc::new(ManualClock::new(START));
        let queue = queue_with_clock(&stores, &clock);
        let dispatcher = queue.dispatcher();
        let owner = VerifiedAuthContext::synthetic(1);
        let mut jobs = Vec::new();
        for content in [
            "cancel queued",
            "cancel leased",
            "cancel running",
            "cancel waiting",
        ] {
            let outbox = append_outbox(&stores, &owner, content).await;
            jobs.push(
                queue
                    .enqueue(&owner, enqueue_command(outbox, JobEnqueueKey::new()))
                    .await
                    .expect("enqueue cancellable job")
                    .job,
            );
        }

        let queued_cancel = queue
            .request_cancel(&owner, cancel_command(jobs[0].id(), jobs[0].revision()))
            .await
            .expect("cancel queued");
        assert_eq!(queued_cancel.job.state(), JobState::Cancelled);
        assert_eq!(queued_cancel.job.attempts_started(), 0);

        let leased = claim_lease(&queue).await;
        assert_eq!(leased.job_id(), jobs[1].id());
        let leased_job = queue
            .read_job(&owner, jobs[1].id())
            .await
            .expect("leased job");
        let leased_cancel = queue
            .request_cancel(
                &owner,
                cancel_command(leased_job.id(), leased_job.revision()),
            )
            .await
            .expect("cancel leased");
        assert_eq!(leased_cancel.job.state(), JobState::Cancelled);
        assert_eq!(
            queue
                .read_attempts(&owner, leased_job.id())
                .await
                .expect("leased cancellation attempt")[0]
                .state(),
            JobAttemptState::Cancelled
        );

        let running_lease = claim_lease(&queue).await;
        assert_eq!(running_lease.job_id(), jobs[2].id());
        let running_lease = dispatcher
            .mark_running(&running_lease)
            .await
            .expect("mark running");
        let running_job = queue
            .read_job(&owner, jobs[2].id())
            .await
            .expect("running job");
        let cancel_requested = queue
            .request_cancel(
                &owner,
                cancel_command(running_job.id(), running_job.revision()),
            )
            .await
            .expect("request running cancellation");
        assert_eq!(cancel_requested.job.state(), JobState::CancelRequested);
        assert_eq!(
            dispatcher.claim_next().await.expect("slot remains held"),
            ClaimResult::Idle
        );
        let running_cancel = dispatcher
            .finish(&running_lease, JobOutcome::Cancelled)
            .await
            .expect("cleanup acknowledgement");
        assert_eq!(running_cancel.job.state(), JobState::Cancelled);

        let waiting_lease = claim_lease(&queue).await;
        assert_eq!(waiting_lease.job_id(), jobs[3].id());
        let waiting_lease = dispatcher
            .mark_running(&waiting_lease)
            .await
            .expect("mark waiting candidate running");
        let waiting = dispatcher
            .finish(&waiting_lease, JobOutcome::WaitingConfirmation)
            .await
            .expect("enter waiting confirmation");
        assert_eq!(waiting.job.state(), JobState::WaitingConfirmation);
        assert_eq!(
            dispatcher
                .claim_next()
                .await
                .expect("waiting holds no slot"),
            ClaimResult::Idle
        );
        let waiting_cancel = queue
            .request_cancel(
                &owner,
                cancel_command(waiting.job.id(), waiting.job.revision()),
            )
            .await
            .expect("cancel waiting");
        assert_eq!(waiting_cancel.job.state(), JobState::Cancelled);
    }

    #[tokio::test]
    async fn retry_backoff_is_durable_and_max_attempts_is_terminal() {
        let directory = tempdir().expect("temporary directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let clock = Arc::new(ManualClock::new(START));
        let queue = queue_with_clock(&stores, &clock);
        let dispatcher = queue.dispatcher();
        let owner = VerifiedAuthContext::synthetic(1);
        let outbox = append_outbox(&stores, &owner, "retry timing").await;
        let job = queue
            .enqueue(&owner, enqueue_command(outbox, JobEnqueueKey::new()))
            .await
            .expect("enqueue")
            .job;

        for (attempt_number, backoff) in [(1, SECOND), (2, 2 * SECOND)] {
            let lease = claim_lease(&queue).await;
            assert_eq!(lease.attempt_number(), attempt_number);
            let lease = dispatcher
                .mark_running(&lease)
                .await
                .expect("mark retry attempt running");
            clock.advance(100);
            let retry = dispatcher
                .finish(
                    &lease,
                    JobOutcome::RetryableFailure(JobFailureKind::ProviderUnavailable),
                )
                .await
                .expect("schedule retry");
            assert_eq!(retry.job.state(), JobState::RetryScheduled);
            assert_eq!(
                dispatcher.claim_next().await.expect("not due yet"),
                ClaimResult::Idle
            );
            clock.advance(backoff - 1);
            assert_eq!(
                dispatcher.claim_next().await.expect("still not due"),
                ClaimResult::Idle
            );
            clock.advance(1);
        }

        let final_lease = claim_lease(&queue).await;
        assert_eq!(final_lease.attempt_number(), 3);
        let final_lease = dispatcher
            .mark_running(&final_lease)
            .await
            .expect("mark final attempt running");
        clock.advance(100);
        let terminal = dispatcher
            .finish(
                &final_lease,
                JobOutcome::RetryableFailure(JobFailureKind::ProviderUnavailable),
            )
            .await
            .expect("retry exhaustion becomes terminal");
        assert_eq!(terminal.job.state(), JobState::Failed);
        assert_eq!(terminal.job.attempts_started(), 3);
        assert_eq!(
            dispatcher.claim_next().await.expect("nothing remains"),
            ClaimResult::Idle
        );
        let attempts = queue
            .read_attempts(&owner, job.id())
            .await
            .expect("attempt history");
        assert_eq!(
            attempts
                .iter()
                .map(|attempt| attempt.state())
                .collect::<Vec<_>>(),
            vec![
                JobAttemptState::RetryScheduled,
                JobAttemptState::RetryScheduled,
                JobAttemptState::Failed
            ]
        );
    }

    #[tokio::test]
    async fn queue_wait_and_execution_time_are_recorded_separately() {
        let directory = tempdir().expect("temporary directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let clock = Arc::new(ManualClock::new(START));
        let queue = queue_with_clock(&stores, &clock);
        let dispatcher = queue.dispatcher();
        let owner = VerifiedAuthContext::synthetic(1);
        let outbox = append_outbox(&stores, &owner, "timing source").await;
        let job = queue
            .enqueue(&owner, enqueue_command(outbox, JobEnqueueKey::new()))
            .await
            .expect("enqueue")
            .job;

        clock.advance(5 * SECOND);
        let lease = claim_lease(&queue).await;
        clock.advance(2 * SECOND);
        let lease = dispatcher.mark_running(&lease).await.expect("mark running");
        clock.advance(3 * SECOND);
        let finished = dispatcher
            .finish(&lease, JobOutcome::Succeeded)
            .await
            .expect("finish success");

        assert_eq!(finished.job.queue_wait_micros(), 7 * SECOND);
        assert_eq!(finished.job.execution_micros(), 3 * SECOND);
        let attempts = queue
            .read_attempts(&owner, job.id())
            .await
            .expect("attempt timing");
        assert_eq!(attempts[0].queue_wait_micros(), Some(7 * SECOND));
        assert_eq!(attempts[0].execution_micros(), Some(3 * SECOND));
        let events = queue
            .read_events(&owner, job.id())
            .await
            .expect("timing events");
        let started = events
            .iter()
            .find(|event| event.kind == JobEventKind::Started)
            .expect("started event");
        let succeeded = events
            .iter()
            .find(|event| event.kind == JobEventKind::Succeeded)
            .expect("succeeded event");
        assert_eq!(started.queue_wait_micros, Some(7 * SECOND));
        assert_eq!(started.execution_micros, None);
        assert_eq!(succeeded.queue_wait_micros, None);
        assert_eq!(succeeded.execution_micros, Some(3 * SECOND));
    }

    #[tokio::test]
    async fn retry_state_attempts_and_events_survive_reopen() {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("stores");
        let clock = Arc::new(ManualClock::new(START));
        let owner = VerifiedAuthContext::synthetic(1);

        let stores = StoreSet::open(&root).await.expect("stores open");
        let queue = queue_with_clock(&stores, &clock);
        let dispatcher = queue.dispatcher();
        let outbox = append_outbox(&stores, &owner, "reopen source").await;
        let job = queue
            .enqueue(&owner, enqueue_command(outbox, JobEnqueueKey::new()))
            .await
            .expect("enqueue")
            .job;
        let lease = claim_lease(&queue).await;
        let lease = dispatcher.mark_running(&lease).await.expect("mark running");
        let result_idempotency_key = lease.result_idempotency_key;
        clock.advance(100);
        dispatcher
            .finish(
                &lease,
                JobOutcome::RetryableFailure(JobFailureKind::Timeout),
            )
            .await
            .expect("schedule retry");
        drop(dispatcher);
        drop(queue);
        stores.close().await.expect("stores close");

        let reopened = StoreSet::open(&root).await.expect("stores reopen");
        let queue = queue_with_clock(&reopened, &clock);
        let restored = queue
            .read_job(&owner, job.id())
            .await
            .expect("job after reopen");
        assert_eq!(restored.state(), JobState::RetryScheduled);
        assert_eq!(
            queue
                .read_attempts(&owner, job.id())
                .await
                .expect("attempts after reopen")
                .len(),
            1
        );
        assert_eq!(
            queue
                .read_events(&owner, job.id())
                .await
                .expect("events after reopen")
                .iter()
                .map(|event| event.kind())
                .collect::<Vec<_>>(),
            vec![
                JobEventKind::Enqueued,
                JobEventKind::Leased,
                JobEventKind::Started,
                JobEventKind::RetryScheduled
            ]
        );
        assert_eq!(
            queue
                .dispatcher()
                .claim_next()
                .await
                .expect("retry is not due"),
            ClaimResult::Idle
        );
        clock.advance(SECOND);
        let retried = claim_lease(&queue).await;
        assert_eq!(retried.job_id(), job.id());
        assert_eq!(retried.attempt_number(), 2);
        assert_eq!(retried.result_idempotency_key, result_idempotency_key);
        let retried_job = queue.read_job(&owner, job.id()).await.expect("retried job");
        queue
            .request_cancel(
                &owner,
                cancel_command(retried_job.id(), retried_job.revision()),
            )
            .await
            .expect("cancel retried lease");
        let other_outbox = append_outbox(&reopened, &owner, "different result key").await;
        let other_job = queue
            .enqueue(&owner, enqueue_command(other_outbox, JobEnqueueKey::new()))
            .await
            .expect("enqueue other job")
            .job;
        let other_lease = claim_lease(&queue).await;
        assert_eq!(other_lease.job_id(), other_job.id());
        assert_ne!(other_lease.result_idempotency_key, result_idempotency_key);
    }

    #[tokio::test]
    async fn enqueue_fault_rolls_back_job_ledger_and_event_before_retry() {
        let directory = tempdir().expect("temporary directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let clock = Arc::new(ManualClock::new(START));
        let queue = queue_with_clock(&stores, &clock);
        let owner = VerifiedAuthContext::synthetic(1);
        let outbox = append_outbox(&stores, &owner, "fault source").await;
        let command = enqueue_command(outbox, JobEnqueueKey::new());

        assert_eq!(
            queue
                .enqueue_with_fault(&owner, command.clone(), JobQueueFault::BeforeEnqueueLedger)
                .await,
            Err(JobQueueError::InjectedFailure)
        );
        assert_eq!(
            queue
                .dispatcher()
                .claim_next()
                .await
                .expect("no leaked job"),
            ClaimResult::Idle
        );

        let receipt = queue
            .enqueue(&owner, command)
            .await
            .expect("retry after rollback");
        assert!(!receipt.replayed);
        assert_eq!(
            queue
                .read_events(&owner, receipt.job.id())
                .await
                .expect("single enqueue event")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn claim_response_loss_preserves_one_attempt_and_recovers_by_expiry() {
        let directory = tempdir().expect("temporary directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let clock = Arc::new(ManualClock::new(START));
        let queue = queue_with_clock(&stores, &clock);
        let dispatcher = queue.dispatcher();
        let owner = VerifiedAuthContext::synthetic(1);
        let outbox = append_outbox(&stores, &owner, "claim response loss").await;
        let job = queue
            .enqueue(&owner, enqueue_command(outbox, JobEnqueueKey::new()))
            .await
            .expect("enqueue")
            .job;

        assert_eq!(
            dispatcher
                .claim_next_with_fault(JobQueueFault::AfterClaimCommitBeforeReadback)
                .await,
            Err(JobQueueError::InjectedFailure)
        );
        assert_eq!(
            dispatcher.claim_next().await.expect("durable lease blocks"),
            ClaimResult::Idle
        );
        let leased = queue
            .read_job(&owner, job.id())
            .await
            .expect("committed leased job");
        assert_eq!(leased.state(), JobState::Leased);
        let attempts = queue
            .read_attempts(&owner, job.id())
            .await
            .expect("one committed attempt");
        assert_eq!(attempts.len(), 1);

        clock.set(attempts[0].lease_expires_at.get());
        assert_eq!(
            dispatcher.claim_next().await.expect("expire lost claim"),
            ClaimResult::Idle
        );
        clock.advance(SECOND);
        let retried = claim_lease(&queue).await;
        assert_eq!(retried.job_id(), job.id());
        assert_eq!(retried.attempt_number(), 2);
    }

    #[tokio::test]
    async fn owner_cancel_and_resume_mutations_replay_by_key_before_revision_checks() {
        let directory = tempdir().expect("temporary directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let clock = Arc::new(ManualClock::new(START));
        let queue = queue_with_clock(&stores, &clock);
        let dispatcher = queue.dispatcher();
        let owner = VerifiedAuthContext::synthetic(1);
        let other_owner = VerifiedAuthContext::synthetic(2);

        let cancelled_outbox = append_outbox(&stores, &owner, "cancel replay").await;
        let cancelled = queue
            .enqueue(
                &owner,
                enqueue_command(cancelled_outbox, JobEnqueueKey::new()),
            )
            .await
            .expect("enqueue cancelled job")
            .job;
        let cancel_key = JobMutationKey::new();
        let cancel = CancelJob {
            job_id: cancelled.id(),
            expected_revision: cancelled.revision(),
            idempotency_key: cancel_key,
        };
        let first_cancel = queue
            .request_cancel(&owner, cancel.clone())
            .await
            .expect("first cancel");
        let replayed_cancel = queue
            .request_cancel(&owner, cancel.clone())
            .await
            .expect("cancel replay");
        assert!(!first_cancel.replayed);
        assert!(replayed_cancel.replayed);
        assert_eq!(first_cancel.job, replayed_cancel.job);
        assert_eq!(first_cancel.job.state(), JobState::Cancelled);
        assert_eq!(
            queue
                .request_cancel(
                    &owner,
                    CancelJob {
                        expected_revision: first_cancel.job.revision(),
                        ..cancel.clone()
                    },
                )
                .await,
            Err(JobQueueError::IdempotencyConflict)
        );
        assert_eq!(
            queue.request_cancel(&other_owner, cancel).await,
            Err(JobQueueError::NotFound)
        );

        let waiting_outbox = append_outbox(&stores, &owner, "resume replay").await;
        let waiting_job = queue
            .enqueue(
                &owner,
                enqueue_command(waiting_outbox, JobEnqueueKey::new()),
            )
            .await
            .expect("enqueue waiting job")
            .job;
        let lease = claim_lease(&queue).await;
        assert_eq!(lease.job_id(), waiting_job.id());
        let running = dispatcher
            .mark_running(&lease)
            .await
            .expect("mark waiting job running");
        clock.advance(SECOND);
        let waiting = dispatcher
            .finish(&running, JobOutcome::WaitingConfirmation)
            .await
            .expect("wait for confirmation");
        let resume = ResumeJob {
            job_id: waiting.job.id(),
            expected_revision: waiting.job.revision(),
            idempotency_key: JobMutationKey::new(),
        };
        let first_resume = queue
            .resume_after_confirmation(&owner, resume.clone())
            .await
            .expect("first resume");
        let replayed_resume = queue
            .resume_after_confirmation(&owner, resume)
            .await
            .expect("resume replay");
        assert!(!first_resume.replayed);
        assert!(replayed_resume.replayed);
        assert_eq!(first_resume.job, replayed_resume.job);
        assert_eq!(first_resume.job.state(), JobState::Queued);
        let resumed_lease = claim_lease(&queue).await;
        assert_eq!(resumed_lease.job_id(), waiting_job.id());
        assert_eq!(resumed_lease.attempt_number(), 2);
    }

    #[tokio::test]
    async fn final_attempt_rejects_waiting_confirmation_without_blocking_fifo() {
        let directory = tempdir().expect("temporary directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let clock = Arc::new(ManualClock::new(START));
        let queue = queue_with_clock(&stores, &clock);
        let dispatcher = queue.dispatcher();
        let owner = VerifiedAuthContext::synthetic(1);
        let first_outbox = append_outbox(&stores, &owner, "finite confirmation budget").await;
        let second_outbox = append_outbox(&stores, &owner, "fifo follower").await;
        let first = queue
            .enqueue(&owner, enqueue_command(first_outbox, JobEnqueueKey::new()))
            .await
            .expect("enqueue first")
            .job;
        let second = queue
            .enqueue(&owner, enqueue_command(second_outbox, JobEnqueueKey::new()))
            .await
            .expect("enqueue second")
            .job;

        for attempt_number in 1..=2 {
            let lease = claim_lease(&queue).await;
            assert_eq!(lease.job_id(), first.id());
            assert_eq!(lease.attempt_number(), attempt_number);
            let running = dispatcher
                .mark_running(&lease)
                .await
                .expect("mark retry attempt running");
            clock.advance(SECOND);
            let retry = dispatcher
                .finish(
                    &running,
                    JobOutcome::RetryableFailure(JobFailureKind::ExecutionFailed),
                )
                .await
                .expect("schedule retry");
            clock.set(retry.job.ready_at().get());
        }

        let final_lease = claim_lease(&queue).await;
        assert_eq!(final_lease.attempt_number(), 3);
        let final_running = dispatcher
            .mark_running(&final_lease)
            .await
            .expect("mark final attempt running");
        crate::storage::job_records::test_final_attempt_waiting_transition_is_guarded(
            &stores.conversation,
            owner.clone(),
            first.id(),
            clock.now().expect("clock"),
        )
        .await
        .expect("schema rejects final waiting transition");
        assert_eq!(
            dispatcher
                .finish(&final_running, JobOutcome::WaitingConfirmation)
                .await,
            Err(JobQueueError::InvalidTransition)
        );
        clock.advance(SECOND);
        dispatcher
            .finish(
                &final_running,
                JobOutcome::PermanentFailure(JobFailureKind::ExecutionFailed),
            )
            .await
            .expect("terminally fail exhausted first job");
        let follower = claim_lease(&queue).await;
        assert_eq!(follower.job_id(), second.id());
    }

    #[tokio::test]
    async fn cancel_is_observable_and_sql_guards_reject_update_delete_and_replace() {
        let directory = tempdir().expect("temporary directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let clock = Arc::new(ManualClock::new(START));
        let queue = queue_with_clock(&stores, &clock);
        let dispatcher = queue.dispatcher();
        let owner = VerifiedAuthContext::synthetic(1);
        let outbox = append_outbox(&stores, &owner, "guarded state").await;
        let enqueue_key = JobEnqueueKey::new();
        let job = queue
            .enqueue(&owner, enqueue_command(outbox, enqueue_key))
            .await
            .expect("enqueue")
            .job;
        let lease = claim_lease(&queue).await;
        let running = dispatcher.mark_running(&lease).await.expect("mark running");
        let mutation_key = JobMutationKey::new();
        let cancelled = queue
            .request_cancel(
                &owner,
                CancelJob {
                    job_id: job.id(),
                    expected_revision: queue
                        .read_job(&owner, job.id())
                        .await
                        .expect("running job")
                        .revision(),
                    idempotency_key: mutation_key,
                },
            )
            .await
            .expect("request cancel");
        assert_eq!(cancelled.job.state(), JobState::CancelRequested);
        let observed = dispatcher
            .renew(&running)
            .await
            .expect("worker observes persisted cancellation");
        assert_eq!(observed.state(), JobAttemptState::CancelRequested);
        assert_eq!(
            dispatcher.finish(&observed, JobOutcome::Succeeded).await,
            Err(JobQueueError::InvalidTransition)
        );
        let terminal = dispatcher
            .finish(&observed, JobOutcome::Cancelled)
            .await
            .expect("acknowledge cleanup and cancel");
        assert_eq!(terminal.job.state(), JobState::Cancelled);

        let attempt = queue
            .read_attempts(&owner, job.id())
            .await
            .expect("attempt history")
            .into_iter()
            .next()
            .expect("one attempt");
        let event = queue
            .read_events(&owner, job.id())
            .await
            .expect("event history")
            .into_iter()
            .next()
            .expect("one event");
        crate::storage::job_records::test_guarded_records_reject_mutation(
            &stores.conversation,
            owner,
            crate::storage::job_records::GuardedRecordIds {
                job_id: job.id(),
                attempt_id: attempt.id(),
                event_id: event.id(),
                enqueue_key,
                mutation_key,
            },
        )
        .await
        .expect("all guarded queue records reject direct mutation");
    }

    #[tokio::test]
    async fn persisted_clock_regression_fails_closed_without_enqueuing() {
        let directory = tempdir().expect("temporary directory");
        let stores = StoreSet::open(directory.path().join("stores"))
            .await
            .expect("stores open");
        let clock = Arc::new(ManualClock::new(START));
        let queue = queue_with_clock(&stores, &clock);
        let owner = VerifiedAuthContext::synthetic(1);
        let other_owner = VerifiedAuthContext::synthetic(2);
        let first_outbox = append_outbox(&stores, &owner, "clock floor").await;
        queue
            .enqueue(&owner, enqueue_command(first_outbox, JobEnqueueKey::new()))
            .await
            .expect("establish clock floor");
        let second_outbox = append_outbox(&stores, &owner, "clock rollback").await;
        let key = JobEnqueueKey::new();

        clock.set(START - 1);
        assert_eq!(
            queue
                .enqueue(&owner, enqueue_command(second_outbox, key))
                .await,
            Err(JobQueueError::ClockRegression)
        );
        assert_eq!(
            queue
                .read_job_by_source(&owner, second_outbox, JobKind::ConversationResponseV1)
                .await,
            Err(JobQueueError::NotFound)
        );
        assert_eq!(
            queue
                .read_job_by_source(&other_owner, first_outbox, JobKind::ConversationResponseV1,)
                .await,
            Err(JobQueueError::NotFound)
        );
        clock.set(START);
        let recovered = queue
            .enqueue(&owner, enqueue_command(second_outbox, key))
            .await
            .expect("retry at clock floor");
        assert_eq!(
            queue
                .read_job_by_source(&owner, second_outbox, JobKind::ConversationResponseV1)
                .await
                .expect("source recovery lookup"),
            recovered.job
        );
    }

    #[test]
    fn durable_job_fingerprints_have_stable_domain_separated_vectors() {
        let owner = VerifiedAuthContext::synthetic(1);
        let source_outbox_id = OutboxId::from_uuid(
            uuid::Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
                .expect("fixed v4 outbox ID"),
        )
        .expect("valid outbox ID");
        let enqueue = super::prepare_enqueue(
            &owner,
            enqueue_command(source_outbox_id, JobEnqueueKey::new()),
        );
        assert_eq!(
            enqueue.fingerprint.as_bytes(),
            &[
                229, 5, 205, 116, 23, 37, 116, 240, 190, 38, 158, 193, 59, 234, 238, 15, 129, 83,
                131, 247, 186, 239, 39, 143, 102, 119, 117, 85, 178, 63, 214, 132,
            ]
        );

        let job_id = super::JobId::from_uuid(
            uuid::Uuid::parse_str("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("fixed v4 job ID"),
        )
        .expect("valid job ID");
        let expected_revision = Revision::new(7).expect("positive revision");
        let cancel = super::prepare_cancel(
            &owner,
            CancelJob {
                job_id,
                expected_revision,
                idempotency_key: JobMutationKey::new(),
            },
        );
        assert_eq!(
            cancel.fingerprint.as_bytes(),
            &[
                3, 28, 115, 188, 63, 140, 214, 177, 152, 129, 77, 91, 202, 7, 62, 237, 89, 5, 100,
                125, 15, 196, 140, 107, 89, 146, 227, 246, 225, 85, 45, 103,
            ]
        );
        let resume = super::prepare_resume(
            &owner,
            ResumeJob {
                job_id,
                expected_revision,
                idempotency_key: JobMutationKey::new(),
            },
        );
        assert_eq!(
            resume.fingerprint.as_bytes(),
            &[
                77, 221, 189, 31, 103, 127, 222, 119, 85, 94, 39, 250, 228, 111, 44, 139, 144, 197,
                11, 246, 234, 206, 51, 15, 23, 201, 33, 93, 140, 92, 77, 135,
            ]
        );
    }

    #[test]
    fn debug_output_redacts_enqueue_fingerprint_keys_and_lease_capabilities() {
        let source_outbox_id = OutboxId::new();
        let idempotency_key = JobEnqueueKey::new();
        assert_eq!(
            JobEnqueueKey::from_uuid(idempotency_key.as_uuid()),
            Some(idempotency_key)
        );
        assert_eq!(JobEnqueueKey::from_uuid(uuid::Uuid::nil()), None);
        assert_eq!(
            idempotency_key.to_string(),
            idempotency_key.as_uuid().to_string()
        );
        assert_eq!(format!("{idempotency_key:?}"), "JobEnqueueKey(<redacted>)");
        let command = enqueue_command(source_outbox_id, idempotency_key);
        let command_debug = format!("{command:?}");
        assert!(!command_debug.contains(&idempotency_key.as_uuid().to_string()));

        let token = JobLeaseToken::new();
        let token_text = token.as_uuid().to_string();
        let result_idempotency_key = IdempotencyKey::new();
        let result_key_text = result_idempotency_key.as_uuid().to_string();
        let lease = JobLease {
            job_id: super::JobId::new(),
            attempt_id: super::JobAttemptId::new(),
            attempt_number: 1,
            source_outbox_id,
            kind: JobKind::ConversationResponseV1,
            result_idempotency_key,
            generation: 37,
            token,
            state: JobAttemptState::Running,
            lease_expires_at: JobTimestampMicros::new(START + 30 * SECOND).expect("lease expiry"),
            attempt_deadline_at: JobTimestampMicros::new(START + 600 * SECOND)
                .expect("attempt deadline"),
        };
        let lease_debug = format!("{lease:?}");
        assert!(!lease_debug.contains(&token_text));
        assert!(!lease_debug.contains(&result_key_text));
        assert!(!lease_debug.contains("generation"));

        let ticket = RecoveryTicket {
            job_id: lease.job_id,
            attempt_id: lease.attempt_id,
            attempt_number: lease.attempt_number,
            generation: lease.generation,
            token,
        };
        let ticket_debug = format!("{ticket:?}");
        assert!(!ticket_debug.contains(&token_text));
        assert!(!ticket_debug.contains("generation"));
        assert_eq!(
            format!("{:?}", EnqueueFingerprint::from_bytes([0x5a; 32])),
            "EnqueueFingerprint(<redacted>)"
        );
        let mutation_key = JobMutationKey::new();
        assert_eq!(format!("{mutation_key:?}"), "JobMutationKey(<redacted>)");
        assert_eq!(format!("{token:?}"), "JobLeaseToken(<redacted>)");
    }
}
