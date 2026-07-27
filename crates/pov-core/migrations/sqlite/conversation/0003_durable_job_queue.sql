CREATE TABLE conversation_jobs (
    enqueue_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    job_id BLOB NOT NULL
        CHECK (typeof(job_id) = 'blob' AND length(job_id) = 16),
    source_outbox_id BLOB NOT NULL
        CHECK (typeof(source_outbox_id) = 'blob' AND length(source_outbox_id) = 16),
    job_kind TEXT NOT NULL
        CHECK (job_kind = 'conversation_response_v1'),
    priority INTEGER NOT NULL
        CHECK (priority = 0),
    state TEXT NOT NULL
        CHECK (
            state IN (
                'queued',
                'leased',
                'running',
                'cancel_requested',
                'retry_scheduled',
                'waiting_confirmation',
                'recovery_required',
                'succeeded',
                'failed',
                'cancelled'
            )
        ),
    state_revision INTEGER NOT NULL
        CHECK (state_revision BETWEEN 1 AND 9223372036854775807),
    max_attempts INTEGER NOT NULL
        CHECK (max_attempts BETWEEN 1 AND 64),
    attempts_started INTEGER NOT NULL
        CHECK (attempts_started BETWEEN 0 AND max_attempts),
    attempt_timeout_micros INTEGER NOT NULL
        CHECK (attempt_timeout_micros BETWEEN 1 AND 9223372036854775807),
    retry_base_micros INTEGER NOT NULL
        CHECK (retry_base_micros BETWEEN 1 AND 9223372036854775807),
    result_idempotency_key BLOB NOT NULL
        CHECK (
            typeof(result_idempotency_key) = 'blob'
            AND length(result_idempotency_key) = 16
        ),
    cancel_requested INTEGER NOT NULL
        CHECK (cancel_requested IN (0, 1)),
    enqueued_at_micros INTEGER NOT NULL
        CHECK (enqueued_at_micros >= 0),
    ready_at_micros INTEGER NOT NULL
        CHECK (ready_at_micros >= enqueued_at_micros),
    first_started_at_micros INTEGER
        CHECK (
            first_started_at_micros IS NULL
            OR first_started_at_micros >= enqueued_at_micros
        ),
    terminal_at_micros INTEGER
        CHECK (
            terminal_at_micros IS NULL
            OR terminal_at_micros >= enqueued_at_micros
        ),
    queue_wait_micros INTEGER NOT NULL
        CHECK (queue_wait_micros >= 0),
    execution_micros INTEGER NOT NULL
        CHECK (execution_micros >= 0),
    correlation_id BLOB NOT NULL
        CHECK (typeof(correlation_id) = 'blob' AND length(correlation_id) = 16),
    updated_at_micros INTEGER NOT NULL
        CHECK (updated_at_micros >= enqueued_at_micros),
    CHECK (
        (state IN ('succeeded', 'failed', 'cancelled') AND terminal_at_micros IS NOT NULL)
        OR
        (state NOT IN ('succeeded', 'failed', 'cancelled') AND terminal_at_micros IS NULL)
    ),
    UNIQUE (owner_id, job_id),
    UNIQUE (owner_id, source_outbox_id, job_kind),
    UNIQUE (owner_id, result_idempotency_key),
    UNIQUE (owner_id, job_id, source_outbox_id, job_kind),
    FOREIGN KEY (owner_id, source_outbox_id)
        REFERENCES conversation_outbox(owner_id, outbox_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE conversation_job_enqueue_idempotency (
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    idempotency_key BLOB NOT NULL
        CHECK (typeof(idempotency_key) = 'blob' AND length(idempotency_key) = 16),
    operation TEXT NOT NULL
        CHECK (operation = 'enqueue_conversation_job_v1'),
    request_fingerprint BLOB NOT NULL
        CHECK (
            typeof(request_fingerprint) = 'blob'
            AND length(request_fingerprint) = 32
        ),
    job_id BLOB NOT NULL
        CHECK (typeof(job_id) = 'blob' AND length(job_id) = 16),
    source_outbox_id BLOB NOT NULL
        CHECK (typeof(source_outbox_id) = 'blob' AND length(source_outbox_id) = 16),
    job_kind TEXT NOT NULL
        CHECK (job_kind = 'conversation_response_v1'),
    created_at_micros INTEGER NOT NULL
        CHECK (created_at_micros >= 0),
    PRIMARY KEY (owner_id, idempotency_key),
    UNIQUE (owner_id, source_outbox_id, job_kind),
    FOREIGN KEY (owner_id, job_id, source_outbox_id, job_kind)
        REFERENCES conversation_jobs(owner_id, job_id, source_outbox_id, job_kind)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE conversation_job_owner_mutation_idempotency (
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    idempotency_key BLOB NOT NULL
        CHECK (typeof(idempotency_key) = 'blob' AND length(idempotency_key) = 16),
    operation TEXT NOT NULL
        CHECK (operation IN ('cancel_job_v1', 'resume_job_v1')),
    request_fingerprint BLOB NOT NULL
        CHECK (
            typeof(request_fingerprint) = 'blob'
            AND length(request_fingerprint) = 32
        ),
    job_id BLOB NOT NULL
        CHECK (typeof(job_id) = 'blob' AND length(job_id) = 16),
    result_revision INTEGER NOT NULL
        CHECK (result_revision BETWEEN 1 AND 9223372036854775807),
    created_at_micros INTEGER NOT NULL
        CHECK (created_at_micros >= 0),
    PRIMARY KEY (owner_id, idempotency_key),
    FOREIGN KEY (owner_id, job_id)
        REFERENCES conversation_jobs(owner_id, job_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE conversation_job_attempts (
    attempt_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    job_id BLOB NOT NULL
        CHECK (typeof(job_id) = 'blob' AND length(job_id) = 16),
    attempt_id BLOB NOT NULL
        CHECK (typeof(attempt_id) = 'blob' AND length(attempt_id) = 16),
    attempt_number INTEGER NOT NULL
        CHECK (attempt_number BETWEEN 1 AND 64),
    lease_generation INTEGER NOT NULL
        CHECK (lease_generation BETWEEN 1 AND 9223372036854775807),
    lease_token BLOB NOT NULL
        CHECK (typeof(lease_token) = 'blob' AND length(lease_token) = 16),
    state TEXT NOT NULL
        CHECK (
            state IN (
                'leased',
                'running',
                'cancel_requested',
                'retry_scheduled',
                'waiting_confirmation',
                'recovery_required',
                'succeeded',
                'failed',
                'cancelled',
                'lease_expired'
            )
        ),
    completion_kind TEXT
        CHECK (
            completion_kind IS NULL
            OR completion_kind IN (
                'succeeded',
                'retryable_failure',
                'permanent_failure',
                'waiting_confirmation',
                'cancelled',
                'owner_cancel_before_start',
                'lease_expired_unstarted',
                'recovery_retry',
                'recovery_retry_exhausted',
                'recovery_fail',
                'recovery_cancelled'
            )
        ),
    leased_at_micros INTEGER NOT NULL
        CHECK (leased_at_micros >= 0),
    started_at_micros INTEGER
        CHECK (
            started_at_micros IS NULL
            OR started_at_micros >= leased_at_micros
        ),
    lease_expires_at_micros INTEGER NOT NULL
        CHECK (lease_expires_at_micros > leased_at_micros),
    attempt_deadline_at_micros INTEGER NOT NULL
        CHECK (attempt_deadline_at_micros >= lease_expires_at_micros),
    finished_at_micros INTEGER
        CHECK (
            finished_at_micros IS NULL
            OR finished_at_micros >= leased_at_micros
        ),
    retry_at_micros INTEGER
        CHECK (
            retry_at_micros IS NULL
            OR (
                finished_at_micros IS NOT NULL
                AND retry_at_micros >= finished_at_micros
            )
        ),
    queue_wait_micros INTEGER
        CHECK (queue_wait_micros IS NULL OR queue_wait_micros >= 0),
    execution_micros INTEGER
        CHECK (execution_micros IS NULL OR execution_micros >= 0),
    failure_kind TEXT
        CHECK (
            failure_kind IS NULL
            OR failure_kind IN (
                'provider_unavailable',
                'timeout',
                'execution_failed',
                'lease_expired',
                'cleanup_uncertain'
            )
        ),
    CHECK (
        (state IN ('leased', 'running', 'cancel_requested', 'recovery_required')
            AND completion_kind IS NULL)
        OR
        (state NOT IN ('leased', 'running', 'cancel_requested', 'recovery_required')
            AND completion_kind IS NOT NULL)
    ),
    UNIQUE (owner_id, job_id, attempt_number),
    UNIQUE (owner_id, job_id, attempt_id),
    UNIQUE (
        owner_id,
        job_id,
        attempt_id,
        attempt_number,
        lease_generation,
        lease_token
    ),
    UNIQUE (lease_token),
    FOREIGN KEY (owner_id, job_id)
        REFERENCES conversation_jobs(owner_id, job_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX conversation_job_attempts_single_active
ON conversation_job_attempts((1))
WHERE state IN ('leased', 'running', 'cancel_requested', 'recovery_required');

CREATE UNIQUE INDEX conversation_jobs_single_active
ON conversation_jobs((1))
WHERE state IN ('leased', 'running', 'cancel_requested', 'recovery_required');

CREATE TABLE conversation_job_events (
    event_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    event_id BLOB NOT NULL
        CHECK (typeof(event_id) = 'blob' AND length(event_id) = 16),
    job_id BLOB NOT NULL
        CHECK (typeof(job_id) = 'blob' AND length(job_id) = 16),
    job_revision INTEGER NOT NULL
        CHECK (job_revision BETWEEN 1 AND 9223372036854775807),
    event_kind TEXT NOT NULL
        CHECK (
            event_kind IN (
                'enqueued',
                'leased',
                'started',
                'cancel_requested',
                'cancelled',
                'retry_scheduled',
                'waiting_confirmation',
                'confirmation_resumed',
                'succeeded',
                'failed',
                'lease_expired',
                'recovery_required',
                'recovery_resolved'
            )
        ),
    state TEXT NOT NULL
        CHECK (
            state IN (
                'queued',
                'leased',
                'running',
                'cancel_requested',
                'retry_scheduled',
                'waiting_confirmation',
                'recovery_required',
                'succeeded',
                'failed',
                'cancelled'
            )
        ),
    attempt_id BLOB
        CHECK (
            attempt_id IS NULL
            OR (typeof(attempt_id) = 'blob' AND length(attempt_id) = 16)
        ),
    happened_at_micros INTEGER NOT NULL
        CHECK (happened_at_micros >= 0),
    queue_wait_micros INTEGER
        CHECK (queue_wait_micros IS NULL OR queue_wait_micros >= 0),
    execution_micros INTEGER
        CHECK (execution_micros IS NULL OR execution_micros >= 0),
    failure_kind TEXT
        CHECK (
            failure_kind IS NULL
            OR failure_kind IN (
                'provider_unavailable',
                'timeout',
                'execution_failed',
                'lease_expired',
                'cleanup_uncertain'
            )
        ),
    correlation_id BLOB NOT NULL
        CHECK (typeof(correlation_id) = 'blob' AND length(correlation_id) = 16),
    UNIQUE (owner_id, event_id),
    UNIQUE (owner_id, job_id, job_revision),
    FOREIGN KEY (owner_id, job_id)
        REFERENCES conversation_jobs(owner_id, job_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    FOREIGN KEY (owner_id, job_id, attempt_id)
        REFERENCES conversation_job_attempts(owner_id, job_id, attempt_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE conversation_job_queue_control (
    control_id INTEGER PRIMARY KEY
        CHECK (control_id = 1),
    status TEXT NOT NULL
        CHECK (status IN ('idle', 'leased', 'recovery_required')),
    lease_generation INTEGER NOT NULL
        CHECK (lease_generation BETWEEN 0 AND 9223372036854775807),
    last_observed_at_micros INTEGER NOT NULL
        CHECK (last_observed_at_micros >= 0),
    owner_id BLOB
        CHECK (
            owner_id IS NULL
            OR (typeof(owner_id) = 'blob' AND length(owner_id) = 16)
        ),
    job_id BLOB
        CHECK (
            job_id IS NULL
            OR (typeof(job_id) = 'blob' AND length(job_id) = 16)
        ),
    attempt_id BLOB
        CHECK (
            attempt_id IS NULL
            OR (typeof(attempt_id) = 'blob' AND length(attempt_id) = 16)
        ),
    attempt_number INTEGER
        CHECK (attempt_number IS NULL OR attempt_number BETWEEN 1 AND 64),
    lease_token BLOB
        CHECK (
            lease_token IS NULL
            OR (typeof(lease_token) = 'blob' AND length(lease_token) = 16)
        ),
    lease_expires_at_micros INTEGER
        CHECK (lease_expires_at_micros IS NULL OR lease_expires_at_micros >= 0),
    attempt_deadline_at_micros INTEGER
        CHECK (attempt_deadline_at_micros IS NULL OR attempt_deadline_at_micros >= 0),
    CHECK (
        (
            status = 'idle'
            AND owner_id IS NULL
            AND job_id IS NULL
            AND attempt_id IS NULL
            AND attempt_number IS NULL
            AND lease_token IS NULL
            AND lease_expires_at_micros IS NULL
            AND attempt_deadline_at_micros IS NULL
        )
        OR
        (
            status IN ('leased', 'recovery_required')
            AND owner_id IS NOT NULL
            AND job_id IS NOT NULL
            AND attempt_id IS NOT NULL
            AND attempt_number IS NOT NULL
            AND lease_token IS NOT NULL
            AND lease_expires_at_micros IS NOT NULL
            AND attempt_deadline_at_micros IS NOT NULL
            AND attempt_deadline_at_micros >= lease_expires_at_micros
        )
    ),
    FOREIGN KEY (
        owner_id,
        job_id,
        attempt_id,
        attempt_number,
        lease_generation,
        lease_token
    )
        REFERENCES conversation_job_attempts(
            owner_id,
            job_id,
            attempt_id,
            attempt_number,
            lease_generation,
            lease_token
        )
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT;

INSERT INTO conversation_job_queue_control(
    control_id,
    status,
    lease_generation,
    last_observed_at_micros
) VALUES (1, 'idle', 0, 0);

CREATE INDEX conversation_jobs_fifo
ON conversation_jobs(priority DESC, enqueue_sequence ASC)
WHERE state IN ('queued', 'retry_scheduled');

CREATE INDEX conversation_jobs_by_owner_and_state
ON conversation_jobs(owner_id, state, enqueue_sequence);

CREATE INDEX conversation_job_events_by_owner_job_revision
ON conversation_job_events(owner_id, job_id, job_revision);

CREATE INDEX conversation_job_owner_mutations_by_job
ON conversation_job_owner_mutation_idempotency(owner_id, job_id, result_revision);

CREATE TRIGGER conversation_jobs_reject_delete
BEFORE DELETE ON conversation_jobs
BEGIN
    SELECT RAISE(ABORT, 'conversation jobs cannot be deleted');
END;

CREATE TRIGGER conversation_jobs_guard_update
BEFORE UPDATE ON conversation_jobs
WHEN
    NEW.enqueue_sequence <> OLD.enqueue_sequence
    OR NEW.owner_id <> OLD.owner_id
    OR NEW.job_id <> OLD.job_id
    OR NEW.source_outbox_id <> OLD.source_outbox_id
    OR NEW.job_kind <> OLD.job_kind
    OR NEW.priority <> OLD.priority
    OR NEW.max_attempts <> OLD.max_attempts
    OR NEW.attempt_timeout_micros <> OLD.attempt_timeout_micros
    OR NEW.retry_base_micros <> OLD.retry_base_micros
    OR NEW.result_idempotency_key <> OLD.result_idempotency_key
    OR NEW.enqueued_at_micros <> OLD.enqueued_at_micros
    OR NEW.correlation_id <> OLD.correlation_id
    OR NEW.state_revision <> OLD.state_revision + 1
    OR NEW.updated_at_micros < OLD.updated_at_micros
    OR NEW.attempts_started < OLD.attempts_started
    OR NEW.attempts_started > OLD.attempts_started + 1
    OR (
        NEW.attempts_started = OLD.attempts_started + 1
        AND NEW.state <> 'leased'
    )
    OR (
        NEW.attempts_started = OLD.attempts_started
        AND NEW.state = 'leased'
    )
    OR (
        OLD.state = 'queued'
        AND NEW.state NOT IN ('leased', 'cancelled')
    )
    OR (
        OLD.state = 'retry_scheduled'
        AND NEW.state NOT IN ('leased', 'cancelled')
    )
    OR (
        OLD.state = 'waiting_confirmation'
        AND NEW.state NOT IN ('queued', 'cancelled')
    )
    OR (
        OLD.state = 'leased'
        AND NEW.state NOT IN ('running', 'retry_scheduled', 'failed', 'cancelled')
    )
    OR (
        OLD.state = 'running'
        AND NEW.state NOT IN (
            'cancel_requested',
            'retry_scheduled',
            'waiting_confirmation',
            'recovery_required',
            'succeeded',
            'failed',
            'cancelled'
        )
    )
    OR (
        OLD.state = 'running'
        AND NEW.state = 'waiting_confirmation'
        AND OLD.attempts_started >= OLD.max_attempts
    )
    OR (
        OLD.state = 'cancel_requested'
        AND NEW.state NOT IN ('recovery_required', 'succeeded', 'failed', 'cancelled')
    )
    OR (
        OLD.state = 'recovery_required'
        AND NEW.state NOT IN ('recovery_required', 'retry_scheduled', 'failed', 'cancelled')
    )
    OR OLD.state IN ('succeeded', 'failed', 'cancelled')
    OR (
        NEW.cancel_requested < OLD.cancel_requested
        AND NOT (OLD.state = 'waiting_confirmation' AND NEW.state = 'queued')
    )
    OR (
        NEW.first_started_at_micros IS NOT OLD.first_started_at_micros
        AND NOT (
            OLD.state = 'leased'
            AND NEW.state = 'running'
            AND OLD.first_started_at_micros IS NULL
            AND NEW.first_started_at_micros IS NOT NULL
        )
    )
    OR (
        NEW.ready_at_micros <> OLD.ready_at_micros
        AND NEW.state NOT IN ('queued', 'retry_scheduled')
    )
    OR NEW.queue_wait_micros < OLD.queue_wait_micros
    OR NEW.execution_micros < OLD.execution_micros
BEGIN
    SELECT RAISE(ABORT, 'invalid conversation job transition');
END;

CREATE TRIGGER conversation_job_idempotency_reject_update
BEFORE UPDATE ON conversation_job_enqueue_idempotency
BEGIN
    SELECT RAISE(ABORT, 'job enqueue idempotency is immutable');
END;

CREATE TRIGGER conversation_job_idempotency_reject_delete
BEFORE DELETE ON conversation_job_enqueue_idempotency
BEGIN
    SELECT RAISE(ABORT, 'job enqueue idempotency is immutable');
END;

CREATE TRIGGER conversation_job_owner_mutation_idempotency_reject_update
BEFORE UPDATE ON conversation_job_owner_mutation_idempotency
BEGIN
    SELECT RAISE(ABORT, 'job owner mutation idempotency is immutable');
END;

CREATE TRIGGER conversation_job_owner_mutation_idempotency_reject_delete
BEFORE DELETE ON conversation_job_owner_mutation_idempotency
BEGIN
    SELECT RAISE(ABORT, 'job owner mutation idempotency is immutable');
END;

CREATE TRIGGER conversation_job_attempts_reject_delete
BEFORE DELETE ON conversation_job_attempts
BEGIN
    SELECT RAISE(ABORT, 'job attempts cannot be deleted');
END;

CREATE TRIGGER conversation_job_attempts_guard_update
BEFORE UPDATE ON conversation_job_attempts
WHEN
    NEW.attempt_sequence <> OLD.attempt_sequence
    OR NEW.owner_id <> OLD.owner_id
    OR NEW.job_id <> OLD.job_id
    OR NEW.attempt_id <> OLD.attempt_id
    OR NEW.attempt_number <> OLD.attempt_number
    OR NEW.lease_generation <> OLD.lease_generation
    OR NEW.lease_token <> OLD.lease_token
    OR NEW.leased_at_micros <> OLD.leased_at_micros
    OR NEW.attempt_deadline_at_micros <> OLD.attempt_deadline_at_micros
    OR NEW.lease_expires_at_micros < OLD.lease_expires_at_micros
    OR (
        NEW.lease_expires_at_micros <> OLD.lease_expires_at_micros
        AND (
            NEW.state <> OLD.state
            OR OLD.state NOT IN ('leased', 'running', 'cancel_requested')
        )
    )
    OR (
        OLD.state = 'leased'
        AND NEW.state NOT IN ('leased', 'running', 'cancelled', 'lease_expired')
    )
    OR (
        OLD.state = 'running'
        AND NEW.state NOT IN (
            'running',
            'cancel_requested',
            'retry_scheduled',
            'waiting_confirmation',
            'recovery_required',
            'succeeded',
            'failed',
            'cancelled'
        )
    )
    OR (
        OLD.state = 'cancel_requested'
        AND NEW.state NOT IN ('cancel_requested', 'recovery_required', 'succeeded', 'failed', 'cancelled')
    )
    OR (
        OLD.state = 'recovery_required'
        AND NEW.state NOT IN ('lease_expired', 'failed', 'cancelled')
    )
    OR OLD.state IN (
        'retry_scheduled',
        'waiting_confirmation',
        'succeeded',
        'failed',
        'cancelled',
        'lease_expired'
    )
    OR (
        NEW.started_at_micros IS NOT OLD.started_at_micros
        AND NOT (
            OLD.state = 'leased'
            AND NEW.state = 'running'
            AND OLD.started_at_micros IS NULL
            AND NEW.started_at_micros IS NOT NULL
        )
    )
    OR (
        NEW.queue_wait_micros IS NOT OLD.queue_wait_micros
        AND NOT (
            OLD.state = 'leased'
            AND NEW.state = 'running'
            AND OLD.queue_wait_micros IS NULL
            AND NEW.queue_wait_micros IS NOT NULL
        )
    )
    OR (
        OLD.state IN ('leased', 'running', 'cancel_requested')
        AND NEW.state IN ('leased', 'running', 'cancel_requested')
        AND (
            NEW.completion_kind IS NOT NULL
            OR NEW.finished_at_micros IS NOT NULL
            OR NEW.retry_at_micros IS NOT NULL
            OR NEW.failure_kind IS NOT NULL
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid job attempt transition');
END;

CREATE TRIGGER conversation_job_events_reject_update
BEFORE UPDATE ON conversation_job_events
BEGIN
    SELECT RAISE(ABORT, 'job events are immutable');
END;

CREATE TRIGGER conversation_job_events_reject_delete
BEFORE DELETE ON conversation_job_events
BEGIN
    SELECT RAISE(ABORT, 'job events are immutable');
END;

CREATE TRIGGER conversation_job_queue_control_reject_insert
BEFORE INSERT ON conversation_job_queue_control
WHEN EXISTS (SELECT 1 FROM conversation_job_queue_control WHERE control_id = 1)
BEGIN
    SELECT RAISE(ABORT, 'job queue control is a singleton');
END;

CREATE TRIGGER conversation_job_queue_control_reject_delete
BEFORE DELETE ON conversation_job_queue_control
BEGIN
    SELECT RAISE(ABORT, 'job queue control cannot be deleted');
END;

CREATE TRIGGER conversation_job_queue_control_guard_update
BEFORE UPDATE ON conversation_job_queue_control
WHEN
    NEW.control_id <> OLD.control_id
    OR NEW.last_observed_at_micros < OLD.last_observed_at_micros
    OR NEW.lease_generation < OLD.lease_generation
    OR NEW.lease_generation > OLD.lease_generation + 1
    OR (
        OLD.status = 'idle'
        AND NEW.status = 'leased'
        AND NEW.lease_generation <> OLD.lease_generation + 1
    )
    OR (
        OLD.status = 'idle'
        AND NEW.status = 'idle'
        AND NEW.lease_generation <> OLD.lease_generation
    )
    OR (
        OLD.status = 'idle'
        AND NEW.status NOT IN ('idle', 'leased')
    )
    OR (
        OLD.status = 'leased'
        AND NEW.status NOT IN ('leased', 'idle', 'recovery_required')
    )
    OR (
        OLD.status = 'recovery_required'
        AND NEW.status NOT IN ('recovery_required', 'idle')
    )
    OR (
        OLD.status IN ('leased', 'recovery_required')
        AND NEW.status IN ('leased', 'recovery_required')
        AND (
            NEW.lease_generation <> OLD.lease_generation
            OR NEW.owner_id IS NOT OLD.owner_id
            OR NEW.job_id IS NOT OLD.job_id
            OR NEW.attempt_id IS NOT OLD.attempt_id
            OR NEW.attempt_number IS NOT OLD.attempt_number
            OR NEW.lease_token IS NOT OLD.lease_token
            OR NEW.attempt_deadline_at_micros IS NOT OLD.attempt_deadline_at_micros
            OR NEW.lease_expires_at_micros < OLD.lease_expires_at_micros
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid job queue control transition');
END;
