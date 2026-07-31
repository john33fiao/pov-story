CREATE TABLE conversation_generation_dispatch_control (
    control_id INTEGER PRIMARY KEY
        CHECK (control_id = 1),
    last_outbox_sequence INTEGER NOT NULL
        CHECK (last_outbox_sequence >= 0)
) STRICT;

INSERT INTO conversation_generation_dispatch_control(
    control_id,
    last_outbox_sequence
)
SELECT 1, COALESCE(MAX(dispatch_sequence), 0)
FROM conversation_outbox;

CREATE TABLE conversation_generation_results (
    result_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    result_idempotency_key BLOB NOT NULL
        CHECK (
            typeof(result_idempotency_key) = 'blob'
            AND length(result_idempotency_key) = 16
        ),
    result_fingerprint BLOB NOT NULL
        CHECK (typeof(result_fingerprint) = 'blob' AND length(result_fingerprint) = 32),
    job_id BLOB NOT NULL
        CHECK (typeof(job_id) = 'blob' AND length(job_id) = 16),
    attempt_id BLOB NOT NULL
        CHECK (typeof(attempt_id) = 'blob' AND length(attempt_id) = 16),
    source_outbox_id BLOB NOT NULL
        CHECK (typeof(source_outbox_id) = 'blob' AND length(source_outbox_id) = 16),
    source_event_id BLOB NOT NULL
        CHECK (typeof(source_event_id) = 'blob' AND length(source_event_id) = 16),
    conversation_id BLOB NOT NULL
        CHECK (typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    assistant_event_id BLOB NOT NULL
        CHECK (typeof(assistant_event_id) = 'blob' AND length(assistant_event_id) = 16),
    assistant_revision INTEGER NOT NULL
        CHECK (assistant_revision BETWEEN 1 AND 9223372036854775807),
    provider_backend_id TEXT NOT NULL
        CHECK (typeof(provider_backend_id) = 'text' AND length(provider_backend_id) BETWEEN 1 AND 128),
    runtime_build TEXT NOT NULL
        CHECK (typeof(runtime_build) = 'text' AND length(runtime_build) BETWEEN 1 AND 256),
    runtime_sha256 BLOB NOT NULL
        CHECK (typeof(runtime_sha256) = 'blob' AND length(runtime_sha256) = 32),
    model_revision TEXT NOT NULL
        CHECK (typeof(model_revision) = 'text' AND length(model_revision) BETWEEN 1 AND 256),
    model_sha256 BLOB NOT NULL
        CHECK (typeof(model_sha256) = 'blob' AND length(model_sha256) = 32),
    canonical_input_sha256 BLOB NOT NULL
        CHECK (typeof(canonical_input_sha256) = 'blob' AND length(canonical_input_sha256) = 32),
    canonical_output_sha256 BLOB NOT NULL
        CHECK (typeof(canonical_output_sha256) = 'blob' AND length(canonical_output_sha256) = 32),
    elapsed_micros INTEGER NOT NULL
        CHECK (elapsed_micros BETWEEN 0 AND 9223372036854775807),
    created_at_micros INTEGER NOT NULL
        CHECK (created_at_micros >= 0),
    UNIQUE (owner_id, result_idempotency_key),
    UNIQUE (owner_id, job_id),
    UNIQUE (owner_id, source_event_id),
    UNIQUE (owner_id, assistant_event_id),
    UNIQUE (owner_id, conversation_id, assistant_revision),
    FOREIGN KEY (owner_id, job_id)
        REFERENCES conversation_jobs(owner_id, job_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    FOREIGN KEY (owner_id, job_id, attempt_id)
        REFERENCES conversation_job_attempts(owner_id, job_id, attempt_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    FOREIGN KEY (owner_id, source_outbox_id)
        REFERENCES conversation_outbox(owner_id, outbox_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    FOREIGN KEY (owner_id, source_event_id)
        REFERENCES conversation_events(owner_id, event_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    FOREIGN KEY (owner_id, assistant_event_id)
        REFERENCES conversation_events(owner_id, event_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX conversation_generation_results_by_conversation
ON conversation_generation_results(owner_id, conversation_id, assistant_revision);

CREATE TRIGGER conversation_generation_dispatch_control_reject_insert
BEFORE INSERT ON conversation_generation_dispatch_control
WHEN EXISTS (
    SELECT 1
    FROM conversation_generation_dispatch_control
    WHERE control_id = 1
)
BEGIN
    SELECT RAISE(ABORT, 'generation dispatch control is a singleton');
END;

CREATE TRIGGER conversation_generation_dispatch_control_reject_delete
BEFORE DELETE ON conversation_generation_dispatch_control
BEGIN
    SELECT RAISE(ABORT, 'generation dispatch control cannot be deleted');
END;

CREATE TRIGGER conversation_generation_dispatch_control_guard_update
BEFORE UPDATE ON conversation_generation_dispatch_control
WHEN
    NEW.control_id <> OLD.control_id
    OR NEW.last_outbox_sequence <= OLD.last_outbox_sequence
    OR NOT EXISTS (
        SELECT 1
        FROM conversation_outbox
        WHERE dispatch_sequence = NEW.last_outbox_sequence
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid generation dispatch cursor transition');
END;

CREATE TRIGGER conversation_generation_results_validate_insert
BEFORE INSERT ON conversation_generation_results
WHEN
    NOT EXISTS (
        SELECT 1
        FROM conversation_outbox AS o
        JOIN conversation_events AS source
          ON source.owner_id = o.owner_id
         AND source.event_id = o.event_id
         AND source.conversation_id = o.conversation_id
         AND source.conversation_revision = o.conversation_revision
        JOIN conversation_events AS assistant
          ON assistant.owner_id = o.owner_id
         AND assistant.conversation_id = o.conversation_id
        WHERE o.owner_id = NEW.owner_id
          AND o.outbox_id = NEW.source_outbox_id
          AND o.event_id = NEW.source_event_id
          AND o.conversation_id = NEW.conversation_id
          AND source.event_kind = 'user_text'
          AND assistant.event_id = NEW.assistant_event_id
          AND assistant.conversation_revision = NEW.assistant_revision
          AND assistant.event_kind = 'assistant_text'
          AND assistant.conversation_revision > source.conversation_revision
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid generation result linkage');
END;

CREATE TRIGGER conversation_generation_results_reject_update
BEFORE UPDATE ON conversation_generation_results
BEGIN
    SELECT RAISE(ABORT, 'generation results are immutable');
END;

CREATE TRIGGER conversation_generation_results_reject_delete
BEFORE DELETE ON conversation_generation_results
BEGIN
    SELECT RAISE(ABORT, 'generation results are immutable');
END;
