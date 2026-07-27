CREATE TABLE conversations (
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    conversation_id BLOB NOT NULL
        CHECK (typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    current_revision INTEGER NOT NULL
        CHECK (current_revision BETWEEN 1 AND 9223372036854775807),
    created_at_micros INTEGER NOT NULL
        CHECK (created_at_micros >= 0),
    updated_at_micros INTEGER NOT NULL
        CHECK (updated_at_micros >= created_at_micros),
    PRIMARY KEY (owner_id, conversation_id)
) STRICT;

CREATE TABLE conversation_events (
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    event_id BLOB NOT NULL
        CHECK (typeof(event_id) = 'blob' AND length(event_id) = 16),
    conversation_id BLOB NOT NULL
        CHECK (typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    conversation_revision INTEGER NOT NULL
        CHECK (conversation_revision BETWEEN 1 AND 9223372036854775807),
    event_kind TEXT NOT NULL
        CHECK (event_kind IN ('user_text', 'assistant_text', 'tool_call', 'tool_result')),
    content TEXT NOT NULL
        CHECK (
            typeof(content) = 'text'
            AND length(CAST(content AS BLOB)) BETWEEN 1 AND 65536
        ),
    content_bytes INTEGER NOT NULL
        CHECK (
            content_bytes BETWEEN 1 AND 65536
            AND content_bytes = length(CAST(content AS BLOB))
        ),
    content_sha256 BLOB NOT NULL
        CHECK (typeof(content_sha256) = 'blob' AND length(content_sha256) = 32),
    correlation_id BLOB NOT NULL
        CHECK (typeof(correlation_id) = 'blob' AND length(correlation_id) = 16),
    created_at_micros INTEGER NOT NULL
        CHECK (created_at_micros >= 0),
    PRIMARY KEY (owner_id, event_id),
    UNIQUE (owner_id, conversation_id, conversation_revision),
    UNIQUE (
        owner_id,
        event_id,
        conversation_id,
        conversation_revision,
        event_kind,
        correlation_id
    ),
    UNIQUE (
        owner_id,
        event_id,
        conversation_id,
        conversation_revision,
        event_kind,
        correlation_id,
        content_sha256
    ),
    FOREIGN KEY (owner_id, conversation_id)
        REFERENCES conversations(owner_id, conversation_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE conversation_append_idempotency (
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    idempotency_key BLOB NOT NULL
        CHECK (typeof(idempotency_key) = 'blob' AND length(idempotency_key) = 16),
    operation TEXT NOT NULL
        CHECK (operation = 'append_user_event_v1'),
    request_fingerprint BLOB NOT NULL
        CHECK (typeof(request_fingerprint) = 'blob' AND length(request_fingerprint) = 32),
    conversation_id BLOB NOT NULL
        CHECK (typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    expected_revision INTEGER
        CHECK (
            expected_revision IS NULL
            OR expected_revision BETWEEN 1 AND 9223372036854775807
        ),
    event_id BLOB NOT NULL
        CHECK (typeof(event_id) = 'blob' AND length(event_id) = 16),
    conversation_revision INTEGER NOT NULL
        CHECK (conversation_revision BETWEEN 1 AND 9223372036854775807),
    event_kind TEXT NOT NULL
        CHECK (event_kind = 'user_text'),
    correlation_id BLOB NOT NULL
        CHECK (typeof(correlation_id) = 'blob' AND length(correlation_id) = 16),
    created_at_micros INTEGER NOT NULL
        CHECK (created_at_micros >= 0),
    PRIMARY KEY (owner_id, idempotency_key),
    UNIQUE (owner_id, event_id),
    FOREIGN KEY (
        owner_id,
        event_id,
        conversation_id,
        conversation_revision,
        event_kind,
        correlation_id
    )
        REFERENCES conversation_events(
            owner_id,
            event_id,
            conversation_id,
            conversation_revision,
            event_kind,
            correlation_id
        )
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE conversation_outbox (
    dispatch_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    outbox_id BLOB NOT NULL
        CHECK (typeof(outbox_id) = 'blob' AND length(outbox_id) = 16),
    event_id BLOB NOT NULL
        CHECK (typeof(event_id) = 'blob' AND length(event_id) = 16),
    conversation_id BLOB NOT NULL
        CHECK (typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    conversation_revision INTEGER NOT NULL
        CHECK (conversation_revision BETWEEN 1 AND 9223372036854775807),
    source_revision INTEGER NOT NULL
        CHECK (source_revision = 1),
    event_kind TEXT NOT NULL
        CHECK (event_kind = 'user_text'),
    topic TEXT NOT NULL
        CHECK (topic = 'conversation.user-appended.v1'),
    content_sha256 BLOB NOT NULL
        CHECK (typeof(content_sha256) = 'blob' AND length(content_sha256) = 32),
    correlation_id BLOB NOT NULL
        CHECK (typeof(correlation_id) = 'blob' AND length(correlation_id) = 16),
    created_at_micros INTEGER NOT NULL
        CHECK (created_at_micros >= 0),
    UNIQUE (owner_id, outbox_id),
    UNIQUE (owner_id, event_id),
    FOREIGN KEY (
        owner_id,
        event_id,
        conversation_id,
        conversation_revision,
        event_kind,
        correlation_id,
        content_sha256
    )
        REFERENCES conversation_events(
            owner_id,
            event_id,
            conversation_id,
            conversation_revision,
            event_kind,
            correlation_id,
            content_sha256
        )
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE conversation_audit (
    audit_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    audit_id BLOB NOT NULL
        CHECK (typeof(audit_id) = 'blob' AND length(audit_id) = 16),
    event_id BLOB NOT NULL
        CHECK (typeof(event_id) = 'blob' AND length(event_id) = 16),
    conversation_id BLOB NOT NULL
        CHECK (typeof(conversation_id) = 'blob' AND length(conversation_id) = 16),
    conversation_revision INTEGER NOT NULL
        CHECK (conversation_revision BETWEEN 1 AND 9223372036854775807),
    event_kind TEXT NOT NULL
        CHECK (event_kind = 'user_text'),
    action TEXT NOT NULL
        CHECK (action = 'conversation.user-appended.v1'),
    correlation_id BLOB NOT NULL
        CHECK (typeof(correlation_id) = 'blob' AND length(correlation_id) = 16),
    created_at_micros INTEGER NOT NULL
        CHECK (created_at_micros >= 0),
    UNIQUE (owner_id, audit_id),
    UNIQUE (owner_id, event_id),
    FOREIGN KEY (
        owner_id,
        event_id,
        conversation_id,
        conversation_revision,
        event_kind,
        correlation_id
    )
        REFERENCES conversation_events(
            owner_id,
            event_id,
            conversation_id,
            conversation_revision,
            event_kind,
            correlation_id
        )
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX conversation_events_by_owner_and_conversation
ON conversation_events(owner_id, conversation_id, conversation_revision);

CREATE TRIGGER conversations_reject_delete
BEFORE DELETE ON conversations
BEGIN
    SELECT RAISE(ABORT, 'conversation rows are append-oriented');
END;

CREATE TRIGGER conversations_guard_update
BEFORE UPDATE ON conversations
WHEN
    NEW.owner_id <> OLD.owner_id
    OR NEW.conversation_id <> OLD.conversation_id
    OR NEW.created_at_micros <> OLD.created_at_micros
    OR NEW.current_revision <> OLD.current_revision + 1
    OR NEW.updated_at_micros < OLD.updated_at_micros
BEGIN
    SELECT RAISE(ABORT, 'invalid conversation revision transition');
END;

CREATE TRIGGER conversation_events_reject_update
BEFORE UPDATE ON conversation_events
BEGIN
    SELECT RAISE(ABORT, 'conversation events are immutable');
END;

CREATE TRIGGER conversation_events_reject_delete
BEFORE DELETE ON conversation_events
BEGIN
    SELECT RAISE(ABORT, 'conversation events are immutable');
END;

CREATE TRIGGER conversation_idempotency_reject_update
BEFORE UPDATE ON conversation_append_idempotency
BEGIN
    SELECT RAISE(ABORT, 'conversation idempotency records are immutable');
END;

CREATE TRIGGER conversation_idempotency_reject_delete
BEFORE DELETE ON conversation_append_idempotency
BEGIN
    SELECT RAISE(ABORT, 'conversation idempotency records are immutable');
END;

CREATE TRIGGER conversation_outbox_reject_update
BEFORE UPDATE ON conversation_outbox
BEGIN
    SELECT RAISE(ABORT, 'conversation outbox records are immutable');
END;

CREATE TRIGGER conversation_outbox_reject_delete
BEFORE DELETE ON conversation_outbox
BEGIN
    SELECT RAISE(ABORT, 'conversation outbox records are immutable');
END;

CREATE TRIGGER conversation_audit_reject_update
BEFORE UPDATE ON conversation_audit
BEGIN
    SELECT RAISE(ABORT, 'conversation audit records are immutable');
END;

CREATE TRIGGER conversation_audit_reject_delete
BEFORE DELETE ON conversation_audit
BEGIN
    SELECT RAISE(ABORT, 'conversation audit records are immutable');
END;
