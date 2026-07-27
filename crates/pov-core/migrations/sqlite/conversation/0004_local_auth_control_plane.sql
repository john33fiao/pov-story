CREATE TABLE auth_key_lifecycle (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    state TEXT NOT NULL
        CHECK (state IN ('uninitialized', 'initializing', 'active', 'transitioning')),
    state_revision INTEGER NOT NULL
        CHECK (state_revision BETWEEN 0 AND 9223372036854775807),
    expected_kid TEXT
        CHECK (
            expected_kid IS NULL
            OR (
                typeof(expected_kid) = 'text'
                AND length(CAST(expected_kid AS BLOB)) = 43
                AND expected_kid NOT GLOB '*[^A-Za-z0-9_-]*'
            )
        ),
    transition_kind TEXT
        CHECK (
            transition_kind IS NULL
            OR transition_kind IN ('initialize', 'planned', 'retire', 'compromise', 'loss')
        ),
    transition_id BLOB
        CHECK (
            transition_id IS NULL
            OR (typeof(transition_id) = 'blob' AND length(transition_id) = 16)
        ),
    keyring_version INTEGER
        CHECK (
            keyring_version IS NULL
            OR keyring_version BETWEEN 1 AND 9223372036854775807
        ),
    updated_at_micros INTEGER NOT NULL CHECK (updated_at_micros >= 0),
    CHECK (
        (
            state = 'uninitialized'
            AND state_revision = 0
            AND expected_kid IS NULL
            AND transition_kind IS NULL
            AND transition_id IS NULL
            AND keyring_version IS NULL
            AND updated_at_micros = 0
        )
        OR (
            state = 'initializing'
            AND expected_kid IS NOT NULL
            AND transition_kind IS NOT NULL
            AND transition_kind = 'initialize'
            AND transition_id IS NOT NULL
            AND keyring_version IS NOT NULL
        )
        OR (
            state = 'active'
            AND expected_kid IS NOT NULL
            AND transition_kind IS NULL
            AND transition_id IS NULL
            AND keyring_version IS NOT NULL
        )
        OR (
            state = 'transitioning'
            AND expected_kid IS NOT NULL
            AND transition_kind IS NOT NULL
            AND transition_kind IN ('planned', 'retire', 'compromise', 'loss')
            AND transition_id IS NOT NULL
            AND keyring_version IS NOT NULL
        )
    )
) STRICT;

INSERT INTO auth_key_lifecycle(
    singleton,
    state,
    state_revision,
    expected_kid,
    transition_kind,
    transition_id,
    keyring_version,
    updated_at_micros
) VALUES (1, 'uninitialized', 0, NULL, NULL, NULL, NULL, 0);

CREATE TABLE auth_accounts (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    owner_id BLOB NOT NULL UNIQUE
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    login_id TEXT NOT NULL UNIQUE
        CHECK (
            typeof(login_id) = 'text'
            AND length(CAST(login_id AS BLOB)) BETWEEN 3 AND 32
            AND substr(login_id, 1, 1) GLOB '[a-z]'
            AND login_id NOT GLOB '*[^a-z0-9_-]*'
        ),
    account_state TEXT NOT NULL CHECK (account_state IN ('enabled', 'disabled')),
    credential_version INTEGER NOT NULL
        CHECK (credential_version BETWEEN 1 AND 9223372036854775807),
    account_revision INTEGER NOT NULL
        CHECK (account_revision BETWEEN 1 AND 9223372036854775807),
    created_at_micros INTEGER NOT NULL CHECK (created_at_micros >= 0),
    updated_at_micros INTEGER NOT NULL CHECK (updated_at_micros >= created_at_micros)
) STRICT;

CREATE TABLE auth_password_credentials (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    owner_id BLOB NOT NULL UNIQUE
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    verifier_phc TEXT NOT NULL
        CHECK (
            typeof(verifier_phc) = 'text'
            AND length(CAST(verifier_phc AS BLOB)) BETWEEN 1 AND 512
        ),
    authenticator_state TEXT NOT NULL
        CHECK (authenticator_state IN ('enabled', 'disabled')),
    credential_revision INTEGER NOT NULL
        CHECK (credential_revision BETWEEN 1 AND 9223372036854775807),
    blocklist_version TEXT NOT NULL
        CHECK (
            typeof(blocklist_version) = 'text'
            AND length(CAST(blocklist_version AS BLOB)) BETWEEN 1 AND 64
        ),
    created_at_micros INTEGER NOT NULL CHECK (created_at_micros >= 0),
    updated_at_micros INTEGER NOT NULL CHECK (updated_at_micros >= created_at_micros),
    FOREIGN KEY (owner_id) REFERENCES auth_accounts(owner_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE TABLE auth_recovery_credentials (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    owner_id BLOB NOT NULL UNIQUE
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    verifier_phc TEXT NOT NULL
        CHECK (
            typeof(verifier_phc) = 'text'
            AND length(CAST(verifier_phc AS BLOB)) BETWEEN 1 AND 512
        ),
    credential_revision INTEGER NOT NULL
        CHECK (credential_revision BETWEEN 1 AND 9223372036854775807),
    created_at_micros INTEGER NOT NULL CHECK (created_at_micros >= 0),
    updated_at_micros INTEGER NOT NULL CHECK (updated_at_micros >= created_at_micros),
    FOREIGN KEY (owner_id) REFERENCES auth_accounts(owner_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE TABLE auth_authenticator_throttles (
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    authenticator TEXT NOT NULL CHECK (authenticator IN ('password', 'recovery')),
    failure_count INTEGER NOT NULL
        CHECK (failure_count BETWEEN 0 AND 9223372036854775807),
    next_allowed_at_micros INTEGER NOT NULL CHECK (next_allowed_at_micros >= 0),
    throttle_revision INTEGER NOT NULL
        CHECK (throttle_revision BETWEEN 1 AND 9223372036854775807),
    updated_at_micros INTEGER NOT NULL CHECK (updated_at_micros >= 0),
    PRIMARY KEY (owner_id, authenticator),
    FOREIGN KEY (owner_id) REFERENCES auth_accounts(owner_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE TABLE auth_login_control (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    owner_id BLOB NOT NULL UNIQUE
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    admission_revision INTEGER NOT NULL
        CHECK (admission_revision BETWEEN 1 AND 9223372036854775807),
    clock_floor_micros INTEGER NOT NULL CHECK (clock_floor_micros >= 0),
    control_revision INTEGER NOT NULL
        CHECK (control_revision BETWEEN 1 AND 9223372036854775807),
    created_at_micros INTEGER NOT NULL CHECK (created_at_micros >= 0),
    updated_at_micros INTEGER NOT NULL CHECK (updated_at_micros >= created_at_micros),
    FOREIGN KEY (owner_id) REFERENCES auth_accounts(owner_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE TABLE auth_login_attempt_markers (
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    profile TEXT NOT NULL CHECK (profile IN ('local', 'remote')),
    attempt_id BLOB NOT NULL
        CHECK (typeof(attempt_id) = 'blob' AND length(attempt_id) = 16),
    admission_revision INTEGER NOT NULL
        CHECK (admission_revision BETWEEN 1 AND 9223372036854775807),
    created_at_micros INTEGER NOT NULL
        CHECK (created_at_micros BETWEEN 0 AND 9223372033254775807),
    expires_at_micros INTEGER NOT NULL
        CHECK (expires_at_micros = created_at_micros + 3600000000),
    PRIMARY KEY (owner_id, profile, attempt_id),
    FOREIGN KEY (owner_id) REFERENCES auth_accounts(owner_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE TABLE auth_login_attempt_outcomes (
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    profile TEXT NOT NULL CHECK (profile IN ('local', 'remote')),
    attempt_id BLOB NOT NULL
        CHECK (typeof(attempt_id) = 'blob' AND length(attempt_id) = 16),
    credential_version INTEGER NOT NULL
        CHECK (credential_version BETWEEN 1 AND 9223372036854775807),
    outcome_kind TEXT NOT NULL
        CHECK (outcome_kind IN ('generic_failure', 'committed_session')),
    session_id BLOB
        CHECK (
            session_id IS NULL
            OR (typeof(session_id) = 'blob' AND length(session_id) = 16)
        ),
    created_at_micros INTEGER NOT NULL CHECK (created_at_micros >= 0),
    CHECK (
        (outcome_kind = 'generic_failure' AND session_id IS NULL)
        OR (outcome_kind = 'committed_session' AND session_id IS NOT NULL)
    ),
    PRIMARY KEY (owner_id, profile, attempt_id),
    FOREIGN KEY (owner_id, profile, attempt_id)
        REFERENCES auth_login_attempt_markers(owner_id, profile, attempt_id)
        ON UPDATE RESTRICT ON DELETE CASCADE
) STRICT;

CREATE TABLE auth_sessions (
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    session_id BLOB NOT NULL
        CHECK (typeof(session_id) = 'blob' AND length(session_id) = 16),
    profile TEXT NOT NULL CHECK (profile IN ('local', 'remote')),
    credential_version INTEGER NOT NULL
        CHECK (credential_version BETWEEN 1 AND 9223372036854775807),
    created_at_micros INTEGER NOT NULL CHECK (created_at_micros >= 0),
    PRIMARY KEY (owner_id, session_id),
    UNIQUE (owner_id, session_id, profile),
    FOREIGN KEY (owner_id) REFERENCES auth_accounts(owner_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE TABLE auth_refresh_families (
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    family_id BLOB NOT NULL
        CHECK (typeof(family_id) = 'blob' AND length(family_id) = 16),
    session_id BLOB NOT NULL
        CHECK (typeof(session_id) = 'blob' AND length(session_id) = 16),
    profile TEXT NOT NULL CHECK (profile IN ('local', 'remote')),
    created_at_micros INTEGER NOT NULL CHECK (created_at_micros >= 0),
    last_refreshed_at_micros INTEGER NOT NULL
        CHECK (last_refreshed_at_micros >= created_at_micros),
    idle_deadline_at_micros INTEGER NOT NULL
        CHECK (idle_deadline_at_micros > last_refreshed_at_micros),
    absolute_deadline_at_micros INTEGER NOT NULL
        CHECK (absolute_deadline_at_micros >= idle_deadline_at_micros),
    CHECK (
        (
            profile = 'local'
            AND created_at_micros <= 9223369444854775807
            AND absolute_deadline_at_micros = created_at_micros + 2592000000000
            AND idle_deadline_at_micros = CASE
                WHEN absolute_deadline_at_micros - last_refreshed_at_micros
                    <= 604800000000
                THEN absolute_deadline_at_micros
                ELSE last_refreshed_at_micros + 604800000000
            END
        )
        OR (
            profile = 'remote'
            AND created_at_micros <= 9223371432054775807
            AND absolute_deadline_at_micros = created_at_micros + 604800000000
            AND idle_deadline_at_micros = CASE
                WHEN absolute_deadline_at_micros - last_refreshed_at_micros
                    <= 43200000000
                THEN absolute_deadline_at_micros
                ELSE last_refreshed_at_micros + 43200000000
            END
        )
    ),
    PRIMARY KEY (owner_id, family_id),
    UNIQUE (owner_id, session_id),
    FOREIGN KEY (owner_id, session_id, profile)
        REFERENCES auth_sessions(owner_id, session_id, profile)
        ON UPDATE RESTRICT ON DELETE CASCADE
) STRICT;

CREATE TABLE auth_refresh_tokens (
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    family_id BLOB NOT NULL
        CHECK (typeof(family_id) = 'blob' AND length(family_id) = 16),
    token_digest BLOB NOT NULL
        CHECK (typeof(token_digest) = 'blob' AND length(token_digest) = 32),
    generation INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 8191),
    predecessor_digest BLOB
        CHECK (
            predecessor_digest IS NULL
            OR (typeof(predecessor_digest) = 'blob' AND length(predecessor_digest) = 32)
        ),
    token_state TEXT NOT NULL CHECK (token_state IN ('active', 'consumed')),
    created_at_micros INTEGER NOT NULL CHECK (created_at_micros >= 0),
    consumed_at_micros INTEGER
        CHECK (consumed_at_micros IS NULL OR consumed_at_micros >= created_at_micros),
    CHECK (
        (generation = 0 AND predecessor_digest IS NULL)
        OR (generation > 0 AND predecessor_digest IS NOT NULL)
    ),
    CHECK (
        (token_state = 'active' AND consumed_at_micros IS NULL)
        OR (token_state = 'consumed' AND consumed_at_micros IS NOT NULL)
    ),
    PRIMARY KEY (owner_id, token_digest),
    UNIQUE (owner_id, family_id, generation),
    FOREIGN KEY (owner_id, family_id)
        REFERENCES auth_refresh_families(owner_id, family_id)
        ON UPDATE RESTRICT ON DELETE CASCADE
) STRICT;

CREATE UNIQUE INDEX auth_refresh_tokens_one_active_per_family
ON auth_refresh_tokens(owner_id, family_id)
WHERE token_state = 'active';

CREATE TABLE auth_audit (
    audit_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id BLOB NOT NULL
        CHECK (typeof(owner_id) = 'blob' AND length(owner_id) = 16),
    audit_id BLOB NOT NULL UNIQUE
        CHECK (typeof(audit_id) = 'blob' AND length(audit_id) = 16),
    action TEXT NOT NULL
        CHECK (
            action IN (
                'auth_initialized',
                'login_succeeded',
                'login_failed',
                'refresh_rotated',
                'refresh_replay_revoked',
                'refresh_exhausted',
                'logout',
                'logout_all',
                'password_changed',
                'recovery_completed',
                'recovery_code_rotated',
                'account_disabled',
                'account_enabled',
                'key_planned',
                'key_retired',
                'key_compromised',
                'key_loss_recovered'
            )
        ),
    profile TEXT CHECK (profile IS NULL OR profile IN ('local', 'remote')),
    session_id BLOB
        CHECK (
            session_id IS NULL
            OR (typeof(session_id) = 'blob' AND length(session_id) = 16)
        ),
    attempt_id BLOB
        CHECK (
            attempt_id IS NULL
            OR (typeof(attempt_id) = 'blob' AND length(attempt_id) = 16)
        ),
    happened_at_micros INTEGER NOT NULL CHECK (happened_at_micros >= 0),
    FOREIGN KEY (owner_id) REFERENCES auth_accounts(owner_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER auth_key_lifecycle_reject_insert
BEFORE INSERT ON auth_key_lifecycle
WHEN EXISTS (SELECT 1 FROM auth_key_lifecycle WHERE singleton = 1)
BEGIN
    SELECT RAISE(ABORT, 'auth key lifecycle is a singleton');
END;

CREATE TRIGGER auth_key_lifecycle_reject_delete
BEFORE DELETE ON auth_key_lifecycle
BEGIN
    SELECT RAISE(ABORT, 'auth key lifecycle cannot be deleted');
END;

CREATE TRIGGER auth_key_lifecycle_guard_update
BEFORE UPDATE ON auth_key_lifecycle
WHEN
    NEW.singleton <> OLD.singleton
    OR NEW.state_revision <> OLD.state_revision + 1
    OR NEW.updated_at_micros < OLD.updated_at_micros
    OR NEW.keyring_version < OLD.keyring_version
    OR (
        OLD.state = 'uninitialized'
        AND NEW.state <> 'initializing'
    )
    OR (
        OLD.state = 'initializing'
        AND (
            NEW.state <> 'active'
            OR NEW.expected_kid <> OLD.expected_kid
            OR NEW.keyring_version <> OLD.keyring_version
        )
    )
    OR (
        OLD.state = 'active'
        AND (
            NEW.state <> 'transitioning'
            OR NEW.keyring_version <> OLD.keyring_version + 1
            OR NEW.transition_kind IS NULL
            OR (
                NEW.transition_kind IN ('planned', 'compromise', 'loss')
                AND NEW.expected_kid = OLD.expected_kid
            )
            OR (
                NEW.transition_kind = 'retire'
                AND NEW.expected_kid <> OLD.expected_kid
            )
        )
    )
    OR (
        OLD.state = 'transitioning'
        AND (
            NEW.state <> 'active'
            OR NEW.expected_kid <> OLD.expected_kid
            OR NEW.keyring_version <> OLD.keyring_version
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid auth key lifecycle transition');
END;

CREATE TRIGGER auth_accounts_reject_delete
BEFORE DELETE ON auth_accounts
BEGIN
    SELECT RAISE(ABORT, 'auth account cannot be deleted');
END;

CREATE TRIGGER auth_accounts_guard_update
BEFORE UPDATE ON auth_accounts
WHEN
    NEW.singleton <> OLD.singleton
    OR NEW.owner_id <> OLD.owner_id
    OR NEW.login_id <> OLD.login_id
    OR NEW.created_at_micros <> OLD.created_at_micros
    OR NEW.account_revision <> OLD.account_revision + 1
    OR NEW.credential_version NOT IN (OLD.credential_version, OLD.credential_version + 1)
    OR (
        NEW.account_state IS NOT OLD.account_state
        AND NEW.credential_version <> OLD.credential_version + 1
    )
    OR (
        NEW.credential_version = OLD.credential_version + 1
        AND (
            EXISTS (
                SELECT 1 FROM auth_sessions
                WHERE owner_id = OLD.owner_id
            )
            OR EXISTS (
                SELECT 1 FROM auth_login_attempt_outcomes
                WHERE owner_id = OLD.owner_id
            )
        )
    )
    OR NEW.updated_at_micros < OLD.updated_at_micros
BEGIN
    SELECT RAISE(ABORT, 'invalid auth account transition');
END;

CREATE TRIGGER auth_password_credentials_reject_delete
BEFORE DELETE ON auth_password_credentials
BEGIN
    SELECT RAISE(ABORT, 'password credential cannot be deleted');
END;

CREATE TRIGGER auth_password_credentials_guard_update
BEFORE UPDATE ON auth_password_credentials
WHEN
    NEW.singleton <> OLD.singleton
    OR NEW.owner_id <> OLD.owner_id
    OR NEW.created_at_micros <> OLD.created_at_micros
    OR NEW.credential_revision <> OLD.credential_revision + 1
    OR NEW.updated_at_micros < OLD.updated_at_micros
BEGIN
    SELECT RAISE(ABORT, 'invalid password credential transition');
END;

CREATE TRIGGER auth_recovery_credentials_reject_delete
BEFORE DELETE ON auth_recovery_credentials
BEGIN
    SELECT RAISE(ABORT, 'recovery credential cannot be deleted');
END;

CREATE TRIGGER auth_recovery_credentials_guard_update
BEFORE UPDATE ON auth_recovery_credentials
WHEN
    NEW.singleton <> OLD.singleton
    OR NEW.owner_id <> OLD.owner_id
    OR NEW.created_at_micros <> OLD.created_at_micros
    OR NEW.credential_revision <> OLD.credential_revision + 1
    OR NEW.updated_at_micros < OLD.updated_at_micros
BEGIN
    SELECT RAISE(ABORT, 'invalid recovery credential transition');
END;

CREATE TRIGGER auth_authenticator_throttles_reject_delete
BEFORE DELETE ON auth_authenticator_throttles
BEGIN
    SELECT RAISE(ABORT, 'authenticator throttle cannot be deleted');
END;

CREATE TRIGGER auth_authenticator_throttles_guard_update
BEFORE UPDATE ON auth_authenticator_throttles
WHEN
    NEW.owner_id <> OLD.owner_id
    OR NEW.authenticator <> OLD.authenticator
    OR NEW.throttle_revision <> OLD.throttle_revision + 1
    OR NEW.updated_at_micros < OLD.updated_at_micros
    OR NEW.failure_count NOT IN (0, OLD.failure_count + 1)
    OR (NEW.failure_count = 0 AND NEW.next_allowed_at_micros <> 0)
BEGIN
    SELECT RAISE(ABORT, 'invalid authenticator throttle transition');
END;

CREATE TRIGGER auth_login_control_reject_delete
BEFORE DELETE ON auth_login_control
BEGIN
    SELECT RAISE(ABORT, 'auth login control cannot be deleted');
END;

CREATE TRIGGER auth_login_control_guard_update
BEFORE UPDATE ON auth_login_control
WHEN
    NEW.singleton <> OLD.singleton
    OR NEW.owner_id <> OLD.owner_id
    OR NEW.created_at_micros <> OLD.created_at_micros
    OR NEW.admission_revision < OLD.admission_revision
    OR NEW.admission_revision > OLD.admission_revision + 1
    OR NEW.clock_floor_micros < OLD.clock_floor_micros
    OR NEW.control_revision <> OLD.control_revision + 1
    OR NEW.updated_at_micros < OLD.updated_at_micros
BEGIN
    SELECT RAISE(ABORT, 'invalid auth login control transition');
END;

CREATE TRIGGER auth_login_attempt_markers_cap
BEFORE INSERT ON auth_login_attempt_markers
WHEN (
    SELECT count(*)
    FROM auth_login_attempt_markers
    WHERE owner_id = NEW.owner_id AND profile = NEW.profile
) >= 64
BEGIN
    SELECT RAISE(ABORT, 'auth login attempt marker cap reached');
END;

CREATE TRIGGER auth_login_attempt_markers_reject_duplicate_insert
BEFORE INSERT ON auth_login_attempt_markers
WHEN EXISTS (
    SELECT 1
    FROM auth_login_attempt_markers
    WHERE
        owner_id = NEW.owner_id
        AND profile = NEW.profile
        AND attempt_id = NEW.attempt_id
)
BEGIN
    SELECT RAISE(ABORT, 'auth login attempt markers cannot be replaced');
END;

CREATE TRIGGER auth_login_attempt_markers_reject_update
BEFORE UPDATE ON auth_login_attempt_markers
BEGIN
    SELECT RAISE(ABORT, 'auth login attempt markers are immutable');
END;

CREATE TRIGGER auth_login_attempt_outcomes_validate_insert
BEFORE INSERT ON auth_login_attempt_outcomes
WHEN
    EXISTS (
        SELECT 1
        FROM auth_login_attempt_outcomes
        WHERE
            owner_id = NEW.owner_id
            AND profile = NEW.profile
            AND attempt_id = NEW.attempt_id
    )
    OR NOT EXISTS (
        SELECT 1
        FROM auth_accounts
        WHERE
            owner_id = NEW.owner_id
            AND credential_version = NEW.credential_version
    )
    OR (
        NEW.outcome_kind = 'committed_session'
        AND NOT EXISTS (
            SELECT 1
            FROM auth_sessions
            WHERE
                owner_id = NEW.owner_id
                AND session_id = NEW.session_id
                AND profile = NEW.profile
                AND credential_version = NEW.credential_version
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid auth login attempt outcome');
END;

CREATE TRIGGER auth_login_attempt_outcomes_reject_update
BEFORE UPDATE ON auth_login_attempt_outcomes
BEGIN
    SELECT RAISE(ABORT, 'auth login attempt outcomes are immutable');
END;

CREATE TRIGGER auth_sessions_cap
BEFORE INSERT ON auth_sessions
WHEN (
    SELECT count(*)
    FROM auth_sessions
    WHERE owner_id = NEW.owner_id AND profile = NEW.profile
) >= 8
BEGIN
    SELECT RAISE(ABORT, 'auth session cap reached');
END;

CREATE TRIGGER auth_sessions_validate_insert
BEFORE INSERT ON auth_sessions
WHEN NOT EXISTS (
    SELECT 1
    FROM auth_accounts
    WHERE
        owner_id = NEW.owner_id
        AND account_state = 'enabled'
        AND credential_version = NEW.credential_version
)
BEGIN
    SELECT RAISE(ABORT, 'auth session requires current enabled account');
END;

CREATE TRIGGER auth_sessions_reject_duplicate_insert
BEFORE INSERT ON auth_sessions
WHEN EXISTS (
    SELECT 1
    FROM auth_sessions
    WHERE owner_id = NEW.owner_id AND session_id = NEW.session_id
)
BEGIN
    SELECT RAISE(ABORT, 'auth sessions cannot be replaced');
END;

CREATE TRIGGER auth_sessions_reject_update
BEFORE UPDATE ON auth_sessions
BEGIN
    SELECT RAISE(ABORT, 'auth sessions are immutable');
END;

CREATE TRIGGER auth_refresh_families_reject_duplicate_insert
BEFORE INSERT ON auth_refresh_families
WHEN EXISTS (
    SELECT 1
    FROM auth_refresh_families
    WHERE
        owner_id = NEW.owner_id
        AND (family_id = NEW.family_id OR session_id = NEW.session_id)
)
BEGIN
    SELECT RAISE(ABORT, 'auth refresh families cannot be replaced');
END;

CREATE TRIGGER auth_refresh_families_guard_update
BEFORE UPDATE ON auth_refresh_families
WHEN
    NEW.owner_id <> OLD.owner_id
    OR NEW.family_id <> OLD.family_id
    OR NEW.session_id <> OLD.session_id
    OR NEW.profile <> OLD.profile
    OR NEW.created_at_micros <> OLD.created_at_micros
    OR NEW.absolute_deadline_at_micros <> OLD.absolute_deadline_at_micros
    OR NEW.last_refreshed_at_micros <= OLD.last_refreshed_at_micros
BEGIN
    SELECT RAISE(ABORT, 'invalid auth refresh family transition');
END;

CREATE TRIGGER auth_refresh_families_require_session_delete
AFTER DELETE ON auth_refresh_families
WHEN EXISTS (
    SELECT 1
    FROM auth_sessions
    WHERE owner_id = OLD.owner_id AND session_id = OLD.session_id
)
BEGIN
    SELECT RAISE(ABORT, 'refresh family deletion requires terminal session deletion');
END;

CREATE TRIGGER auth_refresh_tokens_validate_predecessor
BEFORE INSERT ON auth_refresh_tokens
WHEN
    NEW.token_state <> 'active'
    OR NEW.consumed_at_micros IS NOT NULL
    OR EXISTS (
        SELECT 1
        FROM auth_refresh_tokens
        WHERE
            owner_id = NEW.owner_id
            AND (
                token_digest = NEW.token_digest
                OR (
                    family_id = NEW.family_id
                    AND generation = NEW.generation
                )
                OR (
                    family_id = NEW.family_id
                    AND token_state = 'active'
                    AND NEW.token_state = 'active'
                )
            )
    )
    OR (
        NEW.generation = 0
        AND EXISTS (
            SELECT 1 FROM auth_refresh_tokens
            WHERE owner_id = NEW.owner_id AND family_id = NEW.family_id
        )
    )
    OR (
        NEW.generation > 0
        AND NOT EXISTS (
            SELECT 1
            FROM auth_refresh_tokens
            WHERE
                owner_id = NEW.owner_id
                AND family_id = NEW.family_id
                AND token_digest = NEW.predecessor_digest
                AND generation = NEW.generation - 1
                AND token_state = 'consumed'
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid refresh token predecessor');
END;

CREATE TRIGGER auth_refresh_tokens_guard_update
BEFORE UPDATE ON auth_refresh_tokens
WHEN
    NEW.owner_id <> OLD.owner_id
    OR NEW.family_id <> OLD.family_id
    OR NEW.token_digest <> OLD.token_digest
    OR NEW.generation <> OLD.generation
    OR NEW.predecessor_digest IS NOT OLD.predecessor_digest
    OR NEW.created_at_micros <> OLD.created_at_micros
    OR OLD.token_state <> 'active'
    OR NEW.token_state <> 'consumed'
    OR OLD.consumed_at_micros IS NOT NULL
    OR NEW.consumed_at_micros IS NULL
BEGIN
    SELECT RAISE(ABORT, 'invalid refresh token transition');
END;

CREATE TRIGGER auth_refresh_tokens_require_family_delete
AFTER DELETE ON auth_refresh_tokens
WHEN EXISTS (
    SELECT 1
    FROM auth_refresh_families
    WHERE owner_id = OLD.owner_id AND family_id = OLD.family_id
)
BEGIN
    SELECT RAISE(ABORT, 'refresh token deletion requires terminal family deletion');
END;

CREATE TRIGGER auth_audit_reject_update
BEFORE UPDATE ON auth_audit
BEGIN
    SELECT RAISE(ABORT, 'auth audit records are immutable');
END;

CREATE TRIGGER auth_audit_reject_delete
BEFORE DELETE ON auth_audit
BEGIN
    SELECT RAISE(ABORT, 'auth audit records are immutable');
END;
