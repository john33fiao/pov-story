use std::collections::HashSet;

use pov_core::{
    postgres::{PostgresAdapterStatus, boundary as postgres_boundary},
    storage::{BUSY_TIMEOUT_MILLIS, BackupHook, StoreKind, StoreRole, StoreSet},
};
use tempfile::tempdir;
use tokio_rusqlite::rusqlite::{Connection as RawConnection, params};

fn expected_migration_count(kind: StoreKind) -> usize {
    match kind {
        StoreKind::Conversation => 6,
        StoreKind::Knowledge | StoreKind::Calendar | StoreKind::Embedding => 1,
    }
}

fn exact_auth_throttle_deadline(failure_count: i64, updated_at_micros: i64) -> Option<i64> {
    let delay_micros = match failure_count {
        0 => return Some(0),
        1..=4 => 0,
        5 => 30_000_000,
        6 => 60_000_000,
        7 => 120_000_000,
        8 => 240_000_000,
        9 => 480_000_000,
        10 => 960_000_000,
        11 => 1_920_000_000,
        12..=100 => 3_600_000_000,
        _ => return None,
    };
    updated_at_micros.checked_add(delay_micros)
}

#[tokio::test]
async fn local_auth_migration_starts_with_only_the_exact_uninitialized_sentinel() {
    let directory = tempdir().expect("temporary store directory");
    let root = directory.path().join("stores");
    let stores = StoreSet::open(&root)
        .await
        .expect("clean stores should open");
    stores.close().await.expect("stores should close cleanly");

    let connection =
        RawConnection::open(root.join("conversation.sqlite3")).expect("conversation database");
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("foreign keys");
    connection
        .pragma_update(None, "recursive_triggers", "ON")
        .expect("recursive triggers");

    let sentinel = connection
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
        .expect("auth lifecycle sentinel");
    assert_eq!(
        sentinel,
        ("uninitialized".to_owned(), 0, None, None, None, None, 0)
    );

    for table in [
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
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("auth table count");
        assert_eq!(count, 0, "{table} must start empty");
    }

    assert!(
        connection
            .execute(
                "UPDATE auth_key_lifecycle
                 SET
                    state = 'active',
                    state_revision = 1,
                    expected_kid = ?1,
                    keyring_version = 1,
                    updated_at_micros = 1
                 WHERE singleton = 1",
                ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            )
            .is_err(),
        "uninitialized lifecycle must not skip initialization"
    );

    let first_kid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let next_kid = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    let transition = [9_u8; 16];
    assert!(
        connection
            .execute(
                "UPDATE auth_key_lifecycle
                 SET state = 'initializing', state_revision = 1,
                     expected_kid = ?1, transition_kind = NULL,
                     transition_id = ?2, keyring_version = 1,
                     updated_at_micros = 1
                 WHERE singleton = 1",
                params![first_kid, &transition[..]],
            )
            .is_err(),
        "initialization requires an explicit transition kind"
    );
    connection
        .execute(
            "UPDATE auth_key_lifecycle
             SET state = 'initializing', state_revision = 1, expected_kid = ?1,
                 transition_kind = 'initialize', transition_id = ?2,
                 keyring_version = 1, updated_at_micros = 1
             WHERE singleton = 1",
            params![first_kid, &transition[..]],
        )
        .expect("initialization source transition");
    connection
        .execute(
            "UPDATE auth_key_lifecycle
             SET state = 'active', state_revision = 2, transition_kind = NULL,
                 transition_id = NULL, updated_at_micros = 2
             WHERE singleton = 1",
            [],
        )
        .expect("initialization final transition");
    assert!(
        connection
            .execute(
                "UPDATE auth_key_lifecycle
                 SET state = 'transitioning', state_revision = 3,
                     expected_kid = ?1, transition_kind = NULL,
                     transition_id = ?2, keyring_version = 2,
                     updated_at_micros = 3
                 WHERE singleton = 1",
                params![next_kid, &transition[..]],
            )
            .is_err(),
        "active transition requires an explicit transition kind"
    );
    assert!(
        connection
            .execute(
                "UPDATE auth_key_lifecycle
                 SET state = 'transitioning', state_revision = 3,
                     transition_kind = 'planned', transition_id = ?1,
                     keyring_version = 2, updated_at_micros = 3
                 WHERE singleton = 1",
                [&transition[..]],
            )
            .is_err(),
        "planned rotation must change the active kid"
    );
    assert!(
        connection
            .execute(
                "UPDATE auth_key_lifecycle
                 SET state = 'transitioning', state_revision = 3,
                     expected_kid = ?1, transition_kind = 'retire',
                     transition_id = ?2, keyring_version = 2,
                     updated_at_micros = 3
                 WHERE singleton = 1",
                params![next_kid, &transition[..]],
            )
            .is_err(),
        "verify-only retirement must keep the active kid"
    );
    connection
        .execute(
            "UPDATE auth_key_lifecycle
             SET state = 'transitioning', state_revision = 3,
                 expected_kid = ?1, transition_kind = 'planned',
                 transition_id = ?2, keyring_version = 2,
                 updated_at_micros = 3
             WHERE singleton = 1",
            params![next_kid, &transition[..]],
        )
        .expect("planned rotation source transition");
    connection
        .execute(
            "UPDATE auth_key_lifecycle
             SET state = 'active', state_revision = 4, transition_kind = NULL,
                 transition_id = NULL, updated_at_micros = 4
             WHERE singleton = 1",
            [],
        )
        .expect("planned rotation final transition");
}

#[tokio::test]
async fn local_auth_rows_resist_replace_and_only_terminal_session_delete_cascades() {
    let directory = tempdir().expect("temporary store directory");
    let root = directory.path().join("stores");
    let stores = StoreSet::open(&root)
        .await
        .expect("clean stores should open");
    stores.close().await.expect("stores should close cleanly");

    let connection =
        RawConnection::open(root.join("conversation.sqlite3")).expect("conversation database");
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("foreign keys");
    connection
        .pragma_update(None, "recursive_triggers", "ON")
        .expect("recursive triggers");

    let owner = [1_u8; 16];
    let attempt = [2_u8; 16];
    let other_attempt = [3_u8; 16];
    let session = [4_u8; 16];
    let missing_session = [5_u8; 16];
    let family = [6_u8; 16];
    let digest = [7_u8; 32];
    let replacement_digest = [8_u8; 32];

    connection
        .execute(
            "INSERT INTO auth_accounts(
                singleton, owner_id, login_id, account_state, credential_version,
                account_revision, created_at_micros, updated_at_micros
             ) VALUES (1, ?1, 'owner', 'enabled', 1, 1, 1, 1)",
            [&owner[..]],
        )
        .expect("synthetic auth account");
    connection
        .execute(
            "INSERT INTO auth_login_attempt_markers(
                owner_id, profile, attempt_id, admission_revision,
                created_at_micros, expires_at_micros
             ) VALUES (?1, 'local', ?2, 1, 1, 3600000001)",
            params![&owner[..], &attempt[..]],
        )
        .expect("login marker");
    assert!(
        connection
            .execute(
                "INSERT OR REPLACE INTO auth_login_attempt_markers(
                    owner_id, profile, attempt_id, admission_revision,
                    created_at_micros, expires_at_micros
                 ) VALUES (?1, 'local', ?2, 2, 2, 3600000002)",
                params![&owner[..], &attempt[..]],
            )
            .is_err(),
        "fixed login marker must not be replaced"
    );

    connection
        .execute(
            "INSERT INTO auth_sessions(
                owner_id, session_id, profile, credential_version, created_at_micros
             ) VALUES (?1, ?2, 'local', 1, 1)",
            params![&owner[..], &session[..]],
        )
        .expect("active session");
    assert!(
        connection
            .execute(
                "INSERT OR REPLACE INTO auth_sessions(
                    owner_id, session_id, profile, credential_version, created_at_micros
                 ) VALUES (?1, ?2, 'remote', 2, 2)",
                params![&owner[..], &session[..]],
            )
            .is_err(),
        "active session must not be replaced"
    );
    assert!(
        connection
            .execute(
                "INSERT INTO auth_sessions(
                    owner_id, session_id, profile, credential_version, created_at_micros
                 ) VALUES (?1, ?2, 'local', 2, 1)",
                params![&owner[..], &missing_session[..]],
            )
            .is_err(),
        "session must match the current enabled account version"
    );

    connection
        .execute(
            "INSERT INTO auth_refresh_families(
                owner_id, family_id, session_id, profile, created_at_micros,
                last_refreshed_at_micros, idle_deadline_at_micros,
                absolute_deadline_at_micros
             ) VALUES (?1, ?2, ?3, 'local', 1, 1, 2, 3)",
            params![&owner[..], &family[..], &session[..]],
        )
        .expect_err("refresh lifetime must match the local profile");
    connection
        .execute(
            "INSERT INTO auth_login_attempt_outcomes(
                owner_id, profile, attempt_id, credential_version,
                outcome_kind, session_id, created_at_micros
             ) VALUES (?1, 'local', ?2, 1, 'committed_session', ?3, 1)",
            params![&owner[..], &attempt[..], &session[..]],
        )
        .expect("linked committed-session outcome");
    assert!(
        connection
            .execute(
                "INSERT OR REPLACE INTO auth_login_attempt_outcomes(
                    owner_id, profile, attempt_id, credential_version,
                    outcome_kind, session_id, created_at_micros
                 ) VALUES (?1, 'local', ?2, 1, 'generic_failure', NULL, 2)",
                params![&owner[..], &attempt[..]],
            )
            .is_err(),
        "login outcome must not be replaced"
    );
    connection
        .execute(
            "INSERT INTO auth_login_attempt_markers(
                owner_id, profile, attempt_id, admission_revision,
                created_at_micros, expires_at_micros
             ) VALUES (?1, 'local', ?2, 1, 2, 3600000002)",
            params![&owner[..], &other_attempt[..]],
        )
        .expect("second login marker");
    assert!(
        connection
            .execute(
                "INSERT INTO auth_login_attempt_outcomes(
                    owner_id, profile, attempt_id, credential_version,
                    outcome_kind, session_id, created_at_micros
                 ) VALUES (?1, 'local', ?2, 1, 'committed_session', ?3, 2)",
                params![&owner[..], &other_attempt[..], &missing_session[..]],
            )
            .is_err(),
        "committed outcome must reference a matching active session"
    );

    connection
        .execute(
            "INSERT INTO auth_refresh_families(
                owner_id, family_id, session_id, profile, created_at_micros,
                last_refreshed_at_micros, idle_deadline_at_micros,
                absolute_deadline_at_micros
             ) VALUES (
                ?1, ?2, ?3, 'local', 1, 1, 604800000001, 2592000000001
             )",
            params![&owner[..], &family[..], &session[..]],
        )
        .expect("refresh family");
    assert!(
        connection
            .execute(
                "INSERT OR REPLACE INTO auth_refresh_families(
                    owner_id, family_id, session_id, profile, created_at_micros,
                    last_refreshed_at_micros, idle_deadline_at_micros,
                    absolute_deadline_at_micros
                 ) VALUES (
                    ?1, ?2, ?3, 'local', 2, 2, 604800000002, 2592000000002
                 )",
                params![&owner[..], &family[..], &session[..]],
            )
            .is_err(),
        "refresh family must not be replaced"
    );
    assert!(
        connection
            .execute(
                "INSERT INTO auth_refresh_tokens(
                    owner_id, family_id, token_digest, generation, predecessor_digest,
                    token_state, created_at_micros, consumed_at_micros
                 ) VALUES (?1, ?2, ?3, 0, NULL, 'consumed', 1, 2)",
                params![&owner[..], &family[..], &replacement_digest[..]],
            )
            .is_err(),
        "consumed refresh tokens may only result from guarded updates"
    );
    connection
        .execute(
            "INSERT INTO auth_refresh_tokens(
                owner_id, family_id, token_digest, generation, predecessor_digest,
                token_state, created_at_micros, consumed_at_micros
             ) VALUES (?1, ?2, ?3, 0, NULL, 'active', 1, NULL)",
            params![&owner[..], &family[..], &digest[..]],
        )
        .expect("initial refresh token");
    assert!(
        connection
            .execute(
                "INSERT OR REPLACE INTO auth_refresh_tokens(
                    owner_id, family_id, token_digest, generation, predecessor_digest,
                    token_state, created_at_micros, consumed_at_micros
                 ) VALUES (?1, ?2, ?3, 0, NULL, 'active', 2, NULL)",
                params![&owner[..], &family[..], &replacement_digest[..]],
            )
            .is_err(),
        "same-generation active token must not be replaced"
    );
    assert!(
        connection
            .execute(
                "DELETE FROM auth_refresh_tokens
                 WHERE owner_id = ?1 AND token_digest = ?2",
                params![&owner[..], &digest[..]],
            )
            .is_err(),
        "token deletion requires terminal family deletion"
    );
    assert!(
        connection
            .execute(
                "DELETE FROM auth_refresh_families
                 WHERE owner_id = ?1 AND family_id = ?2",
                params![&owner[..], &family[..]],
            )
            .is_err(),
        "family deletion requires terminal session deletion"
    );

    connection
        .execute(
            "DELETE FROM auth_sessions WHERE owner_id = ?1 AND session_id = ?2",
            params![&owner[..], &session[..]],
        )
        .expect("terminal session delete cascades");
    for table in [
        "auth_sessions",
        "auth_refresh_families",
        "auth_refresh_tokens",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("terminal auth row count");
        assert_eq!(count, 0, "{table} must be terminally empty");
    }
    let retained_outcomes: i64 = connection
        .query_row(
            "SELECT count(*) FROM auth_login_attempt_outcomes",
            [],
            |row| row.get(0),
        )
        .expect("retained login outcome count");
    assert_eq!(retained_outcomes, 1, "response-loss outcome is retained");

    assert!(
        connection
            .execute(
                "UPDATE auth_accounts
                 SET account_state = 'disabled', credential_version = 2,
                     account_revision = 2, updated_at_micros = 2
                 WHERE singleton = 1",
                [],
            )
            .is_err(),
        "credential version cannot change while an outcome remains"
    );
    connection
        .execute(
            "DELETE FROM auth_login_attempt_outcomes WHERE owner_id = ?1",
            [&owner[..]],
        )
        .expect("credential mutation invalidates outcomes");
    connection
        .execute(
            "UPDATE auth_accounts
             SET account_state = 'disabled', credential_version = 2,
                 account_revision = 2, updated_at_micros = 2
             WHERE singleton = 1",
            [],
        )
        .expect("account disable after terminal cleanup");
    assert!(
        connection
            .execute(
                "UPDATE auth_accounts
                 SET account_state = 'enabled', account_revision = 3,
                     updated_at_micros = 3
                 WHERE singleton = 1",
                [],
            )
            .is_err(),
        "account re-enable must increment the credential version"
    );
    let marker_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM auth_login_attempt_markers",
            [],
            |row| row.get(0),
        )
        .expect("retained marker count");
    assert_eq!(
        marker_count, 2,
        "credential mutation preserves fixed markers"
    );
}

#[tokio::test]
async fn local_auth_throttle_bounds_and_recovery_saturation_are_enforced() {
    let directory = tempdir().expect("temporary store directory");
    let root = directory.path().join("stores");
    let stores = StoreSet::open(&root)
        .await
        .expect("clean stores should open");
    stores.close().await.expect("stores should close cleanly");

    let connection =
        RawConnection::open(root.join("conversation.sqlite3")).expect("conversation database");
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("foreign keys");
    connection
        .pragma_update(None, "recursive_triggers", "ON")
        .expect("recursive triggers");

    let owner = [20_u8; 16];
    connection
        .execute(
            "INSERT INTO auth_accounts(
                singleton, owner_id, login_id, account_state, credential_version,
                account_revision, created_at_micros, updated_at_micros
             ) VALUES (1, ?1, 'owner', 'enabled', 1, 1, 0, 0)",
            [&owner[..]],
        )
        .expect("synthetic auth account");

    for (failure_count, next_allowed, revision) in [(1_i64, 0_i64, 1_i64), (0, 1, 1), (0, 0, 2)] {
        assert!(
            connection
                .execute(
                    "INSERT INTO auth_authenticator_throttles(
                        owner_id, authenticator, failure_count,
                        next_allowed_at_micros, throttle_revision, updated_at_micros
                     ) VALUES (?1, 'password', ?2, ?3, ?4, 0)",
                    params![&owner[..], failure_count, next_allowed, revision],
                )
                .is_err(),
            "new throttle rows require the exact zeroed revision-one state"
        );
    }

    connection
        .execute(
            "INSERT INTO auth_authenticator_throttles(
                owner_id, authenticator, failure_count,
                next_allowed_at_micros, throttle_revision, updated_at_micros
             ) VALUES (?1, 'password', 0, 0, 1, 0)",
            [&owner[..]],
        )
        .expect("initial password throttle");
    let other_owner = [21_u8; 16];
    assert!(
        connection
            .execute(
                "UPDATE auth_authenticator_throttles
                 SET owner_id = ?2, throttle_revision = 2
                 WHERE owner_id = ?1 AND authenticator = 'password'",
                params![&owner[..], &other_owner[..]],
            )
            .is_err(),
        "throttle owner identity is immutable"
    );
    assert!(
        connection
            .execute(
                "UPDATE auth_authenticator_throttles
                 SET authenticator = 'recovery', throttle_revision = 2
                 WHERE owner_id = ?1 AND authenticator = 'password'",
                [&owner[..]],
            )
            .is_err(),
        "authenticator identity is immutable"
    );
    connection
        .execute(
            "INSERT INTO auth_authenticator_throttles(
                owner_id, authenticator, failure_count,
                next_allowed_at_micros, throttle_revision, updated_at_micros
             ) VALUES (?1, 'recovery', 0, 0, 1, 0)",
            [&owner[..]],
        )
        .expect("initial recovery throttle");

    let exact_delay_boundaries = [1_i64, 4, 5, 11, 12, 100];
    let mut password_updated_at = 0_i64;
    let mut password_next_allowed_at = 0_i64;
    for failure_count in 1_i64..=100 {
        let updated_at = if failure_count == 1 {
            10_000_000_000
        } else {
            password_next_allowed_at
        };
        let exact_deadline = exact_auth_throttle_deadline(failure_count, updated_at)
            .expect("bounded password deadline");

        if exact_delay_boundaries.contains(&failure_count) {
            for wrong_deadline in [exact_deadline - 1, exact_deadline + 1] {
                assert!(
                    connection
                        .execute(
                            "UPDATE auth_authenticator_throttles
                             SET failure_count = ?2, next_allowed_at_micros = ?3,
                                 throttle_revision = throttle_revision + 1,
                                 updated_at_micros = ?4
                             WHERE owner_id = ?1 AND authenticator = 'password'",
                            params![&owner[..], failure_count, wrong_deadline, updated_at],
                        )
                        .is_err(),
                    "under- and over-delayed password deadlines must be rejected at count {failure_count}"
                );
            }
        }
        if failure_count == 6 {
            let early_updated_at = password_next_allowed_at - 1;
            let early_deadline = exact_auth_throttle_deadline(failure_count, early_updated_at)
                .expect("early password deadline");
            assert!(
                connection
                    .execute(
                        "UPDATE auth_authenticator_throttles
                         SET failure_count = ?2, next_allowed_at_micros = ?3,
                             throttle_revision = throttle_revision + 1,
                             updated_at_micros = ?4
                         WHERE owner_id = ?1 AND authenticator = 'password'",
                        params![&owner[..], failure_count, early_deadline, early_updated_at],
                    )
                    .is_err(),
                "a failure one microsecond before the durable deadline is not admitted"
            );
        }

        connection
            .execute(
                "UPDATE auth_authenticator_throttles
                 SET failure_count = ?2, next_allowed_at_micros = ?3,
                     throttle_revision = throttle_revision + 1,
                     updated_at_micros = ?4
                 WHERE owner_id = ?1 AND authenticator = 'password'",
                params![&owner[..], failure_count, exact_deadline, updated_at],
            )
            .expect("exact password throttle transition");
        password_updated_at = updated_at;
        password_next_allowed_at = exact_deadline;
    }
    assert!(
        connection
            .execute(
                "UPDATE auth_authenticator_throttles
                 SET failure_count = 101, next_allowed_at_micros = ?2,
                     throttle_revision = throttle_revision + 1,
                     updated_at_micros = ?3
                 WHERE owner_id = ?1 AND authenticator = 'password'",
                params![
                    &owner[..],
                    password_next_allowed_at + 3_600_000_000,
                    password_next_allowed_at
                ],
            )
            .is_err(),
        "password throttle cannot increment beyond 100"
    );
    let password_reset_updated_at = password_updated_at + 1;
    assert!(
        connection
            .execute(
                "UPDATE auth_authenticator_throttles
                 SET failure_count = 0, next_allowed_at_micros = 1,
                     throttle_revision = throttle_revision + 1,
                     updated_at_micros = ?2
                 WHERE owner_id = ?1 AND authenticator = 'password'",
                params![&owner[..], password_reset_updated_at],
            )
            .is_err(),
        "a throttle reset must clear its deadline"
    );
    assert!(
        connection
            .execute(
                "UPDATE auth_authenticator_throttles
                 SET failure_count = 0, next_allowed_at_micros = 0,
                     throttle_revision = throttle_revision + 1,
                     updated_at_micros = ?2
                 WHERE owner_id = ?1 AND authenticator = 'password'",
                params![&owner[..], password_updated_at - 1],
            )
            .is_err(),
        "throttle update time cannot regress"
    );
    assert!(
        connection
            .execute(
                "INSERT OR REPLACE INTO auth_authenticator_throttles(
                    owner_id, authenticator, failure_count,
                    next_allowed_at_micros, throttle_revision, updated_at_micros
                 ) VALUES (?1, 'password', 0, 0, 1, ?2)",
                params![&owner[..], password_reset_updated_at],
            )
            .is_err(),
        "replace cannot bypass throttle transition guards"
    );
    connection
        .execute(
            "UPDATE auth_authenticator_throttles
             SET failure_count = 0, next_allowed_at_micros = 0,
                 throttle_revision = throttle_revision + 1,
                 updated_at_micros = ?2
             WHERE owner_id = ?1 AND authenticator = 'password'",
            params![&owner[..], password_reset_updated_at],
        )
        .expect("recovery-authorized password reset remains representable");

    let mut recovery_next_allowed_at = 0_i64;
    for failure_count in 1_i64..=100 {
        let updated_at = if failure_count == 1 {
            20_000_000_000
        } else {
            recovery_next_allowed_at
        };
        let exact_deadline = exact_auth_throttle_deadline(failure_count, updated_at)
            .expect("bounded recovery deadline");
        connection
            .execute(
                "UPDATE auth_authenticator_throttles
                 SET failure_count = ?2, next_allowed_at_micros = ?3,
                     throttle_revision = throttle_revision + 1,
                     updated_at_micros = ?4
                 WHERE owner_id = ?1 AND authenticator = 'recovery'",
                params![&owner[..], failure_count, exact_deadline, updated_at],
            )
            .expect("exact recovery throttle transition");
        recovery_next_allowed_at = exact_deadline;
    }
    let early_saturation_updated_at = recovery_next_allowed_at - 1;
    let early_saturation_deadline = exact_auth_throttle_deadline(100, early_saturation_updated_at)
        .expect("early saturated recovery deadline");
    assert!(
        connection
            .execute(
                "UPDATE auth_authenticator_throttles
                 SET failure_count = 100, next_allowed_at_micros = ?2,
                     throttle_revision = throttle_revision + 1,
                     updated_at_micros = ?3
                 WHERE owner_id = ?1 AND authenticator = 'recovery'",
                params![
                    &owner[..],
                    early_saturation_deadline,
                    early_saturation_updated_at
                ],
            )
            .is_err(),
        "saturated recovery failure before the durable deadline is not admitted"
    );
    let saturation_updated_at = recovery_next_allowed_at;
    let saturation_deadline = exact_auth_throttle_deadline(100, saturation_updated_at)
        .expect("saturated recovery deadline");
    connection
        .execute(
            "UPDATE auth_authenticator_throttles
             SET failure_count = 100, next_allowed_at_micros = ?2,
                 throttle_revision = throttle_revision + 1,
                 updated_at_micros = ?3
             WHERE owner_id = ?1 AND authenticator = 'recovery'",
            params![&owner[..], saturation_deadline, saturation_updated_at],
        )
        .expect("exact-boundary recovery failure refreshes the saturated deadline");
    let saturated: (i64, i64, i64, i64) = connection
        .query_row(
            "SELECT
                failure_count, next_allowed_at_micros,
                throttle_revision, updated_at_micros
             FROM auth_authenticator_throttles
             WHERE owner_id = ?1 AND authenticator = 'recovery'",
            [&owner[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("saturated recovery throttle");
    assert_eq!(
        saturated,
        (100, saturation_deadline, 102, saturation_updated_at)
    );
    assert!(
        connection
            .execute(
                "UPDATE auth_authenticator_throttles
                 SET failure_count = 100, next_allowed_at_micros = ?2,
                     throttle_revision = throttle_revision + 1,
                     updated_at_micros = ?3
                 WHERE owner_id = ?1 AND authenticator = 'recovery'",
                params![&owner[..], saturation_deadline - 1, saturation_updated_at],
            )
            .is_err(),
        "a saturated admitted failure requires its exact one-hour deadline"
    );
    assert!(
        connection
            .execute(
                "UPDATE auth_authenticator_throttles
                 SET failure_count = 101, next_allowed_at_micros = ?2,
                     throttle_revision = throttle_revision + 1,
                     updated_at_micros = ?3
                 WHERE owner_id = ?1 AND authenticator = 'recovery'",
                params![
                    &owner[..],
                    saturation_deadline + 3_600_000_000,
                    saturation_deadline
                ],
            )
            .is_err(),
        "recovery throttle remains saturated at 100"
    );
    let early_recovery_reset_updated_at = saturation_updated_at + 1;
    assert!(
        connection
            .execute(
                "UPDATE auth_authenticator_throttles
                 SET failure_count = 0, next_allowed_at_micros = 0,
                     throttle_revision = throttle_revision + 1,
                     updated_at_micros = ?2
                 WHERE owner_id = ?1 AND authenticator = 'recovery'",
                params![&owner[..], early_recovery_reset_updated_at],
            )
            .is_err(),
        "recovery success cannot reset before its durable deadline"
    );
    let recovery_reset_updated_at = saturation_deadline;
    connection
        .execute(
            "UPDATE auth_authenticator_throttles
             SET failure_count = 0, next_allowed_at_micros = 0,
                 throttle_revision = throttle_revision + 1,
                 updated_at_micros = ?2
             WHERE owner_id = ?1 AND authenticator = 'recovery'",
            params![&owner[..], recovery_reset_updated_at],
        )
        .expect("successful recovery verification resets the throttle");

    let overflow_updated_at = 9_223_372_036_824_775_808_i64;
    for failure_count in 1_i64..=4 {
        connection
            .execute(
                "UPDATE auth_authenticator_throttles
                 SET failure_count = ?2, next_allowed_at_micros = ?3,
                     throttle_revision = throttle_revision + 1,
                     updated_at_micros = ?3
                 WHERE owner_id = ?1 AND authenticator = 'recovery'",
                params![&owner[..], failure_count, overflow_updated_at],
            )
            .expect("zero-delay transition near the integer ceiling");
    }
    assert_eq!(
        exact_auth_throttle_deadline(5, overflow_updated_at),
        None,
        "checked test arithmetic detects the count-five overflow"
    );
    assert!(
        connection
            .execute(
                "UPDATE auth_authenticator_throttles
                 SET failure_count = 5, next_allowed_at_micros = ?2,
                     throttle_revision = throttle_revision + 1,
                     updated_at_micros = ?3
                 WHERE owner_id = ?1 AND authenticator = 'recovery'",
                params![&owner[..], i64::MAX, overflow_updated_at],
            )
            .is_err(),
        "deadline arithmetic cannot overflow into a SQLite REAL"
    );
}

#[test]
fn auth_throttle_bound_migration_rejects_invalid_legacy_rows_without_replacing_the_guard() {
    let mut connection = RawConnection::open_in_memory().expect("synthetic legacy database");
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("foreign keys");
    connection
        .pragma_update(None, "recursive_triggers", "ON")
        .expect("recursive triggers");
    connection
        .execute_batch(include_str!(
            "../migrations/sqlite/conversation/0004_local_auth_control_plane.sql"
        ))
        .expect("legacy auth schema");

    let owner = [30_u8; 16];
    connection
        .execute(
            "INSERT INTO auth_accounts(
                singleton, owner_id, login_id, account_state, credential_version,
                account_revision, created_at_micros, updated_at_micros
             ) VALUES (1, ?1, 'owner', 'enabled', 1, 1, 0, 0)",
            [&owner[..]],
        )
        .expect("synthetic auth account");
    connection
        .execute(
            "INSERT INTO auth_authenticator_throttles(
                owner_id, authenticator, failure_count,
                next_allowed_at_micros, throttle_revision, updated_at_micros
             ) VALUES (?1, 'password', 5, 30000099, 1, 100)",
            [&owner[..]],
        )
        .expect("legacy under-delayed row");
    connection
        .execute(
            "INSERT INTO auth_authenticator_throttles(
                owner_id, authenticator, failure_count,
                next_allowed_at_micros, throttle_revision, updated_at_micros
             ) VALUES (?1, 'recovery', 101, 1, 1, 0)",
            [&owner[..]],
        )
        .expect("legacy overflow row");

    let transaction = connection.transaction().expect("migration transaction");
    transaction
        .execute_batch(include_str!(
            "../migrations/sqlite/conversation/0005_auth_throttle_bounds.sql"
        ))
        .expect_err("overflow must block migration");
    transaction.rollback().expect("failed migration rollback");

    let legacy_trigger: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema
             WHERE type = 'trigger'
               AND name = 'auth_authenticator_throttles_guard_update'",
            [],
            |row| row.get(0),
        )
        .expect("legacy trigger count");
    let replacement_trigger: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema
             WHERE type = 'trigger'
               AND name = 'auth_authenticator_throttles_guard_update_v2'",
            [],
            |row| row.get(0),
        )
        .expect("replacement trigger count");
    let migration_guard_table: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema
             WHERE type = 'table'
               AND name = 'auth_authenticator_throttles_0005_guard'",
            [],
            |row| row.get(0),
        )
        .expect("migration guard table count");
    let retained_failure_count: i64 = connection
        .query_row(
            "SELECT failure_count
             FROM auth_authenticator_throttles
             WHERE owner_id = ?1 AND authenticator = 'recovery'",
            [&owner[..]],
            |row| row.get(0),
        )
        .expect("legacy throttle row");
    let retained_wrong_deadline: i64 = connection
        .query_row(
            "SELECT next_allowed_at_micros
             FROM auth_authenticator_throttles
             WHERE owner_id = ?1 AND authenticator = 'password'",
            [&owner[..]],
            |row| row.get(0),
        )
        .expect("legacy under-delayed throttle row");
    assert_eq!(legacy_trigger, 1);
    assert_eq!(replacement_trigger, 0);
    assert_eq!(migration_guard_table, 0);
    assert_eq!(retained_failure_count, 101);
    assert_eq!(retained_wrong_deadline, 30_000_099);
}

#[tokio::test]
async fn local_auth_profile_caps_and_refresh_generation_bound_are_exact() {
    let directory = tempdir().expect("temporary store directory");
    let root = directory.path().join("stores");
    let stores = StoreSet::open(&root)
        .await
        .expect("clean stores should open");
    stores.close().await.expect("stores should close cleanly");

    let connection =
        RawConnection::open(root.join("conversation.sqlite3")).expect("conversation database");
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("foreign keys");
    connection
        .pragma_update(None, "recursive_triggers", "ON")
        .expect("recursive triggers");
    let owner = [21_u8; 16];
    connection
        .execute(
            "INSERT INTO auth_accounts(
                singleton, owner_id, login_id, account_state, credential_version,
                account_revision, created_at_micros, updated_at_micros
             ) VALUES (1, ?1, 'owner', 'enabled', 1, 1, 0, 0)",
            [&owner[..]],
        )
        .expect("synthetic auth account");

    for index in 0_u8..64 {
        let attempt = [index; 16];
        connection
            .execute(
                "INSERT INTO auth_login_attempt_markers(
                    owner_id, profile, attempt_id, admission_revision,
                    created_at_micros, expires_at_micros
                 ) VALUES (?1, 'local', ?2, 1, 0, 3600000000)",
                params![&owner[..], &attempt[..]],
            )
            .expect("marker below cap");
    }
    let overflow_attempt = [64_u8; 16];
    assert!(
        connection
            .execute(
                "INSERT INTO auth_login_attempt_markers(
                    owner_id, profile, attempt_id, admission_revision,
                    created_at_micros, expires_at_micros
                 ) VALUES (?1, 'local', ?2, 1, 0, 3600000000)",
                params![&owner[..], &overflow_attempt[..]],
            )
            .is_err(),
        "the 65th local marker must be rejected"
    );

    for index in 0_u8..8 {
        let session = [100 + index; 16];
        connection
            .execute(
                "INSERT INTO auth_sessions(
                    owner_id, session_id, profile, credential_version, created_at_micros
                 ) VALUES (?1, ?2, 'local', 1, 0)",
                params![&owner[..], &session[..]],
            )
            .expect("session below cap");
    }
    let overflow_session = [108_u8; 16];
    assert!(
        connection
            .execute(
                "INSERT INTO auth_sessions(
                    owner_id, session_id, profile, credential_version, created_at_micros
                 ) VALUES (?1, ?2, 'local', 1, 0)",
                params![&owner[..], &overflow_session[..]],
            )
            .is_err(),
        "the ninth local session must be rejected"
    );

    let session = [100_u8; 16];
    let family = [120_u8; 16];
    connection
        .execute(
            "INSERT INTO auth_refresh_families(
                owner_id, family_id, session_id, profile, created_at_micros,
                last_refreshed_at_micros, idle_deadline_at_micros,
                absolute_deadline_at_micros
             ) VALUES (
                ?1, ?2, ?3, 'local', 0, 0, 604800000000, 2592000000000
             )",
            params![&owner[..], &family[..], &session[..]],
        )
        .expect("refresh family");
    let mut previous_digest = [0_u8; 32];
    for generation in 0_i64..=8191 {
        let mut digest = [0_u8; 32];
        digest[..8].copy_from_slice(&(generation as u64).to_be_bytes());
        if generation == 0 {
            connection
                .execute(
                    "INSERT INTO auth_refresh_tokens(
                        owner_id, family_id, token_digest, generation,
                        predecessor_digest, token_state, created_at_micros,
                        consumed_at_micros
                     ) VALUES (?1, ?2, ?3, 0, NULL, 'active', 0, NULL)",
                    params![&owner[..], &family[..], &digest[..]],
                )
                .expect("initial refresh token");
        } else {
            connection
                .execute(
                    "INSERT INTO auth_refresh_tokens(
                        owner_id, family_id, token_digest, generation,
                        predecessor_digest, token_state, created_at_micros,
                        consumed_at_micros
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?4, NULL)",
                    params![
                        &owner[..],
                        &family[..],
                        &digest[..],
                        generation,
                        &previous_digest[..]
                    ],
                )
                .expect("next refresh generation");
        }
        if generation < 8191 {
            connection
                .execute(
                    "UPDATE auth_refresh_tokens
                     SET token_state = 'consumed', consumed_at_micros = ?3
                     WHERE owner_id = ?1 AND token_digest = ?2",
                    params![&owner[..], &digest[..], generation + 1],
                )
                .expect("consume refresh generation");
        }
        previous_digest = digest;
    }
    connection
        .execute(
            "UPDATE auth_refresh_tokens
             SET token_state = 'consumed', consumed_at_micros = 8192
             WHERE owner_id = ?1 AND token_digest = ?2",
            params![&owner[..], &previous_digest[..]],
        )
        .expect("consume terminal refresh generation");
    let generation_8192_digest = [255_u8; 32];
    assert!(
        connection
            .execute(
                "INSERT INTO auth_refresh_tokens(
                    owner_id, family_id, token_digest, generation,
                    predecessor_digest, token_state, created_at_micros,
                    consumed_at_micros
                 ) VALUES (?1, ?2, ?3, 8192, ?4, 'active', 8192, NULL)",
                params![
                    &owner[..],
                    &family[..],
                    &generation_8192_digest[..],
                    &previous_digest[..]
                ],
            )
            .is_err(),
        "generation 8192 must never be issued"
    );
}

#[tokio::test]
async fn clean_open_and_reopen_keep_four_independent_store_contracts() {
    let directory = tempdir().expect("temporary store directory");
    let root = directory.path().join("stores");
    let stores = StoreSet::open(&root)
        .await
        .expect("clean stores should open");
    let reports = stores.reports().await.expect("store reports");

    assert_eq!(reports.len(), 4);
    assert_eq!(
        reports
            .iter()
            .map(|report| report.kind)
            .collect::<HashSet<_>>(),
        StoreKind::ALL.into_iter().collect()
    );
    assert_eq!(
        reports
            .iter()
            .map(|report| report.file_name)
            .collect::<HashSet<_>>()
            .len(),
        4
    );

    for report in &reports {
        assert!(root.join(report.file_name).is_file());
        assert_eq!(report.journal_mode, "wal");
        assert_eq!(report.synchronous, "full");
        assert!(report.foreign_keys);
        assert!(report.recursive_triggers);
        assert_eq!(report.busy_timeout_millis, BUSY_TIMEOUT_MILLIS);
        assert!(!report.trusted_schema);
        assert!(report.cell_size_check);
        assert!(report.defensive);
        assert_eq!(report.integrity_check, "ok");
        assert_eq!(report.attached_databases, 1);
        assert_eq!(
            report.applied_migrations.len(),
            expected_migration_count(report.kind)
        );
        assert!(
            report.applied_migrations[0]
                .namespace
                .starts_with("sqlite/")
        );
    }

    stores.close().await.expect("stores should close cleanly");

    let reopened = StoreSet::open(&root)
        .await
        .expect("migrated stores should reopen");
    let reopened_reports = reopened.reports().await.expect("reopened reports");

    for report in &reopened_reports {
        assert_eq!(report.journal_mode, "wal");
        assert_eq!(report.synchronous, "full");
        assert!(report.foreign_keys);
        assert!(report.recursive_triggers);
        assert_eq!(report.busy_timeout_millis, BUSY_TIMEOUT_MILLIS);
        assert!(!report.trusted_schema);
        assert!(report.cell_size_check);
        assert!(report.defensive);
        assert_eq!(report.integrity_check, "ok");
        assert_eq!(report.attached_databases, 1);
    }

    assert_eq!(
        reports
            .iter()
            .map(|report| (
                report.kind,
                report.migration_namespace,
                report.applied_migrations.clone(),
            ))
            .collect::<Vec<_>>(),
        reopened_reports
            .iter()
            .map(|report| (
                report.kind,
                report.migration_namespace,
                report.applied_migrations.clone(),
            ))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn backup_hook_creates_valid_independent_online_snapshots() {
    let directory = tempdir().expect("temporary store directory");
    let root = directory.path().join("stores");
    let stores = StoreSet::open(&root)
        .await
        .expect("clean stores should open");

    let artifacts = [
        stores
            .conversation
            .backup_to_new_file(root.join("conversation.backup"))
            .await
            .expect("conversation backup"),
        stores
            .knowledge
            .backup_to_new_file(root.join("knowledge.backup"))
            .await
            .expect("knowledge backup"),
        stores
            .calendar
            .backup_to_new_file(root.join("calendar.backup"))
            .await
            .expect("calendar backup"),
        stores
            .embedding
            .backup_to_new_file(root.join("embedding.backup"))
            .await
            .expect("embedding backup"),
    ];

    assert_eq!(
        artifacts
            .iter()
            .map(|artifact| artifact.kind)
            .collect::<HashSet<_>>(),
        StoreKind::ALL.into_iter().collect()
    );
    assert!(
        artifacts
            .iter()
            .all(|artifact| artifact.integrity_check == "ok"
                && artifact.applied_migrations.len() == expected_migration_count(artifact.kind))
    );

    let existing = root.join("existing.backup");
    std::fs::write(&existing, b"do not overwrite").expect("synthetic existing file");
    assert!(
        stores
            .conversation
            .backup_to_new_file(&existing)
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(existing).expect("existing file remains"),
        b"do not overwrite"
    );
}

#[test]
fn postgres_boundary_is_separate_and_explicitly_unimplemented() {
    let expected_sqlite_namespaces = HashSet::from([
        "sqlite/conversation",
        "sqlite/knowledge",
        "sqlite/calendar",
        "sqlite/embedding",
    ]);
    let expected_postgres_namespaces = HashSet::from([
        "postgres/conversation",
        "postgres/knowledge",
        "postgres/calendar",
        "postgres/embedding",
    ]);
    assert_eq!(
        StoreKind::ALL
            .into_iter()
            .map(StoreKind::sqlite_migration_namespace)
            .collect::<HashSet<_>>(),
        expected_sqlite_namespaces
    );

    let mut actual_postgres_namespaces = HashSet::new();
    for kind in StoreKind::ALL {
        let boundary = postgres_boundary(kind);

        assert_eq!(boundary.status, PostgresAdapterStatus::NotImplemented);
        assert_eq!(boundary.role, StoreRole::for_kind(kind));
        assert!(boundary.migration_namespace.starts_with("postgres/"));
        assert_ne!(
            boundary.migration_namespace,
            kind.sqlite_migration_namespace()
        );
        assert!(boundary.migration_sql.is_none());
        actual_postgres_namespaces.insert(boundary.migration_namespace);
    }
    assert_eq!(actual_postgres_namespaces, expected_postgres_namespaces);
}
