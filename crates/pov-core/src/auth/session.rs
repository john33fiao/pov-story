#![cfg(unix)]

use std::{fmt, path::Path};

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};
use tokio_rusqlite::rusqlite::{
    Connection as RawConnection, OptionalExtension, Transaction, TransactionBehavior, params,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    identity::{OwnerId, VerifiedAuthContext},
    storage::{
        AuthRuntimeStore, StoreError, StoreSet,
        auth_records::{
            AuthMutationExecutor, AuthRecordsError, AuthRuntimeApplyDecision,
            AuthRuntimeMutationOutcome, AuthRuntimeMutationPostcondition,
        },
    },
};

use super::{
    KdfError, NormalizedPassword, RecoveryCode, SecretBytes, ThrottleState, ValidatedVerifier,
    hash_password, hash_recovery_code,
    jwt::{AuthProfile, IssuedAccessToken, JwtError, issue_access_token, verify_access_token},
    secret_fs::{AuthInstanceLayout, AuthListenerLease, AuthStoreBindingError, SecretFsError},
    throttle::{AuthenticatorKind, ThrottleMathError},
    transition::LoginId,
    verify_password, verify_recovery_code,
};

const LOGIN_ATTEMPT_LIFETIME_MICROS: u64 = 60 * 60 * 1_000_000;
const LOCAL_IDLE_LIFETIME_MICROS: u64 = 7 * 24 * 60 * 60 * 1_000_000;
const LOCAL_ABSOLUTE_LIFETIME_MICROS: u64 = 30 * 24 * 60 * 60 * 1_000_000;
const MAX_LOGIN_MARKERS: u64 = 64;
const MAX_ACTIVE_SESSIONS: u64 = 8;
const MAX_REFRESH_GENERATION: u64 = 8191;
const DUMMY_PASSWORD_PHC: &str = concat!(
    "$argon2id$v=19$m=65536,t=3,p=4$",
    "0NDQ0NDQ0NDQ0NDQ0NDQ0A$",
    "4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4OA"
);

pub struct AuthRuntime {
    lease: AuthListenerLease,
    store: AuthRuntimeStore,
    mutations: AuthMutationExecutor,
    dummy_password: ValidatedVerifier,
}

impl AuthRuntime {
    pub async fn open(
        instance_root: impl AsRef<Path>,
        stores: &StoreSet,
        now_micros: u64,
    ) -> Result<Self, AuthRuntimeError> {
        validate_now(now_micros)?;
        let layout = AuthInstanceLayout::open_or_create(instance_root.as_ref())
            .map_err(AuthRuntimeError::filesystem)?;
        let locked = layout.lock().map_err(AuthRuntimeError::filesystem)?;
        let context = locked
            .bind_conversation(&stores.conversation)
            .map_err(AuthRuntimeError::binding)?
            .into_owned()
            .map_err(AuthRuntimeError::binding)?;
        let store = stores
            .conversation
            .auth_runtime_store()
            .map_err(AuthRuntimeError::store)?;
        let lease = context
            .into_listener_lease()
            .map_err(AuthRuntimeError::binding)?;
        let mutations = store.mutation_executor();
        let dummy_password =
            ValidatedVerifier::parse(SecretBytes::new(DUMMY_PASSWORD_PHC.as_bytes().to_vec()))
                .map_err(|_| AuthRuntimeError::InvalidStartupState)?;
        let runtime = Self {
            lease,
            store,
            mutations,
            dummy_password,
        };
        runtime.prune_expired(now_micros).await?;
        runtime.revalidate()?;
        Ok(runtime)
    }

    pub async fn login(
        &self,
        request: LoginRequest,
        now_micros: u64,
    ) -> Result<LoginOutcome, AuthRuntimeError> {
        validate_now(now_micros)?;
        if request.profile != AuthProfile::Local {
            return Ok(LoginOutcome::GenericFailure);
        }
        self.revalidate()?;
        self.prune_expired(now_micros).await?;
        let snapshot = self
            .read_login_snapshot(
                request.profile,
                request.attempt_id,
                request.login_id.as_str(),
            )
            .await?;
        match snapshot.replay {
            LoginReplay::None => {}
            LoginReplay::GenericFailure => return Ok(LoginOutcome::GenericFailure),
            LoginReplay::OutcomeUnknown => return Ok(LoginOutcome::OutcomeUnknown),
            LoginReplay::AttemptInvalidated => return Ok(LoginOutcome::AttemptInvalidated),
        }
        if !snapshot.expected.throttle.admits_at(now_micros) {
            return Ok(LoginOutcome::Throttled);
        }
        if !snapshot.expected.password_enabled
            && snapshot.expected.login_matches
            && snapshot.expected.account_enabled
        {
            return Ok(LoginOutcome::GenericFailure);
        }
        let use_real_verifier = snapshot.expected.login_matches
            && snapshot.expected.account_enabled
            && snapshot.expected.password_enabled;
        let verified = match verify_password(
            &request.password,
            if use_real_verifier {
                &snapshot.verifier
            } else {
                &self.dummy_password
            },
        )
        .await
        {
            Ok(verified) => verified && use_real_verifier,
            Err(KdfError::Busy) => return Ok(LoginOutcome::Throttled),
            Err(KdfError::OperationFailed) => {
                self.poison();
                return Err(AuthRuntimeError::OperationFailed);
            }
        };

        if !verified {
            let throttle = snapshot
                .expected
                .throttle
                .admitted_failure(now_micros)
                .map_err(AuthRuntimeError::throttle)?;
            let outcome = self
                .commit_login_failure(
                    snapshot.expected,
                    request.attempt_id,
                    request.profile,
                    throttle.state(),
                    throttle.disables_password(),
                    now_micros,
                )
                .await?;
            self.revalidate()?;
            return Ok(match outcome {
                LoginCommitOutcome::Committed | LoginCommitOutcome::GenericFailureReplay => {
                    LoginOutcome::GenericFailure
                }
                LoginCommitOutcome::OutcomeUnknown => LoginOutcome::OutcomeUnknown,
                LoginCommitOutcome::AttemptInvalidated => LoginOutcome::AttemptInvalidated,
                LoginCommitOutcome::RetryRequired => LoginOutcome::RetryRequired,
                LoginCommitOutcome::RateLimited => LoginOutcome::Throttled,
            });
        }

        let candidate = SessionCandidate::generate(
            self.lease.keyring(),
            request.profile,
            snapshot.expected.owner_id,
            snapshot.expected.credential_version,
            now_micros,
        )?;
        let commit = self
            .commit_login_success(
                snapshot.expected,
                request.attempt_id,
                request.profile,
                &candidate,
                now_micros,
            )
            .await?;
        self.revalidate()?;
        Ok(match commit {
            LoginCommitOutcome::Committed => LoginOutcome::Authenticated(candidate.into_issued()),
            LoginCommitOutcome::GenericFailureReplay => LoginOutcome::GenericFailure,
            LoginCommitOutcome::OutcomeUnknown => LoginOutcome::OutcomeUnknown,
            LoginCommitOutcome::AttemptInvalidated => LoginOutcome::AttemptInvalidated,
            LoginCommitOutcome::RetryRequired => LoginOutcome::RetryRequired,
            LoginCommitOutcome::RateLimited => LoginOutcome::Throttled,
        })
    }

    pub async fn refresh(
        &self,
        profile: AuthProfile,
        refresh_token: SecretBytes,
        now_micros: u64,
    ) -> Result<RefreshOutcome, AuthRuntimeError> {
        validate_now(now_micros)?;
        if profile != AuthProfile::Local {
            return Ok(RefreshOutcome::Invalid);
        }
        self.revalidate()?;
        self.prune_expired(now_micros).await?;
        let digest = match parse_refresh_digest(&refresh_token) {
            Ok(digest) => digest,
            Err(_) => return Ok(RefreshOutcome::Invalid),
        };
        let Some(snapshot) = self.read_refresh_snapshot(profile, digest).await? else {
            return Ok(RefreshOutcome::Invalid);
        };
        if snapshot.token_state == RefreshTokenState::Consumed {
            self.revoke_refresh_replay(&snapshot, digest, now_micros)
                .await?;
            self.revalidate()?;
            return Ok(RefreshOutcome::ReplayRevoked);
        }
        if snapshot.generation == MAX_REFRESH_GENERATION {
            self.revoke_refresh_exhaustion(&snapshot, digest, now_micros)
                .await?;
            self.revalidate()?;
            return Ok(RefreshOutcome::Exhausted);
        }
        if now_micros <= snapshot.last_refreshed_at_micros
            || now_micros >= snapshot.idle_deadline_at_micros
            || now_micros >= snapshot.absolute_deadline_at_micros
        {
            return Ok(RefreshOutcome::Invalid);
        }
        let candidate = RefreshCandidate::generate(
            self.lease.keyring(),
            profile,
            snapshot.owner_id,
            snapshot.session_id,
            snapshot.credential_version,
            snapshot.absolute_deadline_at_micros,
            now_micros,
        )?;
        let rotated = self
            .commit_refresh_rotation(&snapshot, digest, &candidate, now_micros)
            .await?;
        self.revalidate()?;
        Ok(if rotated {
            RefreshOutcome::Rotated(candidate.into_issued())
        } else {
            RefreshOutcome::Invalid
        })
    }

    pub async fn logout(
        &self,
        profile: AuthProfile,
        refresh_token: Option<SecretBytes>,
        now_micros: u64,
    ) -> Result<LogoutOutcome, AuthRuntimeError> {
        validate_now(now_micros)?;
        if profile != AuthProfile::Local {
            return Ok(LogoutOutcome::AlreadyTerminal);
        }
        self.revalidate()?;
        let Some(refresh_token) = refresh_token else {
            self.confirm_logout_terminal_read().await?;
            self.revalidate()?;
            return Ok(LogoutOutcome::AlreadyTerminal);
        };
        let digest = match parse_refresh_digest(&refresh_token) {
            Ok(digest) => digest,
            Err(_) => {
                self.confirm_logout_terminal_read().await?;
                self.revalidate()?;
                return Ok(LogoutOutcome::AlreadyTerminal);
            }
        };
        let audit_id = Uuid::new_v4().into_bytes();
        let outcome = self
            .mutations
            .execute_runtime(
                move |transaction| {
                    let row: Option<([u8; 16], [u8; 16])> = transaction
                        .query_row(
                            "SELECT t.owner_id, f.session_id
                         FROM auth_refresh_tokens t
                         JOIN auth_refresh_families f
                           ON f.owner_id = t.owner_id AND f.family_id = t.family_id
                         WHERE t.token_digest = ?1 AND f.profile = ?2",
                            params![digest.as_slice(), profile.as_str()],
                            |row| Ok((read_uuid_blob(row, 0)?, read_uuid_blob(row, 1)?)),
                        )
                        .optional()?;
                    let Some((owner, session)) = row else {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(()));
                    };
                    let changed = transaction.execute(
                        "DELETE FROM auth_sessions
                     WHERE owner_id = ?1 AND session_id = ?2 AND profile = ?3",
                        params![owner.as_slice(), session.as_slice(), profile.as_str()],
                    )?;
                    if changed != 1 {
                        return Err(StoreError::AuthControlPlaneCorrupt.into());
                    }
                    insert_audit(
                        transaction,
                        owner,
                        audit_id,
                        "logout",
                        Some(profile),
                        Some(session),
                        None,
                        now_micros,
                    )?;
                    Ok(AuthRuntimeApplyDecision::Commit)
                },
                move |connection| {
                    let audit: Option<([u8; 16], [u8; 16])> = connection
                        .query_row(
                            "SELECT owner_id, session_id
                             FROM auth_audit
                             WHERE audit_id = ?1
                               AND action = 'logout'
                               AND profile = ?2
                               AND session_id IS NOT NULL
                               AND attempt_id IS NULL
                               AND happened_at_micros = ?3",
                            params![audit_id.as_slice(), profile.as_str(), to_i64(now_micros)?,],
                            |row| Ok((read_uuid_blob(row, 0)?, read_uuid_blob(row, 1)?)),
                        )
                        .optional()?;
                    if let Some((owner, session)) = audit {
                        let terminal: bool = connection.query_row(
                            "SELECT
                                NOT EXISTS(
                                    SELECT 1 FROM auth_sessions
                                    WHERE owner_id = ?1 AND session_id = ?2
                                )
                                AND NOT EXISTS(
                                    SELECT 1 FROM auth_refresh_families
                                    WHERE owner_id = ?1 AND session_id = ?2
                                )
                                AND NOT EXISTS(
                                    SELECT 1 FROM auth_refresh_tokens
                                    WHERE owner_id = ?1 AND token_digest = ?3
                                )",
                            params![owner.as_slice(), session.as_slice(), digest.as_slice(),],
                            |row| row.get(0),
                        )?;
                        if terminal {
                            return Ok(AuthRuntimeMutationPostcondition::Committed);
                        }
                    }
                    let source_exists: bool = connection.query_row(
                        "SELECT EXISTS(
                            SELECT 1
                            FROM auth_refresh_tokens t
                            JOIN auth_refresh_families f
                              ON f.owner_id = t.owner_id AND f.family_id = t.family_id
                            JOIN auth_sessions s
                              ON s.owner_id = f.owner_id AND s.session_id = f.session_id
                            WHERE t.token_digest = ?1
                              AND f.profile = ?2
                              AND s.profile = ?2
                         )",
                        params![digest.as_slice(), profile.as_str()],
                        |row| row.get(0),
                    )?;
                    let audit_absent: bool = connection.query_row(
                        "SELECT NOT EXISTS(
                            SELECT 1 FROM auth_audit WHERE audit_id = ?1
                         )",
                        [audit_id.as_slice()],
                        |row| row.get(0),
                    )?;
                    if audit_absent && source_exists {
                        Ok(AuthRuntimeMutationPostcondition::NotCommitted)
                    } else {
                        Ok(AuthRuntimeMutationPostcondition::Ambiguous)
                    }
                },
            )
            .await
            .map_err(AuthRuntimeError::records)?;
        self.revalidate()?;
        match outcome {
            AuthRuntimeMutationOutcome::Committed => Ok(LogoutOutcome::Revoked),
            AuthRuntimeMutationOutcome::ExpectedNoCommit(()) => Ok(LogoutOutcome::AlreadyTerminal),
            AuthRuntimeMutationOutcome::ConfirmedNotCommitted => {
                Err(AuthRuntimeError::OperationFailed)
            }
        }
    }

    pub async fn logout_all(
        &self,
        access_token: SecretBytes,
        now_micros: u64,
    ) -> Result<LogoutAllOutcome, AuthRuntimeError> {
        validate_now(now_micros)?;
        let claims = match self
            .verify_access_claims(AuthProfile::Local, access_token, now_micros)
            .await
        {
            Ok(claims) => claims,
            Err(_) => return Ok(LogoutAllOutcome::InvalidSession),
        };
        let owner = claims.owner_id.as_uuid().into_bytes();
        let session = claims.session_id.into_bytes();
        let expected_version = claims.credential_version;
        let next_version = expected_version
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(AuthRuntimeError::OperationFailed)?;
        let audit_id = Uuid::new_v4().into_bytes();
        let outcome = self
            .mutations
            .execute_runtime(
                move |transaction| {
                    let source_exists: bool = transaction.query_row(
                        "SELECT EXISTS(
                            SELECT 1
                            FROM auth_sessions s
                            JOIN auth_accounts a ON a.owner_id = s.owner_id
                            WHERE s.owner_id = ?1
                              AND s.session_id = ?2
                              AND s.profile = 'local'
                              AND s.credential_version = ?3
                              AND a.account_state = 'enabled'
                              AND a.credential_version = ?3
                        )",
                        params![
                            owner.as_slice(),
                            session.as_slice(),
                            to_i64(expected_version)?,
                        ],
                        |row| row.get(0),
                    )?;
                    if !source_exists {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(()));
                    }
                    transaction.execute(
                        "DELETE FROM auth_sessions WHERE owner_id = ?1",
                        [owner.as_slice()],
                    )?;
                    transaction.execute(
                        "DELETE FROM auth_login_attempt_outcomes WHERE owner_id = ?1",
                        [owner.as_slice()],
                    )?;
                    if transaction.execute(
                        "UPDATE auth_accounts
                         SET credential_version = credential_version + 1,
                             account_revision = account_revision + 1,
                             updated_at_micros = ?1
                         WHERE owner_id = ?2
                           AND account_state = 'enabled'
                           AND credential_version = ?3",
                        params![
                            to_i64(now_micros)?,
                            owner.as_slice(),
                            to_i64(expected_version)?,
                        ],
                    )? != 1
                    {
                        return Err(StoreError::AuthControlPlaneCorrupt.into());
                    }
                    insert_audit(
                        transaction,
                        owner,
                        audit_id,
                        "logout_all",
                        Some(AuthProfile::Local),
                        None,
                        None,
                        now_micros,
                    )?;
                    Ok(AuthRuntimeApplyDecision::Commit)
                },
                move |connection| {
                    let committed: bool = connection.query_row(
                        "SELECT
                            EXISTS(
                                SELECT 1 FROM auth_audit
                                WHERE audit_id = ?1
                                  AND owner_id = ?2
                                  AND action = 'logout_all'
                                  AND profile = 'local'
                                  AND session_id IS NULL
                                  AND attempt_id IS NULL
                                  AND happened_at_micros = ?3
                            )
                            AND EXISTS(
                                SELECT 1 FROM auth_accounts
                                WHERE owner_id = ?2
                                  AND credential_version = ?4
                            )
                            AND NOT EXISTS(
                                SELECT 1 FROM auth_sessions WHERE owner_id = ?2
                            )
                            AND NOT EXISTS(
                                SELECT 1 FROM auth_refresh_families WHERE owner_id = ?2
                            )
                            AND NOT EXISTS(
                                SELECT 1 FROM auth_refresh_tokens WHERE owner_id = ?2
                            )
                            AND NOT EXISTS(
                                SELECT 1 FROM auth_login_attempt_outcomes WHERE owner_id = ?2
                            )",
                        params![
                            audit_id.as_slice(),
                            owner.as_slice(),
                            to_i64(now_micros)?,
                            to_i64(next_version)?,
                        ],
                        |row| row.get(0),
                    )?;
                    if committed {
                        return Ok(AuthRuntimeMutationPostcondition::Committed);
                    }
                    let not_committed: bool = connection.query_row(
                        "SELECT
                            NOT EXISTS(
                                SELECT 1 FROM auth_audit WHERE audit_id = ?1
                            )
                            AND EXISTS(
                                SELECT 1
                                FROM auth_sessions s
                                JOIN auth_accounts a ON a.owner_id = s.owner_id
                                WHERE s.owner_id = ?2
                                  AND s.session_id = ?3
                                  AND s.profile = 'local'
                                  AND s.credential_version = ?4
                                  AND a.account_state = 'enabled'
                                  AND a.credential_version = ?4
                            )",
                        params![
                            audit_id.as_slice(),
                            owner.as_slice(),
                            session.as_slice(),
                            to_i64(expected_version)?,
                        ],
                        |row| row.get(0),
                    )?;
                    Ok(if not_committed {
                        AuthRuntimeMutationPostcondition::NotCommitted
                    } else {
                        AuthRuntimeMutationPostcondition::Ambiguous
                    })
                },
            )
            .await
            .map_err(AuthRuntimeError::records)?;
        self.revalidate()?;
        Ok(match outcome {
            AuthRuntimeMutationOutcome::Committed => LogoutAllOutcome::Revoked,
            AuthRuntimeMutationOutcome::ExpectedNoCommit(()) => LogoutAllOutcome::InvalidSession,
            AuthRuntimeMutationOutcome::ConfirmedNotCommitted => {
                return Err(AuthRuntimeError::OperationFailed);
            }
        })
    }

    pub async fn change_password(
        &self,
        access_token: SecretBytes,
        current_password: NormalizedPassword,
        new_password: NormalizedPassword,
        now_micros: u64,
    ) -> Result<CredentialMutationOutcome, AuthRuntimeError> {
        validate_now(now_micros)?;
        let owner = match self
            .verify_access(AuthProfile::Local, access_token, now_micros)
            .await
        {
            Ok(context) => context.owner_id(),
            Err(_) => return Ok(CredentialMutationOutcome::InvalidSession),
        };
        self.revalidate()?;
        self.prune_expired(now_micros).await?;
        let snapshot = self.read_password_mutation_snapshot(owner).await?;
        if !snapshot.expected.throttle.admits_at(now_micros) {
            return Ok(CredentialMutationOutcome::Throttled);
        }
        if !snapshot.expected.account_enabled || !snapshot.expected.password_enabled {
            return Ok(CredentialMutationOutcome::GenericFailure);
        }
        let verified = match verify_password(&current_password, &snapshot.verifier).await {
            Ok(verified) => verified,
            Err(KdfError::Busy) => return Ok(CredentialMutationOutcome::Throttled),
            Err(KdfError::OperationFailed) => {
                self.poison();
                return Err(AuthRuntimeError::OperationFailed);
            }
        };
        if !verified {
            let throttle = snapshot
                .expected
                .throttle
                .admitted_failure(now_micros)
                .map_err(AuthRuntimeError::throttle)?;
            return self
                .commit_current_password_failure(
                    snapshot.expected,
                    throttle.state(),
                    throttle.disables_password(),
                    now_micros,
                )
                .await;
        }
        let verifier = match hash_password(&new_password).await {
            Ok(verifier) => verifier,
            Err(KdfError::Busy) => return Ok(CredentialMutationOutcome::Throttled),
            Err(KdfError::OperationFailed) => {
                self.poison();
                return Err(AuthRuntimeError::OperationFailed);
            }
        };
        let outcome = self
            .commit_password_change(snapshot.expected, verifier, now_micros)
            .await?;
        self.revalidate()?;
        Ok(outcome)
    }

    pub async fn rotate_recovery_code(
        &self,
        current_password: NormalizedPassword,
        replacement: RecoveryCode,
        now_micros: u64,
    ) -> Result<CredentialMutationOutcome, AuthRuntimeError> {
        validate_now(now_micros)?;
        self.revalidate()?;
        self.prune_expired(now_micros).await?;
        let snapshot = self.read_operator_password_snapshot().await?;
        if !snapshot.expected.throttle.admits_at(now_micros) {
            return Ok(CredentialMutationOutcome::Throttled);
        }
        if !snapshot.expected.account_enabled || !snapshot.expected.password_enabled {
            return Ok(CredentialMutationOutcome::GenericFailure);
        }
        let verified = match verify_password(&current_password, &snapshot.verifier).await {
            Ok(verified) => verified,
            Err(KdfError::Busy) => return Ok(CredentialMutationOutcome::Throttled),
            Err(KdfError::OperationFailed) => {
                self.poison();
                return Err(AuthRuntimeError::OperationFailed);
            }
        };
        if !verified {
            let throttle = snapshot
                .expected
                .throttle
                .admitted_failure(now_micros)
                .map_err(AuthRuntimeError::throttle)?;
            return self
                .commit_current_password_failure(
                    snapshot.expected,
                    throttle.state(),
                    throttle.disables_password(),
                    now_micros,
                )
                .await;
        }
        let replacement_verifier = match hash_recovery_code(&replacement).await {
            Ok(verifier) => verifier,
            Err(KdfError::Busy) => return Ok(CredentialMutationOutcome::Throttled),
            Err(KdfError::OperationFailed) => {
                self.poison();
                return Err(AuthRuntimeError::OperationFailed);
            }
        };
        let recovery_source = self.read_recovery_snapshot().await?.source;
        if !recovery_source_matches_login(&recovery_source, &snapshot.expected) {
            return Ok(CredentialMutationOutcome::RetryRequired);
        }
        let outcome = self
            .commit_recovery_rotation(recovery_source, replacement_verifier, now_micros)
            .await?;
        self.revalidate()?;
        Ok(outcome)
    }

    pub async fn recover_account(
        &self,
        current_recovery: RecoveryCode,
        new_password: NormalizedPassword,
        replacement: RecoveryCode,
        now_micros: u64,
    ) -> Result<CredentialMutationOutcome, AuthRuntimeError> {
        validate_now(now_micros)?;
        self.revalidate()?;
        self.prune_expired(now_micros).await?;
        let snapshot = self.read_recovery_snapshot().await?;
        if !snapshot.source.recovery_throttle.admits_at(now_micros) {
            return Ok(CredentialMutationOutcome::Throttled);
        }
        let verified = match verify_recovery_code(&current_recovery, &snapshot.verifier).await {
            Ok(verified) => verified,
            Err(KdfError::Busy) => return Ok(CredentialMutationOutcome::Throttled),
            Err(KdfError::OperationFailed) => {
                self.poison();
                return Err(AuthRuntimeError::OperationFailed);
            }
        };
        if !verified {
            let next = snapshot
                .source
                .recovery_throttle
                .admitted_failure(now_micros)
                .map_err(AuthRuntimeError::throttle)?
                .state();
            return self.commit_recovery_failure(snapshot.source, next).await;
        }
        let password_verifier = match hash_password(&new_password).await {
            Ok(verifier) => verifier,
            Err(KdfError::Busy) => return Ok(CredentialMutationOutcome::Throttled),
            Err(KdfError::OperationFailed) => {
                self.poison();
                return Err(AuthRuntimeError::OperationFailed);
            }
        };
        let recovery_verifier = match hash_recovery_code(&replacement).await {
            Ok(verifier) => verifier,
            Err(KdfError::Busy) => return Ok(CredentialMutationOutcome::Throttled),
            Err(KdfError::OperationFailed) => {
                self.poison();
                return Err(AuthRuntimeError::OperationFailed);
            }
        };
        let outcome = self
            .commit_account_recovery(
                snapshot.source,
                password_verifier,
                recovery_verifier,
                now_micros,
            )
            .await?;
        self.revalidate()?;
        Ok(outcome)
    }

    pub async fn set_account_enabled(
        &self,
        current_recovery: RecoveryCode,
        enabled: bool,
        now_micros: u64,
    ) -> Result<CredentialMutationOutcome, AuthRuntimeError> {
        validate_now(now_micros)?;
        self.revalidate()?;
        self.prune_expired(now_micros).await?;
        let snapshot = self.read_recovery_snapshot().await?;
        if snapshot.source.account_enabled == enabled {
            return Ok(CredentialMutationOutcome::AlreadyApplied);
        }
        if !snapshot.source.recovery_throttle.admits_at(now_micros) {
            return Ok(CredentialMutationOutcome::Throttled);
        }
        let verified = match verify_recovery_code(&current_recovery, &snapshot.verifier).await {
            Ok(verified) => verified,
            Err(KdfError::Busy) => return Ok(CredentialMutationOutcome::Throttled),
            Err(KdfError::OperationFailed) => {
                self.poison();
                return Err(AuthRuntimeError::OperationFailed);
            }
        };
        if !verified {
            let next = snapshot
                .source
                .recovery_throttle
                .admitted_failure(now_micros)
                .map_err(AuthRuntimeError::throttle)?
                .state();
            return self.commit_recovery_failure(snapshot.source, next).await;
        }
        let outcome = self
            .commit_account_enabled_state(snapshot.source, enabled, now_micros)
            .await?;
        self.revalidate()?;
        Ok(outcome)
    }

    pub async fn verify_access(
        &self,
        profile: AuthProfile,
        token: SecretBytes,
        now_micros: u64,
    ) -> Result<VerifiedAuthContext, AccessDenied> {
        let claims = self
            .verify_access_claims(profile, token, now_micros)
            .await?;
        Ok(VerifiedAuthContext::from_verified_owner(claims.owner_id))
    }

    async fn verify_access_claims(
        &self,
        profile: AuthProfile,
        token: SecretBytes,
        now_micros: u64,
    ) -> Result<super::jwt::VerifiedAccessClaims, AccessDenied> {
        if validate_now(now_micros).is_err() || profile != AuthProfile::Local {
            return Err(AccessDenied);
        }
        self.revalidate().map_err(|_| AccessDenied)?;
        let claims = verify_access_token(self.lease.keyring(), profile, &token, now_micros)
            .map_err(|_| AccessDenied)?;
        let owner = claims.owner_id.as_uuid().into_bytes();
        let session = claims.session_id.into_bytes();
        let version = i64::try_from(claims.credential_version).map_err(|_| AccessDenied)?;
        let active = self
            .store
            .call("authentication access verification", move |connection| {
                let count: i64 = connection.query_row(
                    "SELECT count(*)
                     FROM auth_sessions s
                     JOIN auth_accounts a ON a.owner_id = s.owner_id
                     JOIN auth_key_lifecycle k ON k.singleton = 1
                     WHERE s.owner_id = ?1
                       AND s.session_id = ?2
                       AND s.profile = ?3
                       AND s.credential_version = ?4
                       AND a.account_state = 'enabled'
                       AND a.credential_version = ?4
                       AND k.state = 'active'
                       AND k.transition_kind IS NULL
                       AND k.transition_id IS NULL",
                    params![
                        owner.as_slice(),
                        session.as_slice(),
                        profile.as_str(),
                        version
                    ],
                    |row| row.get(0),
                )?;
                Ok(count == 1)
            })
            .await
            .map_err(|_| AccessDenied)?;
        if !active {
            return Err(AccessDenied);
        }
        self.revalidate().map_err(|_| AccessDenied)?;
        Ok(claims)
    }

    fn revalidate(&self) -> Result<(), AuthRuntimeError> {
        self.lease.revalidate().map_err(AuthRuntimeError::binding)
    }

    fn poison(&self) {
        self.lease.poison();
        self.store.poison();
    }

    async fn confirm_logout_terminal_read(&self) -> Result<(), AuthRuntimeError> {
        let healthy = self
            .store
            .call("authentication logout terminal read", |connection| {
                let count: i64 = connection.query_row(
                    "SELECT count(*)
                     FROM auth_accounts a
                     JOIN auth_key_lifecycle k ON k.singleton = 1
                     WHERE a.singleton = 1
                       AND k.state = 'active'
                       AND k.transition_kind IS NULL
                       AND k.transition_id IS NULL",
                    [],
                    |row| row.get(0),
                )?;
                Ok(count == 1)
            })
            .await
            .map_err(AuthRuntimeError::store)?;
        if !healthy {
            self.poison();
            return Err(AuthRuntimeError::OperationFailed);
        }
        Ok(())
    }

    async fn prune_expired(&self, now_micros: u64) -> Result<(), AuthRuntimeError> {
        let now = to_i64(now_micros).map_err(AuthRuntimeError::store)?;
        let outcome = self
            .mutations
            .execute_runtime(
                move |transaction| {
                    transaction.execute(
                        "DELETE FROM auth_sessions
                     WHERE EXISTS (
                         SELECT 1
                         FROM auth_refresh_families f
                         WHERE f.owner_id = auth_sessions.owner_id
                           AND f.session_id = auth_sessions.session_id
                           AND (
                               f.idle_deadline_at_micros <= ?1
                               OR f.absolute_deadline_at_micros <= ?1
                           )
                     )",
                        [now],
                    )?;
                    transaction.execute(
                        "DELETE FROM auth_login_attempt_markers WHERE expires_at_micros <= ?1",
                        [now],
                    )?;
                    Ok(AuthRuntimeApplyDecision::<std::convert::Infallible>::Commit)
                },
                move |connection| {
                    let expired: i64 = connection.query_row(
                        "SELECT
                            (SELECT count(*)
                             FROM auth_refresh_families
                             WHERE idle_deadline_at_micros <= ?1
                                OR absolute_deadline_at_micros <= ?1)
                            +
                            (SELECT count(*)
                             FROM auth_login_attempt_markers
                             WHERE expires_at_micros <= ?1)",
                        [now],
                        |row| row.get(0),
                    )?;
                    Ok(if expired == 0 {
                        AuthRuntimeMutationPostcondition::Committed
                    } else {
                        AuthRuntimeMutationPostcondition::NotCommitted
                    })
                },
            )
            .await
            .map_err(AuthRuntimeError::records)?;
        match outcome {
            AuthRuntimeMutationOutcome::Committed => Ok(()),
            AuthRuntimeMutationOutcome::ConfirmedNotCommitted => {
                self.poison();
                Err(AuthRuntimeError::OperationFailed)
            }
            AuthRuntimeMutationOutcome::ExpectedNoCommit(never) => match never {},
        }
    }

    async fn read_login_snapshot(
        &self,
        profile: AuthProfile,
        attempt_id: Uuid,
        requested_login: &str,
    ) -> Result<LoginSnapshot, AuthRuntimeError> {
        let requested_login = requested_login.to_owned();
        let attempt = attempt_id.into_bytes();
        self.store
            .call("authentication login observation", move |connection| {
                let transaction =
                    connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
                let snapshot = read_login_source(&transaction, requested_login.as_str())?;
                let replay = read_login_replay(
                    &transaction,
                    snapshot.expected.owner_id,
                    profile,
                    attempt,
                    snapshot.expected.credential_version,
                )?;
                transaction.rollback()?;
                Ok(LoginSnapshot {
                    expected: snapshot.expected,
                    verifier: snapshot.verifier,
                    replay,
                })
            })
            .await
            .map_err(AuthRuntimeError::store)
    }

    async fn read_password_mutation_snapshot(
        &self,
        owner: OwnerId,
    ) -> Result<LoginSource, AuthRuntimeError> {
        let owner = owner.as_uuid().into_bytes();
        self.store
            .call("password mutation observation", move |connection| {
                let stored_login: String = connection.query_row(
                    "SELECT login_id FROM auth_accounts
                     WHERE singleton = 1 AND owner_id = ?1",
                    [owner.as_slice()],
                    |row| row.get(0),
                )?;
                let source = read_login_source(connection, stored_login.as_str())?;
                if source.expected.owner_id != owner || !source.expected.login_matches {
                    return Err(StoreError::AuthControlPlaneCorrupt);
                }
                Ok(source)
            })
            .await
            .map_err(AuthRuntimeError::store)
    }

    async fn read_operator_password_snapshot(&self) -> Result<LoginSource, AuthRuntimeError> {
        self.store
            .call("operator password observation", |connection| {
                let stored_login: String = connection.query_row(
                    "SELECT login_id FROM auth_accounts WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )?;
                read_login_source(connection, stored_login.as_str())
            })
            .await
            .map_err(AuthRuntimeError::store)
    }

    async fn read_recovery_snapshot(&self) -> Result<RecoverySnapshot, AuthRuntimeError> {
        self.store
            .call("operator recovery observation", |connection| {
                read_recovery_source(connection)
            })
            .await
            .map_err(AuthRuntimeError::store)
    }

    async fn commit_current_password_failure(
        &self,
        expected: LoginExpected,
        next_throttle: ThrottleState,
        disable_password: bool,
        now_micros: u64,
    ) -> Result<CredentialMutationOutcome, AuthRuntimeError> {
        let expected = std::sync::Arc::new(expected);
        let apply_expected = std::sync::Arc::clone(&expected);
        let classify_expected = std::sync::Arc::clone(&expected);
        let outcome = self
            .mutations
            .execute_runtime(
                move |transaction| {
                    let expected = apply_expected.as_ref();
                    if !login_source_matches(transaction, expected)? {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(()));
                    }
                    let changed = transaction.execute(
                        "UPDATE auth_authenticator_throttles
                         SET failure_count = ?1,
                             next_allowed_at_micros = ?2,
                             throttle_revision = ?3,
                             updated_at_micros = ?4
                         WHERE owner_id = ?5
                           AND authenticator = 'password'
                           AND failure_count = ?6
                           AND next_allowed_at_micros = ?7
                           AND throttle_revision = ?8
                           AND updated_at_micros = ?9",
                        params![
                            to_i64(next_throttle.failure_count())?,
                            to_i64(next_throttle.next_allowed_at_micros())?,
                            to_i64(next_throttle.revision())?,
                            to_i64(now_micros)?,
                            expected.owner_id.as_slice(),
                            to_i64(expected.throttle.failure_count())?,
                            to_i64(expected.throttle.next_allowed_at_micros())?,
                            to_i64(expected.throttle.revision())?,
                            to_i64(expected.throttle.updated_at_micros())?,
                        ],
                    )?;
                    if changed != 1 {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(()));
                    }
                    if disable_password
                        && transaction.execute(
                            "UPDATE auth_password_credentials
                             SET authenticator_state = 'disabled',
                                 credential_revision = credential_revision + 1,
                                 updated_at_micros = ?1
                             WHERE owner_id = ?2
                               AND credential_revision = ?3
                               AND authenticator_state = 'enabled'",
                            params![
                                to_i64(now_micros)?,
                                expected.owner_id.as_slice(),
                                to_i64(expected.password_revision)?,
                            ],
                        )? != 1
                    {
                        return Err(StoreError::AuthControlPlaneCorrupt.into());
                    }
                    Ok(AuthRuntimeApplyDecision::Commit)
                },
                move |connection| {
                    let expected = classify_expected.as_ref();
                    if password_failure_post_matches(
                        connection,
                        expected,
                        next_throttle,
                        disable_password,
                    )? {
                        Ok(AuthRuntimeMutationPostcondition::Committed)
                    } else if login_source_matches(connection, expected)? {
                        Ok(AuthRuntimeMutationPostcondition::NotCommitted)
                    } else {
                        Ok(AuthRuntimeMutationPostcondition::Ambiguous)
                    }
                },
            )
            .await
            .map_err(AuthRuntimeError::records)?;
        Ok(match outcome {
            AuthRuntimeMutationOutcome::Committed => CredentialMutationOutcome::GenericFailure,
            AuthRuntimeMutationOutcome::ConfirmedNotCommitted
            | AuthRuntimeMutationOutcome::ExpectedNoCommit(()) => {
                CredentialMutationOutcome::RetryRequired
            }
        })
    }

    async fn commit_recovery_failure(
        &self,
        expected: RecoverySource,
        next_throttle: ThrottleState,
    ) -> Result<CredentialMutationOutcome, AuthRuntimeError> {
        let expected = std::sync::Arc::new(expected);
        let apply_expected = std::sync::Arc::clone(&expected);
        let classify_expected = std::sync::Arc::clone(&expected);
        let outcome = self
            .mutations
            .execute_runtime(
                move |transaction| {
                    let expected = apply_expected.as_ref();
                    if !recovery_source_matches(transaction, expected)? {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(()));
                    }
                    if transaction.execute(
                        "UPDATE auth_authenticator_throttles
                         SET failure_count = ?1,
                             next_allowed_at_micros = ?2,
                             throttle_revision = ?3,
                             updated_at_micros = ?4
                         WHERE owner_id = ?5
                           AND authenticator = 'recovery'
                           AND failure_count = ?6
                           AND next_allowed_at_micros = ?7
                           AND throttle_revision = ?8
                           AND updated_at_micros = ?9",
                        params![
                            to_i64(next_throttle.failure_count())?,
                            to_i64(next_throttle.next_allowed_at_micros())?,
                            to_i64(next_throttle.revision())?,
                            to_i64(next_throttle.updated_at_micros())?,
                            expected.owner_id.as_slice(),
                            to_i64(expected.recovery_throttle.failure_count())?,
                            to_i64(expected.recovery_throttle.next_allowed_at_micros())?,
                            to_i64(expected.recovery_throttle.revision())?,
                            to_i64(expected.recovery_throttle.updated_at_micros())?,
                        ],
                    )? != 1
                    {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(()));
                    }
                    Ok(AuthRuntimeApplyDecision::Commit)
                },
                move |connection| {
                    let expected = classify_expected.as_ref();
                    let current = read_recovery_source(connection)?.source;
                    let post_matches = current.owner_id == expected.owner_id
                        && current.account_enabled == expected.account_enabled
                        && current.credential_version == expected.credential_version
                        && current.account_revision == expected.account_revision
                        && current.password_phc.expose_secret()
                            == expected.password_phc.expose_secret()
                        && current.password_enabled == expected.password_enabled
                        && current.password_revision == expected.password_revision
                        && current.recovery_phc.expose_secret()
                            == expected.recovery_phc.expose_secret()
                        && current.recovery_revision == expected.recovery_revision
                        && current.password_throttle == expected.password_throttle
                        && current.recovery_throttle == next_throttle;
                    if post_matches {
                        Ok(AuthRuntimeMutationPostcondition::Committed)
                    } else if recovery_source_matches(connection, expected)? {
                        Ok(AuthRuntimeMutationPostcondition::NotCommitted)
                    } else {
                        Ok(AuthRuntimeMutationPostcondition::Ambiguous)
                    }
                },
            )
            .await
            .map_err(AuthRuntimeError::records)?;
        Ok(match outcome {
            AuthRuntimeMutationOutcome::Committed => CredentialMutationOutcome::GenericFailure,
            AuthRuntimeMutationOutcome::ConfirmedNotCommitted
            | AuthRuntimeMutationOutcome::ExpectedNoCommit(()) => {
                CredentialMutationOutcome::RetryRequired
            }
        })
    }

    async fn commit_password_change(
        &self,
        expected: LoginExpected,
        new_verifier: ValidatedVerifier,
        now_micros: u64,
    ) -> Result<CredentialMutationOutcome, AuthRuntimeError> {
        let new_phc = std::sync::Arc::new(Zeroizing::new(new_verifier.expose_phc().to_owned()));
        let expected = std::sync::Arc::new(expected);
        let apply_expected = std::sync::Arc::clone(&expected);
        let classify_expected = std::sync::Arc::clone(&expected);
        let apply_phc = std::sync::Arc::clone(&new_phc);
        let classify_phc = std::sync::Arc::clone(&new_phc);
        let audit_id = Uuid::new_v4().into_bytes();
        let outcome = self
            .mutations
            .execute_runtime(
                move |transaction| {
                    let expected = apply_expected.as_ref();
                    if !login_source_matches(transaction, expected)?
                        || !expected.account_enabled
                        || !expected.password_enabled
                    {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(()));
                    }
                    transaction.execute(
                        "DELETE FROM auth_sessions WHERE owner_id = ?1",
                        [expected.owner_id.as_slice()],
                    )?;
                    transaction.execute(
                        "DELETE FROM auth_login_attempt_outcomes WHERE owner_id = ?1",
                        [expected.owner_id.as_slice()],
                    )?;
                    if transaction.execute(
                        "UPDATE auth_password_credentials
                         SET verifier_phc = ?1,
                             authenticator_state = 'enabled',
                             credential_revision = credential_revision + 1,
                             updated_at_micros = ?2
                         WHERE owner_id = ?3
                           AND verifier_phc = ?4
                           AND authenticator_state = 'enabled'
                           AND credential_revision = ?5",
                        params![
                            apply_phc.as_str(),
                            to_i64(now_micros)?,
                            expected.owner_id.as_slice(),
                            std::str::from_utf8(expected.password_phc.expose_secret())
                                .map_err(|_| StoreError::AuthControlPlaneCorrupt)?,
                            to_i64(expected.password_revision)?,
                        ],
                    )? != 1
                    {
                        return Err(StoreError::AuthControlPlaneCorrupt.into());
                    }
                    if expected.throttle.failure_count() != 0 {
                        let reset = expected
                            .throttle
                            .successful_verification(now_micros)
                            .map_err(|_| StoreError::AuthControlPlaneCorrupt)?;
                        if transaction.execute(
                            "UPDATE auth_authenticator_throttles
                             SET failure_count = 0,
                                 next_allowed_at_micros = 0,
                                 throttle_revision = ?1,
                                 updated_at_micros = ?2
                             WHERE owner_id = ?3
                               AND authenticator = 'password'
                               AND failure_count = ?4
                               AND next_allowed_at_micros = ?5
                               AND throttle_revision = ?6
                               AND updated_at_micros = ?7",
                            params![
                                to_i64(reset.revision())?,
                                to_i64(now_micros)?,
                                expected.owner_id.as_slice(),
                                to_i64(expected.throttle.failure_count())?,
                                to_i64(expected.throttle.next_allowed_at_micros())?,
                                to_i64(expected.throttle.revision())?,
                                to_i64(expected.throttle.updated_at_micros())?,
                            ],
                        )? != 1
                        {
                            return Err(StoreError::AuthControlPlaneCorrupt.into());
                        }
                    }
                    if transaction.execute(
                        "UPDATE auth_accounts
                         SET credential_version = credential_version + 1,
                             account_revision = account_revision + 1,
                             updated_at_micros = ?1
                         WHERE owner_id = ?2
                           AND account_state = 'enabled'
                           AND credential_version = ?3
                           AND account_revision = ?4",
                        params![
                            to_i64(now_micros)?,
                            expected.owner_id.as_slice(),
                            to_i64(expected.credential_version)?,
                            to_i64(expected.account_revision)?,
                        ],
                    )? != 1
                    {
                        return Err(StoreError::AuthControlPlaneCorrupt.into());
                    }
                    insert_audit(
                        transaction,
                        expected.owner_id,
                        audit_id,
                        "password_changed",
                        None,
                        None,
                        None,
                        now_micros,
                    )?;
                    Ok(AuthRuntimeApplyDecision::Commit)
                },
                move |connection| {
                    let expected = classify_expected.as_ref();
                    let next_version = expected
                        .credential_version
                        .checked_add(1)
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    let next_account_revision = expected
                        .account_revision
                        .checked_add(1)
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    let next_password_revision = expected
                        .password_revision
                        .checked_add(1)
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    let (throttle_revision, throttle_updated) =
                        if expected.throttle.failure_count() == 0 {
                            (
                                expected.throttle.revision(),
                                expected.throttle.updated_at_micros(),
                            )
                        } else {
                            (
                                expected
                                    .throttle
                                    .revision()
                                    .checked_add(1)
                                    .ok_or(StoreError::AuthControlPlaneCorrupt)?,
                                now_micros,
                            )
                        };
                    let committed: i64 = connection.query_row(
                        "SELECT count(*)
                         FROM auth_accounts a
                         JOIN auth_password_credentials p ON p.owner_id = a.owner_id
                         JOIN auth_authenticator_throttles t
                           ON t.owner_id = a.owner_id AND t.authenticator = 'password'
                         JOIN auth_audit au
                           ON au.owner_id = a.owner_id AND au.audit_id = ?1
                         WHERE a.owner_id = ?2
                           AND a.account_state = 'enabled'
                           AND a.credential_version = ?3
                           AND a.account_revision = ?4
                           AND a.updated_at_micros = ?5
                           AND p.verifier_phc = ?6
                           AND p.authenticator_state = 'enabled'
                           AND p.credential_revision = ?7
                           AND p.updated_at_micros = ?5
                           AND t.failure_count = 0
                           AND t.next_allowed_at_micros = 0
                           AND t.throttle_revision = ?8
                           AND t.updated_at_micros = ?9
                           AND NOT EXISTS(
                               SELECT 1 FROM auth_sessions s
                               WHERE s.owner_id = a.owner_id
                           )
                           AND NOT EXISTS(
                               SELECT 1 FROM auth_login_attempt_outcomes o
                               WHERE o.owner_id = a.owner_id
                           )
                           AND au.action = 'password_changed'
                           AND au.profile IS NULL
                           AND au.session_id IS NULL
                           AND au.attempt_id IS NULL
                           AND au.happened_at_micros = ?5",
                        params![
                            audit_id.as_slice(),
                            expected.owner_id.as_slice(),
                            to_i64(next_version)?,
                            to_i64(next_account_revision)?,
                            to_i64(now_micros)?,
                            classify_phc.as_str(),
                            to_i64(next_password_revision)?,
                            to_i64(throttle_revision)?,
                            to_i64(throttle_updated)?,
                        ],
                        |row| row.get(0),
                    )?;
                    if committed == 1 {
                        return Ok(AuthRuntimeMutationPostcondition::Committed);
                    }
                    let audit_absent: bool = connection.query_row(
                        "SELECT NOT EXISTS(
                            SELECT 1 FROM auth_audit WHERE audit_id = ?1
                         )",
                        [audit_id.as_slice()],
                        |row| row.get(0),
                    )?;
                    if audit_absent && login_source_matches(connection, expected)? {
                        Ok(AuthRuntimeMutationPostcondition::NotCommitted)
                    } else {
                        Ok(AuthRuntimeMutationPostcondition::Ambiguous)
                    }
                },
            )
            .await
            .map_err(AuthRuntimeError::records)?;
        Ok(match outcome {
            AuthRuntimeMutationOutcome::Committed => CredentialMutationOutcome::Changed,
            AuthRuntimeMutationOutcome::ConfirmedNotCommitted
            | AuthRuntimeMutationOutcome::ExpectedNoCommit(()) => {
                CredentialMutationOutcome::RetryRequired
            }
        })
    }

    async fn commit_recovery_rotation(
        &self,
        expected: RecoverySource,
        new_verifier: ValidatedVerifier,
        now_micros: u64,
    ) -> Result<CredentialMutationOutcome, AuthRuntimeError> {
        let new_phc = std::sync::Arc::new(Zeroizing::new(new_verifier.expose_phc().to_owned()));
        let expected = std::sync::Arc::new(expected);
        let apply_expected = std::sync::Arc::clone(&expected);
        let classify_expected = std::sync::Arc::clone(&expected);
        let apply_phc = std::sync::Arc::clone(&new_phc);
        let classify_phc = std::sync::Arc::clone(&new_phc);
        let audit_id = Uuid::new_v4().into_bytes();
        let outcome = self
            .mutations
            .execute_runtime(
                move |transaction| {
                    let expected = apply_expected.as_ref();
                    if !recovery_source_matches(transaction, expected)?
                        || !expected.account_enabled
                        || !expected.password_enabled
                    {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(()));
                    }
                    transaction.execute(
                        "DELETE FROM auth_sessions WHERE owner_id = ?1",
                        [expected.owner_id.as_slice()],
                    )?;
                    transaction.execute(
                        "DELETE FROM auth_login_attempt_outcomes WHERE owner_id = ?1",
                        [expected.owner_id.as_slice()],
                    )?;
                    if transaction.execute(
                        "UPDATE auth_recovery_credentials
                         SET verifier_phc = ?1,
                             credential_revision = credential_revision + 1,
                             updated_at_micros = ?2
                         WHERE owner_id = ?3
                           AND verifier_phc = ?4
                           AND credential_revision = ?5",
                        params![
                            apply_phc.as_str(),
                            to_i64(now_micros)?,
                            expected.owner_id.as_slice(),
                            std::str::from_utf8(expected.recovery_phc.expose_secret())
                                .map_err(|_| StoreError::AuthControlPlaneCorrupt)?,
                            to_i64(expected.recovery_revision)?,
                        ],
                    )? != 1
                    {
                        return Err(StoreError::AuthControlPlaneCorrupt.into());
                    }
                    if expected.password_throttle.failure_count() != 0 {
                        let reset = expected
                            .password_throttle
                            .successful_verification(now_micros)
                            .map_err(|_| StoreError::AuthControlPlaneCorrupt)?;
                        if transaction.execute(
                            "UPDATE auth_authenticator_throttles
                             SET failure_count = 0,
                                 next_allowed_at_micros = 0,
                                 throttle_revision = ?1,
                                 updated_at_micros = ?2
                             WHERE owner_id = ?3
                               AND authenticator = 'password'
                               AND failure_count = ?4
                               AND next_allowed_at_micros = ?5
                               AND throttle_revision = ?6
                               AND updated_at_micros = ?7",
                            params![
                                to_i64(reset.revision())?,
                                to_i64(now_micros)?,
                                expected.owner_id.as_slice(),
                                to_i64(expected.password_throttle.failure_count())?,
                                to_i64(expected.password_throttle.next_allowed_at_micros())?,
                                to_i64(expected.password_throttle.revision())?,
                                to_i64(expected.password_throttle.updated_at_micros())?,
                            ],
                        )? != 1
                        {
                            return Err(StoreError::AuthControlPlaneCorrupt.into());
                        }
                    }
                    if transaction.execute(
                        "UPDATE auth_accounts
                         SET credential_version = credential_version + 1,
                             account_revision = account_revision + 1,
                             updated_at_micros = ?1
                         WHERE owner_id = ?2
                           AND account_state = 'enabled'
                           AND credential_version = ?3
                           AND account_revision = ?4",
                        params![
                            to_i64(now_micros)?,
                            expected.owner_id.as_slice(),
                            to_i64(expected.credential_version)?,
                            to_i64(expected.account_revision)?,
                        ],
                    )? != 1
                    {
                        return Err(StoreError::AuthControlPlaneCorrupt.into());
                    }
                    insert_audit(
                        transaction,
                        expected.owner_id,
                        audit_id,
                        "recovery_code_rotated",
                        None,
                        None,
                        None,
                        now_micros,
                    )?;
                    Ok(AuthRuntimeApplyDecision::Commit)
                },
                move |connection| {
                    let expected = classify_expected.as_ref();
                    let next_credential_version = expected
                        .credential_version
                        .checked_add(1)
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    let next_account_revision = expected
                        .account_revision
                        .checked_add(1)
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    let next_recovery_revision = expected
                        .recovery_revision
                        .checked_add(1)
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    let (password_throttle_revision, password_throttle_updated) =
                        if expected.password_throttle.failure_count() == 0 {
                            (
                                expected.password_throttle.revision(),
                                expected.password_throttle.updated_at_micros(),
                            )
                        } else {
                            (
                                expected
                                    .password_throttle
                                    .revision()
                                    .checked_add(1)
                                    .ok_or(StoreError::AuthControlPlaneCorrupt)?,
                                now_micros,
                            )
                        };
                    let committed: i64 = connection.query_row(
                        "SELECT count(*)
                         FROM auth_accounts a
                         JOIN auth_password_credentials p ON p.owner_id = a.owner_id
                         JOIN auth_recovery_credentials r ON r.owner_id = a.owner_id
                         JOIN auth_authenticator_throttles pt
                           ON pt.owner_id = a.owner_id AND pt.authenticator = 'password'
                         JOIN auth_authenticator_throttles rt
                           ON rt.owner_id = a.owner_id AND rt.authenticator = 'recovery'
                         JOIN auth_audit au
                           ON au.owner_id = a.owner_id AND au.audit_id = ?1
                         WHERE a.owner_id = ?2
                           AND a.account_state = 'enabled'
                           AND a.credential_version = ?3
                           AND a.account_revision = ?4
                           AND a.updated_at_micros = ?5
                           AND p.verifier_phc = ?6
                           AND p.authenticator_state = 'enabled'
                           AND p.credential_revision = ?7
                           AND r.verifier_phc = ?8
                           AND r.credential_revision = ?9
                           AND r.updated_at_micros = ?5
                           AND pt.failure_count = 0
                           AND pt.next_allowed_at_micros = 0
                           AND pt.throttle_revision = ?10
                           AND pt.updated_at_micros = ?11
                           AND rt.failure_count = ?12
                           AND rt.next_allowed_at_micros = ?13
                           AND rt.throttle_revision = ?14
                           AND rt.updated_at_micros = ?15
                           AND NOT EXISTS(
                               SELECT 1 FROM auth_sessions s WHERE s.owner_id = a.owner_id
                           )
                           AND NOT EXISTS(
                               SELECT 1 FROM auth_login_attempt_outcomes o
                               WHERE o.owner_id = a.owner_id
                           )
                           AND au.action = 'recovery_code_rotated'
                           AND au.profile IS NULL
                           AND au.session_id IS NULL
                           AND au.attempt_id IS NULL
                           AND au.happened_at_micros = ?5",
                        params![
                            audit_id.as_slice(),
                            expected.owner_id.as_slice(),
                            to_i64(next_credential_version)?,
                            to_i64(next_account_revision)?,
                            to_i64(now_micros)?,
                            std::str::from_utf8(expected.password_phc.expose_secret())
                                .map_err(|_| StoreError::AuthControlPlaneCorrupt)?,
                            to_i64(expected.password_revision)?,
                            classify_phc.as_str(),
                            to_i64(next_recovery_revision)?,
                            to_i64(password_throttle_revision)?,
                            to_i64(password_throttle_updated)?,
                            to_i64(expected.recovery_throttle.failure_count())?,
                            to_i64(expected.recovery_throttle.next_allowed_at_micros())?,
                            to_i64(expected.recovery_throttle.revision())?,
                            to_i64(expected.recovery_throttle.updated_at_micros())?,
                        ],
                        |row| row.get(0),
                    )?;
                    if committed == 1 {
                        return Ok(AuthRuntimeMutationPostcondition::Committed);
                    }
                    let audit_absent: bool = connection.query_row(
                        "SELECT NOT EXISTS(
                            SELECT 1 FROM auth_audit WHERE audit_id = ?1
                         )",
                        [audit_id.as_slice()],
                        |row| row.get(0),
                    )?;
                    if audit_absent && recovery_source_matches(connection, expected)? {
                        Ok(AuthRuntimeMutationPostcondition::NotCommitted)
                    } else {
                        Ok(AuthRuntimeMutationPostcondition::Ambiguous)
                    }
                },
            )
            .await
            .map_err(AuthRuntimeError::records)?;
        Ok(match outcome {
            AuthRuntimeMutationOutcome::Committed => CredentialMutationOutcome::Changed,
            AuthRuntimeMutationOutcome::ConfirmedNotCommitted
            | AuthRuntimeMutationOutcome::ExpectedNoCommit(()) => {
                CredentialMutationOutcome::RetryRequired
            }
        })
    }

    async fn commit_account_recovery(
        &self,
        expected: RecoverySource,
        password_verifier: ValidatedVerifier,
        recovery_verifier: ValidatedVerifier,
        now_micros: u64,
    ) -> Result<CredentialMutationOutcome, AuthRuntimeError> {
        let password_phc =
            std::sync::Arc::new(Zeroizing::new(password_verifier.expose_phc().to_owned()));
        let recovery_phc =
            std::sync::Arc::new(Zeroizing::new(recovery_verifier.expose_phc().to_owned()));
        let expected = std::sync::Arc::new(expected);
        let apply_expected = std::sync::Arc::clone(&expected);
        let classify_expected = std::sync::Arc::clone(&expected);
        let apply_password = std::sync::Arc::clone(&password_phc);
        let classify_password = std::sync::Arc::clone(&password_phc);
        let apply_recovery = std::sync::Arc::clone(&recovery_phc);
        let classify_recovery = std::sync::Arc::clone(&recovery_phc);
        let audit_id = Uuid::new_v4().into_bytes();
        let outcome = self
            .mutations
            .execute_runtime(
                move |transaction| {
                    let expected = apply_expected.as_ref();
                    if !recovery_source_matches(transaction, expected)? {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(()));
                    }
                    transaction.execute(
                        "DELETE FROM auth_sessions WHERE owner_id = ?1",
                        [expected.owner_id.as_slice()],
                    )?;
                    transaction.execute(
                        "DELETE FROM auth_login_attempt_outcomes WHERE owner_id = ?1",
                        [expected.owner_id.as_slice()],
                    )?;
                    if transaction.execute(
                        "UPDATE auth_password_credentials
                         SET verifier_phc = ?1,
                             authenticator_state = 'enabled',
                             credential_revision = credential_revision + 1,
                             updated_at_micros = ?2
                         WHERE owner_id = ?3
                           AND verifier_phc = ?4
                           AND authenticator_state = ?5
                           AND credential_revision = ?6",
                        params![
                            apply_password.as_str(),
                            to_i64(now_micros)?,
                            expected.owner_id.as_slice(),
                            std::str::from_utf8(expected.password_phc.expose_secret())
                                .map_err(|_| StoreError::AuthControlPlaneCorrupt)?,
                            if expected.password_enabled {
                                "enabled"
                            } else {
                                "disabled"
                            },
                            to_i64(expected.password_revision)?,
                        ],
                    )? != 1
                    {
                        return Err(StoreError::AuthControlPlaneCorrupt.into());
                    }
                    if transaction.execute(
                        "UPDATE auth_recovery_credentials
                         SET verifier_phc = ?1,
                             credential_revision = credential_revision + 1,
                             updated_at_micros = ?2
                         WHERE owner_id = ?3
                           AND verifier_phc = ?4
                           AND credential_revision = ?5",
                        params![
                            apply_recovery.as_str(),
                            to_i64(now_micros)?,
                            expected.owner_id.as_slice(),
                            std::str::from_utf8(expected.recovery_phc.expose_secret())
                                .map_err(|_| StoreError::AuthControlPlaneCorrupt)?,
                            to_i64(expected.recovery_revision)?,
                        ],
                    )? != 1
                    {
                        return Err(StoreError::AuthControlPlaneCorrupt.into());
                    }
                    if expected.password_throttle.failure_count() != 0 {
                        let reset = expected
                            .password_throttle
                            .reset_after_recovery(now_micros)
                            .map_err(|_| StoreError::AuthControlPlaneCorrupt)?;
                        update_throttle_to_reset(
                            transaction,
                            expected.owner_id,
                            expected.password_throttle,
                            reset,
                        )?;
                    }
                    if expected.recovery_throttle.failure_count() != 0 {
                        let reset = expected
                            .recovery_throttle
                            .successful_verification(now_micros)
                            .map_err(|_| StoreError::AuthControlPlaneCorrupt)?;
                        update_throttle_to_reset(
                            transaction,
                            expected.owner_id,
                            expected.recovery_throttle,
                            reset,
                        )?;
                    }
                    if transaction.execute(
                        "UPDATE auth_accounts
                         SET credential_version = credential_version + 1,
                             account_revision = account_revision + 1,
                             updated_at_micros = ?1
                         WHERE owner_id = ?2
                           AND account_state = ?3
                           AND credential_version = ?4
                           AND account_revision = ?5",
                        params![
                            to_i64(now_micros)?,
                            expected.owner_id.as_slice(),
                            if expected.account_enabled {
                                "enabled"
                            } else {
                                "disabled"
                            },
                            to_i64(expected.credential_version)?,
                            to_i64(expected.account_revision)?,
                        ],
                    )? != 1
                    {
                        return Err(StoreError::AuthControlPlaneCorrupt.into());
                    }
                    insert_audit(
                        transaction,
                        expected.owner_id,
                        audit_id,
                        "recovery_completed",
                        None,
                        None,
                        None,
                        now_micros,
                    )?;
                    Ok(AuthRuntimeApplyDecision::Commit)
                },
                move |connection| {
                    let expected = classify_expected.as_ref();
                    let current = read_recovery_source(connection)?.source;
                    let password_throttle =
                        expected_password_recovery_reset(expected.password_throttle, now_micros)?;
                    let recovery_throttle =
                        expected_success_reset(expected.recovery_throttle, now_micros)?;
                    let audit_matches = exact_account_audit(
                        connection,
                        expected.owner_id,
                        audit_id,
                        "recovery_completed",
                        now_micros,
                    )?;
                    let terminal = no_owner_sessions_or_outcomes(connection, expected.owner_id)?;
                    let committed = current.owner_id == expected.owner_id
                        && current.account_enabled == expected.account_enabled
                        && current.credential_version
                            == expected
                                .credential_version
                                .checked_add(1)
                                .ok_or(StoreError::AuthControlPlaneCorrupt)?
                        && current.account_revision
                            == expected
                                .account_revision
                                .checked_add(1)
                                .ok_or(StoreError::AuthControlPlaneCorrupt)?
                        && current.password_phc.expose_secret() == classify_password.as_bytes()
                        && current.password_enabled
                        && current.password_revision
                            == expected
                                .password_revision
                                .checked_add(1)
                                .ok_or(StoreError::AuthControlPlaneCorrupt)?
                        && current.recovery_phc.expose_secret() == classify_recovery.as_bytes()
                        && current.recovery_revision
                            == expected
                                .recovery_revision
                                .checked_add(1)
                                .ok_or(StoreError::AuthControlPlaneCorrupt)?
                        && current.password_throttle == password_throttle
                        && current.recovery_throttle == recovery_throttle
                        && audit_matches
                        && terminal;
                    if committed {
                        return Ok(AuthRuntimeMutationPostcondition::Committed);
                    }
                    let audit_absent = !audit_id_exists(connection, audit_id)?;
                    if audit_absent && recovery_source_matches(connection, expected)? {
                        Ok(AuthRuntimeMutationPostcondition::NotCommitted)
                    } else {
                        Ok(AuthRuntimeMutationPostcondition::Ambiguous)
                    }
                },
            )
            .await
            .map_err(AuthRuntimeError::records)?;
        Ok(match outcome {
            AuthRuntimeMutationOutcome::Committed => CredentialMutationOutcome::Changed,
            AuthRuntimeMutationOutcome::ConfirmedNotCommitted
            | AuthRuntimeMutationOutcome::ExpectedNoCommit(()) => {
                CredentialMutationOutcome::RetryRequired
            }
        })
    }

    async fn commit_account_enabled_state(
        &self,
        expected: RecoverySource,
        enabled: bool,
        now_micros: u64,
    ) -> Result<CredentialMutationOutcome, AuthRuntimeError> {
        let expected = std::sync::Arc::new(expected);
        let apply_expected = std::sync::Arc::clone(&expected);
        let classify_expected = std::sync::Arc::clone(&expected);
        let audit_id = Uuid::new_v4().into_bytes();
        let action = if enabled {
            "account_enabled"
        } else {
            "account_disabled"
        };
        let outcome = self
            .mutations
            .execute_runtime(
                move |transaction| {
                    let expected = apply_expected.as_ref();
                    if !recovery_source_matches(transaction, expected)?
                        || expected.account_enabled == enabled
                    {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(()));
                    }
                    transaction.execute(
                        "DELETE FROM auth_sessions WHERE owner_id = ?1",
                        [expected.owner_id.as_slice()],
                    )?;
                    transaction.execute(
                        "DELETE FROM auth_login_attempt_outcomes WHERE owner_id = ?1",
                        [expected.owner_id.as_slice()],
                    )?;
                    if expected.recovery_throttle.failure_count() != 0 {
                        let reset = expected
                            .recovery_throttle
                            .successful_verification(now_micros)
                            .map_err(|_| StoreError::AuthControlPlaneCorrupt)?;
                        update_throttle_to_reset(
                            transaction,
                            expected.owner_id,
                            expected.recovery_throttle,
                            reset,
                        )?;
                    }
                    if transaction.execute(
                        "UPDATE auth_accounts
                         SET account_state = ?1,
                             credential_version = credential_version + 1,
                             account_revision = account_revision + 1,
                             updated_at_micros = ?2
                         WHERE owner_id = ?3
                           AND account_state = ?4
                           AND credential_version = ?5
                           AND account_revision = ?6",
                        params![
                            if enabled { "enabled" } else { "disabled" },
                            to_i64(now_micros)?,
                            expected.owner_id.as_slice(),
                            if expected.account_enabled {
                                "enabled"
                            } else {
                                "disabled"
                            },
                            to_i64(expected.credential_version)?,
                            to_i64(expected.account_revision)?,
                        ],
                    )? != 1
                    {
                        return Err(StoreError::AuthControlPlaneCorrupt.into());
                    }
                    insert_audit(
                        transaction,
                        expected.owner_id,
                        audit_id,
                        action,
                        None,
                        None,
                        None,
                        now_micros,
                    )?;
                    Ok(AuthRuntimeApplyDecision::Commit)
                },
                move |connection| {
                    let expected = classify_expected.as_ref();
                    let current = read_recovery_source(connection)?.source;
                    let recovery_throttle =
                        expected_success_reset(expected.recovery_throttle, now_micros)?;
                    let committed = current.owner_id == expected.owner_id
                        && current.account_enabled == enabled
                        && current.credential_version
                            == expected
                                .credential_version
                                .checked_add(1)
                                .ok_or(StoreError::AuthControlPlaneCorrupt)?
                        && current.account_revision
                            == expected
                                .account_revision
                                .checked_add(1)
                                .ok_or(StoreError::AuthControlPlaneCorrupt)?
                        && current.password_phc.expose_secret()
                            == expected.password_phc.expose_secret()
                        && current.password_enabled == expected.password_enabled
                        && current.password_revision == expected.password_revision
                        && current.recovery_phc.expose_secret()
                            == expected.recovery_phc.expose_secret()
                        && current.recovery_revision == expected.recovery_revision
                        && current.password_throttle == expected.password_throttle
                        && current.recovery_throttle == recovery_throttle
                        && exact_account_audit(
                            connection,
                            expected.owner_id,
                            audit_id,
                            action,
                            now_micros,
                        )?
                        && no_owner_sessions_or_outcomes(connection, expected.owner_id)?;
                    if committed {
                        return Ok(AuthRuntimeMutationPostcondition::Committed);
                    }
                    let audit_absent = !audit_id_exists(connection, audit_id)?;
                    if audit_absent && recovery_source_matches(connection, expected)? {
                        Ok(AuthRuntimeMutationPostcondition::NotCommitted)
                    } else {
                        Ok(AuthRuntimeMutationPostcondition::Ambiguous)
                    }
                },
            )
            .await
            .map_err(AuthRuntimeError::records)?;
        Ok(match outcome {
            AuthRuntimeMutationOutcome::Committed => CredentialMutationOutcome::Changed,
            AuthRuntimeMutationOutcome::ExpectedNoCommit(()) => {
                CredentialMutationOutcome::AlreadyApplied
            }
            AuthRuntimeMutationOutcome::ConfirmedNotCommitted => {
                CredentialMutationOutcome::RetryRequired
            }
        })
    }

    async fn commit_login_failure(
        &self,
        expected: LoginExpected,
        attempt_id: Uuid,
        profile: AuthProfile,
        next_throttle: ThrottleState,
        disable_password: bool,
        now_micros: u64,
    ) -> Result<LoginCommitOutcome, AuthRuntimeError> {
        let attempt = attempt_id.into_bytes();
        let audit_id = Uuid::new_v4().into_bytes();
        let expected = std::sync::Arc::new(expected);
        let apply_expected = std::sync::Arc::clone(&expected);
        let classify_expected = std::sync::Arc::clone(&expected);
        let outcome = self
            .mutations
            .execute_runtime(
                move |transaction| {
                    let expected = apply_expected.as_ref();
                    if let Some(replay) = classify_existing_login_attempt(
                        transaction,
                        expected.owner_id,
                        profile,
                        attempt,
                        expected.credential_version,
                    )? {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(replay));
                    }
                    if !login_source_matches(transaction, expected)? {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(
                            LoginCommitOutcome::RetryRequired,
                        ));
                    }
                    if marker_count(transaction, expected.owner_id, profile)? >= MAX_LOGIN_MARKERS {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(
                            LoginCommitOutcome::RateLimited,
                        ));
                    }
                    let now = to_i64(now_micros)?;
                    let next_admission = expected
                        .admission_revision
                        .checked_add(1)
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    let expires = now_micros
                        .checked_add(LOGIN_ATTEMPT_LIFETIME_MICROS)
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    transaction.execute(
                        "INSERT INTO auth_login_attempt_markers(
                        owner_id, profile, attempt_id, admission_revision,
                        created_at_micros, expires_at_micros
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            expected.owner_id.as_slice(),
                            profile.as_str(),
                            attempt.as_slice(),
                            to_i64(next_admission)?,
                            now,
                            to_i64(expires)?
                        ],
                    )?;
                    let changed = transaction.execute(
                        "UPDATE auth_authenticator_throttles
                     SET failure_count = ?1,
                         next_allowed_at_micros = ?2,
                         throttle_revision = ?3,
                         updated_at_micros = ?4
                     WHERE owner_id = ?5
                       AND authenticator = 'password'
                       AND failure_count = ?6
                       AND next_allowed_at_micros = ?7
                       AND throttle_revision = ?8
                       AND updated_at_micros = ?9",
                        params![
                            to_i64(next_throttle.failure_count())?,
                            to_i64(next_throttle.next_allowed_at_micros())?,
                            to_i64(next_throttle.revision())?,
                            now,
                            expected.owner_id.as_slice(),
                            to_i64(expected.throttle.failure_count())?,
                            to_i64(expected.throttle.next_allowed_at_micros())?,
                            to_i64(expected.throttle.revision())?,
                            to_i64(expected.throttle.updated_at_micros())?,
                        ],
                    )?;
                    if changed != 1 {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(
                            LoginCommitOutcome::RetryRequired,
                        ));
                    }
                    if disable_password {
                        let changed = transaction.execute(
                            "UPDATE auth_password_credentials
                         SET authenticator_state = 'disabled',
                             credential_revision = credential_revision + 1,
                             updated_at_micros = ?1
                         WHERE owner_id = ?2
                           AND credential_revision = ?3
                           AND authenticator_state = 'enabled'",
                            params![
                                now,
                                expected.owner_id.as_slice(),
                                to_i64(expected.password_revision)?
                            ],
                        )?;
                        if changed != 1 {
                            return Err(StoreError::AuthControlPlaneCorrupt.into());
                        }
                    }
                    update_login_control(&transaction, &expected, next_admission, now_micros)?;
                    transaction.execute(
                        "INSERT INTO auth_login_attempt_outcomes(
                        owner_id, profile, attempt_id, credential_version,
                        outcome_kind, session_id, created_at_micros
                     ) VALUES (?1, ?2, ?3, ?4, 'generic_failure', NULL, ?5)",
                        params![
                            expected.owner_id.as_slice(),
                            profile.as_str(),
                            attempt.as_slice(),
                            to_i64(expected.credential_version)?,
                            now,
                        ],
                    )?;
                    insert_audit(
                        transaction,
                        expected.owner_id,
                        audit_id,
                        "login_failed",
                        Some(profile),
                        None,
                        Some(attempt),
                        now_micros,
                    )?;
                    Ok(AuthRuntimeApplyDecision::Commit)
                },
                move |connection| {
                    let expected = classify_expected.as_ref();
                    let next_admission = expected
                        .admission_revision
                        .checked_add(1)
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    let next_control = expected
                        .control_revision
                        .checked_add(1)
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    let marker_expires = now_micros
                        .checked_add(LOGIN_ATTEMPT_LIFETIME_MICROS)
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    let password_revision = expected
                        .password_revision
                        .checked_add(u64::from(disable_password))
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    let password_state = if disable_password {
                        "disabled"
                    } else if expected.password_enabled {
                        "enabled"
                    } else {
                        "disabled"
                    };
                    let committed: i64 = connection.query_row(
                        "SELECT count(*)
                         FROM auth_login_attempt_markers m
                         JOIN auth_login_attempt_outcomes o
                           ON o.owner_id = m.owner_id
                          AND o.profile = m.profile
                          AND o.attempt_id = m.attempt_id
                         JOIN auth_authenticator_throttles t
                           ON t.owner_id = m.owner_id AND t.authenticator = 'password'
                         JOIN auth_login_control c
                           ON c.owner_id = m.owner_id AND c.singleton = 1
                         JOIN auth_password_credentials p
                           ON p.owner_id = m.owner_id AND p.singleton = 1
                         JOIN auth_audit au
                           ON au.owner_id = m.owner_id AND au.audit_id = ?1
                         WHERE m.owner_id = ?2
                           AND m.profile = ?3
                           AND m.attempt_id = ?4
                           AND m.admission_revision = ?5
                           AND m.created_at_micros = ?6
                           AND m.expires_at_micros = ?7
                           AND o.credential_version = ?8
                           AND o.outcome_kind = 'generic_failure'
                           AND o.session_id IS NULL
                           AND o.created_at_micros = ?6
                           AND t.failure_count = ?9
                           AND t.next_allowed_at_micros = ?10
                           AND t.throttle_revision = ?11
                           AND t.updated_at_micros = ?6
                           AND c.admission_revision = ?5
                           AND c.clock_floor_micros = ?6
                           AND c.control_revision = ?12
                           AND c.updated_at_micros = ?6
                           AND p.authenticator_state = ?13
                           AND p.credential_revision = ?14
                           AND (?15 = 0 OR p.updated_at_micros = ?6)
                           AND au.action = 'login_failed'
                           AND au.profile = ?3
                           AND au.session_id IS NULL
                           AND au.attempt_id = ?4
                           AND au.happened_at_micros = ?6",
                        params![
                            audit_id.as_slice(),
                            expected.owner_id.as_slice(),
                            profile.as_str(),
                            attempt.as_slice(),
                            to_i64(next_admission)?,
                            to_i64(now_micros)?,
                            to_i64(marker_expires)?,
                            to_i64(expected.credential_version)?,
                            to_i64(next_throttle.failure_count())?,
                            to_i64(next_throttle.next_allowed_at_micros())?,
                            to_i64(next_throttle.revision())?,
                            to_i64(next_control)?,
                            password_state,
                            to_i64(password_revision)?,
                            disable_password,
                        ],
                        |row| row.get(0),
                    )?;
                    if committed == 1 {
                        return Ok(AuthRuntimeMutationPostcondition::Committed);
                    }
                    let audit_absent: bool = connection.query_row(
                        "SELECT NOT EXISTS(
                            SELECT 1 FROM auth_audit WHERE audit_id = ?1
                         )",
                        [audit_id.as_slice()],
                        |row| row.get(0),
                    )?;
                    let marker_absent = classify_existing_login_attempt(
                        connection,
                        expected.owner_id,
                        profile,
                        attempt,
                        expected.credential_version,
                    )?
                    .is_none();
                    if audit_absent && marker_absent && login_source_matches(connection, expected)?
                    {
                        Ok(AuthRuntimeMutationPostcondition::NotCommitted)
                    } else {
                        Ok(AuthRuntimeMutationPostcondition::Ambiguous)
                    }
                },
            )
            .await
            .map_err(AuthRuntimeError::records)?;
        Ok(match outcome {
            AuthRuntimeMutationOutcome::Committed => LoginCommitOutcome::Committed,
            AuthRuntimeMutationOutcome::ConfirmedNotCommitted => LoginCommitOutcome::RetryRequired,
            AuthRuntimeMutationOutcome::ExpectedNoCommit(outcome) => outcome,
        })
    }

    async fn commit_login_success(
        &self,
        expected: LoginExpected,
        attempt_id: Uuid,
        profile: AuthProfile,
        candidate: &SessionCandidate,
        now_micros: u64,
    ) -> Result<LoginCommitOutcome, AuthRuntimeError> {
        let attempt = attempt_id.into_bytes();
        let session = candidate.session_id.into_bytes();
        let family = candidate.family_id.into_bytes();
        let refresh_digest = candidate.refresh_digest;
        let audit_id = Uuid::new_v4().into_bytes();
        let absolute = now_micros
            .checked_add(LOCAL_ABSOLUTE_LIFETIME_MICROS)
            .ok_or(AuthRuntimeError::OperationFailed)?;
        let idle = now_micros
            .checked_add(LOCAL_IDLE_LIFETIME_MICROS)
            .ok_or(AuthRuntimeError::OperationFailed)?
            .min(absolute);
        let expected = std::sync::Arc::new(expected);
        let apply_expected = std::sync::Arc::clone(&expected);
        let classify_expected = std::sync::Arc::clone(&expected);
        let outcome = self
            .mutations
            .execute_runtime(
                move |transaction| {
                    let expected = apply_expected.as_ref();
                    if let Some(replay) = classify_existing_login_attempt(
                        transaction,
                        expected.owner_id,
                        profile,
                        attempt,
                        expected.credential_version,
                    )? {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(replay));
                    }
                    if !login_source_matches(transaction, expected)?
                        || !expected.login_matches
                        || !expected.account_enabled
                        || !expected.password_enabled
                    {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(
                            LoginCommitOutcome::RetryRequired,
                        ));
                    }
                    if marker_count(transaction, expected.owner_id, profile)? >= MAX_LOGIN_MARKERS {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(
                            LoginCommitOutcome::RateLimited,
                        ));
                    }
                    let active_sessions: u64 = transaction.query_row(
                        "SELECT count(*) FROM auth_sessions
                     WHERE owner_id = ?1 AND profile = ?2",
                        params![expected.owner_id.as_slice(), profile.as_str()],
                        |row| row.get(0),
                    )?;
                    if active_sessions >= MAX_ACTIVE_SESSIONS {
                        let oldest: Option<[u8; 16]> = transaction
                            .query_row(
                                "SELECT session_id
                             FROM auth_sessions
                             WHERE owner_id = ?1 AND profile = ?2
                             ORDER BY created_at_micros, session_id
                             LIMIT 1",
                                params![expected.owner_id.as_slice(), profile.as_str()],
                                |row| read_uuid_blob(row, 0),
                            )
                            .optional()?;
                        let oldest = oldest.ok_or(StoreError::AuthControlPlaneCorrupt)?;
                        if transaction.execute(
                            "DELETE FROM auth_sessions
                         WHERE owner_id = ?1 AND session_id = ?2 AND profile = ?3",
                            params![
                                expected.owner_id.as_slice(),
                                oldest.as_slice(),
                                profile.as_str()
                            ],
                        )? != 1
                        {
                            return Err(StoreError::AuthControlPlaneCorrupt.into());
                        }
                    }
                    let now = to_i64(now_micros)?;
                    if expected.throttle.failure_count() != 0 {
                        let reset = expected
                            .throttle
                            .successful_verification(now_micros)
                            .map_err(|_| StoreError::AuthControlPlaneCorrupt)?;
                        if transaction.execute(
                            "UPDATE auth_authenticator_throttles
                         SET failure_count = 0,
                             next_allowed_at_micros = 0,
                             throttle_revision = ?1,
                             updated_at_micros = ?2
                         WHERE owner_id = ?3
                           AND authenticator = 'password'
                           AND failure_count = ?4
                           AND next_allowed_at_micros = ?5
                           AND throttle_revision = ?6
                           AND updated_at_micros = ?7",
                            params![
                                to_i64(reset.revision())?,
                                now,
                                expected.owner_id.as_slice(),
                                to_i64(expected.throttle.failure_count())?,
                                to_i64(expected.throttle.next_allowed_at_micros())?,
                                to_i64(expected.throttle.revision())?,
                                to_i64(expected.throttle.updated_at_micros())?,
                            ],
                        )? != 1
                        {
                            return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(
                                LoginCommitOutcome::RetryRequired,
                            ));
                        }
                    }
                    let next_admission = expected
                        .admission_revision
                        .checked_add(1)
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    let marker_expires = now_micros
                        .checked_add(LOGIN_ATTEMPT_LIFETIME_MICROS)
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    transaction.execute(
                        "INSERT INTO auth_login_attempt_markers(
                        owner_id, profile, attempt_id, admission_revision,
                        created_at_micros, expires_at_micros
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            expected.owner_id.as_slice(),
                            profile.as_str(),
                            attempt.as_slice(),
                            to_i64(next_admission)?,
                            now,
                            to_i64(marker_expires)?
                        ],
                    )?;
                    update_login_control(&transaction, &expected, next_admission, now_micros)?;
                    transaction.execute(
                        "INSERT INTO auth_sessions(
                        owner_id, session_id, profile, credential_version, created_at_micros
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            expected.owner_id.as_slice(),
                            session.as_slice(),
                            profile.as_str(),
                            to_i64(expected.credential_version)?,
                            now,
                        ],
                    )?;
                    transaction.execute(
                        "INSERT INTO auth_refresh_families(
                        owner_id, family_id, session_id, profile, created_at_micros,
                        last_refreshed_at_micros, idle_deadline_at_micros,
                        absolute_deadline_at_micros
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7)",
                        params![
                            expected.owner_id.as_slice(),
                            family.as_slice(),
                            session.as_slice(),
                            profile.as_str(),
                            now,
                            to_i64(idle)?,
                            to_i64(absolute)?,
                        ],
                    )?;
                    transaction.execute(
                        "INSERT INTO auth_refresh_tokens(
                        owner_id, family_id, token_digest, generation,
                        predecessor_digest, token_state, created_at_micros, consumed_at_micros
                     ) VALUES (?1, ?2, ?3, 0, NULL, 'active', ?4, NULL)",
                        params![
                            expected.owner_id.as_slice(),
                            family.as_slice(),
                            refresh_digest.as_slice(),
                            now,
                        ],
                    )?;
                    transaction.execute(
                        "INSERT INTO auth_login_attempt_outcomes(
                        owner_id, profile, attempt_id, credential_version,
                        outcome_kind, session_id, created_at_micros
                     ) VALUES (?1, ?2, ?3, ?4, 'committed_session', ?5, ?6)",
                        params![
                            expected.owner_id.as_slice(),
                            profile.as_str(),
                            attempt.as_slice(),
                            to_i64(expected.credential_version)?,
                            session.as_slice(),
                            now,
                        ],
                    )?;
                    insert_audit(
                        transaction,
                        expected.owner_id,
                        audit_id,
                        "login_succeeded",
                        Some(profile),
                        Some(session),
                        Some(attempt),
                        now_micros,
                    )?;
                    Ok(AuthRuntimeApplyDecision::Commit)
                },
                move |connection| {
                    let expected = classify_expected.as_ref();
                    let next_admission = expected
                        .admission_revision
                        .checked_add(1)
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    let next_control = expected
                        .control_revision
                        .checked_add(1)
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    let marker_expires = now_micros
                        .checked_add(LOGIN_ATTEMPT_LIFETIME_MICROS)
                        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
                    let (throttle_revision, throttle_updated_at) =
                        if expected.throttle.failure_count() == 0 {
                            (
                                expected.throttle.revision(),
                                expected.throttle.updated_at_micros(),
                            )
                        } else {
                            (
                                expected
                                    .throttle
                                    .revision()
                                    .checked_add(1)
                                    .ok_or(StoreError::AuthControlPlaneCorrupt)?,
                                now_micros,
                            )
                        };
                    let committed: i64 = connection.query_row(
                        "SELECT count(*)
                         FROM auth_login_attempt_markers m
                         JOIN auth_login_attempt_outcomes o
                           ON o.owner_id = m.owner_id
                          AND o.profile = m.profile
                          AND o.attempt_id = m.attempt_id
                         JOIN auth_sessions s
                           ON s.owner_id = m.owner_id AND s.session_id = ?1
                         JOIN auth_refresh_families f
                           ON f.owner_id = s.owner_id AND f.session_id = s.session_id
                         JOIN auth_refresh_tokens t
                           ON t.owner_id = f.owner_id AND t.family_id = f.family_id
                         JOIN auth_authenticator_throttles th
                           ON th.owner_id = m.owner_id AND th.authenticator = 'password'
                         JOIN auth_login_control c
                           ON c.owner_id = m.owner_id AND c.singleton = 1
                         JOIN auth_audit au
                           ON au.owner_id = m.owner_id AND au.audit_id = ?2
                         WHERE m.owner_id = ?3
                           AND m.profile = ?4
                           AND m.attempt_id = ?5
                           AND m.admission_revision = ?6
                           AND m.created_at_micros = ?7
                           AND m.expires_at_micros = ?8
                           AND o.credential_version = ?9
                           AND o.outcome_kind = 'committed_session'
                           AND o.session_id = ?1
                           AND o.created_at_micros = ?7
                           AND s.profile = ?4
                           AND s.credential_version = ?9
                           AND s.created_at_micros = ?7
                           AND f.family_id = ?10
                           AND f.profile = ?4
                           AND f.created_at_micros = ?7
                           AND f.last_refreshed_at_micros = ?7
                           AND f.idle_deadline_at_micros = ?11
                           AND f.absolute_deadline_at_micros = ?12
                           AND t.token_digest = ?13
                           AND t.generation = 0
                           AND t.predecessor_digest IS NULL
                           AND t.token_state = 'active'
                           AND t.created_at_micros = ?7
                           AND t.consumed_at_micros IS NULL
                           AND th.failure_count = 0
                           AND th.next_allowed_at_micros = 0
                           AND th.throttle_revision = ?14
                           AND th.updated_at_micros = ?15
                           AND c.admission_revision = ?6
                           AND c.clock_floor_micros = ?7
                           AND c.control_revision = ?16
                           AND c.updated_at_micros = ?7
                           AND au.action = 'login_succeeded'
                           AND au.profile = ?4
                           AND au.session_id = ?1
                           AND au.attempt_id = ?5
                           AND au.happened_at_micros = ?7",
                        params![
                            session.as_slice(),
                            audit_id.as_slice(),
                            expected.owner_id.as_slice(),
                            profile.as_str(),
                            attempt.as_slice(),
                            to_i64(next_admission)?,
                            to_i64(now_micros)?,
                            to_i64(marker_expires)?,
                            to_i64(expected.credential_version)?,
                            family.as_slice(),
                            to_i64(idle)?,
                            to_i64(absolute)?,
                            refresh_digest.as_slice(),
                            to_i64(throttle_revision)?,
                            to_i64(throttle_updated_at)?,
                            to_i64(next_control)?,
                        ],
                        |row| row.get(0),
                    )?;
                    if committed == 1 {
                        return Ok(AuthRuntimeMutationPostcondition::Committed);
                    }
                    let audit_absent: bool = connection.query_row(
                        "SELECT NOT EXISTS(
                            SELECT 1 FROM auth_audit WHERE audit_id = ?1
                         )",
                        [audit_id.as_slice()],
                        |row| row.get(0),
                    )?;
                    let candidate_absent: bool = connection.query_row(
                        "SELECT
                            NOT EXISTS(
                                SELECT 1 FROM auth_sessions
                                WHERE owner_id = ?1 AND session_id = ?2
                            )
                            AND NOT EXISTS(
                                SELECT 1 FROM auth_refresh_families
                                WHERE owner_id = ?1 AND family_id = ?3
                            )
                            AND NOT EXISTS(
                                SELECT 1 FROM auth_refresh_tokens
                                WHERE owner_id = ?1 AND token_digest = ?4
                            )",
                        params![
                            expected.owner_id.as_slice(),
                            session.as_slice(),
                            family.as_slice(),
                            refresh_digest.as_slice(),
                        ],
                        |row| row.get(0),
                    )?;
                    let marker_absent = classify_existing_login_attempt(
                        connection,
                        expected.owner_id,
                        profile,
                        attempt,
                        expected.credential_version,
                    )?
                    .is_none();
                    if audit_absent
                        && candidate_absent
                        && marker_absent
                        && login_source_matches(connection, expected)?
                    {
                        Ok(AuthRuntimeMutationPostcondition::NotCommitted)
                    } else {
                        Ok(AuthRuntimeMutationPostcondition::Ambiguous)
                    }
                },
            )
            .await
            .map_err(AuthRuntimeError::records)?;
        Ok(match outcome {
            AuthRuntimeMutationOutcome::Committed => LoginCommitOutcome::Committed,
            AuthRuntimeMutationOutcome::ConfirmedNotCommitted => LoginCommitOutcome::RetryRequired,
            AuthRuntimeMutationOutcome::ExpectedNoCommit(outcome) => outcome,
        })
    }

    async fn read_refresh_snapshot(
        &self,
        profile: AuthProfile,
        digest: [u8; 32],
    ) -> Result<Option<RefreshSnapshot>, AuthRuntimeError> {
        self.store
            .call("authentication refresh observation", move |connection| {
                connection
                    .query_row(
                        "SELECT t.owner_id, f.family_id, f.session_id,
                                a.credential_version, t.generation, t.token_state,
                                f.created_at_micros, f.last_refreshed_at_micros,
                                f.idle_deadline_at_micros, f.absolute_deadline_at_micros
                         FROM auth_refresh_tokens t
                         JOIN auth_refresh_families f
                           ON f.owner_id = t.owner_id AND f.family_id = t.family_id
                         JOIN auth_sessions s
                           ON s.owner_id = f.owner_id AND s.session_id = f.session_id
                         JOIN auth_accounts a ON a.owner_id = s.owner_id
                         WHERE t.token_digest = ?1
                           AND f.profile = ?2
                           AND s.profile = ?2
                           AND a.account_state = 'enabled'
                           AND s.credential_version = a.credential_version",
                        params![digest.as_slice(), profile.as_str()],
                        |row| {
                            let token_state: String = row.get(5)?;
                            Ok(RefreshSnapshot {
                                owner_id: read_owner(row, 0)?,
                                family_id: uuid_from_blob(row, 1)?,
                                session_id: uuid_from_blob(row, 2)?,
                                credential_version: read_positive_u64(row, 3)?,
                                generation: read_nonnegative_u64(row, 4)?,
                                token_state: match token_state.as_str() {
                                    "active" => RefreshTokenState::Active,
                                    "consumed" => RefreshTokenState::Consumed,
                                    _ => {
                                        return Err(tokio_rusqlite::rusqlite::Error::InvalidQuery);
                                    }
                                },
                                created_at_micros: read_nonnegative_u64(row, 6)?,
                                last_refreshed_at_micros: read_nonnegative_u64(row, 7)?,
                                idle_deadline_at_micros: read_nonnegative_u64(row, 8)?,
                                absolute_deadline_at_micros: read_nonnegative_u64(row, 9)?,
                            })
                        },
                    )
                    .optional()
                    .map_err(StoreError::Sqlite)
            })
            .await
            .map_err(AuthRuntimeError::store)
    }

    async fn commit_refresh_rotation(
        &self,
        expected: &RefreshSnapshot,
        old_digest: [u8; 32],
        candidate: &RefreshCandidate,
        now_micros: u64,
    ) -> Result<bool, AuthRuntimeError> {
        let expected = *expected;
        let next_digest = candidate.refresh_digest;
        let audit_id = Uuid::new_v4().into_bytes();
        let idle = now_micros
            .checked_add(LOCAL_IDLE_LIFETIME_MICROS)
            .ok_or(AuthRuntimeError::OperationFailed)?
            .min(expected.absolute_deadline_at_micros);
        let outcome = self
            .mutations
            .execute_runtime(
                move |transaction| {
                    if !refresh_source_matches(transaction, &expected, old_digest)? {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(()));
                    }
                    let now = to_i64(now_micros)?;
                    if transaction.execute(
                        "UPDATE auth_refresh_tokens
                     SET token_state = 'consumed', consumed_at_micros = ?1
                     WHERE owner_id = ?2
                       AND family_id = ?3
                       AND token_digest = ?4
                       AND generation = ?5
                       AND token_state = 'active'
                       AND consumed_at_micros IS NULL",
                        params![
                            now,
                            expected.owner_id.as_uuid().as_bytes(),
                            expected.family_id.as_bytes(),
                            old_digest.as_slice(),
                            to_i64(expected.generation)?,
                        ],
                    )? != 1
                    {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(()));
                    }
                    if transaction.execute(
                        "UPDATE auth_refresh_families
                     SET last_refreshed_at_micros = ?1, idle_deadline_at_micros = ?2
                     WHERE owner_id = ?3
                       AND family_id = ?4
                       AND session_id = ?5
                       AND profile = ?6
                       AND last_refreshed_at_micros = ?7
                       AND idle_deadline_at_micros = ?8
                       AND absolute_deadline_at_micros = ?9",
                        params![
                            now,
                            to_i64(idle)?,
                            expected.owner_id.as_uuid().as_bytes(),
                            expected.family_id.as_bytes(),
                            expected.session_id.as_bytes(),
                            expected.profile().as_str(),
                            to_i64(expected.last_refreshed_at_micros)?,
                            to_i64(expected.idle_deadline_at_micros)?,
                            to_i64(expected.absolute_deadline_at_micros)?,
                        ],
                    )? != 1
                    {
                        return Err(StoreError::AuthControlPlaneCorrupt.into());
                    }
                    transaction.execute(
                        "INSERT INTO auth_refresh_tokens(
                        owner_id, family_id, token_digest, generation,
                        predecessor_digest, token_state, created_at_micros, consumed_at_micros
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, NULL)",
                        params![
                            expected.owner_id.as_uuid().as_bytes(),
                            expected.family_id.as_bytes(),
                            next_digest.as_slice(),
                            to_i64(expected.generation + 1)?,
                            old_digest.as_slice(),
                            now,
                        ],
                    )?;
                    insert_audit(
                        transaction,
                        expected.owner_id.as_uuid().into_bytes(),
                        audit_id,
                        "refresh_rotated",
                        Some(expected.profile()),
                        Some(expected.session_id.into_bytes()),
                        None,
                        now_micros,
                    )?;
                    Ok(AuthRuntimeApplyDecision::Commit)
                },
                move |connection| {
                    let committed: i64 = connection.query_row(
                        "SELECT count(*)
                         FROM auth_refresh_tokens old
                         JOIN auth_refresh_families f
                           ON f.owner_id = old.owner_id AND f.family_id = old.family_id
                         JOIN auth_sessions s
                           ON s.owner_id = f.owner_id AND s.session_id = f.session_id
                         JOIN auth_accounts a ON a.owner_id = s.owner_id
                         JOIN auth_refresh_tokens child
                           ON child.owner_id = old.owner_id
                          AND child.family_id = old.family_id
                          AND child.token_digest = ?1
                         JOIN auth_audit au
                           ON au.owner_id = old.owner_id AND au.audit_id = ?2
                         WHERE old.owner_id = ?3
                           AND old.family_id = ?4
                           AND old.token_digest = ?5
                           AND old.generation = ?6
                           AND old.token_state = 'consumed'
                           AND old.consumed_at_micros = ?7
                           AND f.session_id = ?8
                           AND f.profile = ?9
                           AND f.created_at_micros = ?10
                           AND f.last_refreshed_at_micros = ?7
                           AND f.idle_deadline_at_micros = ?11
                           AND f.absolute_deadline_at_micros = ?12
                           AND s.profile = ?9
                           AND s.credential_version = ?13
                           AND a.account_state = 'enabled'
                           AND a.credential_version = ?13
                           AND child.generation = ?14
                           AND child.predecessor_digest = ?5
                           AND child.token_state = 'active'
                           AND child.created_at_micros = ?7
                           AND child.consumed_at_micros IS NULL
                           AND au.action = 'refresh_rotated'
                           AND au.profile = ?9
                           AND au.session_id = ?8
                           AND au.attempt_id IS NULL
                           AND au.happened_at_micros = ?7",
                        params![
                            next_digest.as_slice(),
                            audit_id.as_slice(),
                            expected.owner_id.as_uuid().as_bytes(),
                            expected.family_id.as_bytes(),
                            old_digest.as_slice(),
                            to_i64(expected.generation)?,
                            to_i64(now_micros)?,
                            expected.session_id.as_bytes(),
                            expected.profile().as_str(),
                            to_i64(expected.created_at_micros)?,
                            to_i64(idle)?,
                            to_i64(expected.absolute_deadline_at_micros)?,
                            to_i64(expected.credential_version)?,
                            to_i64(expected.generation + 1)?,
                        ],
                        |row| row.get(0),
                    )?;
                    if committed == 1 {
                        return Ok(AuthRuntimeMutationPostcondition::Committed);
                    }
                    let audit_absent: bool = connection.query_row(
                        "SELECT NOT EXISTS(
                            SELECT 1 FROM auth_audit WHERE audit_id = ?1
                         )",
                        [audit_id.as_slice()],
                        |row| row.get(0),
                    )?;
                    let child_absent: bool = connection.query_row(
                        "SELECT NOT EXISTS(
                            SELECT 1 FROM auth_refresh_tokens
                            WHERE owner_id = ?1 AND token_digest = ?2
                         )",
                        params![
                            expected.owner_id.as_uuid().as_bytes(),
                            next_digest.as_slice(),
                        ],
                        |row| row.get(0),
                    )?;
                    if audit_absent
                        && child_absent
                        && refresh_source_matches(connection, &expected, old_digest)?
                    {
                        Ok(AuthRuntimeMutationPostcondition::NotCommitted)
                    } else {
                        Ok(AuthRuntimeMutationPostcondition::Ambiguous)
                    }
                },
            )
            .await
            .map_err(AuthRuntimeError::records)?;
        Ok(matches!(outcome, AuthRuntimeMutationOutcome::Committed))
    }

    async fn revoke_refresh_replay(
        &self,
        expected: &RefreshSnapshot,
        digest: [u8; 32],
        now_micros: u64,
    ) -> Result<(), AuthRuntimeError> {
        self.revoke_refresh_terminal(*expected, digest, "refresh_replay_revoked", now_micros)
            .await
    }

    async fn revoke_refresh_exhaustion(
        &self,
        expected: &RefreshSnapshot,
        digest: [u8; 32],
        now_micros: u64,
    ) -> Result<(), AuthRuntimeError> {
        self.revoke_refresh_terminal(*expected, digest, "refresh_exhausted", now_micros)
            .await
    }

    async fn revoke_refresh_terminal(
        &self,
        expected: RefreshSnapshot,
        digest: [u8; 32],
        action: &'static str,
        now_micros: u64,
    ) -> Result<(), AuthRuntimeError> {
        let audit_id = Uuid::new_v4().into_bytes();
        let outcome = self
            .mutations
            .execute_runtime(
                move |transaction| {
                    if !refresh_token_exists(transaction, &expected, digest)? {
                        return Ok(AuthRuntimeApplyDecision::ExpectedNoCommit(()));
                    }
                    if transaction.execute(
                        "DELETE FROM auth_sessions
                         WHERE owner_id = ?1 AND session_id = ?2 AND profile = ?3",
                        params![
                            expected.owner_id.as_uuid().as_bytes(),
                            expected.session_id.as_bytes(),
                            expected.profile().as_str(),
                        ],
                    )? != 1
                    {
                        return Err(StoreError::AuthControlPlaneCorrupt.into());
                    }
                    insert_audit(
                        transaction,
                        expected.owner_id.as_uuid().into_bytes(),
                        audit_id,
                        action,
                        Some(expected.profile()),
                        Some(expected.session_id.into_bytes()),
                        None,
                        now_micros,
                    )?;
                    Ok(AuthRuntimeApplyDecision::Commit)
                },
                move |connection| {
                    let audit_matches: i64 = connection.query_row(
                        "SELECT count(*)
                         FROM auth_audit
                         WHERE owner_id = ?1
                           AND audit_id = ?2
                           AND action = ?3
                           AND profile = ?4
                           AND session_id = ?5
                           AND attempt_id IS NULL
                           AND happened_at_micros = ?6",
                        params![
                            expected.owner_id.as_uuid().as_bytes(),
                            audit_id.as_slice(),
                            action,
                            expected.profile().as_str(),
                            expected.session_id.as_bytes(),
                            to_i64(now_micros)?,
                        ],
                        |row| row.get(0),
                    )?;
                    let terminal: bool = connection.query_row(
                        "SELECT
                            NOT EXISTS(
                                SELECT 1 FROM auth_sessions
                                WHERE owner_id = ?1 AND session_id = ?2
                            )
                            AND NOT EXISTS(
                                SELECT 1 FROM auth_refresh_families
                                WHERE owner_id = ?1 AND family_id = ?3
                            )
                            AND NOT EXISTS(
                                SELECT 1 FROM auth_refresh_tokens
                                WHERE owner_id = ?1 AND family_id = ?3
                            )",
                        params![
                            expected.owner_id.as_uuid().as_bytes(),
                            expected.session_id.as_bytes(),
                            expected.family_id.as_bytes(),
                        ],
                        |row| row.get(0),
                    )?;
                    if audit_matches == 1 && terminal {
                        return Ok(AuthRuntimeMutationPostcondition::Committed);
                    }
                    if audit_matches == 0 && refresh_token_exists(connection, &expected, digest)? {
                        Ok(AuthRuntimeMutationPostcondition::NotCommitted)
                    } else {
                        Ok(AuthRuntimeMutationPostcondition::Ambiguous)
                    }
                },
            )
            .await
            .map_err(AuthRuntimeError::records)?;
        match outcome {
            AuthRuntimeMutationOutcome::Committed
            | AuthRuntimeMutationOutcome::ExpectedNoCommit(()) => Ok(()),
            AuthRuntimeMutationOutcome::ConfirmedNotCommitted => {
                Err(AuthRuntimeError::OperationFailed)
            }
        }
    }
}

impl fmt::Debug for AuthRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthRuntime")
            .field("lock", &"[HELD]")
            .field("keyring", &"[REDACTED]")
            .finish()
    }
}

pub struct LoginRequest {
    profile: AuthProfile,
    attempt_id: Uuid,
    login_id: String,
    password: NormalizedPassword,
}

impl LoginRequest {
    pub fn local(
        attempt_id: Uuid,
        login_id: impl Into<String>,
        password: NormalizedPassword,
    ) -> Result<Self, AuthInputError> {
        let login_id = login_id.into();
        if !is_uuid_v4(attempt_id) || LoginId::parse(login_id.as_bytes()).is_err() {
            return Err(AuthInputError);
        }
        Ok(Self {
            profile: AuthProfile::Local,
            attempt_id,
            login_id,
            password,
        })
    }
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoginRequest([REDACTED])")
    }
}

pub enum LoginOutcome {
    Authenticated(IssuedSession),
    GenericFailure,
    Throttled,
    OutcomeUnknown,
    AttemptInvalidated,
    RetryRequired,
}

impl fmt::Debug for LoginOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Authenticated(_) => "LoginOutcome::Authenticated([REDACTED])",
            Self::GenericFailure => "LoginOutcome::GenericFailure",
            Self::Throttled => "LoginOutcome::Throttled",
            Self::OutcomeUnknown => "LoginOutcome::OutcomeUnknown",
            Self::AttemptInvalidated => "LoginOutcome::AttemptInvalidated",
            Self::RetryRequired => "LoginOutcome::RetryRequired",
        })
    }
}

pub struct IssuedSession {
    access_token: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    access_expires_at_seconds: u64,
    refresh_expires_at_seconds: u64,
}

impl IssuedSession {
    pub fn access_token(&self) -> &str {
        self.access_token.as_str()
    }

    pub fn refresh_token(&self) -> &str {
        self.refresh_token.as_str()
    }

    pub const fn access_expires_at_seconds(&self) -> u64 {
        self.access_expires_at_seconds
    }

    pub const fn refresh_expires_at_seconds(&self) -> u64 {
        self.refresh_expires_at_seconds
    }
}

impl fmt::Debug for IssuedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IssuedSession([REDACTED])")
    }
}

pub enum RefreshOutcome {
    Rotated(IssuedSession),
    ReplayRevoked,
    Exhausted,
    Invalid,
}

impl fmt::Debug for RefreshOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Rotated(_) => "RefreshOutcome::Rotated([REDACTED])",
            Self::ReplayRevoked => "RefreshOutcome::ReplayRevoked",
            Self::Exhausted => "RefreshOutcome::Exhausted",
            Self::Invalid => "RefreshOutcome::Invalid",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialMutationOutcome {
    Changed,
    GenericFailure,
    Throttled,
    RetryRequired,
    InvalidSession,
    AlreadyApplied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogoutOutcome {
    Revoked,
    AlreadyTerminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogoutAllOutcome {
    Revoked,
    InvalidSession,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessDenied;

impl fmt::Display for AccessDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("access token is invalid")
    }
}

impl std::error::Error for AccessDenied {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthInputError;

impl fmt::Display for AuthInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("authentication input is invalid")
    }
}

impl std::error::Error for AuthInputError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthRuntimeError {
    InvalidStartupState,
    OperationFailed,
}

impl AuthRuntimeError {
    fn filesystem(_error: SecretFsError) -> Self {
        Self::InvalidStartupState
    }

    fn binding(_error: AuthStoreBindingError) -> Self {
        Self::InvalidStartupState
    }

    fn store(_error: StoreError) -> Self {
        Self::OperationFailed
    }

    fn records(_error: AuthRecordsError) -> Self {
        Self::OperationFailed
    }

    fn throttle(_error: ThrottleMathError) -> Self {
        Self::OperationFailed
    }
}

impl fmt::Display for AuthRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidStartupState => "authentication startup state is invalid",
            Self::OperationFailed => "authentication operation failed",
        })
    }
}

impl std::error::Error for AuthRuntimeError {}

struct LoginSnapshot {
    expected: LoginExpected,
    verifier: ValidatedVerifier,
    replay: LoginReplay,
}

struct LoginSource {
    expected: LoginExpected,
    verifier: ValidatedVerifier,
}

struct RecoverySnapshot {
    source: RecoverySource,
    verifier: ValidatedVerifier,
}

struct RecoverySource {
    owner_id: [u8; 16],
    account_enabled: bool,
    credential_version: u64,
    account_revision: u64,
    password_phc: SecretBytes,
    password_enabled: bool,
    password_revision: u64,
    recovery_phc: SecretBytes,
    recovery_revision: u64,
    password_throttle: ThrottleState,
    recovery_throttle: ThrottleState,
}

struct LoginExpected {
    owner_id: [u8; 16],
    requested_login: String,
    stored_login: String,
    login_matches: bool,
    account_enabled: bool,
    credential_version: u64,
    account_revision: u64,
    password_phc: SecretBytes,
    password_enabled: bool,
    password_revision: u64,
    throttle: ThrottleState,
    admission_revision: u64,
    control_revision: u64,
}

impl fmt::Debug for LoginExpected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoginExpected([REDACTED])")
    }
}

#[derive(Clone, Copy)]
enum LoginReplay {
    None,
    GenericFailure,
    OutcomeUnknown,
    AttemptInvalidated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoginCommitOutcome {
    Committed,
    GenericFailureReplay,
    OutcomeUnknown,
    AttemptInvalidated,
    RetryRequired,
    RateLimited,
}

struct SessionCandidate {
    session_id: Uuid,
    family_id: Uuid,
    refresh_token: Zeroizing<String>,
    refresh_digest: [u8; 32],
    access_token: IssuedAccessToken,
    refresh_expires_at_seconds: u64,
}

impl SessionCandidate {
    fn generate(
        keyring: &super::keyring::Keyring,
        profile: AuthProfile,
        owner_id: [u8; 16],
        credential_version: u64,
        now_micros: u64,
    ) -> Result<Self, AuthRuntimeError> {
        let session_id = Uuid::new_v4();
        let family_id = Uuid::new_v4();
        let jti = Uuid::new_v4();
        let (refresh_token, refresh_digest) = generate_refresh_token()?;
        let owner_id = OwnerId::from_verified_uuid(Uuid::from_bytes(owner_id));
        let access_token = issue_access_token(
            keyring,
            profile,
            owner_id,
            session_id,
            jti,
            credential_version,
            now_micros,
        )
        .map_err(|_| AuthRuntimeError::OperationFailed)?;
        let absolute_deadline_at_micros = now_micros
            .checked_add(LOCAL_ABSOLUTE_LIFETIME_MICROS)
            .ok_or(AuthRuntimeError::OperationFailed)?;
        let refresh_expires_at_seconds = now_micros
            .checked_add(LOCAL_IDLE_LIFETIME_MICROS)
            .map(|value| value.min(absolute_deadline_at_micros))
            .map(|value| value / 1_000_000)
            .ok_or(AuthRuntimeError::OperationFailed)?;
        Ok(Self {
            session_id,
            family_id,
            refresh_token,
            refresh_digest,
            access_token,
            refresh_expires_at_seconds,
        })
    }

    fn into_issued(self) -> IssuedSession {
        IssuedSession {
            access_token: Zeroizing::new(self.access_token.as_str().to_owned()),
            refresh_token: self.refresh_token,
            access_expires_at_seconds: self.access_token.expires_at_seconds(),
            refresh_expires_at_seconds: self.refresh_expires_at_seconds,
        }
    }
}

#[derive(Clone, Copy)]
struct RefreshSnapshot {
    owner_id: OwnerId,
    family_id: Uuid,
    session_id: Uuid,
    credential_version: u64,
    generation: u64,
    token_state: RefreshTokenState,
    created_at_micros: u64,
    last_refreshed_at_micros: u64,
    idle_deadline_at_micros: u64,
    absolute_deadline_at_micros: u64,
}

impl RefreshSnapshot {
    const fn profile(self) -> AuthProfile {
        AuthProfile::Local
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RefreshTokenState {
    Active,
    Consumed,
}

struct RefreshCandidate {
    refresh_token: Zeroizing<String>,
    refresh_digest: [u8; 32],
    access_token: IssuedAccessToken,
    refresh_expires_at_seconds: u64,
}

impl RefreshCandidate {
    fn generate(
        keyring: &super::keyring::Keyring,
        profile: AuthProfile,
        owner_id: OwnerId,
        session_id: Uuid,
        credential_version: u64,
        absolute_deadline_at_micros: u64,
        now_micros: u64,
    ) -> Result<Self, AuthRuntimeError> {
        let (refresh_token, refresh_digest) = generate_refresh_token()?;
        let access_token = issue_access_token(
            keyring,
            profile,
            owner_id,
            session_id,
            Uuid::new_v4(),
            credential_version,
            now_micros,
        )
        .map_err(|_| AuthRuntimeError::OperationFailed)?;
        Ok(Self {
            refresh_token,
            refresh_digest,
            access_token,
            refresh_expires_at_seconds: now_micros
                .checked_add(LOCAL_IDLE_LIFETIME_MICROS)
                .ok_or(AuthRuntimeError::OperationFailed)?
                .min(absolute_deadline_at_micros)
                / 1_000_000,
        })
    }

    fn into_issued(self) -> IssuedSession {
        IssuedSession {
            access_token: Zeroizing::new(self.access_token.as_str().to_owned()),
            refresh_token: self.refresh_token,
            access_expires_at_seconds: self.access_token.expires_at_seconds(),
            refresh_expires_at_seconds: self.refresh_expires_at_seconds,
        }
    }
}

fn read_login_source(
    connection: &RawConnection,
    requested_login: &str,
) -> Result<LoginSource, StoreError> {
    let row = connection.query_row(
        "SELECT a.owner_id, a.login_id, a.account_state, a.credential_version,
                a.account_revision, p.verifier_phc, p.authenticator_state,
                p.credential_revision, t.failure_count, t.next_allowed_at_micros,
                t.throttle_revision, t.updated_at_micros,
                c.admission_revision, c.control_revision
         FROM auth_accounts a
         JOIN auth_password_credentials p
           ON p.singleton = 1 AND p.owner_id = a.owner_id
         JOIN auth_authenticator_throttles t
           ON t.owner_id = a.owner_id AND t.authenticator = 'password'
         JOIN auth_login_control c
           ON c.singleton = 1 AND c.owner_id = a.owner_id
         JOIN auth_key_lifecycle k ON k.singleton = 1
         WHERE a.singleton = 1
           AND k.state = 'active'
           AND k.transition_kind IS NULL
           AND k.transition_id IS NULL",
        [],
        |row| {
            Ok((
                read_uuid_blob(row, 0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                read_positive_u64(row, 3)?,
                read_positive_u64(row, 4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                read_positive_u64(row, 7)?,
                read_nonnegative_u64(row, 8)?,
                read_nonnegative_u64(row, 9)?,
                read_positive_u64(row, 10)?,
                read_nonnegative_u64(row, 11)?,
                read_positive_u64(row, 12)?,
                read_positive_u64(row, 13)?,
            ))
        },
    )?;
    let (
        owner_id,
        stored_login,
        account_state,
        credential_version,
        account_revision,
        password_phc,
        password_state,
        password_revision,
        failure_count,
        next_allowed_at_micros,
        throttle_revision,
        throttle_updated_at_micros,
        admission_revision,
        control_revision,
    ) = row;
    if !is_uuid_v4(Uuid::from_bytes(owner_id))
        || LoginId::parse(stored_login.as_bytes()).is_err()
        || !matches!(account_state.as_str(), "enabled" | "disabled")
        || !matches!(password_state.as_str(), "enabled" | "disabled")
    {
        return Err(StoreError::AuthControlPlaneCorrupt);
    }
    let verifier = ValidatedVerifier::parse(SecretBytes::new(password_phc.as_bytes().to_vec()))
        .map_err(|_| StoreError::AuthControlPlaneCorrupt)?;
    let throttle = ThrottleState::new(
        AuthenticatorKind::Password,
        failure_count,
        next_allowed_at_micros,
        throttle_revision,
        throttle_updated_at_micros,
    )
    .map_err(|_| StoreError::AuthControlPlaneCorrupt)?;
    Ok(LoginSource {
        expected: LoginExpected {
            owner_id,
            requested_login: requested_login.to_owned(),
            login_matches: requested_login == stored_login,
            stored_login,
            account_enabled: account_state == "enabled",
            credential_version,
            account_revision,
            password_phc: SecretBytes::new(password_phc.into_bytes()),
            password_enabled: password_state == "enabled",
            password_revision,
            throttle,
            admission_revision,
            control_revision,
        },
        verifier,
    })
}

fn read_recovery_source(connection: &RawConnection) -> Result<RecoverySnapshot, StoreError> {
    let row = connection.query_row(
        "SELECT a.owner_id, a.account_state, a.credential_version, a.account_revision,
                p.verifier_phc, p.authenticator_state, p.credential_revision,
                r.verifier_phc, r.credential_revision,
                pt.failure_count, pt.next_allowed_at_micros,
                pt.throttle_revision, pt.updated_at_micros,
                rt.failure_count, rt.next_allowed_at_micros,
                rt.throttle_revision, rt.updated_at_micros
         FROM auth_accounts a
         JOIN auth_password_credentials p
           ON p.singleton = 1 AND p.owner_id = a.owner_id
         JOIN auth_recovery_credentials r
           ON r.singleton = 1 AND r.owner_id = a.owner_id
         JOIN auth_authenticator_throttles pt
           ON pt.owner_id = a.owner_id AND pt.authenticator = 'password'
         JOIN auth_authenticator_throttles rt
           ON rt.owner_id = a.owner_id AND rt.authenticator = 'recovery'
         JOIN auth_key_lifecycle k ON k.singleton = 1
         WHERE a.singleton = 1
           AND k.state = 'active'
           AND k.transition_kind IS NULL
           AND k.transition_id IS NULL",
        [],
        |row| {
            Ok((
                read_uuid_blob(row, 0)?,
                row.get::<_, String>(1)?,
                read_positive_u64(row, 2)?,
                read_positive_u64(row, 3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                read_positive_u64(row, 6)?,
                row.get::<_, String>(7)?,
                read_positive_u64(row, 8)?,
                read_nonnegative_u64(row, 9)?,
                read_nonnegative_u64(row, 10)?,
                read_positive_u64(row, 11)?,
                read_nonnegative_u64(row, 12)?,
                read_nonnegative_u64(row, 13)?,
                read_nonnegative_u64(row, 14)?,
                read_positive_u64(row, 15)?,
                read_nonnegative_u64(row, 16)?,
            ))
        },
    )?;
    let (
        owner_id,
        account_state,
        credential_version,
        account_revision,
        password_phc,
        password_state,
        password_revision,
        recovery_phc,
        recovery_revision,
        password_failure_count,
        password_next_allowed,
        password_throttle_revision,
        password_throttle_updated,
        recovery_failure_count,
        recovery_next_allowed,
        recovery_throttle_revision,
        recovery_throttle_updated,
    ) = row;
    if !is_uuid_v4(Uuid::from_bytes(owner_id))
        || !matches!(account_state.as_str(), "enabled" | "disabled")
        || !matches!(password_state.as_str(), "enabled" | "disabled")
    {
        return Err(StoreError::AuthControlPlaneCorrupt);
    }
    let _password_verifier =
        ValidatedVerifier::parse(SecretBytes::new(password_phc.as_bytes().to_vec()))
            .map_err(|_| StoreError::AuthControlPlaneCorrupt)?;
    let verifier = ValidatedVerifier::parse(SecretBytes::new(recovery_phc.as_bytes().to_vec()))
        .map_err(|_| StoreError::AuthControlPlaneCorrupt)?;
    let password_throttle = ThrottleState::new(
        AuthenticatorKind::Password,
        password_failure_count,
        password_next_allowed,
        password_throttle_revision,
        password_throttle_updated,
    )
    .map_err(|_| StoreError::AuthControlPlaneCorrupt)?;
    let recovery_throttle = ThrottleState::new(
        AuthenticatorKind::Recovery,
        recovery_failure_count,
        recovery_next_allowed,
        recovery_throttle_revision,
        recovery_throttle_updated,
    )
    .map_err(|_| StoreError::AuthControlPlaneCorrupt)?;
    Ok(RecoverySnapshot {
        source: RecoverySource {
            owner_id,
            account_enabled: account_state == "enabled",
            credential_version,
            account_revision,
            password_phc: SecretBytes::new(password_phc.into_bytes()),
            password_enabled: password_state == "enabled",
            password_revision,
            recovery_phc: SecretBytes::new(recovery_phc.into_bytes()),
            recovery_revision,
            password_throttle,
            recovery_throttle,
        },
        verifier,
    })
}

fn recovery_source_matches(
    connection: &RawConnection,
    expected: &RecoverySource,
) -> Result<bool, StoreError> {
    let current = read_recovery_source(connection)?.source;
    Ok(current.owner_id == expected.owner_id
        && current.account_enabled == expected.account_enabled
        && current.credential_version == expected.credential_version
        && current.account_revision == expected.account_revision
        && current.password_phc.expose_secret() == expected.password_phc.expose_secret()
        && current.password_enabled == expected.password_enabled
        && current.password_revision == expected.password_revision
        && current.recovery_phc.expose_secret() == expected.recovery_phc.expose_secret()
        && current.recovery_revision == expected.recovery_revision
        && current.password_throttle == expected.password_throttle
        && current.recovery_throttle == expected.recovery_throttle)
}

fn recovery_source_matches_login(source: &RecoverySource, expected: &LoginExpected) -> bool {
    source.owner_id == expected.owner_id
        && source.account_enabled == expected.account_enabled
        && source.credential_version == expected.credential_version
        && source.account_revision == expected.account_revision
        && source.password_phc.expose_secret() == expected.password_phc.expose_secret()
        && source.password_enabled == expected.password_enabled
        && source.password_revision == expected.password_revision
        && source.password_throttle == expected.throttle
}

fn read_login_replay(
    connection: &RawConnection,
    owner_id: [u8; 16],
    profile: AuthProfile,
    attempt_id: [u8; 16],
    credential_version: u64,
) -> Result<LoginReplay, StoreError> {
    Ok(
        match classify_existing_login_attempt(
            connection,
            owner_id,
            profile,
            attempt_id,
            credential_version,
        )? {
            None => LoginReplay::None,
            Some(LoginCommitOutcome::GenericFailureReplay) => LoginReplay::GenericFailure,
            Some(LoginCommitOutcome::OutcomeUnknown) => LoginReplay::OutcomeUnknown,
            Some(LoginCommitOutcome::AttemptInvalidated) => LoginReplay::AttemptInvalidated,
            Some(_) => return Err(StoreError::AuthControlPlaneCorrupt),
        },
    )
}

fn classify_existing_login_attempt(
    connection: &RawConnection,
    owner_id: [u8; 16],
    profile: AuthProfile,
    attempt_id: [u8; 16],
    credential_version: u64,
) -> Result<Option<LoginCommitOutcome>, StoreError> {
    let marker: Option<(Option<u64>, Option<String>)> = connection
        .query_row(
            "SELECT o.credential_version, o.outcome_kind
             FROM auth_login_attempt_markers m
             LEFT JOIN auth_login_attempt_outcomes o
               ON o.owner_id = m.owner_id
              AND o.profile = m.profile
              AND o.attempt_id = m.attempt_id
             WHERE m.owner_id = ?1 AND m.profile = ?2 AND m.attempt_id = ?3",
            params![owner_id.as_slice(), profile.as_str(), attempt_id.as_slice()],
            |row| {
                let version = row
                    .get::<_, Option<i64>>(0)?
                    .map(|value| {
                        u64::try_from(value)
                            .ok()
                            .filter(|value| *value > 0)
                            .ok_or(tokio_rusqlite::rusqlite::Error::InvalidQuery)
                    })
                    .transpose()?;
                Ok((version, row.get(1)?))
            },
        )
        .optional()?;
    Ok(
        marker.map(|(version, kind)| match (version, kind.as_deref()) {
            (Some(version), Some("generic_failure")) if version == credential_version => {
                LoginCommitOutcome::GenericFailureReplay
            }
            (Some(version), Some("committed_session")) if version == credential_version => {
                LoginCommitOutcome::OutcomeUnknown
            }
            _ => LoginCommitOutcome::AttemptInvalidated,
        }),
    )
}

fn login_source_matches(
    connection: &RawConnection,
    expected: &LoginExpected,
) -> Result<bool, StoreError> {
    let current = read_login_source(connection, expected.requested_login.as_str())?;
    Ok(current.expected.owner_id == expected.owner_id
        && current.expected.stored_login == expected.stored_login
        && current.expected.login_matches == expected.login_matches
        && current.expected.account_enabled == expected.account_enabled
        && current.expected.credential_version == expected.credential_version
        && current.expected.account_revision == expected.account_revision
        && current.expected.password_phc.expose_secret() == expected.password_phc.expose_secret()
        && current.expected.password_enabled == expected.password_enabled
        && current.expected.password_revision == expected.password_revision
        && current.expected.throttle == expected.throttle
        && current.expected.admission_revision == expected.admission_revision
        && current.expected.control_revision == expected.control_revision)
}

fn password_failure_post_matches(
    connection: &RawConnection,
    expected: &LoginExpected,
    next_throttle: ThrottleState,
    disable_password: bool,
) -> Result<bool, StoreError> {
    let current = read_login_source(connection, expected.stored_login.as_str())?;
    let expected_password_revision = expected
        .password_revision
        .checked_add(u64::from(disable_password))
        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
    Ok(current.expected.owner_id == expected.owner_id
        && current.expected.stored_login == expected.stored_login
        && current.expected.login_matches
        && current.expected.account_enabled == expected.account_enabled
        && current.expected.credential_version == expected.credential_version
        && current.expected.account_revision == expected.account_revision
        && current.expected.password_phc.expose_secret() == expected.password_phc.expose_secret()
        && current.expected.password_enabled == (expected.password_enabled && !disable_password)
        && current.expected.password_revision == expected_password_revision
        && current.expected.throttle == next_throttle
        && current.expected.admission_revision == expected.admission_revision
        && current.expected.control_revision == expected.control_revision)
}

fn update_login_control(
    transaction: &Transaction<'_>,
    expected: &LoginExpected,
    next_admission: u64,
    now_micros: u64,
) -> Result<(), StoreError> {
    let next_control = expected
        .control_revision
        .checked_add(1)
        .ok_or(StoreError::AuthControlPlaneCorrupt)?;
    if transaction.execute(
        "UPDATE auth_login_control
         SET admission_revision = ?1,
             clock_floor_micros = ?2,
             control_revision = ?3,
             updated_at_micros = ?2
         WHERE owner_id = ?4
           AND admission_revision = ?5
           AND control_revision = ?6
           AND clock_floor_micros <= ?2
           AND updated_at_micros <= ?2",
        params![
            to_i64(next_admission)?,
            to_i64(now_micros)?,
            to_i64(next_control)?,
            expected.owner_id.as_slice(),
            to_i64(expected.admission_revision)?,
            to_i64(expected.control_revision)?,
        ],
    )? != 1
    {
        return Err(StoreError::AuthControlPlaneCorrupt);
    }
    Ok(())
}

fn marker_count(
    connection: &RawConnection,
    owner_id: [u8; 16],
    profile: AuthProfile,
) -> Result<u64, StoreError> {
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM auth_login_attempt_markers
         WHERE owner_id = ?1 AND profile = ?2",
        params![owner_id.as_slice(), profile.as_str()],
        |row| row.get(0),
    )?;
    u64::try_from(count).map_err(|_| StoreError::AuthControlPlaneCorrupt)
}

fn refresh_source_matches(
    connection: &RawConnection,
    expected: &RefreshSnapshot,
    digest: [u8; 32],
) -> Result<bool, StoreError> {
    Ok(
        read_refresh_for_match(connection, expected.profile(), digest)?.is_some_and(|current| {
            current.owner_id == expected.owner_id
                && current.family_id == expected.family_id
                && current.session_id == expected.session_id
                && current.credential_version == expected.credential_version
                && current.generation == expected.generation
                && current.token_state == expected.token_state
                && current.created_at_micros == expected.created_at_micros
                && current.last_refreshed_at_micros == expected.last_refreshed_at_micros
                && current.idle_deadline_at_micros == expected.idle_deadline_at_micros
                && current.absolute_deadline_at_micros == expected.absolute_deadline_at_micros
        }),
    )
}

fn refresh_token_exists(
    connection: &RawConnection,
    expected: &RefreshSnapshot,
    digest: [u8; 32],
) -> Result<bool, StoreError> {
    Ok(read_refresh_for_match(connection, expected.profile(), digest)?.is_some())
}

fn read_refresh_for_match(
    connection: &RawConnection,
    profile: AuthProfile,
    digest: [u8; 32],
) -> Result<Option<RefreshSnapshot>, StoreError> {
    connection
        .query_row(
            "SELECT t.owner_id, f.family_id, f.session_id,
                    a.credential_version, t.generation, t.token_state,
                    f.created_at_micros, f.last_refreshed_at_micros,
                    f.idle_deadline_at_micros, f.absolute_deadline_at_micros
             FROM auth_refresh_tokens t
             JOIN auth_refresh_families f
               ON f.owner_id = t.owner_id AND f.family_id = t.family_id
             JOIN auth_sessions s
               ON s.owner_id = f.owner_id AND s.session_id = f.session_id
             JOIN auth_accounts a ON a.owner_id = s.owner_id
             WHERE t.token_digest = ?1
               AND f.profile = ?2
               AND s.profile = ?2
               AND a.account_state = 'enabled'
               AND s.credential_version = a.credential_version",
            params![digest.as_slice(), profile.as_str()],
            |row| {
                let state: String = row.get(5)?;
                Ok(RefreshSnapshot {
                    owner_id: read_owner(row, 0)?,
                    family_id: uuid_from_blob(row, 1)?,
                    session_id: uuid_from_blob(row, 2)?,
                    credential_version: read_positive_u64(row, 3)?,
                    generation: read_nonnegative_u64(row, 4)?,
                    token_state: match state.as_str() {
                        "active" => RefreshTokenState::Active,
                        "consumed" => RefreshTokenState::Consumed,
                        _ => return Err(tokio_rusqlite::rusqlite::Error::InvalidQuery),
                    },
                    created_at_micros: read_nonnegative_u64(row, 6)?,
                    last_refreshed_at_micros: read_nonnegative_u64(row, 7)?,
                    idle_deadline_at_micros: read_nonnegative_u64(row, 8)?,
                    absolute_deadline_at_micros: read_nonnegative_u64(row, 9)?,
                })
            },
        )
        .optional()
        .map_err(StoreError::Sqlite)
}

fn update_throttle_to_reset(
    transaction: &Transaction<'_>,
    owner_id: [u8; 16],
    previous: ThrottleState,
    reset: ThrottleState,
) -> Result<(), StoreError> {
    let authenticator = match previous.authenticator() {
        AuthenticatorKind::Password => "password",
        AuthenticatorKind::Recovery => "recovery",
    };
    if reset.failure_count() != 0
        || reset.next_allowed_at_micros() != 0
        || reset.authenticator() != previous.authenticator()
        || transaction.execute(
            "UPDATE auth_authenticator_throttles
             SET failure_count = 0,
                 next_allowed_at_micros = 0,
                 throttle_revision = ?1,
                 updated_at_micros = ?2
             WHERE owner_id = ?3
               AND authenticator = ?4
               AND failure_count = ?5
               AND next_allowed_at_micros = ?6
               AND throttle_revision = ?7
               AND updated_at_micros = ?8",
            params![
                to_i64(reset.revision())?,
                to_i64(reset.updated_at_micros())?,
                owner_id.as_slice(),
                authenticator,
                to_i64(previous.failure_count())?,
                to_i64(previous.next_allowed_at_micros())?,
                to_i64(previous.revision())?,
                to_i64(previous.updated_at_micros())?,
            ],
        )? != 1
    {
        return Err(StoreError::AuthControlPlaneCorrupt);
    }
    Ok(())
}

fn expected_success_reset(
    state: ThrottleState,
    now_micros: u64,
) -> Result<ThrottleState, StoreError> {
    if state.failure_count() == 0 {
        Ok(state)
    } else {
        state
            .successful_verification(now_micros)
            .map_err(|_| StoreError::AuthControlPlaneCorrupt)
    }
}

fn expected_password_recovery_reset(
    state: ThrottleState,
    now_micros: u64,
) -> Result<ThrottleState, StoreError> {
    if state.failure_count() == 0 {
        Ok(state)
    } else {
        state
            .reset_after_recovery(now_micros)
            .map_err(|_| StoreError::AuthControlPlaneCorrupt)
    }
}

fn exact_account_audit(
    connection: &RawConnection,
    owner_id: [u8; 16],
    audit_id: [u8; 16],
    action: &'static str,
    now_micros: u64,
) -> Result<bool, StoreError> {
    let count: i64 = connection.query_row(
        "SELECT count(*)
         FROM auth_audit
         WHERE owner_id = ?1
           AND audit_id = ?2
           AND action = ?3
           AND profile IS NULL
           AND session_id IS NULL
           AND attempt_id IS NULL
           AND happened_at_micros = ?4",
        params![
            owner_id.as_slice(),
            audit_id.as_slice(),
            action,
            to_i64(now_micros)?,
        ],
        |row| row.get(0),
    )?;
    Ok(count == 1)
}

fn audit_id_exists(connection: &RawConnection, audit_id: [u8; 16]) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM auth_audit WHERE audit_id = ?1)",
            [audit_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(StoreError::Sqlite)
}

fn no_owner_sessions_or_outcomes(
    connection: &RawConnection,
    owner_id: [u8; 16],
) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT
                NOT EXISTS(
                    SELECT 1 FROM auth_sessions WHERE owner_id = ?1
                )
                AND NOT EXISTS(
                    SELECT 1 FROM auth_login_attempt_outcomes WHERE owner_id = ?1
                )",
            [owner_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(StoreError::Sqlite)
}

fn insert_audit(
    transaction: &Transaction<'_>,
    owner_id: [u8; 16],
    audit_id: [u8; 16],
    action: &'static str,
    profile: Option<AuthProfile>,
    session_id: Option<[u8; 16]>,
    attempt_id: Option<[u8; 16]>,
    now_micros: u64,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO auth_audit(
            owner_id, audit_id, action, profile, session_id, attempt_id, happened_at_micros
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            owner_id.as_slice(),
            audit_id.as_slice(),
            action,
            profile.map(AuthProfile::as_str),
            session_id.as_ref().map(<[u8; 16]>::as_slice),
            attempt_id.as_ref().map(<[u8; 16]>::as_slice),
            to_i64(now_micros)?,
        ],
    )?;
    Ok(())
}

fn generate_refresh_token() -> Result<(Zeroizing<String>, [u8; 32]), AuthRuntimeError> {
    let mut raw = Zeroizing::new([0_u8; 32]);
    getrandom::fill(raw.as_mut()).map_err(|_| AuthRuntimeError::OperationFailed)?;
    let encoded = Zeroizing::new(Base64UrlUnpadded::encode_string(raw.as_ref()));
    let digest: [u8; 32] = Sha256::digest(raw.as_ref()).into();
    Ok((encoded, digest))
}

fn parse_refresh_digest(token: &SecretBytes) -> Result<[u8; 32], AuthRuntimeError> {
    let text = std::str::from_utf8(token.expose_secret())
        .map_err(|_| AuthRuntimeError::OperationFailed)?;
    let decoded =
        Base64UrlUnpadded::decode_vec(text).map_err(|_| AuthRuntimeError::OperationFailed)?;
    if decoded.len() != 32
        || Base64UrlUnpadded::encode_string(&decoded).as_bytes() != token.expose_secret()
    {
        return Err(AuthRuntimeError::OperationFailed);
    }
    Ok(Sha256::digest(decoded).into())
}

fn validate_now(now_micros: u64) -> Result<(), AuthRuntimeError> {
    if now_micros > i64::MAX as u64 {
        Err(AuthRuntimeError::OperationFailed)
    } else {
        Ok(())
    }
}

fn to_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::AuthControlPlaneCorrupt)
}

fn read_uuid_blob(
    row: &tokio_rusqlite::rusqlite::Row<'_>,
    index: usize,
) -> tokio_rusqlite::rusqlite::Result<[u8; 16]> {
    let value: Vec<u8> = row.get(index)?;
    value
        .try_into()
        .map_err(|_| tokio_rusqlite::rusqlite::Error::InvalidQuery)
}

fn uuid_from_blob(
    row: &tokio_rusqlite::rusqlite::Row<'_>,
    index: usize,
) -> tokio_rusqlite::rusqlite::Result<Uuid> {
    let value = Uuid::from_bytes(read_uuid_blob(row, index)?);
    if !is_uuid_v4(value) {
        return Err(tokio_rusqlite::rusqlite::Error::InvalidQuery);
    }
    Ok(value)
}

fn read_owner(
    row: &tokio_rusqlite::rusqlite::Row<'_>,
    index: usize,
) -> tokio_rusqlite::rusqlite::Result<OwnerId> {
    Ok(OwnerId::from_verified_uuid(uuid_from_blob(row, index)?))
}

fn read_positive_u64(
    row: &tokio_rusqlite::rusqlite::Row<'_>,
    index: usize,
) -> tokio_rusqlite::rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(tokio_rusqlite::rusqlite::Error::InvalidQuery)
}

fn read_nonnegative_u64(
    row: &tokio_rusqlite::rusqlite::Row<'_>,
    index: usize,
) -> tokio_rusqlite::rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| tokio_rusqlite::rusqlite::Error::InvalidQuery)
}

fn is_uuid_v4(value: Uuid) -> bool {
    matches!(value.get_version(), Some(uuid::Version::Random))
        && matches!(value.get_variant(), uuid::Variant::RFC4122)
}

impl From<JwtError> for AuthRuntimeError {
    fn from(_error: JwtError) -> Self {
        Self::OperationFailed
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{
        AccessDenied, AuthRuntime, AuthRuntimeError, LoginOutcome, LoginRequest, LogoutAllOutcome,
        LogoutOutcome, RefreshOutcome, to_i64,
    };
    use crate::{
        auth::{
            NormalizedPassword, RecoveryCode, SecretBytes, hash_password, hash_recovery_code,
            keyring::Keyring,
            maintenance::AuthMaintenanceActor,
            secret_fs::{
                AuthInitializationActiveKeyInstallOutcome, AuthInitializationCleanupOutcome,
                AuthInitializationFinalLifecycleOutcome, AuthInitializationPrepareOutcome,
                AuthInitializationSourceOutcome, AuthInstanceLayout,
            },
            transition::{
                AuditId, AuthOwnerId, InitializationMetadataInput, InitializationPreparationV1,
                LoginId, SourceTimestampMicros, TransitionId,
            },
        },
        storage::StoreSet,
    };
    use tokio_rusqlite::rusqlite::{TransactionBehavior, params};
    use uuid::Uuid;

    const NOW_MICROS: u64 = 1_700_000_000_000_000;
    const OWNER: &str = "33333333-3333-4333-8333-333333333333";
    const TRANSITION: &str = "11111111-1111-4111-8111-111111111111";
    const AUDIT: &str = "22222222-2222-4222-8222-222222222222";
    const PASSWORD: &[u8] = b"correct horse battery staple";
    const WRONG_PASSWORD: &[u8] = b"wrong horse battery staple";
    const NEW_PASSWORD: &[u8] = b"correct horse changed staple";
    const RECOVERY_CODE: &[u8] = b"povrec1_AAECAwQFBgcICQoLDA0ODw";
    const REPLACEMENT_CODE: &[u8] = b"povrec1_EBESExQVFhcYGRobHB0eHw";
    const SECOND_REPLACEMENT_CODE: &[u8] = b"povrec1_ICEiIyQlJicoKSorLC0uLw";

    fn password(raw: &[u8]) -> NormalizedPassword {
        NormalizedPassword::parse(SecretBytes::new(raw.to_vec())).expect("test password")
    }

    fn recovery_code(raw: &[u8]) -> RecoveryCode {
        RecoveryCode::parse(SecretBytes::new(raw.to_vec())).expect("test recovery code")
    }

    async fn initialized_fixture(root: &std::path::Path) -> (StoreSet, crate::identity::OwnerId) {
        let layout = AuthInstanceLayout::open_or_create(root).expect("instance layout");
        let stores = StoreSet::open(root.join("stores"))
            .await
            .expect("fixture stores");
        let context = layout
            .lock()
            .expect("maintenance lock")
            .bind_conversation(&stores.conversation)
            .expect("bound conversation");
        let actor = AuthMaintenanceActor::start(context).expect("maintenance actor");
        let password_verifier = hash_password(&password(PASSWORD))
            .await
            .expect("password verifier");
        let recovery_verifier = hash_recovery_code(&recovery_code(RECOVERY_CODE))
            .await
            .expect("recovery verifier");
        let keyring =
            Keyring::from_test_seeds(1, NOW_MICROS - 1, [0x31; 32], None).expect("keyring");
        let owner_uuid = Uuid::parse_str(OWNER).expect("owner UUID");
        let preparation = InitializationPreparationV1::from_keyring(
            InitializationMetadataInput {
                transition_id: TransitionId::from_uuid(
                    Uuid::parse_str(TRANSITION).expect("transition UUID"),
                )
                .expect("transition ID"),
                owner_id: AuthOwnerId::from_uuid(owner_uuid).expect("owner ID"),
                audit_id: AuditId::from_uuid(Uuid::parse_str(AUDIT).expect("audit UUID"))
                    .expect("audit ID"),
                source_at_micros: SourceTimestampMicros::new(NOW_MICROS).expect("source timestamp"),
                login_id: LoginId::parse(b"owner_01").expect("login ID"),
                password_verifier,
                recovery_verifier,
            },
            &keyring,
        )
        .expect("initialization preparation");
        assert_eq!(
            actor
                .prepare_initialization(preparation)
                .await
                .expect("prepare initialization"),
            AuthInitializationPrepareOutcome::Prepared
        );
        assert_eq!(
            actor
                .commit_initialization_source()
                .await
                .expect("commit initialization source"),
            AuthInitializationSourceOutcome::Committed
        );
        assert_eq!(
            actor
                .install_initialization_active_key()
                .await
                .expect("install active key"),
            AuthInitializationActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas
        );
        assert_eq!(
            actor
                .commit_initialization_final_lifecycle()
                .await
                .expect("activate lifecycle"),
            AuthInitializationFinalLifecycleOutcome::ActivatedAwaitingCleanup
        );
        assert_eq!(
            actor
                .cleanup_initialization()
                .await
                .expect("cleanup initialization"),
            AuthInitializationCleanupOutcome::Completed
        );
        actor.shutdown().await.expect("maintenance shutdown");
        (
            stores,
            crate::identity::OwnerId::from_verified_uuid(owner_uuid),
        )
    }

    #[tokio::test]
    async fn login_refresh_replay_revoke_and_logout_are_source_backed() {
        let _serial = super::super::kdf::KDF_TEST_SERIAL.lock().await;
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("instance");
        let (stores, owner) = initialized_fixture(&root).await;
        let runtime = AuthRuntime::open(&root, &stores, NOW_MICROS)
            .await
            .expect("auth runtime");

        let failed_attempt =
            Uuid::parse_str("44444444-4444-4444-8444-444444444444").expect("attempt");
        assert!(matches!(
            runtime
                .login(
                    LoginRequest::local(failed_attempt, "owner_01", password(WRONG_PASSWORD))
                        .expect("failed request"),
                    NOW_MICROS + 1,
                )
                .await
                .expect("failed login outcome"),
            LoginOutcome::GenericFailure
        ));
        assert!(matches!(
            runtime
                .login(
                    LoginRequest::local(failed_attempt, "owner_01", password(WRONG_PASSWORD))
                        .expect("replayed failed request"),
                    NOW_MICROS + 2,
                )
                .await
                .expect("replayed failed outcome"),
            LoginOutcome::GenericFailure
        ));

        let login_attempt =
            Uuid::parse_str("55555555-5555-4555-8555-555555555555").expect("attempt");
        let first = match runtime
            .login(
                LoginRequest::local(login_attempt, "owner_01", password(PASSWORD))
                    .expect("login request"),
                NOW_MICROS + 3,
            )
            .await
            .expect("login outcome")
        {
            LoginOutcome::Authenticated(session) => session,
            other => panic!("unexpected login outcome: {other:?}"),
        };
        let first_access = first.access_token().as_bytes().to_vec();
        let first_refresh = first.refresh_token().as_bytes().to_vec();
        assert_eq!(
            runtime
                .verify_access(
                    super::AuthProfile::Local,
                    SecretBytes::new(first_access.clone()),
                    NOW_MICROS + 4,
                )
                .await
                .expect("verified owner")
                .owner_id(),
            owner
        );

        let rotated = match runtime
            .refresh(
                super::AuthProfile::Local,
                SecretBytes::new(first_refresh.clone()),
                NOW_MICROS + 5,
            )
            .await
            .expect("refresh outcome")
        {
            RefreshOutcome::Rotated(session) => session,
            other => panic!("unexpected refresh outcome: {other:?}"),
        };
        assert_ne!(rotated.refresh_token().as_bytes(), first_refresh.as_slice());
        assert!(matches!(
            runtime
                .refresh(
                    super::AuthProfile::Local,
                    SecretBytes::new(first_refresh),
                    NOW_MICROS + 6,
                )
                .await
                .expect("replay outcome"),
            RefreshOutcome::ReplayRevoked
        ));
        assert_eq!(
            runtime
                .verify_access(
                    super::AuthProfile::Local,
                    SecretBytes::new(first_access),
                    NOW_MICROS + 7,
                )
                .await,
            Err(AccessDenied)
        );

        let second_attempt =
            Uuid::parse_str("66666666-6666-4666-8666-666666666666").expect("attempt");
        let second = match runtime
            .login(
                LoginRequest::local(second_attempt, "owner_01", password(PASSWORD))
                    .expect("second login request"),
                NOW_MICROS + 8,
            )
            .await
            .expect("second login outcome")
        {
            LoginOutcome::Authenticated(session) => session,
            other => panic!("unexpected second login outcome: {other:?}"),
        };
        let second_access = second.access_token().as_bytes().to_vec();
        let second_refresh = second.refresh_token().as_bytes().to_vec();
        assert_eq!(
            runtime
                .logout(
                    super::AuthProfile::Local,
                    Some(SecretBytes::new(second_refresh.clone())),
                    NOW_MICROS + 9,
                )
                .await
                .expect("logout"),
            LogoutOutcome::Revoked
        );
        assert_eq!(
            runtime
                .logout(
                    super::AuthProfile::Local,
                    Some(SecretBytes::new(second_refresh)),
                    NOW_MICROS + 10,
                )
                .await
                .expect("replayed logout"),
            LogoutOutcome::AlreadyTerminal
        );
        assert_eq!(
            runtime
                .verify_access(
                    super::AuthProfile::Local,
                    SecretBytes::new(second_access),
                    NOW_MICROS + 11,
                )
                .await,
            Err(AccessDenied)
        );
        drop(runtime);
        stores.close().await.expect("close fixture stores");
    }

    #[tokio::test]
    async fn logout_all_revokes_every_session_and_increments_credential_version() {
        let _serial = super::super::kdf::KDF_TEST_SERIAL.lock().await;
        let directory = tempdir().expect("temporary instance");
        let root = directory.path().join("instance");
        let (stores, _) = initialized_fixture(&root).await;
        let runtime = AuthRuntime::open(&root, &stores, NOW_MICROS)
            .await
            .expect("auth runtime");

        let mut sessions = Vec::new();
        for (attempt, now) in [
            ("77777777-7777-4777-8777-777777777777", NOW_MICROS + 1),
            ("88888888-8888-4888-8888-888888888888", NOW_MICROS + 2),
        ] {
            let session = match runtime
                .login(
                    LoginRequest::local(
                        Uuid::parse_str(attempt).expect("attempt"),
                        "owner_01",
                        password(PASSWORD),
                    )
                    .expect("login request"),
                    now,
                )
                .await
                .expect("login outcome")
            {
                LoginOutcome::Authenticated(session) => session,
                other => panic!("unexpected login outcome: {other:?}"),
            };
            sessions.push((
                session.access_token().as_bytes().to_vec(),
                session.refresh_token().as_bytes().to_vec(),
            ));
        }

        assert_eq!(
            runtime
                .logout_all(SecretBytes::new(sessions[0].0.clone()), NOW_MICROS + 3,)
                .await
                .expect("logout all"),
            LogoutAllOutcome::Revoked
        );
        for (access, refresh) in sessions {
            assert_eq!(
                runtime
                    .verify_access(
                        super::AuthProfile::Local,
                        SecretBytes::new(access),
                        NOW_MICROS + 4,
                    )
                    .await,
                Err(AccessDenied)
            );
            assert!(matches!(
                runtime
                    .refresh(
                        super::AuthProfile::Local,
                        SecretBytes::new(refresh),
                        NOW_MICROS + 4,
                    )
                    .await
                    .expect("terminal refresh"),
                RefreshOutcome::Invalid
            ));
        }
        assert_eq!(
            runtime
                .logout_all(SecretBytes::new(b"invalid".to_vec()), NOW_MICROS + 5)
                .await
                .expect("invalid logout all"),
            LogoutAllOutcome::InvalidSession
        );
        drop(runtime);
        stores.close().await.expect("close stores");
    }

    #[tokio::test]
    async fn malformed_refresh_is_invalid_without_poisoning_runtime() {
        let _serial = super::super::kdf::KDF_TEST_SERIAL.lock().await;
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("instance");
        let (stores, _) = initialized_fixture(&root).await;
        let runtime = AuthRuntime::open(&root, &stores, NOW_MICROS)
            .await
            .expect("auth runtime");

        assert!(matches!(
            runtime
                .refresh(
                    super::AuthProfile::Local,
                    SecretBytes::new(b"not-a-refresh-token".to_vec()),
                    NOW_MICROS + 1,
                )
                .await
                .expect("ordinary invalid outcome"),
            RefreshOutcome::Invalid
        ));
        assert!(matches!(
            runtime
                .login(
                    LoginRequest::local(
                        Uuid::parse_str("77777777-7777-4777-8777-777777777777").expect("attempt"),
                        "owner_01",
                        password(PASSWORD),
                    )
                    .expect("login request"),
                    NOW_MICROS + 2,
                )
                .await
                .expect("runtime remains usable"),
            LoginOutcome::Authenticated(_)
        ));

        drop(runtime);
        stores.close().await.expect("close fixture stores");
    }

    #[tokio::test]
    async fn exact_idle_deadline_is_pruned_on_fresh_runtime() {
        let _serial = super::super::kdf::KDF_TEST_SERIAL.lock().await;
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("instance");
        let (stores, _) = initialized_fixture(&root).await;
        let runtime = AuthRuntime::open(&root, &stores, NOW_MICROS)
            .await
            .expect("auth runtime");
        let issued = match runtime
            .login(
                LoginRequest::local(
                    Uuid::parse_str("88888888-8888-4888-8888-888888888888").expect("attempt"),
                    "owner_01",
                    password(PASSWORD),
                )
                .expect("login request"),
                NOW_MICROS + 1,
            )
            .await
            .expect("login outcome")
        {
            LoginOutcome::Authenticated(session) => session,
            other => panic!("unexpected login outcome: {other:?}"),
        };
        assert_eq!(
            issued.refresh_expires_at_seconds(),
            (NOW_MICROS + 1 + super::LOCAL_IDLE_LIFETIME_MICROS) / 1_000_000
        );
        let access = issued.access_token().as_bytes().to_vec();
        let refresh = issued.refresh_token().as_bytes().to_vec();
        drop(runtime);

        let exact_idle = NOW_MICROS + 1 + super::LOCAL_IDLE_LIFETIME_MICROS;
        let reopened = AuthRuntime::open(&root, &stores, exact_idle)
            .await
            .expect("fresh runtime prunes expiry");
        assert_eq!(
            reopened
                .verify_access(
                    super::AuthProfile::Local,
                    SecretBytes::new(access),
                    exact_idle,
                )
                .await,
            Err(AccessDenied)
        );
        assert!(matches!(
            reopened
                .refresh(
                    super::AuthProfile::Local,
                    SecretBytes::new(refresh),
                    exact_idle,
                )
                .await
                .expect("expired refresh outcome"),
            RefreshOutcome::Invalid
        ));
        let terminal_counts = reopened
            .store
            .call("test terminal row counts", |connection| {
                let sessions: i64 =
                    connection
                        .query_row("SELECT count(*) FROM auth_sessions", [], |row| row.get(0))?;
                let families: i64 = connection.query_row(
                    "SELECT count(*) FROM auth_refresh_families",
                    [],
                    |row| row.get(0),
                )?;
                let tokens: i64 = connection.query_row(
                    "SELECT count(*) FROM auth_refresh_tokens",
                    [],
                    |row| row.get(0),
                )?;
                Ok((sessions, families, tokens))
            })
            .await
            .expect("terminal row counts");
        assert_eq!(terminal_counts, (0, 0, 0));

        drop(reopened);
        stores.close().await.expect("close fixture stores");
    }

    #[tokio::test]
    async fn generation_8191_is_terminally_revoked_without_child_8192() {
        let _serial = super::super::kdf::KDF_TEST_SERIAL.lock().await;
        use base64ct::Encoding;
        use sha2::Digest;

        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("instance");
        let (stores, _) = initialized_fixture(&root).await;
        let runtime = AuthRuntime::open(&root, &stores, NOW_MICROS)
            .await
            .expect("auth runtime");
        let owner = Uuid::parse_str(OWNER).expect("owner UUID").into_bytes();
        let session =
            Uuid::parse_str("99999999-9999-4999-8999-999999999999").expect("session UUID");
        let family = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("family UUID");
        let raw_refresh = [0xa5_u8; 32];
        let refresh_text = base64ct::Base64UrlUnpadded::encode_string(&raw_refresh);
        let final_digest: [u8; 32] = sha2::Sha256::digest(raw_refresh).into();
        runtime
            .store
            .call("test generation exhaustion setup", move |connection| {
                let transaction =
                    connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let version: i64 = transaction.query_row(
                    "SELECT credential_version FROM auth_accounts WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )?;
                transaction.execute(
                    "INSERT INTO auth_sessions(
                        owner_id, session_id, profile, credential_version, created_at_micros
                     ) VALUES (?1, ?2, 'local', ?3, ?4)",
                    params![
                        owner.as_slice(),
                        session.as_bytes(),
                        version,
                        to_i64(NOW_MICROS + 10)?
                    ],
                )?;
                transaction.execute(
                    "INSERT INTO auth_refresh_families(
                        owner_id, family_id, session_id, profile, created_at_micros,
                        last_refreshed_at_micros, idle_deadline_at_micros,
                        absolute_deadline_at_micros
                     ) VALUES (?1, ?2, ?3, 'local', ?4, ?4, ?5, ?6)",
                    params![
                        owner.as_slice(),
                        family.as_bytes(),
                        session.as_bytes(),
                        to_i64(NOW_MICROS + 10)?,
                        to_i64(NOW_MICROS + 10 + super::LOCAL_IDLE_LIFETIME_MICROS)?,
                        to_i64(NOW_MICROS + 10 + super::LOCAL_ABSOLUTE_LIFETIME_MICROS)?,
                    ],
                )?;
                let mut predecessor: Option<[u8; 32]> = None;
                for generation in 0..=super::MAX_REFRESH_GENERATION {
                    let digest = if generation == super::MAX_REFRESH_GENERATION {
                        final_digest
                    } else {
                        sha2::Sha256::digest(generation.to_be_bytes()).into()
                    };
                    transaction.execute(
                        "INSERT INTO auth_refresh_tokens(
                            owner_id, family_id, token_digest, generation,
                            predecessor_digest, token_state, created_at_micros,
                            consumed_at_micros
                         ) VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, NULL)",
                        params![
                            owner.as_slice(),
                            family.as_bytes(),
                            digest.as_slice(),
                            to_i64(generation)?,
                            predecessor.as_ref().map(|value| value.as_slice()),
                            to_i64(NOW_MICROS + 10 + generation)?,
                        ],
                    )?;
                    if generation < super::MAX_REFRESH_GENERATION {
                        transaction.execute(
                            "UPDATE auth_refresh_tokens
                             SET token_state = 'consumed', consumed_at_micros = ?1
                             WHERE owner_id = ?2 AND token_digest = ?3",
                            params![
                                to_i64(NOW_MICROS + 10 + generation)?,
                                owner.as_slice(),
                                digest.as_slice(),
                            ],
                        )?;
                    }
                    predecessor = Some(digest);
                }
                transaction.commit()?;
                Ok(())
            })
            .await
            .expect("generation exhaustion setup");

        assert!(matches!(
            runtime
                .refresh(
                    super::AuthProfile::Local,
                    SecretBytes::new(refresh_text.into_bytes()),
                    NOW_MICROS + 20_000,
                )
                .await
                .expect("exhaustion outcome"),
            RefreshOutcome::Exhausted
        ));
        let terminal_counts = runtime
            .store
            .call("test exhausted terminal rows", move |connection| {
                let sessions: i64 = connection.query_row(
                    "SELECT count(*) FROM auth_sessions WHERE session_id = ?1",
                    [session.as_bytes().as_slice()],
                    |row| row.get(0),
                )?;
                let families: i64 = connection.query_row(
                    "SELECT count(*) FROM auth_refresh_families WHERE family_id = ?1",
                    [family.as_bytes().as_slice()],
                    |row| row.get(0),
                )?;
                let tokens: i64 = connection.query_row(
                    "SELECT count(*) FROM auth_refresh_tokens WHERE family_id = ?1",
                    [family.as_bytes().as_slice()],
                    |row| row.get(0),
                )?;
                Ok((sessions, families, tokens))
            })
            .await
            .expect("terminal rows");
        assert_eq!(terminal_counts, (0, 0, 0));

        drop(runtime);
        stores.close().await.expect("close fixture stores");
    }

    #[tokio::test]
    async fn password_change_rechecks_current_secret_and_revokes_all_sessions() {
        let _serial = super::super::kdf::KDF_TEST_SERIAL.lock().await;
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("instance");
        let (stores, _) = initialized_fixture(&root).await;
        let runtime = AuthRuntime::open(&root, &stores, NOW_MICROS)
            .await
            .expect("auth runtime");
        let issued = match runtime
            .login(
                LoginRequest::local(
                    Uuid::parse_str("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("attempt"),
                    "owner_01",
                    password(PASSWORD),
                )
                .expect("login request"),
                NOW_MICROS + 1,
            )
            .await
            .expect("login outcome")
        {
            LoginOutcome::Authenticated(session) => session,
            other => panic!("unexpected login outcome: {other:?}"),
        };
        let access = issued.access_token().as_bytes().to_vec();
        let refresh = issued.refresh_token().as_bytes().to_vec();

        assert_eq!(
            runtime
                .change_password(
                    SecretBytes::new(access.clone()),
                    password(WRONG_PASSWORD),
                    password(NEW_PASSWORD),
                    NOW_MICROS + 2,
                )
                .await
                .expect("wrong current password outcome"),
            super::CredentialMutationOutcome::GenericFailure
        );
        assert!(
            runtime
                .verify_access(
                    super::AuthProfile::Local,
                    SecretBytes::new(access.clone()),
                    NOW_MICROS + 3,
                )
                .await
                .is_ok()
        );
        assert_eq!(
            runtime
                .change_password(
                    SecretBytes::new(access.clone()),
                    password(PASSWORD),
                    password(NEW_PASSWORD),
                    NOW_MICROS + 4,
                )
                .await
                .expect("password change"),
            super::CredentialMutationOutcome::Changed
        );
        assert_eq!(
            runtime
                .verify_access(
                    super::AuthProfile::Local,
                    SecretBytes::new(access),
                    NOW_MICROS + 5,
                )
                .await,
            Err(AccessDenied)
        );
        assert!(matches!(
            runtime
                .refresh(
                    super::AuthProfile::Local,
                    SecretBytes::new(refresh),
                    NOW_MICROS + 6,
                )
                .await
                .expect("revoked refresh"),
            RefreshOutcome::Invalid
        ));
        assert!(matches!(
            runtime
                .login(
                    LoginRequest::local(
                        Uuid::parse_str("dddddddd-dddd-4ddd-8ddd-dddddddddddd").expect("attempt"),
                        "owner_01",
                        password(PASSWORD),
                    )
                    .expect("old password login"),
                    NOW_MICROS + 7,
                )
                .await
                .expect("old password outcome"),
            LoginOutcome::GenericFailure
        ));
        assert!(matches!(
            runtime
                .login(
                    LoginRequest::local(
                        Uuid::parse_str("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee").expect("attempt"),
                        "owner_01",
                        password(NEW_PASSWORD),
                    )
                    .expect("new password login"),
                    NOW_MICROS + 8,
                )
                .await
                .expect("new password outcome"),
            LoginOutcome::Authenticated(_)
        ));

        drop(runtime);
        stores.close().await.expect("close fixture stores");
    }

    #[tokio::test]
    async fn runtime_commit_uncertainty_uses_fresh_authoritative_classifiers() {
        use crate::storage::auth_records::AuthRuntimeMutationTestFault;

        let _serial = super::super::kdf::KDF_TEST_SERIAL.lock().await;
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("instance");
        let (stores, _) = initialized_fixture(&root).await;
        let runtime = AuthRuntime::open(&root, &stores, NOW_MICROS)
            .await
            .expect("auth runtime");
        let attempt =
            Uuid::parse_str("ffffffff-ffff-4fff-8fff-ffffffffffff").expect("attempt UUID");
        let snapshot = runtime
            .read_login_snapshot(super::AuthProfile::Local, attempt, "owner_01")
            .await
            .expect("login snapshot");
        let first_candidate = super::SessionCandidate::generate(
            runtime.lease.keyring(),
            super::AuthProfile::Local,
            snapshot.expected.owner_id,
            snapshot.expected.credential_version,
            NOW_MICROS + 1,
        )
        .expect("session candidate");
        runtime.mutations.inject_next_runtime_test_fault(
            AuthRuntimeMutationTestFault::DeferredForeignKeyCommitFailure,
        );
        assert_eq!(
            runtime
                .commit_login_success(
                    snapshot.expected,
                    attempt,
                    super::AuthProfile::Local,
                    &first_candidate,
                    NOW_MICROS + 1,
                )
                .await
                .expect("confirmed no-commit"),
            super::LoginCommitOutcome::RetryRequired
        );

        let retry_snapshot = runtime
            .read_login_snapshot(super::AuthProfile::Local, attempt, "owner_01")
            .await
            .expect("retry snapshot");
        assert!(matches!(retry_snapshot.replay, super::LoginReplay::None));
        let committed_candidate = super::SessionCandidate::generate(
            runtime.lease.keyring(),
            super::AuthProfile::Local,
            retry_snapshot.expected.owner_id,
            retry_snapshot.expected.credential_version,
            NOW_MICROS + 2,
        )
        .expect("committed candidate");
        runtime
            .mutations
            .inject_next_runtime_test_fault(AuthRuntimeMutationTestFault::AfterCommitResponseLoss);
        assert_eq!(
            runtime
                .commit_login_success(
                    retry_snapshot.expected,
                    attempt,
                    super::AuthProfile::Local,
                    &committed_candidate,
                    NOW_MICROS + 2,
                )
                .await
                .expect("response-loss login classification"),
            super::LoginCommitOutcome::Committed
        );
        runtime
            .verify_access(
                super::AuthProfile::Local,
                SecretBytes::new(
                    committed_candidate
                        .access_token
                        .as_str()
                        .as_bytes()
                        .to_vec(),
                ),
                NOW_MICROS + 3,
            )
            .await
            .expect("committed access remains valid");

        let refresh_snapshot = runtime
            .read_refresh_snapshot(
                super::AuthProfile::Local,
                committed_candidate.refresh_digest,
            )
            .await
            .expect("refresh observation")
            .expect("refresh row");
        let refresh_candidate = super::RefreshCandidate::generate(
            runtime.lease.keyring(),
            super::AuthProfile::Local,
            refresh_snapshot.owner_id,
            refresh_snapshot.session_id,
            refresh_snapshot.credential_version,
            refresh_snapshot.absolute_deadline_at_micros,
            NOW_MICROS + 4,
        )
        .expect("refresh candidate");
        runtime
            .mutations
            .inject_next_runtime_test_fault(AuthRuntimeMutationTestFault::AfterCommitResponseLoss);
        assert!(
            runtime
                .commit_refresh_rotation(
                    &refresh_snapshot,
                    committed_candidate.refresh_digest,
                    &refresh_candidate,
                    NOW_MICROS + 4,
                )
                .await
                .expect("response-loss refresh classification")
        );

        runtime
            .mutations
            .inject_next_runtime_test_fault(AuthRuntimeMutationTestFault::AfterCommitResponseLoss);
        assert_eq!(
            runtime
                .logout(
                    super::AuthProfile::Local,
                    Some(SecretBytes::new(
                        refresh_candidate.refresh_token.as_bytes().to_vec()
                    )),
                    NOW_MICROS + 5,
                )
                .await
                .expect("response-loss logout classification"),
            LogoutOutcome::Revoked
        );

        drop(runtime);
        stores.close().await.expect("close fixture stores");
    }

    #[tokio::test]
    async fn recovery_rotation_recovery_disable_and_reenable_are_atomic() {
        let _serial = super::super::kdf::KDF_TEST_SERIAL.lock().await;
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("instance");
        let (stores, _) = initialized_fixture(&root).await;
        let runtime = AuthRuntime::open(&root, &stores, NOW_MICROS)
            .await
            .expect("auth runtime");
        let issued = match runtime
            .login(
                LoginRequest::local(
                    Uuid::parse_str("12121212-1212-4212-8212-121212121212").expect("attempt"),
                    "owner_01",
                    password(PASSWORD),
                )
                .expect("login request"),
                NOW_MICROS + 1,
            )
            .await
            .expect("login outcome")
        {
            LoginOutcome::Authenticated(session) => session,
            other => panic!("unexpected login outcome: {other:?}"),
        };
        let access = issued.access_token().as_bytes().to_vec();
        let refresh = issued.refresh_token().as_bytes().to_vec();
        assert_eq!(
            runtime
                .rotate_recovery_code(
                    password(PASSWORD),
                    recovery_code(REPLACEMENT_CODE),
                    NOW_MICROS + 2,
                )
                .await
                .expect("recovery rotation"),
            super::CredentialMutationOutcome::Changed
        );
        assert_eq!(
            runtime
                .verify_access(
                    super::AuthProfile::Local,
                    SecretBytes::new(access),
                    NOW_MICROS + 3,
                )
                .await,
            Err(AccessDenied)
        );
        assert!(matches!(
            runtime
                .refresh(
                    super::AuthProfile::Local,
                    SecretBytes::new(refresh),
                    NOW_MICROS + 4,
                )
                .await
                .expect("rotated-code session revoke"),
            RefreshOutcome::Invalid
        ));

        assert_eq!(
            runtime
                .recover_account(
                    recovery_code(RECOVERY_CODE),
                    password(NEW_PASSWORD),
                    recovery_code(SECOND_REPLACEMENT_CODE),
                    NOW_MICROS + 5,
                )
                .await
                .expect("old recovery code failure"),
            super::CredentialMutationOutcome::GenericFailure
        );
        assert_eq!(
            runtime
                .recover_account(
                    recovery_code(REPLACEMENT_CODE),
                    password(NEW_PASSWORD),
                    recovery_code(SECOND_REPLACEMENT_CODE),
                    NOW_MICROS + 6,
                )
                .await
                .expect("account recovery"),
            super::CredentialMutationOutcome::Changed
        );
        assert!(matches!(
            runtime
                .login(
                    LoginRequest::local(
                        Uuid::parse_str("13131313-1313-4313-8313-131313131313").expect("attempt"),
                        "owner_01",
                        password(PASSWORD),
                    )
                    .expect("old password login"),
                    NOW_MICROS + 7,
                )
                .await
                .expect("old password outcome"),
            LoginOutcome::GenericFailure
        ));
        let current = match runtime
            .login(
                LoginRequest::local(
                    Uuid::parse_str("14141414-1414-4414-8414-141414141414").expect("attempt"),
                    "owner_01",
                    password(NEW_PASSWORD),
                )
                .expect("new password login"),
                NOW_MICROS + 8,
            )
            .await
            .expect("new password outcome")
        {
            LoginOutcome::Authenticated(session) => session,
            other => panic!("unexpected new password outcome: {other:?}"),
        };
        let current_access = current.access_token().as_bytes().to_vec();
        assert_eq!(
            runtime
                .set_account_enabled(
                    recovery_code(SECOND_REPLACEMENT_CODE),
                    false,
                    NOW_MICROS + 9,
                )
                .await
                .expect("account disable"),
            super::CredentialMutationOutcome::Changed
        );
        assert_eq!(
            runtime
                .verify_access(
                    super::AuthProfile::Local,
                    SecretBytes::new(current_access),
                    NOW_MICROS + 10,
                )
                .await,
            Err(AccessDenied)
        );
        assert!(matches!(
            runtime
                .login(
                    LoginRequest::local(
                        Uuid::parse_str("15151515-1515-4515-8515-151515151515").expect("attempt"),
                        "owner_01",
                        password(NEW_PASSWORD),
                    )
                    .expect("disabled login"),
                    NOW_MICROS + 11,
                )
                .await
                .expect("disabled login outcome"),
            LoginOutcome::GenericFailure
        ));
        assert_eq!(
            runtime
                .set_account_enabled(
                    recovery_code(SECOND_REPLACEMENT_CODE),
                    true,
                    NOW_MICROS + 12,
                )
                .await
                .expect("account re-enable"),
            super::CredentialMutationOutcome::Changed
        );
        assert!(matches!(
            runtime
                .login(
                    LoginRequest::local(
                        Uuid::parse_str("16161616-1616-4616-8616-161616161616").expect("attempt"),
                        "owner_01",
                        password(NEW_PASSWORD),
                    )
                    .expect("re-enabled login"),
                    NOW_MICROS + 13,
                )
                .await
                .expect("re-enabled login outcome"),
            LoginOutcome::Authenticated(_)
        ));

        drop(runtime);
        stores.close().await.expect("close fixture stores");
    }

    #[test]
    fn public_debug_and_errors_do_not_disclose_auth_material() {
        let canary = "canary credential 012345";
        let request = LoginRequest::local(
            Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("attempt"),
            "owner_01",
            password(canary.as_bytes()),
        )
        .expect("login request");
        assert_eq!(format!("{request:?}"), "LoginRequest([REDACTED])");
        assert!(!format!("{request:?}").contains(canary));
        assert_eq!(
            format!("{:?}", LoginOutcome::GenericFailure),
            "LoginOutcome::GenericFailure"
        );
        assert_eq!(
            format!("{:?}", RefreshOutcome::Invalid),
            "RefreshOutcome::Invalid"
        );
        assert!(
            !AuthRuntimeError::OperationFailed
                .to_string()
                .contains(canary)
        );
        assert!(!AccessDenied.to_string().contains(canary));
    }
}
