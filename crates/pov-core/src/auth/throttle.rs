use std::{error::Error, fmt};

const MAX_FAILURE_COUNT: u64 = 100;
const FIRST_BACKOFF_FAILURE: u64 = 5;
const INITIAL_BACKOFF_MICROS: u64 = 30_000_000;
const MAX_BACKOFF_MICROS: u64 = 3_600_000_000;
const MAX_UNCAPPED_BACKOFF_EXPONENT: u64 = 6;
const MAX_SQLITE_INTEGER: u64 = i64::MAX as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatorKind {
    Password,
    Recovery,
}

/// Durable throttle values read from the authentication source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThrottleState {
    authenticator: AuthenticatorKind,
    failure_count: u64,
    next_allowed_at_micros: u64,
    revision: u64,
    updated_at_micros: u64,
}

impl ThrottleState {
    pub fn new(
        authenticator: AuthenticatorKind,
        failure_count: u64,
        next_allowed_at_micros: u64,
        revision: u64,
        updated_at_micros: u64,
    ) -> Result<Self, ThrottleMathError> {
        let exact_deadline = if failure_count == 0 {
            Some(0)
        } else {
            updated_at_micros.checked_add(backoff_micros(failure_count))
        };
        if failure_count > MAX_FAILURE_COUNT
            || next_allowed_at_micros > MAX_SQLITE_INTEGER
            || !(1..=MAX_SQLITE_INTEGER).contains(&revision)
            || updated_at_micros > MAX_SQLITE_INTEGER
            || exact_deadline != Some(next_allowed_at_micros)
        {
            return Err(ThrottleMathError::InvalidPersistedState);
        }
        Ok(Self {
            authenticator,
            failure_count,
            next_allowed_at_micros,
            revision,
            updated_at_micros,
        })
    }

    #[must_use]
    pub const fn authenticator(self) -> AuthenticatorKind {
        self.authenticator
    }

    #[must_use]
    pub const fn failure_count(self) -> u64 {
        self.failure_count
    }

    #[must_use]
    pub const fn next_allowed_at_micros(self) -> u64 {
        self.next_allowed_at_micros
    }

    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn updated_at_micros(self) -> u64 {
        self.updated_at_micros
    }

    #[must_use]
    pub const fn admits_at(self, now_micros: u64) -> bool {
        now_micros >= self.updated_at_micros
            && now_micros >= self.next_allowed_at_micros
            && now_micros <= MAX_SQLITE_INTEGER
    }

    /// Compute the source values for one verifier failure that was already
    /// admitted. Calling this for a throttled attempt is rejected without an
    /// update.
    pub fn admitted_failure(
        self,
        now_micros: u64,
    ) -> Result<ThrottleFailureUpdate, ThrottleMathError> {
        if now_micros > MAX_SQLITE_INTEGER {
            return Err(ThrottleMathError::TimeOverflow);
        }
        if now_micros < self.updated_at_micros {
            return Err(ThrottleMathError::ClockRegressed);
        }
        if now_micros < self.next_allowed_at_micros {
            return Err(ThrottleMathError::NotAdmitted);
        }
        if self.authenticator == AuthenticatorKind::Password
            && self.failure_count == MAX_FAILURE_COUNT
        {
            return Err(ThrottleMathError::PasswordAuthenticatorDisabled);
        }

        let next_count = self.failure_count.saturating_add(1).min(MAX_FAILURE_COUNT);
        let delay = backoff_micros(next_count);
        let next_allowed_at_micros = now_micros
            .checked_add(delay)
            .filter(|value| *value <= MAX_SQLITE_INTEGER)
            .ok_or(ThrottleMathError::TimeOverflow)?;
        let revision = self
            .revision
            .checked_add(1)
            .filter(|value| *value <= MAX_SQLITE_INTEGER)
            .ok_or(ThrottleMathError::RevisionOverflow)?;

        Ok(ThrottleFailureUpdate {
            state: Self {
                authenticator: self.authenticator,
                failure_count: next_count,
                next_allowed_at_micros,
                revision,
                updated_at_micros: now_micros,
            },
            disable_password: self.authenticator == AuthenticatorKind::Password
                && next_count == MAX_FAILURE_COUNT,
        })
    }

    /// Reset the matching durable counter after a successful verification.
    pub fn successful_verification(self, now_micros: u64) -> Result<Self, ThrottleMathError> {
        if now_micros > MAX_SQLITE_INTEGER {
            return Err(ThrottleMathError::TimeOverflow);
        }
        if now_micros < self.updated_at_micros {
            return Err(ThrottleMathError::ClockRegressed);
        }
        if now_micros < self.next_allowed_at_micros {
            return Err(ThrottleMathError::NotAdmitted);
        }
        if self.authenticator == AuthenticatorKind::Password
            && self.failure_count == MAX_FAILURE_COUNT
        {
            return Err(ThrottleMathError::PasswordAuthenticatorDisabled);
        }
        self.reset_at(now_micros)
    }

    /// Reset and re-enable the password throttle only after the separate saved
    /// recovery-code workflow has been verified and authorized its source
    /// transaction. This is not a password-verification success path.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn reset_after_recovery(self, now_micros: u64) -> Result<Self, ThrottleMathError> {
        if self.authenticator != AuthenticatorKind::Password {
            return Err(ThrottleMathError::WrongAuthenticator);
        }
        if now_micros > MAX_SQLITE_INTEGER {
            return Err(ThrottleMathError::TimeOverflow);
        }
        if now_micros < self.updated_at_micros {
            return Err(ThrottleMathError::ClockRegressed);
        }
        self.reset_at(now_micros)
    }

    fn reset_at(self, now_micros: u64) -> Result<Self, ThrottleMathError> {
        let revision = self
            .revision
            .checked_add(1)
            .filter(|value| *value <= MAX_SQLITE_INTEGER)
            .ok_or(ThrottleMathError::RevisionOverflow)?;
        Ok(Self {
            authenticator: self.authenticator,
            failure_count: 0,
            next_allowed_at_micros: 0,
            revision,
            updated_at_micros: now_micros,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThrottleFailureUpdate {
    state: ThrottleState,
    disable_password: bool,
}

impl ThrottleFailureUpdate {
    #[must_use]
    pub const fn state(self) -> ThrottleState {
        self.state
    }

    #[must_use]
    pub const fn disables_password(self) -> bool {
        self.disable_password
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThrottleMathError {
    InvalidPersistedState,
    NotAdmitted,
    PasswordAuthenticatorDisabled,
    WrongAuthenticator,
    ClockRegressed,
    TimeOverflow,
    RevisionOverflow,
}

impl fmt::Display for ThrottleMathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPersistedState => "persisted authenticator throttle state is invalid",
            Self::NotAdmitted => "authenticator attempt is not admitted",
            Self::PasswordAuthenticatorDisabled => "password authenticator is disabled",
            Self::WrongAuthenticator => {
                "authenticator throttle operation does not match the stored kind"
            }
            Self::ClockRegressed => "authenticator throttle clock regressed",
            Self::TimeOverflow => "authenticator throttle time overflowed",
            Self::RevisionOverflow => "authenticator throttle revision overflowed",
        })
    }
}

impl Error for ThrottleMathError {}

const fn backoff_micros(failure_count: u64) -> u64 {
    if failure_count < FIRST_BACKOFF_FAILURE {
        return 0;
    }
    let exponent = failure_count - FIRST_BACKOFF_FAILURE;
    if exponent > MAX_UNCAPPED_BACKOFF_EXPONENT {
        return MAX_BACKOFF_MICROS;
    }
    match INITIAL_BACKOFF_MICROS.checked_shl(exponent as u32) {
        Some(value) if value < MAX_BACKOFF_MICROS => value,
        _ => MAX_BACKOFF_MICROS,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthenticatorKind, MAX_BACKOFF_MICROS, ThrottleMathError, ThrottleState, backoff_micros,
    };

    const SECOND: u64 = 1_000_000;

    #[test]
    fn backoff_starts_on_fifth_failure_and_caps_at_one_hour() {
        assert_eq!(backoff_micros(4), 0);
        assert_eq!(backoff_micros(5), 30 * SECOND);
        assert_eq!(backoff_micros(6), 60 * SECOND);
        assert_eq!(backoff_micros(7), 120 * SECOND);
        assert_eq!(backoff_micros(11), 1_920 * SECOND);
        assert_eq!(backoff_micros(12), MAX_BACKOFF_MICROS);
        assert_eq!(backoff_micros(100), MAX_BACKOFF_MICROS);
    }

    #[test]
    fn exact_deadline_is_admitted_and_throttled_attempt_does_not_mutate() {
        let state = ThrottleState::new(AuthenticatorKind::Password, 4, 10 * SECOND, 7, 10 * SECOND)
            .expect("valid state");
        let update = state
            .admitted_failure(10 * SECOND)
            .expect("fifth admitted failure");
        let throttled = update.state();
        assert_eq!(throttled.failure_count(), 5);
        assert_eq!(throttled.next_allowed_at_micros(), 40 * SECOND);
        assert!(!throttled.admits_at(40 * SECOND - 1));
        assert!(throttled.admits_at(40 * SECOND));
        assert_eq!(
            throttled.admitted_failure(40 * SECOND - 1).unwrap_err(),
            ThrottleMathError::NotAdmitted
        );
        assert_eq!(throttled.failure_count(), 5);
    }

    #[test]
    fn hundredth_password_failure_requests_disable() {
        let state = ThrottleState::new(
            AuthenticatorKind::Password,
            99,
            1 + MAX_BACKOFF_MICROS,
            1,
            1,
        )
        .expect("valid state");
        let update = state
            .admitted_failure(state.next_allowed_at_micros())
            .expect("hundredth failure");
        assert_eq!(update.state().failure_count(), 100);
        assert!(update.disables_password());
        assert_eq!(
            update
                .state()
                .admitted_failure(update.state().next_allowed_at_micros())
                .unwrap_err(),
            ThrottleMathError::PasswordAuthenticatorDisabled
        );
    }

    #[test]
    fn recovery_saturates_at_one_hundred_but_advances_deadline_and_revision() {
        let state = ThrottleState::new(
            AuthenticatorKind::Recovery,
            100,
            1 + MAX_BACKOFF_MICROS,
            9,
            1,
        )
        .expect("valid state");
        let admitted_at = state.next_allowed_at_micros();
        let update = state
            .admitted_failure(admitted_at)
            .expect("saturated recovery failure");

        assert_eq!(update.state().failure_count(), 100);
        assert_eq!(update.state().revision(), 10);
        assert_eq!(
            update.state().next_allowed_at_micros(),
            admitted_at + MAX_BACKOFF_MICROS
        );
        assert!(!update.disables_password());
    }

    #[test]
    fn success_resets_only_the_supplied_counter_values() {
        let state = ThrottleState::new(
            AuthenticatorKind::Recovery,
            17,
            100 + MAX_BACKOFF_MICROS,
            41,
            100,
        )
        .expect("valid state");
        let reset = state
            .successful_verification(state.next_allowed_at_micros())
            .expect("reset");

        assert_eq!(reset.failure_count(), 0);
        assert_eq!(reset.next_allowed_at_micros(), 0);
        assert_eq!(reset.revision(), 42);
        assert_eq!(reset.updated_at_micros(), 100 + MAX_BACKOFF_MICROS);
    }

    #[test]
    fn throttled_success_cannot_reset_the_counter() {
        let state = ThrottleState::new(AuthenticatorKind::Password, 5, 100 + 30 * SECOND, 41, 100)
            .expect("valid state");
        assert_eq!(
            state
                .successful_verification(state.next_allowed_at_micros() - 1)
                .unwrap_err(),
            ThrottleMathError::NotAdmitted
        );
        assert_eq!(state.failure_count(), 5);
        assert_eq!(state.revision(), 41);
    }

    #[test]
    fn invalid_persisted_and_overflow_states_fail_closed() {
        assert_eq!(
            ThrottleState::new(AuthenticatorKind::Password, 101, 0, 1, 0).unwrap_err(),
            ThrottleMathError::InvalidPersistedState
        );
        assert_eq!(
            ThrottleState::new(AuthenticatorKind::Password, 0, 1, 1, 0).unwrap_err(),
            ThrottleMathError::InvalidPersistedState
        );
        assert_eq!(
            ThrottleState::new(AuthenticatorKind::Password, 1, 9, 1, 10).unwrap_err(),
            ThrottleMathError::InvalidPersistedState
        );
        assert_eq!(
            ThrottleState::new(AuthenticatorKind::Password, 5, 100, 1, 100).unwrap_err(),
            ThrottleMathError::InvalidPersistedState
        );
        assert_eq!(
            ThrottleState::new(
                AuthenticatorKind::Password,
                5,
                100 + 30 * SECOND + 1,
                1,
                100,
            )
            .unwrap_err(),
            ThrottleMathError::InvalidPersistedState
        );
        let at_revision_limit =
            ThrottleState::new(AuthenticatorKind::Password, 1, 1, i64::MAX as u64, 1)
                .expect("valid terminal revision");
        assert_eq!(
            at_revision_limit.successful_verification(1).unwrap_err(),
            ThrottleMathError::RevisionOverflow
        );
        assert_eq!(
            ThrottleState::new(
                AuthenticatorKind::Recovery,
                100,
                i64::MAX as u64,
                1,
                i64::MAX as u64,
            )
            .unwrap_err(),
            ThrottleMathError::InvalidPersistedState
        );
    }

    #[test]
    fn clock_regression_is_detected_even_without_an_active_deadline() {
        let reset = ThrottleState::new(AuthenticatorKind::Recovery, 0, 0, 10, 50)
            .expect("valid reset state");
        assert!(!reset.admits_at(49));
        assert_eq!(
            reset.admitted_failure(49).unwrap_err(),
            ThrottleMathError::ClockRegressed
        );
        assert_eq!(
            reset.successful_verification(49).unwrap_err(),
            ThrottleMathError::ClockRegressed
        );
    }

    #[test]
    fn disabled_password_cannot_be_reset_by_a_password_success_path() {
        let state = ThrottleState::new(
            AuthenticatorKind::Password,
            100,
            1 + MAX_BACKOFF_MICROS,
            7,
            1,
        )
        .expect("disabled password throttle");

        assert_eq!(
            state
                .successful_verification(state.next_allowed_at_micros())
                .unwrap_err(),
            ThrottleMathError::PasswordAuthenticatorDisabled
        );
    }

    #[test]
    fn authorized_recovery_reset_is_explicit_and_password_only() {
        let disabled_password = ThrottleState::new(
            AuthenticatorKind::Password,
            100,
            1 + MAX_BACKOFF_MICROS,
            7,
            1,
        )
        .expect("disabled password throttle");
        let reset = disabled_password
            .reset_after_recovery(2)
            .expect("authorized recovery may reset before password deadline");
        assert_eq!(reset.authenticator(), AuthenticatorKind::Password);
        assert_eq!(reset.failure_count(), 0);
        assert_eq!(reset.next_allowed_at_micros(), 0);
        assert_eq!(reset.revision(), 8);
        assert_eq!(reset.updated_at_micros(), 2);

        let recovery = ThrottleState::new(AuthenticatorKind::Recovery, 5, 30_000_001, 3, 1)
            .expect("recovery throttle");
        assert_eq!(
            recovery.reset_after_recovery(30_000_001).unwrap_err(),
            ThrottleMathError::WrongAuthenticator
        );
    }
}
