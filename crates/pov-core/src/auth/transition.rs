use std::{error::Error, fmt, str};

#[cfg(test)]
use base64ct::{Base64Unpadded, Encoding};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    SecretBytes, ValidatedVerifier,
    keyring::{
        ACTIVE_ONLY_LENGTH, AuthTimestampMicros, KeyId, Keyring, KeyringVersion,
        WITH_VERIFY_ONLY_LENGTH,
    },
};

pub(crate) const AUTH_MAINTENANCE_LOCK_NAME: &str = "auth-maintenance.lock";
pub(crate) const ACTIVE_KEYRING_NAME: &str = "auth-keyring.v1";
pub(crate) const TRANSITION_METADATA_NAME: &str = "metadata";
pub(crate) const STAGED_KEYRING_NAME: &str = "staged-keyring";
pub(crate) const PREPARED_SENTINEL_NAME: &str = "prepared";

const TRANSITION_PREFIX: &str = ".auth-transition-";
const CLEANUP_PREFIX: &str = ".auth-cleanup-";
const INSTALL_PREFIX: &str = ".auth-keyring-install-";
const INSTALL_SUFFIX: &str = ".tmp";
const CANONICAL_UUID_TEXT_LENGTH: usize = 36;

const METADATA_MAGIC: &[u8; 8] = b"POVAUTHM";
const METADATA_FORMAT_VERSION: u16 = 1;
const INITIALIZE_METADATA_TAG: u8 = 1;
const PLANNED_METADATA_TAG: u8 = 2;
const RETIRE_METADATA_TAG: u8 = 3;
const METADATA_CHECKSUM_BYTES: usize = 32;
const METADATA_FIXED_HEADER_BYTES: usize = 166;
pub(super) const MAX_INITIALIZATION_METADATA_BYTES: usize = 512;
pub(super) const PLANNED_ROTATION_METADATA_BYTES: usize = 305;
const PLANNED_ROTATION_CHECKSUM_OFFSET: usize =
    PLANNED_ROTATION_METADATA_BYTES - METADATA_CHECKSUM_BYTES;
pub(super) const RETIRE_METADATA_BYTES: usize = 349;
const RETIRE_CHECKSUM_OFFSET: usize = RETIRE_METADATA_BYTES - METADATA_CHECKSUM_BYTES;
const KID_BYTES: usize = 43;
const STAGED_HASH_BYTES: usize = 32;
const MAX_LOGIN_ID_BYTES: usize = 32;
const MAX_LEGACY_POLICY_PROVENANCE_BYTES: usize = 64;

pub(crate) const NO_BLOCKLIST_CHECK_SENTINEL: &str = "no-blocklist-check-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransitionKind {
    Initialize,
    Planned,
    Retire,
    Compromise,
    Loss,
}

impl TransitionKind {
    const ALL: [Self; 5] = [
        Self::Initialize,
        Self::Planned,
        Self::Retire,
        Self::Compromise,
        Self::Loss,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::Planned => "planned",
            Self::Retire => "retire",
            Self::Compromise => "compromise",
            Self::Loss => "loss",
        }
    }

    pub(crate) fn parse_persisted(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
    }
}

macro_rules! auth_v4_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub(crate) struct $name(Uuid);

        impl $name {
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

            fn from_bytes(bytes: &[u8]) -> Result<Self, TransitionContractError> {
                let uuid = Uuid::from_slice(bytes)
                    .map_err(|_| TransitionContractError::InvalidIdentifier)?;
                Self::from_uuid(uuid).ok_or(TransitionContractError::InvalidIdentifier)
            }

            pub(crate) const fn as_uuid(self) -> Uuid {
                self.0
            }

            fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&"[REDACTED]")
                    .finish()
            }
        }
    };
}

auth_v4_id!(TransitionId);
auth_v4_id!(AuditId);
auth_v4_id!(AuthOwnerId);

impl TransitionId {
    fn parse_canonical(raw: &[u8]) -> Result<Self, TransitionContractError> {
        if raw.len() != CANONICAL_UUID_TEXT_LENGTH || !raw.is_ascii() {
            return Err(TransitionContractError::InvalidIdentifier);
        }
        let text = str::from_utf8(raw).map_err(|_| TransitionContractError::InvalidIdentifier)?;
        let uuid = Uuid::parse_str(text).map_err(|_| TransitionContractError::InvalidIdentifier)?;
        let transition_id =
            Self::from_uuid(uuid).ok_or(TransitionContractError::InvalidIdentifier)?;
        if transition_id.canonical_text().as_bytes() != raw {
            return Err(TransitionContractError::InvalidIdentifier);
        }
        Ok(transition_id)
    }

    fn canonical_text(self) -> String {
        self.0.hyphenated().to_string()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TopLevelArtifactName {
    MaintenanceLock,
    ActiveKeyring,
    Transition {
        kind: TransitionKind,
        id: TransitionId,
    },
    Cleanup {
        kind: TransitionKind,
        id: TransitionId,
    },
    InstallTemp {
        id: TransitionId,
    },
}

impl TopLevelArtifactName {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, TransitionContractError> {
        match raw {
            name if name == AUTH_MAINTENANCE_LOCK_NAME.as_bytes() => {
                return Ok(Self::MaintenanceLock);
            }
            name if name == ACTIVE_KEYRING_NAME.as_bytes() => return Ok(Self::ActiveKeyring),
            _ => {}
        }

        if let Some(parsed) = parse_kind_and_id(raw, TRANSITION_PREFIX)? {
            return Ok(Self::Transition {
                kind: parsed.0,
                id: parsed.1,
            });
        }
        if let Some(parsed) = parse_kind_and_id(raw, CLEANUP_PREFIX)? {
            return Ok(Self::Cleanup {
                kind: parsed.0,
                id: parsed.1,
            });
        }
        if let Some(id_bytes) = raw
            .strip_prefix(INSTALL_PREFIX.as_bytes())
            .and_then(|remainder| remainder.strip_suffix(INSTALL_SUFFIX.as_bytes()))
        {
            return Ok(Self::InstallTemp {
                id: TransitionId::parse_canonical(id_bytes)?,
            });
        }

        Err(TransitionContractError::InvalidArtifactName)
    }

    pub(crate) fn format(self) -> String {
        match self {
            Self::MaintenanceLock => AUTH_MAINTENANCE_LOCK_NAME.to_owned(),
            Self::ActiveKeyring => ACTIVE_KEYRING_NAME.to_owned(),
            Self::Transition { kind, id } => {
                format!(
                    "{TRANSITION_PREFIX}{}-{}",
                    kind.as_str(),
                    id.canonical_text()
                )
            }
            Self::Cleanup { kind, id } => {
                format!("{CLEANUP_PREFIX}{}-{}", kind.as_str(), id.canonical_text())
            }
            Self::InstallTemp { id } => {
                format!("{INSTALL_PREFIX}{}{INSTALL_SUFFIX}", id.canonical_text())
            }
        }
    }
}

fn parse_kind_and_id(
    raw: &[u8],
    namespace_prefix: &str,
) -> Result<Option<(TransitionKind, TransitionId)>, TransitionContractError> {
    let Some(remainder) = raw.strip_prefix(namespace_prefix.as_bytes()) else {
        return Ok(None);
    };
    for kind in TransitionKind::ALL {
        let mut kind_prefix = kind.as_str().as_bytes().to_vec();
        kind_prefix.push(b'-');
        if let Some(id_bytes) = remainder.strip_prefix(kind_prefix.as_slice()) {
            return TransitionId::parse_canonical(id_bytes)
                .map(|id| Some((kind, id)))
                .map_err(|_| TransitionContractError::InvalidArtifactName);
        }
    }
    Err(TransitionContractError::InvalidArtifactName)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReservationEntryName {
    Metadata,
    StagedKeyring,
    Prepared,
}

impl ReservationEntryName {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, TransitionContractError> {
        match raw {
            name if name == TRANSITION_METADATA_NAME.as_bytes() => Ok(Self::Metadata),
            name if name == STAGED_KEYRING_NAME.as_bytes() => Ok(Self::StagedKeyring),
            name if name == PREPARED_SENTINEL_NAME.as_bytes() => Ok(Self::Prepared),
            _ => Err(TransitionContractError::InvalidArtifactName),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => TRANSITION_METADATA_NAME,
            Self::StagedKeyring => STAGED_KEYRING_NAME,
            Self::Prepared => PREPARED_SENTINEL_NAME,
        }
    }
}

#[derive(Eq, PartialEq)]
pub(crate) struct LoginId(String);

impl LoginId {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, TransitionContractError> {
        if !(3..=MAX_LOGIN_ID_BYTES).contains(&raw.len())
            || !raw[0].is_ascii_lowercase()
            || !raw[1..].iter().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(byte)
            })
        {
            return Err(TransitionContractError::InvalidLoginId);
        }
        let value = str::from_utf8(raw)
            .map_err(|_| TransitionContractError::InvalidLoginId)?
            .to_owned();
        Ok(Self(value))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for LoginId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoginId([REDACTED])")
    }
}

#[derive(Eq, PartialEq)]
pub(crate) struct LegacyPolicyProvenance(String);

impl LegacyPolicyProvenance {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, TransitionContractError> {
        if raw.is_empty()
            || raw.len() > MAX_LEGACY_POLICY_PROVENANCE_BYTES
            || !raw[0].is_ascii_lowercase()
            || !raw[raw.len() - 1].is_ascii_lowercase() && !raw[raw.len() - 1].is_ascii_digit()
            || !raw
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return Err(TransitionContractError::InvalidLegacyPolicyProvenance);
        }
        let value = str::from_utf8(raw)
            .map_err(|_| TransitionContractError::InvalidLegacyPolicyProvenance)?
            .to_owned();
        Ok(Self(value))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for LegacyPolicyProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LegacyPolicyProvenance([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct SourceTimestampMicros(u64);

impl SourceTimestampMicros {
    pub(crate) fn new(value: u64) -> Result<Self, TransitionContractError> {
        if value > i64::MAX as u64 {
            return Err(TransitionContractError::InvalidMetadata);
        }
        Ok(Self(value))
    }

    const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct PersistedLifecycleKeyId(KeyId);

impl PersistedLifecycleKeyId {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        KeyId::from_stored_bytes(value.as_bytes()).ok().map(Self)
    }

    pub(crate) fn matches_key(self, value: KeyId) -> bool {
        self.0 == value
    }
}

impl fmt::Debug for PersistedLifecycleKeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PersistedLifecycleKeyId([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct PersistedLifecycleTransitionId(TransitionId);

impl PersistedLifecycleTransitionId {
    pub(crate) fn parse(value: &[u8]) -> Option<Self> {
        TransitionId::from_bytes(value).ok().map(Self)
    }
}

impl fmt::Debug for PersistedLifecycleTransitionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PersistedLifecycleTransitionId([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct PersistedLifecycleKeyringVersion(KeyringVersion);

impl PersistedLifecycleKeyringVersion {
    pub(crate) fn parse(value: i64) -> Option<Self> {
        u64::try_from(value)
            .ok()
            .and_then(|value| KeyringVersion::new(value).ok())
            .map(Self)
    }

    pub(crate) fn get(self) -> u64 {
        self.0.get()
    }

    pub(crate) fn matches_version(self, value: KeyringVersion) -> bool {
        self.0 == value
    }
}

impl fmt::Debug for PersistedLifecycleKeyringVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PersistedLifecycleKeyringVersion([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct PersistedLifecycleTimestamp(SourceTimestampMicros);

impl PersistedLifecycleTimestamp {
    pub(crate) fn parse(value: i64) -> Option<Self> {
        u64::try_from(value)
            .ok()
            .filter(|value| *value > 0)
            .and_then(|value| SourceTimestampMicros::new(value).ok())
            .map(Self)
    }

    pub(crate) fn matches_i64(self, value: i64) -> bool {
        u64::try_from(value).ok() == Some(self.0.get())
    }

    pub(crate) fn is_at_or_after(self, value: AuthTimestampMicros) -> bool {
        self.0.get() >= value.get()
    }
}

impl fmt::Debug for PersistedLifecycleTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PersistedLifecycleTimestamp([REDACTED])")
    }
}

pub(crate) struct InitializationMetadataInput {
    pub(crate) transition_id: TransitionId,
    pub(crate) owner_id: AuthOwnerId,
    pub(crate) audit_id: AuditId,
    pub(crate) source_at_micros: SourceTimestampMicros,
    pub(crate) login_id: LoginId,
    pub(crate) password_verifier: ValidatedVerifier,
    pub(crate) recovery_verifier: ValidatedVerifier,
}

impl fmt::Debug for InitializationMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InitializationMetadataInput([REDACTED])")
    }
}

pub(crate) struct InitializationMetadataV1 {
    transition_id: TransitionId,
    owner_id: AuthOwnerId,
    audit_id: AuditId,
    result_kid: KeyId,
    result_keyring_version: KeyringVersion,
    key_activated_at_micros: AuthTimestampMicros,
    source_at_micros: SourceTimestampMicros,
    staged_keyring_length: u32,
    staged_keyring_hash: [u8; STAGED_HASH_BYTES],
    login_id: LoginId,
    password_verifier: ValidatedVerifier,
    recovery_verifier: ValidatedVerifier,
    legacy_policy_provenance: LegacyPolicyProvenance,
}

pub(crate) struct InitializationPreparationV1 {
    metadata: InitializationMetadataV1,
    staged_keyring: SecretBytes,
}

pub(crate) struct PlannedRotationMetadataInput {
    pub(crate) transition_id: TransitionId,
    pub(crate) owner_id: AuthOwnerId,
    pub(crate) audit_id: AuditId,
    pub(crate) key_activated_at_micros: AuthTimestampMicros,
    pub(crate) source_at_micros: SourceTimestampMicros,
    pub(crate) expected_lifecycle_revision: u64,
    pub(crate) expected_lifecycle_updated_at_micros: SourceTimestampMicros,
    pub(crate) credential_version: u64,
    pub(crate) account_revision: u64,
    pub(crate) password_credential_revision: u64,
    pub(crate) recovery_credential_revision: u64,
}

impl fmt::Debug for PlannedRotationMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlannedRotationMetadataInput([REDACTED])")
    }
}

pub(crate) struct PlannedRotationMetadataV1 {
    transition_id: TransitionId,
    owner_id: AuthOwnerId,
    audit_id: AuditId,
    expected_active_kid: KeyId,
    expected_keyring_version: KeyringVersion,
    expected_key_activated_at_micros: AuthTimestampMicros,
    expected_lifecycle_revision: u64,
    expected_lifecycle_updated_at_micros: SourceTimestampMicros,
    result_kid: KeyId,
    result_keyring_version: KeyringVersion,
    key_activated_at_micros: AuthTimestampMicros,
    source_at_micros: SourceTimestampMicros,
    staged_keyring_length: u32,
    staged_keyring_hash: [u8; STAGED_HASH_BYTES],
    credential_version: u64,
    account_revision: u64,
    password_credential_revision: u64,
    recovery_credential_revision: u64,
}

pub(crate) struct PlannedRotationPreparationV1 {
    metadata: PlannedRotationMetadataV1,
    staged_keyring: SecretBytes,
}

pub(crate) struct RetireMetadataInput {
    pub(crate) transition_id: TransitionId,
    pub(crate) owner_id: AuthOwnerId,
    pub(crate) audit_id: AuditId,
    pub(crate) source_at_micros: SourceTimestampMicros,
    pub(crate) expected_lifecycle_revision: u64,
    pub(crate) expected_lifecycle_updated_at_micros: SourceTimestampMicros,
    pub(crate) credential_version: u64,
    pub(crate) account_revision: u64,
    pub(crate) password_credential_revision: u64,
    pub(crate) recovery_credential_revision: u64,
}

impl fmt::Debug for RetireMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetireMetadataInput([REDACTED])")
    }
}

pub(crate) struct RetireMetadataV1 {
    transition_id: TransitionId,
    owner_id: AuthOwnerId,
    audit_id: AuditId,
    expected_active_kid: KeyId,
    expected_verify_only_kid: KeyId,
    expected_keyring_version: KeyringVersion,
    expected_active_activated_at_micros: AuthTimestampMicros,
    expected_verify_only_activated_at_micros: AuthTimestampMicros,
    expected_verify_until_micros: AuthTimestampMicros,
    expected_lifecycle_revision: u64,
    expected_lifecycle_updated_at_micros: SourceTimestampMicros,
    source_at_micros: SourceTimestampMicros,
    result_keyring_version: KeyringVersion,
    current_keyring_length: u32,
    current_keyring_hash: [u8; STAGED_HASH_BYTES],
    staged_keyring_length: u32,
    staged_keyring_hash: [u8; STAGED_HASH_BYTES],
    credential_version: u64,
    account_revision: u64,
    password_credential_revision: u64,
    recovery_credential_revision: u64,
}

pub(crate) struct RetirePreparationV1 {
    metadata: RetireMetadataV1,
    staged_keyring: SecretBytes,
}

#[derive(Clone, Copy)]
pub(crate) struct PlannedRotationSourceExpectation<'a> {
    metadata: &'a PlannedRotationMetadataV1,
}

#[derive(Clone, Copy)]
pub(crate) struct RetireSourceExpectation<'a> {
    metadata: &'a RetireMetadataV1,
}

pub(crate) trait KeyTransitionSourceExpectation: Copy {
    fn transition_kind(self) -> TransitionKind;
    fn audit_action(self) -> &'static str;
    fn transition_id(&self) -> &[u8; 16];
    fn owner_id(&self) -> &[u8; 16];
    fn audit_id(&self) -> &[u8; 16];
    fn expected_active_kid(&self) -> &str;
    fn expected_keyring_version(self) -> i64;
    fn expected_key_activated_at_micros(self) -> i64;
    fn expected_lifecycle_revision(self) -> i64;
    fn expected_lifecycle_updated_at_micros(self) -> i64;
    fn matches_active_lifecycle(
        self,
        state_revision: u64,
        expected_kid: PersistedLifecycleKeyId,
        keyring_version: PersistedLifecycleKeyringVersion,
        updated_at_micros: PersistedLifecycleTimestamp,
    ) -> bool;
    fn matches_owner_id(self, raw: &[u8]) -> bool;
    fn result_kid(&self) -> &str;
    fn result_keyring_version(self) -> i64;
    fn source_at_micros(self) -> i64;
    fn transitioning_lifecycle_revision(self) -> i64;
    fn final_lifecycle_revision(self) -> i64;
    fn matches_transitioning_lifecycle(
        self,
        state_revision: u64,
        kind: TransitionKind,
        transition_id: PersistedLifecycleTransitionId,
        expected_kid: PersistedLifecycleKeyId,
        keyring_version: PersistedLifecycleKeyringVersion,
        updated_at_micros: PersistedLifecycleTimestamp,
    ) -> bool;
    fn matches_final_active_lifecycle(
        self,
        state_revision: u64,
        expected_kid: PersistedLifecycleKeyId,
        keyring_version: PersistedLifecycleKeyringVersion,
        updated_at_micros: PersistedLifecycleTimestamp,
    ) -> bool;
    fn credential_version(self) -> i64;
    fn account_revision(self) -> i64;
    fn password_credential_revision(self) -> i64;
    fn recovery_credential_revision(self) -> i64;
}

impl PlannedRotationPreparationV1 {
    pub(crate) fn from_current_keyring(
        input: PlannedRotationMetadataInput,
        current_keyring: &Keyring,
    ) -> Result<Self, TransitionContractError> {
        validate_planned_rotation_input(&input)?;
        let staged_keyring = current_keyring
            .planned_rotation(input.key_activated_at_micros)
            .map_err(|_| TransitionContractError::InvalidPlannedRotationKeyring)?;
        Self::from_keyrings(input, current_keyring, staged_keyring)
    }

    pub(super) fn from_keyrings(
        input: PlannedRotationMetadataInput,
        current_keyring: &Keyring,
        staged_keyring: Keyring,
    ) -> Result<Self, TransitionContractError> {
        validate_planned_rotation_input(&input)?;
        let metadata =
            PlannedRotationMetadataV1::from_keyrings(input, current_keyring, &staged_keyring)?;
        let staged_keyring = staged_keyring.encode();
        metadata
            .validate_staged_keyring(SecretBytes::new(staged_keyring.expose_secret().to_vec()))?;
        Ok(Self {
            metadata,
            staged_keyring,
        })
    }

    pub(super) fn transition_artifact(&self) -> TopLevelArtifactName {
        TopLevelArtifactName::Transition {
            kind: TransitionKind::Planned,
            id: self.metadata.transition_id,
        }
    }

    pub(super) fn encoded_metadata(&self) -> Result<SecretBytes, TransitionContractError> {
        self.metadata.encode()
    }

    pub(super) fn staged_keyring_bytes(&self) -> &[u8] {
        self.staged_keyring.expose_secret()
    }

    pub(crate) const fn source_expectation(&self) -> PlannedRotationSourceExpectation<'_> {
        self.metadata.source_expectation()
    }
}

impl fmt::Debug for PlannedRotationPreparationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlannedRotationPreparationV1([REDACTED])")
    }
}

impl RetirePreparationV1 {
    pub(crate) fn from_current_keyring(
        input: RetireMetadataInput,
        current_keyring: &Keyring,
    ) -> Result<Self, TransitionContractError> {
        validate_retire_input(&input)?;
        let retired_at = AuthTimestampMicros::new(input.source_at_micros.get())
            .map_err(|_| TransitionContractError::InvalidRetirementKeyring)?;
        let staged_keyring = current_keyring
            .retire_verify_only(retired_at)
            .map_err(|_| TransitionContractError::InvalidRetirementKeyring)?;
        Self::from_keyrings(input, current_keyring, staged_keyring)
    }

    pub(super) fn from_keyrings(
        input: RetireMetadataInput,
        current_keyring: &Keyring,
        staged_keyring: Keyring,
    ) -> Result<Self, TransitionContractError> {
        validate_retire_input(&input)?;
        let metadata = RetireMetadataV1::from_keyrings(input, current_keyring, &staged_keyring)?;
        let staged_keyring = staged_keyring.encode();
        metadata
            .validate_staged_keyring(SecretBytes::new(staged_keyring.expose_secret().to_vec()))?;
        Ok(Self {
            metadata,
            staged_keyring,
        })
    }

    pub(super) fn transition_artifact(&self) -> TopLevelArtifactName {
        TopLevelArtifactName::Transition {
            kind: TransitionKind::Retire,
            id: self.metadata.transition_id,
        }
    }

    pub(super) fn encoded_metadata(&self) -> Result<SecretBytes, TransitionContractError> {
        self.metadata.encode()
    }

    pub(super) fn staged_keyring_bytes(&self) -> &[u8] {
        self.staged_keyring.expose_secret()
    }

    pub(super) fn matches_current_keyring(&self, bytes: &[u8]) -> bool {
        self.metadata
            .validate_current_keyring(SecretBytes::new(bytes.to_vec()))
            .is_ok()
    }

    pub(crate) const fn source_expectation(&self) -> RetireSourceExpectation<'_> {
        self.metadata.source_expectation()
    }
}

impl fmt::Debug for RetirePreparationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetirePreparationV1([REDACTED])")
    }
}

impl InitializationPreparationV1 {
    pub(crate) fn from_keyring(
        input: InitializationMetadataInput,
        keyring: &Keyring,
    ) -> Result<Self, TransitionContractError> {
        if input.source_at_micros.get() == 0 {
            return Err(TransitionContractError::InvalidMetadata);
        }
        let metadata = InitializationMetadataV1::from_keyring(input, keyring)?;
        let staged_keyring = keyring.encode();
        metadata
            .validate_staged_keyring(SecretBytes::new(staged_keyring.expose_secret().to_vec()))?;
        Ok(Self {
            metadata,
            staged_keyring,
        })
    }

    pub(super) fn transition_artifact(&self) -> TopLevelArtifactName {
        TopLevelArtifactName::Transition {
            kind: TransitionKind::Initialize,
            id: self.metadata.transition_id,
        }
    }

    pub(super) fn encoded_metadata(&self) -> Result<SecretBytes, TransitionContractError> {
        self.metadata.encode()
    }

    pub(super) fn staged_keyring_bytes(&self) -> &[u8] {
        self.staged_keyring.expose_secret()
    }
}

impl fmt::Debug for InitializationPreparationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InitializationPreparationV1([REDACTED])")
    }
}

#[derive(Clone, Copy)]
pub(crate) struct InitializationSourceExpectation<'a> {
    metadata: &'a InitializationMetadataV1,
}

#[derive(Clone, Copy)]
pub(crate) struct InitializationSourceSeed<'a> {
    metadata: &'a InitializationMetadataV1,
}

impl<'a> InitializationSourceSeed<'a> {
    pub(crate) const fn expectation(self) -> InitializationSourceExpectation<'a> {
        InitializationSourceExpectation {
            metadata: self.metadata,
        }
    }

    pub(crate) fn transition_id(self) -> &'a [u8; 16] {
        self.metadata.transition_id.as_bytes()
    }

    pub(crate) fn owner_id(self) -> &'a [u8; 16] {
        self.metadata.owner_id.as_bytes()
    }

    pub(crate) fn audit_id(self) -> &'a [u8; 16] {
        self.metadata.audit_id.as_bytes()
    }

    pub(crate) fn result_kid(self) -> &'a str {
        self.metadata.result_kid.as_str()
    }

    pub(crate) fn result_keyring_version(self) -> i64 {
        i64::try_from(self.metadata.result_keyring_version.get())
            .expect("validated keyring versions fit SQLite integers")
    }

    pub(crate) fn source_at_micros(self) -> i64 {
        i64::try_from(self.metadata.source_at_micros.get())
            .expect("validated source timestamps fit SQLite integers")
    }

    pub(crate) fn login_id(self) -> &'a str {
        str::from_utf8(self.metadata.login_id.as_bytes())
            .expect("validated login identifiers are ASCII")
    }

    pub(crate) fn password_phc(self) -> &'a str {
        self.metadata.password_verifier.expose_phc()
    }

    pub(crate) fn recovery_phc(self) -> &'a str {
        self.metadata.recovery_verifier.expose_phc()
    }

    pub(crate) fn legacy_policy_provenance(self) -> &'a str {
        str::from_utf8(self.metadata.legacy_policy_provenance.as_bytes())
            .expect("validated legacy policy provenance is ASCII")
    }

    #[cfg(test)]
    pub(crate) fn with_test_metadata<R>(
        transition_id: [u8; 16],
        login_id: &[u8],
        signing_seed: [u8; 32],
        run: impl FnOnce(InitializationSourceSeed<'_>) -> R,
    ) -> R {
        const OWNER_ID: [u8; 16] = [
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x84, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44,
        ];
        const AUDIT_ID: [u8; 16] = [
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x45, 0x55, 0x85, 0x55, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55,
        ];
        const SOURCE_AT_MICROS: u64 = 1_700_000_000_000_001;

        let verifier = |fill| {
            let salt = Base64Unpadded::encode_string(&[fill; 16]);
            let output = Base64Unpadded::encode_string(&[fill; 32]);
            ValidatedVerifier::parse(SecretBytes::new(
                format!("$argon2id$v=19$m=65536,t=3,p=4${salt}${output}").into_bytes(),
            ))
            .expect("canonical synthetic verifier")
        };
        let keyring = Keyring::from_test_seeds(1, SOURCE_AT_MICROS - 1, signing_seed, None)
            .expect("synthetic initialization keyring");
        let metadata = InitializationMetadataV1::from_keyring(
            InitializationMetadataInput {
                transition_id: TransitionId::from_uuid(Uuid::from_bytes(transition_id))
                    .expect("transition ID"),
                owner_id: AuthOwnerId::from_uuid(Uuid::from_bytes(OWNER_ID)).expect("owner ID"),
                audit_id: AuditId::from_uuid(Uuid::from_bytes(AUDIT_ID)).expect("audit ID"),
                source_at_micros: SourceTimestampMicros::new(SOURCE_AT_MICROS)
                    .expect("source timestamp"),
                login_id: LoginId::parse(login_id).expect("login ID"),
                password_verifier: verifier(0x61),
                recovery_verifier: verifier(0x62),
            },
            &keyring,
        )
        .expect("initialization metadata");
        run(InitializationSourceSeed {
            metadata: &metadata,
        })
    }
}

impl fmt::Debug for InitializationSourceSeed<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InitializationSourceSeed([REDACTED])")
    }
}

impl<'a> InitializationSourceExpectation<'a> {
    pub(crate) fn uses_no_blocklist_check_policy(self) -> bool {
        self.metadata.legacy_policy_provenance.as_bytes() == NO_BLOCKLIST_CHECK_SENTINEL.as_bytes()
    }

    pub(crate) fn transition_id(self) -> &'a [u8; 16] {
        self.metadata.transition_id.as_bytes()
    }

    pub(crate) fn result_kid(self) -> &'a str {
        self.metadata.result_kid.as_str()
    }

    pub(crate) fn result_keyring_version(self) -> i64 {
        i64::try_from(self.metadata.result_keyring_version.get())
            .expect("validated keyring versions fit SQLite integers")
    }

    pub(crate) fn source_at_micros(self) -> i64 {
        i64::try_from(self.metadata.source_at_micros.get())
            .expect("validated source timestamps fit SQLite integers")
    }

    pub(crate) fn matches_lifecycle(
        self,
        transition_id: PersistedLifecycleTransitionId,
        expected_kid: PersistedLifecycleKeyId,
        keyring_version: PersistedLifecycleKeyringVersion,
        updated_at_micros: PersistedLifecycleTimestamp,
    ) -> bool {
        transition_id.0 == self.metadata.transition_id
            && expected_kid.0 == self.metadata.result_kid
            && keyring_version.0 == self.metadata.result_keyring_version
            && updated_at_micros.0 == self.metadata.source_at_micros
    }

    pub(crate) fn matches_active_lifecycle(
        self,
        expected_kid: PersistedLifecycleKeyId,
        keyring_version: PersistedLifecycleKeyringVersion,
        updated_at_micros: PersistedLifecycleTimestamp,
    ) -> bool {
        expected_kid.0 == self.metadata.result_kid
            && keyring_version.0 == self.metadata.result_keyring_version
            && updated_at_micros.0 == self.metadata.source_at_micros
    }

    pub(crate) fn matches_owner_id(self, raw: &[u8]) -> bool {
        raw == self.metadata.owner_id.as_bytes()
    }

    pub(crate) fn matches_audit_id(self, raw: &[u8]) -> bool {
        raw == self.metadata.audit_id.as_bytes()
    }

    pub(crate) fn matches_login_id(self, raw: &[u8]) -> bool {
        raw == self.metadata.login_id.as_bytes()
    }

    pub(crate) fn matches_password_phc(self, raw: &[u8]) -> bool {
        raw == self.metadata.password_verifier.expose_phc().as_bytes()
    }

    pub(crate) fn matches_recovery_phc(self, raw: &[u8]) -> bool {
        raw == self.metadata.recovery_verifier.expose_phc().as_bytes()
    }

    pub(crate) fn matches_legacy_policy_provenance(self, raw: &[u8]) -> bool {
        raw == self.metadata.legacy_policy_provenance.as_bytes()
    }

    pub(crate) fn is_canonical_owner_id(raw: &[u8]) -> bool {
        AuthOwnerId::from_bytes(raw).is_ok()
    }

    pub(crate) fn is_canonical_audit_id(raw: &[u8]) -> bool {
        AuditId::from_bytes(raw).is_ok()
    }

    pub(crate) fn is_canonical_login_id(raw: &[u8]) -> bool {
        LoginId::parse(raw).is_ok()
    }

    pub(crate) fn is_canonical_verifier(raw: &[u8]) -> bool {
        ValidatedVerifier::is_canonical_encoded(raw)
    }

    pub(crate) fn verifiers_have_independent_salts(left: &[u8], right: &[u8]) -> bool {
        ValidatedVerifier::encoded_salts_are_independent(left, right)
    }

    pub(crate) fn is_canonical_legacy_policy_provenance(raw: &[u8]) -> bool {
        LegacyPolicyProvenance::parse(raw).is_ok()
    }
}

impl fmt::Debug for InitializationSourceExpectation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InitializationSourceExpectation([REDACTED])")
    }
}

impl InitializationMetadataV1 {
    pub(crate) fn from_keyring(
        input: InitializationMetadataInput,
        keyring: &Keyring,
    ) -> Result<Self, TransitionContractError> {
        if keyring.version().get() != 1 {
            return Err(TransitionContractError::InvalidInitializationKeyring);
        }
        let key_activated_at_micros = keyring.active_activated_at();
        if input.source_at_micros.get() < key_activated_at_micros.get() {
            return Err(TransitionContractError::InvalidMetadata);
        }
        let staged_keyring = keyring.encode();
        let staged_bytes = staged_keyring.expose_secret();
        if staged_bytes.len() != ACTIVE_ONLY_LENGTH {
            return Err(TransitionContractError::InvalidInitializationKeyring);
        }
        validate_independent_verifier_salts(&input.password_verifier, &input.recovery_verifier)?;
        let staged_keyring_hash = Sha256::digest(staged_bytes).into();
        let metadata = Self {
            transition_id: input.transition_id,
            owner_id: input.owner_id,
            audit_id: input.audit_id,
            result_kid: keyring.active_kid(),
            result_keyring_version: keyring.version(),
            key_activated_at_micros,
            source_at_micros: input.source_at_micros,
            staged_keyring_length: u32::try_from(staged_bytes.len())
                .map_err(|_| TransitionContractError::InvalidInitializationKeyring)?,
            staged_keyring_hash,
            login_id: input.login_id,
            password_verifier: input.password_verifier,
            recovery_verifier: input.recovery_verifier,
            legacy_policy_provenance: LegacyPolicyProvenance::parse(
                NO_BLOCKLIST_CHECK_SENTINEL.as_bytes(),
            )?,
        };
        metadata.validate_encoded_length()?;
        Ok(metadata)
    }

    pub(crate) fn decode(encoded: SecretBytes) -> Result<Self, TransitionContractError> {
        let bytes = encoded.expose_secret();
        if bytes.len() > MAX_INITIALIZATION_METADATA_BYTES
            || bytes.len() < METADATA_FIXED_HEADER_BYTES + 1 + METADATA_CHECKSUM_BYTES
            || bytes.get(..METADATA_MAGIC.len()) != Some(METADATA_MAGIC.as_slice())
        {
            return Err(TransitionContractError::InvalidMetadata);
        }
        if read_u16(bytes, 8)? != METADATA_FORMAT_VERSION {
            return Err(TransitionContractError::UnsupportedMetadataVersion);
        }
        if usize::try_from(read_u32(bytes, 10)?).ok() != Some(bytes.len()) {
            return Err(TransitionContractError::InvalidMetadata);
        }
        if bytes[14] != INITIALIZE_METADATA_TAG {
            return Err(TransitionContractError::UnsupportedMetadataKind);
        }

        let checksum_offset = bytes
            .len()
            .checked_sub(METADATA_CHECKSUM_BYTES)
            .ok_or(TransitionContractError::InvalidMetadata)?;
        if Sha256::digest(&bytes[..checksum_offset]).as_slice() != &bytes[checksum_offset..] {
            return Err(TransitionContractError::InvalidMetadata);
        }

        let transition_id = TransitionId::from_bytes(read_slice(bytes, 15, 16)?)?;
        let owner_id = AuthOwnerId::from_bytes(read_slice(bytes, 31, 16)?)?;
        let audit_id = AuditId::from_bytes(read_slice(bytes, 47, 16)?)?;
        let result_kid = KeyId::from_stored_bytes(read_slice(bytes, 63, KID_BYTES)?)
            .map_err(|_| TransitionContractError::InvalidMetadata)?;
        let result_keyring_version = KeyringVersion::new(read_u64(bytes, 106)?)
            .map_err(|_| TransitionContractError::InvalidMetadata)?;
        if result_keyring_version.get() != 1 {
            return Err(TransitionContractError::InvalidInitializationKeyring);
        }
        let key_activated_at_micros = AuthTimestampMicros::new(read_u64(bytes, 114)?)
            .map_err(|_| TransitionContractError::InvalidMetadata)?;
        let source_at_micros = SourceTimestampMicros::new(read_u64(bytes, 122)?)?;
        if source_at_micros.get() < key_activated_at_micros.get() {
            return Err(TransitionContractError::InvalidMetadata);
        }
        let staged_keyring_length = read_u32(bytes, 130)?;
        if staged_keyring_length as usize != ACTIVE_ONLY_LENGTH {
            return Err(TransitionContractError::InvalidInitializationKeyring);
        }
        let mut staged_keyring_hash = [0_u8; STAGED_HASH_BYTES];
        staged_keyring_hash.copy_from_slice(read_slice(bytes, 134, STAGED_HASH_BYTES)?);

        let mut offset = METADATA_FIXED_HEADER_BYTES;
        let login_length = usize::from(read_byte(bytes, &mut offset, checksum_offset)?);
        let login_id = LoginId::parse(read_field(
            bytes,
            &mut offset,
            login_length,
            checksum_offset,
        )?)?;
        let password_length = usize::from(read_u16_at_cursor(bytes, &mut offset, checksum_offset)?);
        let password_verifier = ValidatedVerifier::parse(SecretBytes::new(
            read_field(bytes, &mut offset, password_length, checksum_offset)?.to_vec(),
        ))
        .map_err(|_| TransitionContractError::InvalidMetadata)?;
        let recovery_length = usize::from(read_u16_at_cursor(bytes, &mut offset, checksum_offset)?);
        let recovery_verifier = ValidatedVerifier::parse(SecretBytes::new(
            read_field(bytes, &mut offset, recovery_length, checksum_offset)?.to_vec(),
        ))
        .map_err(|_| TransitionContractError::InvalidMetadata)?;
        let provenance_length = usize::from(read_byte(bytes, &mut offset, checksum_offset)?);
        let legacy_policy_provenance = LegacyPolicyProvenance::parse(read_field(
            bytes,
            &mut offset,
            provenance_length,
            checksum_offset,
        )?)?;
        if offset != checksum_offset {
            return Err(TransitionContractError::InvalidMetadata);
        }
        validate_independent_verifier_salts(&password_verifier, &recovery_verifier)?;

        let metadata = Self {
            transition_id,
            owner_id,
            audit_id,
            result_kid,
            result_keyring_version,
            key_activated_at_micros,
            source_at_micros,
            staged_keyring_length,
            staged_keyring_hash,
            login_id,
            password_verifier,
            recovery_verifier,
            legacy_policy_provenance,
        };
        let canonical = metadata.encode()?;
        if canonical.expose_secret() != bytes {
            return Err(TransitionContractError::InvalidMetadata);
        }
        Ok(metadata)
    }

    pub(crate) fn encode(&self) -> Result<SecretBytes, TransitionContractError> {
        let total_length = self.encoded_length()?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(total_length));
        bytes.extend_from_slice(METADATA_MAGIC);
        bytes.extend_from_slice(&METADATA_FORMAT_VERSION.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(total_length)
                .map_err(|_| TransitionContractError::InvalidMetadata)?
                .to_be_bytes(),
        );
        bytes.push(INITIALIZE_METADATA_TAG);
        bytes.extend_from_slice(self.transition_id.as_bytes());
        bytes.extend_from_slice(self.owner_id.as_bytes());
        bytes.extend_from_slice(self.audit_id.as_bytes());
        bytes.extend_from_slice(self.result_kid.as_bytes());
        bytes.extend_from_slice(&self.result_keyring_version.get().to_be_bytes());
        bytes.extend_from_slice(&self.key_activated_at_micros.get().to_be_bytes());
        bytes.extend_from_slice(&self.source_at_micros.get().to_be_bytes());
        bytes.extend_from_slice(&self.staged_keyring_length.to_be_bytes());
        bytes.extend_from_slice(&self.staged_keyring_hash);
        push_u8_length_field(&mut bytes, self.login_id.as_bytes())?;
        push_u16_length_field(&mut bytes, self.password_verifier.expose_phc().as_bytes())?;
        push_u16_length_field(&mut bytes, self.recovery_verifier.expose_phc().as_bytes())?;
        push_u8_length_field(&mut bytes, self.legacy_policy_provenance.as_bytes())?;
        let checksum = Sha256::digest(bytes.as_slice());
        bytes.extend_from_slice(&checksum);
        if bytes.len() != total_length {
            return Err(TransitionContractError::InvalidMetadata);
        }
        Ok(SecretBytes::from_zeroizing(bytes))
    }

    pub(crate) fn validate_staged_keyring(
        &self,
        staged_keyring: SecretBytes,
    ) -> Result<Keyring, TransitionContractError> {
        if !self.matches_staged_keyring(staged_keyring.expose_secret()) {
            return Err(TransitionContractError::InvalidInitializationKeyring);
        }
        let keyring = Keyring::decode(staged_keyring)
            .map_err(|_| TransitionContractError::InvalidInitializationKeyring)?;
        if keyring.version() != self.result_keyring_version
            || keyring.active_kid() != self.result_kid
            || keyring.active_activated_at() != self.key_activated_at_micros
            || keyring.encode().expose_secret().len() != ACTIVE_ONLY_LENGTH
        {
            return Err(TransitionContractError::InvalidInitializationKeyring);
        }
        Ok(keyring)
    }

    pub(crate) const fn source_expectation(&self) -> InitializationSourceExpectation<'_> {
        InitializationSourceExpectation { metadata: self }
    }

    pub(crate) fn sentinel_source_seed(&self) -> Option<InitializationSourceSeed<'_>> {
        let expectation = self.source_expectation();
        (self.source_at_micros.get() > 0 && expectation.uses_no_blocklist_check_policy())
            .then_some(InitializationSourceSeed { metadata: self })
    }

    fn matches_staged_keyring(&self, staged_keyring: &[u8]) -> bool {
        staged_keyring.len() == self.staged_keyring_length as usize
            && Sha256::digest(staged_keyring).as_slice() == self.staged_keyring_hash
    }

    pub(crate) fn matches_transition_artifact(&self, artifact: TopLevelArtifactName) -> bool {
        matches!(
            artifact,
            TopLevelArtifactName::Transition {
                kind: TransitionKind::Initialize,
                id
            } if id == self.transition_id
        )
    }

    pub(super) fn matches_reservation_artifact(&self, artifact: TopLevelArtifactName) -> bool {
        matches!(
            artifact,
            TopLevelArtifactName::Transition {
                kind: TransitionKind::Initialize,
                id
            } | TopLevelArtifactName::Cleanup {
                kind: TransitionKind::Initialize,
                id
            } if id == self.transition_id
        )
    }

    fn encoded_length(&self) -> Result<usize, TransitionContractError> {
        METADATA_FIXED_HEADER_BYTES
            .checked_add(1)
            .and_then(|length| length.checked_add(self.login_id.as_bytes().len()))
            .and_then(|length| length.checked_add(2))
            .and_then(|length| length.checked_add(self.password_verifier.expose_phc().len()))
            .and_then(|length| length.checked_add(2))
            .and_then(|length| length.checked_add(self.recovery_verifier.expose_phc().len()))
            .and_then(|length| length.checked_add(1))
            .and_then(|length| length.checked_add(self.legacy_policy_provenance.as_bytes().len()))
            .and_then(|length| length.checked_add(METADATA_CHECKSUM_BYTES))
            .filter(|length| *length <= MAX_INITIALIZATION_METADATA_BYTES)
            .ok_or(TransitionContractError::InvalidMetadata)
    }

    fn validate_encoded_length(&self) -> Result<(), TransitionContractError> {
        self.encoded_length().map(|_| ())
    }
}

impl PlannedRotationMetadataV1 {
    fn from_keyrings(
        input: PlannedRotationMetadataInput,
        current_keyring: &Keyring,
        staged_keyring: &Keyring,
    ) -> Result<Self, TransitionContractError> {
        if current_keyring.encode().expose_secret().len() != ACTIVE_ONLY_LENGTH
            || staged_keyring.encode().expose_secret().len()
                != super::keyring::WITH_VERIFY_ONLY_LENGTH
        {
            return Err(TransitionContractError::InvalidPlannedRotationKeyring);
        }
        let expected_result_version = current_keyring
            .version()
            .get()
            .checked_add(1)
            .ok_or(TransitionContractError::InvalidPlannedRotationKeyring)?;
        let Some((previous_kid, previous_activated_at, _)) = staged_keyring.verify_only_facts()
        else {
            return Err(TransitionContractError::InvalidPlannedRotationKeyring);
        };
        if staged_keyring.version().get() != expected_result_version
            || staged_keyring.active_activated_at() != input.key_activated_at_micros
            || staged_keyring.active_kid() == current_keyring.active_kid()
            || previous_kid != current_keyring.active_kid()
            || previous_activated_at != current_keyring.active_activated_at()
        {
            return Err(TransitionContractError::InvalidPlannedRotationKeyring);
        }

        let staged_bytes = staged_keyring.encode();
        let staged_bytes = staged_bytes.expose_secret();
        let metadata = Self {
            transition_id: input.transition_id,
            owner_id: input.owner_id,
            audit_id: input.audit_id,
            expected_active_kid: current_keyring.active_kid(),
            expected_keyring_version: current_keyring.version(),
            expected_key_activated_at_micros: current_keyring.active_activated_at(),
            expected_lifecycle_revision: input.expected_lifecycle_revision,
            expected_lifecycle_updated_at_micros: input.expected_lifecycle_updated_at_micros,
            result_kid: staged_keyring.active_kid(),
            result_keyring_version: staged_keyring.version(),
            key_activated_at_micros: staged_keyring.active_activated_at(),
            source_at_micros: input.source_at_micros,
            staged_keyring_length: u32::try_from(staged_bytes.len())
                .map_err(|_| TransitionContractError::InvalidPlannedRotationKeyring)?,
            staged_keyring_hash: Sha256::digest(staged_bytes).into(),
            credential_version: input.credential_version,
            account_revision: input.account_revision,
            password_credential_revision: input.password_credential_revision,
            recovery_credential_revision: input.recovery_credential_revision,
        };
        metadata.validate_semantics()?;
        Ok(metadata)
    }

    pub(crate) fn decode(encoded: SecretBytes) -> Result<Self, TransitionContractError> {
        let bytes = encoded.expose_secret();
        if bytes.len() != PLANNED_ROTATION_METADATA_BYTES
            || bytes.get(..METADATA_MAGIC.len()) != Some(METADATA_MAGIC.as_slice())
        {
            return Err(TransitionContractError::InvalidMetadata);
        }
        if read_u16(bytes, 8)? != METADATA_FORMAT_VERSION {
            return Err(TransitionContractError::UnsupportedMetadataVersion);
        }
        if usize::try_from(read_u32(bytes, 10)?).ok() != Some(bytes.len()) {
            return Err(TransitionContractError::InvalidMetadata);
        }
        if bytes[14] != PLANNED_METADATA_TAG {
            return Err(TransitionContractError::UnsupportedMetadataKind);
        }
        if Sha256::digest(&bytes[..PLANNED_ROTATION_CHECKSUM_OFFSET]).as_slice()
            != &bytes[PLANNED_ROTATION_CHECKSUM_OFFSET..]
        {
            return Err(TransitionContractError::InvalidMetadata);
        }

        let metadata = Self {
            transition_id: TransitionId::from_bytes(read_slice(bytes, 15, 16)?)?,
            owner_id: AuthOwnerId::from_bytes(read_slice(bytes, 31, 16)?)?,
            audit_id: AuditId::from_bytes(read_slice(bytes, 47, 16)?)?,
            expected_active_kid: KeyId::from_stored_bytes(read_slice(bytes, 63, KID_BYTES)?)
                .map_err(|_| TransitionContractError::InvalidMetadata)?,
            expected_keyring_version: KeyringVersion::new(read_u64(bytes, 106)?)
                .map_err(|_| TransitionContractError::InvalidMetadata)?,
            expected_key_activated_at_micros: AuthTimestampMicros::new(read_u64(bytes, 114)?)
                .map_err(|_| TransitionContractError::InvalidMetadata)?,
            expected_lifecycle_revision: read_u64(bytes, 122)?,
            expected_lifecycle_updated_at_micros: SourceTimestampMicros::new(read_u64(
                bytes, 130,
            )?)?,
            result_kid: KeyId::from_stored_bytes(read_slice(bytes, 138, KID_BYTES)?)
                .map_err(|_| TransitionContractError::InvalidMetadata)?,
            result_keyring_version: KeyringVersion::new(read_u64(bytes, 181)?)
                .map_err(|_| TransitionContractError::InvalidMetadata)?,
            key_activated_at_micros: AuthTimestampMicros::new(read_u64(bytes, 189)?)
                .map_err(|_| TransitionContractError::InvalidMetadata)?,
            source_at_micros: SourceTimestampMicros::new(read_u64(bytes, 197)?)?,
            staged_keyring_length: read_u32(bytes, 205)?,
            staged_keyring_hash: read_slice(bytes, 209, STAGED_HASH_BYTES)?
                .try_into()
                .map_err(|_| TransitionContractError::InvalidMetadata)?,
            credential_version: read_u64(bytes, 241)?,
            account_revision: read_u64(bytes, 249)?,
            password_credential_revision: read_u64(bytes, 257)?,
            recovery_credential_revision: read_u64(bytes, 265)?,
        };
        metadata.validate_semantics()?;
        let canonical = metadata.encode()?;
        if canonical.expose_secret() != bytes {
            return Err(TransitionContractError::InvalidMetadata);
        }
        Ok(metadata)
    }

    pub(crate) fn encode(&self) -> Result<SecretBytes, TransitionContractError> {
        self.validate_semantics()?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(PLANNED_ROTATION_METADATA_BYTES));
        bytes.extend_from_slice(METADATA_MAGIC);
        bytes.extend_from_slice(&METADATA_FORMAT_VERSION.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(PLANNED_ROTATION_METADATA_BYTES)
                .expect("planned metadata length fits u32")
                .to_be_bytes(),
        );
        bytes.push(PLANNED_METADATA_TAG);
        bytes.extend_from_slice(self.transition_id.as_bytes());
        bytes.extend_from_slice(self.owner_id.as_bytes());
        bytes.extend_from_slice(self.audit_id.as_bytes());
        bytes.extend_from_slice(self.expected_active_kid.as_bytes());
        bytes.extend_from_slice(&self.expected_keyring_version.get().to_be_bytes());
        bytes.extend_from_slice(&self.expected_key_activated_at_micros.get().to_be_bytes());
        bytes.extend_from_slice(&self.expected_lifecycle_revision.to_be_bytes());
        bytes.extend_from_slice(
            &self
                .expected_lifecycle_updated_at_micros
                .get()
                .to_be_bytes(),
        );
        bytes.extend_from_slice(self.result_kid.as_bytes());
        bytes.extend_from_slice(&self.result_keyring_version.get().to_be_bytes());
        bytes.extend_from_slice(&self.key_activated_at_micros.get().to_be_bytes());
        bytes.extend_from_slice(&self.source_at_micros.get().to_be_bytes());
        bytes.extend_from_slice(&self.staged_keyring_length.to_be_bytes());
        bytes.extend_from_slice(&self.staged_keyring_hash);
        bytes.extend_from_slice(&self.credential_version.to_be_bytes());
        bytes.extend_from_slice(&self.account_revision.to_be_bytes());
        bytes.extend_from_slice(&self.password_credential_revision.to_be_bytes());
        bytes.extend_from_slice(&self.recovery_credential_revision.to_be_bytes());
        if bytes.len() != PLANNED_ROTATION_CHECKSUM_OFFSET {
            return Err(TransitionContractError::InvalidMetadata);
        }
        let checksum = Sha256::digest(bytes.as_slice());
        bytes.extend_from_slice(&checksum);
        Ok(SecretBytes::from_zeroizing(bytes))
    }

    pub(crate) fn validate_staged_keyring(
        &self,
        staged_keyring: SecretBytes,
    ) -> Result<Keyring, TransitionContractError> {
        let bytes = staged_keyring.expose_secret();
        if bytes.len() != self.staged_keyring_length as usize
            || Sha256::digest(bytes).as_slice() != self.staged_keyring_hash
        {
            return Err(TransitionContractError::InvalidPlannedRotationKeyring);
        }
        let keyring = Keyring::decode(staged_keyring)
            .map_err(|_| TransitionContractError::InvalidPlannedRotationKeyring)?;
        let Some((previous_kid, previous_activated_at, _)) = keyring.verify_only_facts() else {
            return Err(TransitionContractError::InvalidPlannedRotationKeyring);
        };
        if keyring.encode().expose_secret().len() != super::keyring::WITH_VERIFY_ONLY_LENGTH
            || keyring.version() != self.result_keyring_version
            || keyring.active_kid() != self.result_kid
            || keyring.active_activated_at() != self.key_activated_at_micros
            || previous_kid != self.expected_active_kid
            || previous_activated_at != self.expected_key_activated_at_micros
        {
            return Err(TransitionContractError::InvalidPlannedRotationKeyring);
        }
        Ok(keyring)
    }

    pub(crate) const fn source_expectation(&self) -> PlannedRotationSourceExpectation<'_> {
        PlannedRotationSourceExpectation { metadata: self }
    }

    pub(super) fn matches_reservation_artifact(&self, artifact: TopLevelArtifactName) -> bool {
        artifact
            == (TopLevelArtifactName::Transition {
                kind: TransitionKind::Planned,
                id: self.transition_id,
            })
            || artifact
                == (TopLevelArtifactName::Cleanup {
                    kind: TransitionKind::Planned,
                    id: self.transition_id,
                })
    }

    fn validate_semantics(&self) -> Result<(), TransitionContractError> {
        if self.expected_active_kid == self.result_kid
            || self.expected_keyring_version.get().checked_add(1)
                != Some(self.result_keyring_version.get())
            || self.key_activated_at_micros < self.expected_key_activated_at_micros
            || self.source_at_micros.get() == 0
            || self.expected_lifecycle_updated_at_micros.get() == 0
            || self.source_at_micros.get() < self.key_activated_at_micros.get()
            || self.source_at_micros.get() < self.expected_lifecycle_updated_at_micros.get()
            || self.staged_keyring_length as usize != super::keyring::WITH_VERIFY_ONLY_LENGTH
            || !is_positive_sqlite_integer(self.expected_lifecycle_revision)
            || self.expected_lifecycle_revision > (i64::MAX as u64).saturating_sub(2)
            || !is_positive_sqlite_integer(self.credential_version)
            || !is_positive_sqlite_integer(self.account_revision)
            || !is_positive_sqlite_integer(self.password_credential_revision)
            || !is_positive_sqlite_integer(self.recovery_credential_revision)
        {
            return Err(TransitionContractError::InvalidMetadata);
        }
        Ok(())
    }
}

impl RetireMetadataV1 {
    fn from_keyrings(
        input: RetireMetadataInput,
        current_keyring: &Keyring,
        staged_keyring: &Keyring,
    ) -> Result<Self, TransitionContractError> {
        let current_bytes = current_keyring.encode();
        let staged_bytes = staged_keyring.encode();
        if current_bytes.expose_secret().len() != WITH_VERIFY_ONLY_LENGTH
            || staged_bytes.expose_secret().len() != ACTIVE_ONLY_LENGTH
        {
            return Err(TransitionContractError::InvalidRetirementKeyring);
        }
        let Some((
            expected_verify_only_kid,
            expected_verify_only_activated_at_micros,
            expected_verify_until_micros,
        )) = current_keyring.verify_only_facts()
        else {
            return Err(TransitionContractError::InvalidRetirementKeyring);
        };
        let expected_result_version = current_keyring
            .version()
            .get()
            .checked_add(1)
            .ok_or(TransitionContractError::InvalidRetirementKeyring)?;
        if staged_keyring.version().get() != expected_result_version
            || staged_keyring.active_kid() != current_keyring.active_kid()
            || staged_keyring.active_activated_at() != current_keyring.active_activated_at()
            || staged_keyring.verify_only_facts().is_some()
            || input.source_at_micros.get() < expected_verify_until_micros.get()
        {
            return Err(TransitionContractError::InvalidRetirementKeyring);
        }

        let metadata = Self {
            transition_id: input.transition_id,
            owner_id: input.owner_id,
            audit_id: input.audit_id,
            expected_active_kid: current_keyring.active_kid(),
            expected_verify_only_kid,
            expected_keyring_version: current_keyring.version(),
            expected_active_activated_at_micros: current_keyring.active_activated_at(),
            expected_verify_only_activated_at_micros,
            expected_verify_until_micros,
            expected_lifecycle_revision: input.expected_lifecycle_revision,
            expected_lifecycle_updated_at_micros: input.expected_lifecycle_updated_at_micros,
            source_at_micros: input.source_at_micros,
            result_keyring_version: staged_keyring.version(),
            current_keyring_length: u32::try_from(current_bytes.expose_secret().len())
                .map_err(|_| TransitionContractError::InvalidRetirementKeyring)?,
            current_keyring_hash: Sha256::digest(current_bytes.expose_secret()).into(),
            staged_keyring_length: u32::try_from(staged_bytes.expose_secret().len())
                .map_err(|_| TransitionContractError::InvalidRetirementKeyring)?,
            staged_keyring_hash: Sha256::digest(staged_bytes.expose_secret()).into(),
            credential_version: input.credential_version,
            account_revision: input.account_revision,
            password_credential_revision: input.password_credential_revision,
            recovery_credential_revision: input.recovery_credential_revision,
        };
        metadata.validate_semantics()?;
        Ok(metadata)
    }

    pub(crate) fn decode(encoded: SecretBytes) -> Result<Self, TransitionContractError> {
        let bytes = encoded.expose_secret();
        if bytes.len() != RETIRE_METADATA_BYTES
            || bytes.get(..METADATA_MAGIC.len()) != Some(METADATA_MAGIC.as_slice())
        {
            return Err(TransitionContractError::InvalidMetadata);
        }
        if read_u16(bytes, 8)? != METADATA_FORMAT_VERSION {
            return Err(TransitionContractError::UnsupportedMetadataVersion);
        }
        if usize::try_from(read_u32(bytes, 10)?).ok() != Some(bytes.len()) {
            return Err(TransitionContractError::InvalidMetadata);
        }
        if bytes[14] != RETIRE_METADATA_TAG {
            return Err(TransitionContractError::UnsupportedMetadataKind);
        }
        if Sha256::digest(&bytes[..RETIRE_CHECKSUM_OFFSET]).as_slice()
            != &bytes[RETIRE_CHECKSUM_OFFSET..]
        {
            return Err(TransitionContractError::InvalidMetadata);
        }

        let metadata = Self {
            transition_id: TransitionId::from_bytes(read_slice(bytes, 15, 16)?)?,
            owner_id: AuthOwnerId::from_bytes(read_slice(bytes, 31, 16)?)?,
            audit_id: AuditId::from_bytes(read_slice(bytes, 47, 16)?)?,
            expected_active_kid: KeyId::from_stored_bytes(read_slice(bytes, 63, KID_BYTES)?)
                .map_err(|_| TransitionContractError::InvalidMetadata)?,
            expected_verify_only_kid: KeyId::from_stored_bytes(read_slice(bytes, 106, KID_BYTES)?)
                .map_err(|_| TransitionContractError::InvalidMetadata)?,
            expected_keyring_version: KeyringVersion::new(read_u64(bytes, 149)?)
                .map_err(|_| TransitionContractError::InvalidMetadata)?,
            expected_active_activated_at_micros: AuthTimestampMicros::new(read_u64(bytes, 157)?)
                .map_err(|_| TransitionContractError::InvalidMetadata)?,
            expected_verify_only_activated_at_micros: AuthTimestampMicros::new(read_u64(
                bytes, 165,
            )?)
            .map_err(|_| TransitionContractError::InvalidMetadata)?,
            expected_verify_until_micros: AuthTimestampMicros::new(read_u64(bytes, 173)?)
                .map_err(|_| TransitionContractError::InvalidMetadata)?,
            expected_lifecycle_revision: read_u64(bytes, 181)?,
            expected_lifecycle_updated_at_micros: SourceTimestampMicros::new(read_u64(
                bytes, 189,
            )?)?,
            source_at_micros: SourceTimestampMicros::new(read_u64(bytes, 197)?)?,
            result_keyring_version: KeyringVersion::new(read_u64(bytes, 205)?)
                .map_err(|_| TransitionContractError::InvalidMetadata)?,
            current_keyring_length: read_u32(bytes, 213)?,
            current_keyring_hash: read_slice(bytes, 217, STAGED_HASH_BYTES)?
                .try_into()
                .map_err(|_| TransitionContractError::InvalidMetadata)?,
            staged_keyring_length: read_u32(bytes, 249)?,
            staged_keyring_hash: read_slice(bytes, 253, STAGED_HASH_BYTES)?
                .try_into()
                .map_err(|_| TransitionContractError::InvalidMetadata)?,
            credential_version: read_u64(bytes, 285)?,
            account_revision: read_u64(bytes, 293)?,
            password_credential_revision: read_u64(bytes, 301)?,
            recovery_credential_revision: read_u64(bytes, 309)?,
        };
        metadata.validate_semantics()?;
        let canonical = metadata.encode()?;
        if canonical.expose_secret() != bytes {
            return Err(TransitionContractError::InvalidMetadata);
        }
        Ok(metadata)
    }

    pub(crate) fn encode(&self) -> Result<SecretBytes, TransitionContractError> {
        self.validate_semantics()?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(RETIRE_METADATA_BYTES));
        bytes.extend_from_slice(METADATA_MAGIC);
        bytes.extend_from_slice(&METADATA_FORMAT_VERSION.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(RETIRE_METADATA_BYTES)
                .expect("retire metadata length fits u32")
                .to_be_bytes(),
        );
        bytes.push(RETIRE_METADATA_TAG);
        bytes.extend_from_slice(self.transition_id.as_bytes());
        bytes.extend_from_slice(self.owner_id.as_bytes());
        bytes.extend_from_slice(self.audit_id.as_bytes());
        bytes.extend_from_slice(self.expected_active_kid.as_bytes());
        bytes.extend_from_slice(self.expected_verify_only_kid.as_bytes());
        bytes.extend_from_slice(&self.expected_keyring_version.get().to_be_bytes());
        bytes.extend_from_slice(&self.expected_active_activated_at_micros.get().to_be_bytes());
        bytes.extend_from_slice(
            &self
                .expected_verify_only_activated_at_micros
                .get()
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.expected_verify_until_micros.get().to_be_bytes());
        bytes.extend_from_slice(&self.expected_lifecycle_revision.to_be_bytes());
        bytes.extend_from_slice(
            &self
                .expected_lifecycle_updated_at_micros
                .get()
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.source_at_micros.get().to_be_bytes());
        bytes.extend_from_slice(&self.result_keyring_version.get().to_be_bytes());
        bytes.extend_from_slice(&self.current_keyring_length.to_be_bytes());
        bytes.extend_from_slice(&self.current_keyring_hash);
        bytes.extend_from_slice(&self.staged_keyring_length.to_be_bytes());
        bytes.extend_from_slice(&self.staged_keyring_hash);
        bytes.extend_from_slice(&self.credential_version.to_be_bytes());
        bytes.extend_from_slice(&self.account_revision.to_be_bytes());
        bytes.extend_from_slice(&self.password_credential_revision.to_be_bytes());
        bytes.extend_from_slice(&self.recovery_credential_revision.to_be_bytes());
        if bytes.len() != RETIRE_CHECKSUM_OFFSET {
            return Err(TransitionContractError::InvalidMetadata);
        }
        let checksum = Sha256::digest(bytes.as_slice());
        bytes.extend_from_slice(&checksum);
        Ok(SecretBytes::from_zeroizing(bytes))
    }

    pub(crate) fn validate_current_keyring(
        &self,
        current_keyring: SecretBytes,
    ) -> Result<Keyring, TransitionContractError> {
        let bytes = current_keyring.expose_secret();
        if bytes.len() != self.current_keyring_length as usize
            || Sha256::digest(bytes).as_slice() != self.current_keyring_hash
        {
            return Err(TransitionContractError::InvalidRetirementKeyring);
        }
        let keyring = Keyring::decode(current_keyring)
            .map_err(|_| TransitionContractError::InvalidRetirementKeyring)?;
        let Some((verify_kid, verify_activated_at, verify_until)) = keyring.verify_only_facts()
        else {
            return Err(TransitionContractError::InvalidRetirementKeyring);
        };
        if keyring.encode().expose_secret().len() != WITH_VERIFY_ONLY_LENGTH
            || keyring.version() != self.expected_keyring_version
            || keyring.active_kid() != self.expected_active_kid
            || keyring.active_activated_at() != self.expected_active_activated_at_micros
            || verify_kid != self.expected_verify_only_kid
            || verify_activated_at != self.expected_verify_only_activated_at_micros
            || verify_until != self.expected_verify_until_micros
        {
            return Err(TransitionContractError::InvalidRetirementKeyring);
        }
        Ok(keyring)
    }

    pub(crate) fn validate_staged_keyring(
        &self,
        staged_keyring: SecretBytes,
    ) -> Result<Keyring, TransitionContractError> {
        let bytes = staged_keyring.expose_secret();
        if bytes.len() != self.staged_keyring_length as usize
            || Sha256::digest(bytes).as_slice() != self.staged_keyring_hash
        {
            return Err(TransitionContractError::InvalidRetirementKeyring);
        }
        let keyring = Keyring::decode(staged_keyring)
            .map_err(|_| TransitionContractError::InvalidRetirementKeyring)?;
        if keyring.encode().expose_secret().len() != ACTIVE_ONLY_LENGTH
            || keyring.version() != self.result_keyring_version
            || keyring.active_kid() != self.expected_active_kid
            || keyring.active_activated_at() != self.expected_active_activated_at_micros
            || keyring.verify_only_facts().is_some()
        {
            return Err(TransitionContractError::InvalidRetirementKeyring);
        }
        Ok(keyring)
    }

    pub(crate) const fn source_expectation(&self) -> RetireSourceExpectation<'_> {
        RetireSourceExpectation { metadata: self }
    }

    pub(super) fn matches_reservation_artifact(&self, artifact: TopLevelArtifactName) -> bool {
        artifact
            == (TopLevelArtifactName::Transition {
                kind: TransitionKind::Retire,
                id: self.transition_id,
            })
            || artifact
                == (TopLevelArtifactName::Cleanup {
                    kind: TransitionKind::Retire,
                    id: self.transition_id,
                })
    }

    fn validate_semantics(&self) -> Result<(), TransitionContractError> {
        if self.expected_active_kid == self.expected_verify_only_kid
            || self.expected_keyring_version.get().checked_add(1)
                != Some(self.result_keyring_version.get())
            || self.expected_verify_only_activated_at_micros
                > self.expected_active_activated_at_micros
            || self.expected_verify_until_micros < self.expected_active_activated_at_micros
            || self.source_at_micros.get() < self.expected_verify_until_micros.get()
            || self.source_at_micros.get() < self.expected_lifecycle_updated_at_micros.get()
            || self.current_keyring_length as usize != WITH_VERIFY_ONLY_LENGTH
            || self.staged_keyring_length as usize != ACTIVE_ONLY_LENGTH
            || !is_positive_sqlite_integer(self.expected_lifecycle_revision)
            || self.expected_lifecycle_revision > (i64::MAX as u64).saturating_sub(2)
            || !is_positive_sqlite_integer(self.credential_version)
            || !is_positive_sqlite_integer(self.account_revision)
            || !is_positive_sqlite_integer(self.password_credential_revision)
            || !is_positive_sqlite_integer(self.recovery_credential_revision)
        {
            return Err(TransitionContractError::InvalidMetadata);
        }
        Ok(())
    }
}

impl<'a> PlannedRotationSourceExpectation<'a> {
    pub(crate) fn transition_id(self) -> &'a [u8; 16] {
        self.metadata.transition_id.as_bytes()
    }

    pub(crate) fn owner_id(self) -> &'a [u8; 16] {
        self.metadata.owner_id.as_bytes()
    }

    pub(crate) fn audit_id(self) -> &'a [u8; 16] {
        self.metadata.audit_id.as_bytes()
    }

    pub(crate) fn expected_active_kid(self) -> &'a str {
        self.metadata.expected_active_kid.as_str()
    }

    pub(crate) fn expected_keyring_version(self) -> i64 {
        i64::try_from(self.metadata.expected_keyring_version.get())
            .expect("validated keyring version fits SQLite")
    }

    pub(crate) fn expected_key_activated_at_micros(self) -> i64 {
        i64::try_from(self.metadata.expected_key_activated_at_micros.get())
            .expect("validated key activation fits SQLite")
    }

    pub(crate) fn expected_lifecycle_revision(self) -> i64 {
        i64::try_from(self.metadata.expected_lifecycle_revision)
            .expect("validated lifecycle revision fits SQLite")
    }

    pub(crate) fn expected_lifecycle_updated_at_micros(self) -> i64 {
        i64::try_from(self.metadata.expected_lifecycle_updated_at_micros.get())
            .expect("validated lifecycle timestamp fits SQLite")
    }

    pub(crate) fn matches_active_lifecycle(
        self,
        state_revision: u64,
        expected_kid: PersistedLifecycleKeyId,
        keyring_version: PersistedLifecycleKeyringVersion,
        updated_at_micros: PersistedLifecycleTimestamp,
    ) -> bool {
        state_revision == self.metadata.expected_lifecycle_revision
            && expected_kid.0 == self.metadata.expected_active_kid
            && keyring_version.0 == self.metadata.expected_keyring_version
            && updated_at_micros.0 == self.metadata.expected_lifecycle_updated_at_micros
    }

    pub(crate) fn matches_owner_id(self, raw: &[u8]) -> bool {
        raw == self.metadata.owner_id.as_bytes()
    }

    pub(crate) fn result_kid(self) -> &'a str {
        self.metadata.result_kid.as_str()
    }

    pub(crate) fn result_keyring_version(self) -> i64 {
        i64::try_from(self.metadata.result_keyring_version.get())
            .expect("validated keyring version fits SQLite")
    }

    pub(crate) fn source_at_micros(self) -> i64 {
        i64::try_from(self.metadata.source_at_micros.get())
            .expect("validated source timestamp fits SQLite")
    }

    pub(crate) fn transitioning_lifecycle_revision(self) -> i64 {
        self.expected_lifecycle_revision()
            .checked_add(1)
            .expect("validated lifecycle revision can advance once")
    }

    pub(crate) fn final_lifecycle_revision(self) -> i64 {
        self.expected_lifecycle_revision()
            .checked_add(2)
            .expect("validated lifecycle revision can advance twice")
    }

    pub(crate) fn matches_transitioning_lifecycle(
        self,
        state_revision: u64,
        kind: TransitionKind,
        transition_id: PersistedLifecycleTransitionId,
        expected_kid: PersistedLifecycleKeyId,
        keyring_version: PersistedLifecycleKeyringVersion,
        updated_at_micros: PersistedLifecycleTimestamp,
    ) -> bool {
        state_revision
            == self
                .metadata
                .expected_lifecycle_revision
                .checked_add(1)
                .unwrap_or(u64::MAX)
            && kind == TransitionKind::Planned
            && transition_id.0 == self.metadata.transition_id
            && expected_kid.0 == self.metadata.result_kid
            && keyring_version.0 == self.metadata.result_keyring_version
            && updated_at_micros.0 == self.metadata.source_at_micros
    }

    pub(crate) fn matches_final_active_lifecycle(
        self,
        state_revision: u64,
        expected_kid: PersistedLifecycleKeyId,
        keyring_version: PersistedLifecycleKeyringVersion,
        updated_at_micros: PersistedLifecycleTimestamp,
    ) -> bool {
        state_revision
            == self
                .metadata
                .expected_lifecycle_revision
                .checked_add(2)
                .unwrap_or(u64::MAX)
            && expected_kid.0 == self.metadata.result_kid
            && keyring_version.0 == self.metadata.result_keyring_version
            && updated_at_micros.0 == self.metadata.source_at_micros
    }

    pub(crate) fn credential_version(self) -> i64 {
        i64::try_from(self.metadata.credential_version)
            .expect("validated credential version fits SQLite")
    }

    pub(crate) fn account_revision(self) -> i64 {
        i64::try_from(self.metadata.account_revision)
            .expect("validated account revision fits SQLite")
    }

    pub(crate) fn password_credential_revision(self) -> i64 {
        i64::try_from(self.metadata.password_credential_revision)
            .expect("validated password revision fits SQLite")
    }

    pub(crate) fn recovery_credential_revision(self) -> i64 {
        i64::try_from(self.metadata.recovery_credential_revision)
            .expect("validated recovery revision fits SQLite")
    }
}

impl<'a> RetireSourceExpectation<'a> {
    pub(crate) fn transition_id(self) -> &'a [u8; 16] {
        self.metadata.transition_id.as_bytes()
    }

    pub(crate) fn owner_id(self) -> &'a [u8; 16] {
        self.metadata.owner_id.as_bytes()
    }

    pub(crate) fn audit_id(self) -> &'a [u8; 16] {
        self.metadata.audit_id.as_bytes()
    }

    pub(crate) fn expected_active_kid(self) -> &'a str {
        self.metadata.expected_active_kid.as_str()
    }

    pub(crate) fn expected_keyring_version(self) -> i64 {
        i64::try_from(self.metadata.expected_keyring_version.get())
            .expect("validated keyring version fits SQLite")
    }

    pub(crate) fn expected_key_activated_at_micros(self) -> i64 {
        i64::try_from(self.metadata.expected_active_activated_at_micros.get())
            .expect("validated key activation fits SQLite")
    }

    pub(crate) fn expected_lifecycle_revision(self) -> i64 {
        i64::try_from(self.metadata.expected_lifecycle_revision)
            .expect("validated lifecycle revision fits SQLite")
    }

    pub(crate) fn expected_lifecycle_updated_at_micros(self) -> i64 {
        i64::try_from(self.metadata.expected_lifecycle_updated_at_micros.get())
            .expect("validated lifecycle timestamp fits SQLite")
    }

    pub(crate) fn matches_active_lifecycle(
        self,
        state_revision: u64,
        expected_kid: PersistedLifecycleKeyId,
        keyring_version: PersistedLifecycleKeyringVersion,
        updated_at_micros: PersistedLifecycleTimestamp,
    ) -> bool {
        state_revision == self.metadata.expected_lifecycle_revision
            && expected_kid.0 == self.metadata.expected_active_kid
            && keyring_version.0 == self.metadata.expected_keyring_version
            && updated_at_micros.0 == self.metadata.expected_lifecycle_updated_at_micros
    }

    pub(crate) fn matches_owner_id(self, raw: &[u8]) -> bool {
        raw == self.metadata.owner_id.as_bytes()
    }

    pub(crate) fn result_kid(self) -> &'a str {
        self.metadata.expected_active_kid.as_str()
    }

    pub(crate) fn result_keyring_version(self) -> i64 {
        i64::try_from(self.metadata.result_keyring_version.get())
            .expect("validated keyring version fits SQLite")
    }

    pub(crate) fn source_at_micros(self) -> i64 {
        i64::try_from(self.metadata.source_at_micros.get())
            .expect("validated source timestamp fits SQLite")
    }

    pub(crate) fn transitioning_lifecycle_revision(self) -> i64 {
        self.expected_lifecycle_revision()
            .checked_add(1)
            .expect("validated lifecycle revision can advance once")
    }

    pub(crate) fn final_lifecycle_revision(self) -> i64 {
        self.expected_lifecycle_revision()
            .checked_add(2)
            .expect("validated lifecycle revision can advance twice")
    }

    pub(crate) fn matches_transitioning_lifecycle(
        self,
        state_revision: u64,
        kind: TransitionKind,
        transition_id: PersistedLifecycleTransitionId,
        expected_kid: PersistedLifecycleKeyId,
        keyring_version: PersistedLifecycleKeyringVersion,
        updated_at_micros: PersistedLifecycleTimestamp,
    ) -> bool {
        state_revision
            == self
                .metadata
                .expected_lifecycle_revision
                .checked_add(1)
                .unwrap_or(u64::MAX)
            && kind == TransitionKind::Retire
            && transition_id.0 == self.metadata.transition_id
            && expected_kid.0 == self.metadata.expected_active_kid
            && keyring_version.0 == self.metadata.result_keyring_version
            && updated_at_micros.0 == self.metadata.source_at_micros
    }

    pub(crate) fn matches_final_active_lifecycle(
        self,
        state_revision: u64,
        expected_kid: PersistedLifecycleKeyId,
        keyring_version: PersistedLifecycleKeyringVersion,
        updated_at_micros: PersistedLifecycleTimestamp,
    ) -> bool {
        state_revision
            == self
                .metadata
                .expected_lifecycle_revision
                .checked_add(2)
                .unwrap_or(u64::MAX)
            && expected_kid.0 == self.metadata.expected_active_kid
            && keyring_version.0 == self.metadata.result_keyring_version
            && updated_at_micros.0 == self.metadata.source_at_micros
    }

    pub(crate) fn credential_version(self) -> i64 {
        i64::try_from(self.metadata.credential_version)
            .expect("validated credential version fits SQLite")
    }

    pub(crate) fn account_revision(self) -> i64 {
        i64::try_from(self.metadata.account_revision)
            .expect("validated account revision fits SQLite")
    }

    pub(crate) fn password_credential_revision(self) -> i64 {
        i64::try_from(self.metadata.password_credential_revision)
            .expect("validated password revision fits SQLite")
    }

    pub(crate) fn recovery_credential_revision(self) -> i64 {
        i64::try_from(self.metadata.recovery_credential_revision)
            .expect("validated recovery revision fits SQLite")
    }
}

macro_rules! impl_key_transition_source_expectation {
    ($type:ident, $kind:expr, $audit_action:literal) => {
        impl KeyTransitionSourceExpectation for $type<'_> {
            fn transition_kind(self) -> TransitionKind {
                $kind
            }

            fn audit_action(self) -> &'static str {
                $audit_action
            }

            fn transition_id(&self) -> &[u8; 16] {
                $type::transition_id(*self)
            }

            fn owner_id(&self) -> &[u8; 16] {
                $type::owner_id(*self)
            }

            fn audit_id(&self) -> &[u8; 16] {
                $type::audit_id(*self)
            }

            fn expected_active_kid(&self) -> &str {
                $type::expected_active_kid(*self)
            }

            fn expected_keyring_version(self) -> i64 {
                $type::expected_keyring_version(self)
            }

            fn expected_key_activated_at_micros(self) -> i64 {
                $type::expected_key_activated_at_micros(self)
            }

            fn expected_lifecycle_revision(self) -> i64 {
                $type::expected_lifecycle_revision(self)
            }

            fn expected_lifecycle_updated_at_micros(self) -> i64 {
                $type::expected_lifecycle_updated_at_micros(self)
            }

            fn matches_active_lifecycle(
                self,
                state_revision: u64,
                expected_kid: PersistedLifecycleKeyId,
                keyring_version: PersistedLifecycleKeyringVersion,
                updated_at_micros: PersistedLifecycleTimestamp,
            ) -> bool {
                $type::matches_active_lifecycle(
                    self,
                    state_revision,
                    expected_kid,
                    keyring_version,
                    updated_at_micros,
                )
            }

            fn matches_owner_id(self, raw: &[u8]) -> bool {
                $type::matches_owner_id(self, raw)
            }

            fn result_kid(&self) -> &str {
                $type::result_kid(*self)
            }

            fn result_keyring_version(self) -> i64 {
                $type::result_keyring_version(self)
            }

            fn source_at_micros(self) -> i64 {
                $type::source_at_micros(self)
            }

            fn transitioning_lifecycle_revision(self) -> i64 {
                $type::transitioning_lifecycle_revision(self)
            }

            fn final_lifecycle_revision(self) -> i64 {
                $type::final_lifecycle_revision(self)
            }

            fn matches_transitioning_lifecycle(
                self,
                state_revision: u64,
                kind: TransitionKind,
                transition_id: PersistedLifecycleTransitionId,
                expected_kid: PersistedLifecycleKeyId,
                keyring_version: PersistedLifecycleKeyringVersion,
                updated_at_micros: PersistedLifecycleTimestamp,
            ) -> bool {
                $type::matches_transitioning_lifecycle(
                    self,
                    state_revision,
                    kind,
                    transition_id,
                    expected_kid,
                    keyring_version,
                    updated_at_micros,
                )
            }

            fn matches_final_active_lifecycle(
                self,
                state_revision: u64,
                expected_kid: PersistedLifecycleKeyId,
                keyring_version: PersistedLifecycleKeyringVersion,
                updated_at_micros: PersistedLifecycleTimestamp,
            ) -> bool {
                $type::matches_final_active_lifecycle(
                    self,
                    state_revision,
                    expected_kid,
                    keyring_version,
                    updated_at_micros,
                )
            }

            fn credential_version(self) -> i64 {
                $type::credential_version(self)
            }

            fn account_revision(self) -> i64 {
                $type::account_revision(self)
            }

            fn password_credential_revision(self) -> i64 {
                $type::password_credential_revision(self)
            }

            fn recovery_credential_revision(self) -> i64 {
                $type::recovery_credential_revision(self)
            }
        }
    };
}

impl_key_transition_source_expectation!(
    PlannedRotationSourceExpectation,
    TransitionKind::Planned,
    "key_planned"
);
impl_key_transition_source_expectation!(
    RetireSourceExpectation,
    TransitionKind::Retire,
    "key_retired"
);

impl fmt::Debug for PlannedRotationMetadataV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlannedRotationMetadataV1([REDACTED])")
    }
}

impl fmt::Debug for RetireMetadataV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetireMetadataV1([REDACTED])")
    }
}

impl fmt::Debug for RetireSourceExpectation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetireSourceExpectation([REDACTED])")
    }
}

impl fmt::Debug for PlannedRotationSourceExpectation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlannedRotationSourceExpectation([REDACTED])")
    }
}

fn is_positive_sqlite_integer(value: u64) -> bool {
    (1..=i64::MAX as u64).contains(&value)
}

fn validate_planned_rotation_input(
    input: &PlannedRotationMetadataInput,
) -> Result<(), TransitionContractError> {
    if input.source_at_micros.get() == 0
        || input.expected_lifecycle_updated_at_micros.get() == 0
        || input.source_at_micros.get() < input.key_activated_at_micros.get()
        || input.source_at_micros.get() < input.expected_lifecycle_updated_at_micros.get()
        || !is_positive_sqlite_integer(input.expected_lifecycle_revision)
        || input.expected_lifecycle_revision > (i64::MAX as u64).saturating_sub(2)
        || !is_positive_sqlite_integer(input.credential_version)
        || !is_positive_sqlite_integer(input.account_revision)
        || !is_positive_sqlite_integer(input.password_credential_revision)
        || !is_positive_sqlite_integer(input.recovery_credential_revision)
    {
        return Err(TransitionContractError::InvalidMetadata);
    }
    Ok(())
}

fn validate_retire_input(input: &RetireMetadataInput) -> Result<(), TransitionContractError> {
    if input.source_at_micros.get() == 0
        || input.expected_lifecycle_updated_at_micros.get() == 0
        || input.source_at_micros.get() < input.expected_lifecycle_updated_at_micros.get()
        || !is_positive_sqlite_integer(input.expected_lifecycle_revision)
        || input.expected_lifecycle_revision > (i64::MAX as u64).saturating_sub(2)
        || !is_positive_sqlite_integer(input.credential_version)
        || !is_positive_sqlite_integer(input.account_revision)
        || !is_positive_sqlite_integer(input.password_credential_revision)
        || !is_positive_sqlite_integer(input.recovery_credential_revision)
    {
        return Err(TransitionContractError::InvalidMetadata);
    }
    Ok(())
}

impl fmt::Debug for InitializationMetadataV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InitializationMetadataV1([REDACTED])")
    }
}

fn validate_independent_verifier_salts(
    password: &ValidatedVerifier,
    recovery: &ValidatedVerifier,
) -> Result<(), TransitionContractError> {
    let password_salt = password
        .expose_phc()
        .rsplit_once('$')
        .and_then(|(prefix, _)| prefix.rsplit_once('$'))
        .map(|(_, salt)| salt)
        .ok_or(TransitionContractError::InvalidMetadata)?;
    let recovery_salt = recovery
        .expose_phc()
        .rsplit_once('$')
        .and_then(|(prefix, _)| prefix.rsplit_once('$'))
        .map(|(_, salt)| salt)
        .ok_or(TransitionContractError::InvalidMetadata)?;
    if password_salt == recovery_salt {
        return Err(TransitionContractError::InvalidMetadata);
    }
    Ok(())
}

fn push_u8_length_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), TransitionContractError> {
    output.push(u8::try_from(value.len()).map_err(|_| TransitionContractError::InvalidMetadata)?);
    output.extend_from_slice(value);
    Ok(())
}

fn push_u16_length_field(
    output: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), TransitionContractError> {
    output.extend_from_slice(
        &u16::try_from(value.len())
            .map_err(|_| TransitionContractError::InvalidMetadata)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn read_slice(
    bytes: &[u8],
    offset: usize,
    length: usize,
) -> Result<&[u8], TransitionContractError> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(length)
                    .ok_or(TransitionContractError::InvalidMetadata)?,
        )
        .ok_or(TransitionContractError::InvalidMetadata)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, TransitionContractError> {
    let raw: [u8; 2] = read_slice(bytes, offset, 2)?
        .try_into()
        .map_err(|_| TransitionContractError::InvalidMetadata)?;
    Ok(u16::from_be_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, TransitionContractError> {
    let raw: [u8; 4] = read_slice(bytes, offset, 4)?
        .try_into()
        .map_err(|_| TransitionContractError::InvalidMetadata)?;
    Ok(u32::from_be_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, TransitionContractError> {
    let raw: [u8; 8] = read_slice(bytes, offset, 8)?
        .try_into()
        .map_err(|_| TransitionContractError::InvalidMetadata)?;
    Ok(u64::from_be_bytes(raw))
}

fn read_byte(
    bytes: &[u8],
    offset: &mut usize,
    limit: usize,
) -> Result<u8, TransitionContractError> {
    if *offset >= limit {
        return Err(TransitionContractError::InvalidMetadata);
    }
    let byte = bytes[*offset];
    *offset += 1;
    Ok(byte)
}

fn read_u16_at_cursor(
    bytes: &[u8],
    offset: &mut usize,
    limit: usize,
) -> Result<u16, TransitionContractError> {
    if offset
        .checked_add(2)
        .filter(|next| *next <= limit)
        .is_none()
    {
        return Err(TransitionContractError::InvalidMetadata);
    }
    let value = read_u16(bytes, *offset)?;
    *offset += 2;
    Ok(value)
}

fn read_field<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
    limit: usize,
) -> Result<&'a [u8], TransitionContractError> {
    let next = offset
        .checked_add(length)
        .filter(|next| *next <= limit)
        .ok_or(TransitionContractError::InvalidMetadata)?;
    let value = &bytes[*offset..next];
    *offset = next;
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransitionContractError {
    InvalidArtifactName,
    InvalidIdentifier,
    InvalidLoginId,
    InvalidLegacyPolicyProvenance,
    InvalidInitializationKeyring,
    InvalidPlannedRotationKeyring,
    InvalidRetirementKeyring,
    InvalidMetadata,
    UnsupportedMetadataVersion,
    UnsupportedMetadataKind,
}

impl fmt::Display for TransitionContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArtifactName => "authentication artifact name is invalid",
            Self::InvalidIdentifier => "authentication transition identifier is invalid",
            Self::InvalidLoginId => "authentication login identifier is invalid",
            Self::InvalidLegacyPolicyProvenance => {
                "authentication legacy policy provenance is invalid"
            }
            Self::InvalidInitializationKeyring => {
                "authentication initialization keyring is invalid"
            }
            Self::InvalidPlannedRotationKeyring => {
                "authentication planned rotation keyring is invalid"
            }
            Self::InvalidRetirementKeyring => "authentication retirement keyring is invalid",
            Self::InvalidMetadata => "authentication transition metadata is invalid",
            Self::UnsupportedMetadataVersion => {
                "authentication transition metadata version is unsupported"
            }
            Self::UnsupportedMetadataKind => {
                "authentication transition metadata kind is unsupported"
            }
        })
    }
}

impl Error for TransitionContractError {}

#[cfg(test)]
mod tests {
    use base64ct::{Base64Unpadded, Encoding};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::{
        ACTIVE_KEYRING_NAME, AUTH_MAINTENANCE_LOCK_NAME, AuditId, AuthOwnerId,
        INITIALIZE_METADATA_TAG, InitializationMetadataInput, InitializationMetadataV1,
        LegacyPolicyProvenance, LoginId, MAX_INITIALIZATION_METADATA_BYTES,
        METADATA_CHECKSUM_BYTES, METADATA_FIXED_HEADER_BYTES, METADATA_FORMAT_VERSION,
        METADATA_MAGIC, NO_BLOCKLIST_CHECK_SENTINEL, PLANNED_METADATA_TAG,
        PLANNED_ROTATION_METADATA_BYTES, PREPARED_SENTINEL_NAME, PlannedRotationMetadataInput,
        PlannedRotationMetadataV1, PlannedRotationPreparationV1, RETIRE_METADATA_BYTES,
        RETIRE_METADATA_TAG, ReservationEntryName, RetireMetadataInput, RetireMetadataV1,
        RetirePreparationV1, STAGED_KEYRING_NAME, SourceTimestampMicros, TRANSITION_METADATA_NAME,
        TopLevelArtifactName, TransitionContractError, TransitionId, TransitionKind,
    };
    use crate::auth::{
        SecretBytes, ValidatedVerifier,
        keyring::{
            ACTIVE_ONLY_LENGTH, AuthTimestampMicros, Keyring, KeyringVersion,
            WITH_VERIFY_ONLY_LENGTH,
        },
    };

    const TRANSITION_UUID: &str = "a1111111-b222-4c33-8d44-e55555555555";
    const OTHER_UUID: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const ACTIVE_AT: u64 = 1_700_000_000_000_000;
    const ROTATED_AT: u64 = ACTIVE_AT + 90 * 24 * 60 * 60 * 1_000_000;
    const RETIRE_AT: u64 = ROTATED_AT + 11 * 60 * 1_000_000;
    const RFC8032_SEED_ONE: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC8032_SEED_TWO: [u8; 32] = [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
    ];

    fn fixed_id(raw: &str) -> Uuid {
        Uuid::parse_str(raw).expect("fixed UUID")
    }

    fn transition_id() -> TransitionId {
        TransitionId::from_uuid(fixed_id(TRANSITION_UUID)).expect("fixed transition ID")
    }

    fn owner_id() -> AuthOwnerId {
        AuthOwnerId::from_uuid(fixed_id("01234567-89ab-4cde-8fab-0123456789ab"))
            .expect("fixed owner ID")
    }

    fn audit_id() -> AuditId {
        AuditId::from_uuid(fixed_id("fedcba98-7654-4321-8abc-fedcba987654"))
            .expect("fixed audit ID")
    }

    fn verifier(fill: u8) -> ValidatedVerifier {
        let salt = Base64Unpadded::encode_string(&[fill; 16]);
        let output = Base64Unpadded::encode_string(&[fill; 32]);
        ValidatedVerifier::parse(SecretBytes::new(
            format!("$argon2id$v=19$m=65536,t=3,p=4${salt}${output}").into_bytes(),
        ))
        .expect("canonical synthetic verifier")
    }

    fn keyring() -> Keyring {
        Keyring::from_test_seeds(1, ACTIVE_AT, RFC8032_SEED_ONE, None)
            .expect("fixed initialization keyring")
    }

    fn metadata() -> InitializationMetadataV1 {
        InitializationMetadataV1::from_keyring(
            InitializationMetadataInput {
                transition_id: transition_id(),
                owner_id: owner_id(),
                audit_id: audit_id(),
                source_at_micros: SourceTimestampMicros::new(ACTIVE_AT + 1)
                    .expect("source timestamp"),
                login_id: LoginId::parse(b"owner_01").expect("login ID"),
                password_verifier: verifier(0x11),
                recovery_verifier: verifier(0x22),
            },
            &keyring(),
        )
        .expect("initialization metadata")
    }

    fn planned_input() -> PlannedRotationMetadataInput {
        PlannedRotationMetadataInput {
            transition_id: transition_id(),
            owner_id: owner_id(),
            audit_id: audit_id(),
            key_activated_at_micros: AuthTimestampMicros::new(ROTATED_AT)
                .expect("rotation timestamp"),
            source_at_micros: SourceTimestampMicros::new(ROTATED_AT + 1).expect("source timestamp"),
            expected_lifecycle_revision: 2,
            expected_lifecycle_updated_at_micros: SourceTimestampMicros::new(ACTIVE_AT + 1)
                .expect("lifecycle timestamp"),
            credential_version: 1,
            account_revision: 1,
            password_credential_revision: 1,
            recovery_credential_revision: 1,
        }
    }

    fn planned_preparation() -> PlannedRotationPreparationV1 {
        let current = keyring();
        let rotated = current
            .planned_rotation_from_test_seed(ROTATED_AT, RFC8032_SEED_TWO)
            .expect("fixed planned rotation");
        PlannedRotationPreparationV1::from_keyrings(planned_input(), &current, rotated)
            .expect("planned preparation")
    }

    fn retire_current_keyring() -> Keyring {
        Keyring::from_test_seeds(
            2,
            ROTATED_AT,
            RFC8032_SEED_TWO,
            Some((ACTIVE_AT, RFC8032_SEED_ONE)),
        )
        .expect("fixed overlap keyring")
    }

    fn retire_input() -> RetireMetadataInput {
        RetireMetadataInput {
            transition_id: transition_id(),
            owner_id: owner_id(),
            audit_id: audit_id(),
            source_at_micros: SourceTimestampMicros::new(RETIRE_AT)
                .expect("retire source timestamp"),
            expected_lifecycle_revision: 4,
            expected_lifecycle_updated_at_micros: SourceTimestampMicros::new(ROTATED_AT + 1)
                .expect("lifecycle timestamp"),
            credential_version: 1,
            account_revision: 1,
            password_credential_revision: 1,
            recovery_credential_revision: 1,
        }
    }

    fn retire_preparation() -> RetirePreparationV1 {
        RetirePreparationV1::from_current_keyring(retire_input(), &retire_current_keyring())
            .expect("retire preparation")
    }

    #[test]
    fn exact_top_level_and_inner_artifact_names_round_trip() {
        let id = transition_id();
        for generated in [
            TransitionId::new().as_uuid(),
            AuditId::new().as_uuid(),
            AuthOwnerId::new().as_uuid(),
        ] {
            assert_eq!(generated.get_version(), Some(uuid::Version::Random));
            assert_eq!(generated.get_variant(), uuid::Variant::RFC4122);
        }
        let mut names = vec![
            TopLevelArtifactName::MaintenanceLock,
            TopLevelArtifactName::ActiveKeyring,
            TopLevelArtifactName::InstallTemp { id },
        ];
        for kind in TransitionKind::ALL {
            names.push(TopLevelArtifactName::Transition { kind, id });
            names.push(TopLevelArtifactName::Cleanup { kind, id });
        }

        for name in names {
            let encoded = name.format();
            assert_eq!(TopLevelArtifactName::parse(encoded.as_bytes()), Ok(name));
        }
        assert_eq!(
            TopLevelArtifactName::MaintenanceLock.format(),
            AUTH_MAINTENANCE_LOCK_NAME
        );
        assert_eq!(
            TopLevelArtifactName::ActiveKeyring.format(),
            ACTIVE_KEYRING_NAME
        );
        assert_eq!(
            TopLevelArtifactName::Transition {
                kind: TransitionKind::Initialize,
                id
            }
            .format(),
            format!(".auth-transition-initialize-{TRANSITION_UUID}")
        );
        assert_eq!(
            TopLevelArtifactName::InstallTemp { id }.format(),
            format!(".auth-keyring-install-{TRANSITION_UUID}.tmp")
        );

        for (raw, expected) in [
            (
                TRANSITION_METADATA_NAME.as_bytes(),
                ReservationEntryName::Metadata,
            ),
            (
                STAGED_KEYRING_NAME.as_bytes(),
                ReservationEntryName::StagedKeyring,
            ),
            (
                PREPARED_SENTINEL_NAME.as_bytes(),
                ReservationEntryName::Prepared,
            ),
        ] {
            assert_eq!(ReservationEntryName::parse(raw), Ok(expected));
            assert_eq!(expected.as_str().as_bytes(), raw);
        }
    }

    #[test]
    fn artifact_names_reject_aliases_wrong_uuid_forms_and_raw_bytes() {
        let uppercase = TRANSITION_UUID.to_ascii_uppercase();
        let simple = TRANSITION_UUID.replace('-', "");
        for invalid in [
            ".auth-transition-initialize-",
            ".auth-transition-INITIALIZE-11111111-2222-4333-8444-555555555555",
            ".auth-transition-unknown-11111111-2222-4333-8444-555555555555",
            ".auth-transition-initialize-11111111-2222-3333-8444-555555555555",
            ".auth-transition-initialize-11111111-2222-4333-c444-555555555555",
            ".auth-transition-initialize-{11111111-2222-4333-8444-555555555555}",
            "urn:uuid:11111111-2222-4333-8444-555555555555",
            ".auth-keyring.v1",
            "auth-keyring.v2",
            "metadata",
            ".DS_Store",
            "../auth-keyring.v1",
        ] {
            assert!(
                TopLevelArtifactName::parse(invalid.as_bytes()).is_err(),
                "{invalid}"
            );
        }
        for invalid in [
            format!(".auth-transition-initialize-{uppercase}"),
            format!(".auth-transition-initialize-{simple}"),
            format!(".auth-transition-initialize-{TRANSITION_UUID}-tail"),
            format!(".auth-keyring-install-{uppercase}.tmp"),
            format!(".auth-keyring-install-{simple}.tmp"),
            format!(".auth-keyring-install-{TRANSITION_UUID}.TMP"),
        ] {
            assert!(
                TopLevelArtifactName::parse(invalid.as_bytes()).is_err(),
                "{invalid}"
            );
        }
        for invalid in [
            b".auth-transition-initialize-\xff".as_slice(),
            b".auth-transition-initialize-11111111-2222-4333-8444-555555555555\0",
            b".auth-keyring-install-11111111-2222-4333-8444-555555555555.tmp/child",
        ] {
            assert!(TopLevelArtifactName::parse(invalid).is_err());
        }
        for invalid in [b"Metadata".as_slice(), b"staged_keyring", b"prepared\0"] {
            assert!(ReservationEntryName::parse(invalid).is_err());
        }
    }

    #[test]
    fn login_and_legacy_policy_provenance_are_exact_ascii_contracts() {
        for valid in [
            b"abc".as_slice(),
            b"a-b",
            b"a_b",
            b"a0123456789012345678901234567890",
        ] {
            LoginId::parse(valid).expect("valid login ID");
        }
        for invalid in [
            b"ab".as_slice(),
            b"Aaa",
            b"1aa",
            b"a.a",
            b" aa",
            b"aaa ",
            b"a\xffb",
            b"a01234567890123456789012345678901",
        ] {
            assert_eq!(
                LoginId::parse(invalid).unwrap_err(),
                TransitionContractError::InvalidLoginId
            );
        }

        for valid in [
            b"v1".as_slice(),
            NO_BLOCKLIST_CHECK_SENTINEL.as_bytes(),
            b"legacy-policy-v1",
        ] {
            LegacyPolicyProvenance::parse(valid).expect("valid legacy policy provenance");
        }
        for invalid in [
            b"".as_slice(),
            b"V1",
            b"1v",
            b"-v1",
            b"v1-",
            b"v_1",
            b"v1\xff",
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert_eq!(
                LegacyPolicyProvenance::parse(invalid).unwrap_err(),
                TransitionContractError::InvalidLegacyPolicyProvenance
            );
        }
    }

    #[test]
    fn planned_rotation_metadata_round_trips_and_recovers_exact_source_evidence() {
        let preparation = planned_preparation();
        assert_eq!(
            preparation.transition_artifact(),
            TopLevelArtifactName::Transition {
                kind: TransitionKind::Planned,
                id: transition_id()
            }
        );
        let encoded = preparation
            .encoded_metadata()
            .expect("encode planned metadata");
        let staged = preparation.staged_keyring_bytes().to_vec();
        assert_eq!(
            encoded.expose_secret().len(),
            PLANNED_ROTATION_METADATA_BYTES
        );
        assert_eq!(staged.len(), WITH_VERIFY_ONLY_LENGTH);
        drop(preparation);

        let recovered =
            PlannedRotationMetadataV1::decode(SecretBytes::new(encoded.expose_secret().to_vec()))
                .expect("recover planned metadata");
        let recovered_keyring = recovered
            .validate_staged_keyring(SecretBytes::new(staged.clone()))
            .expect("recover staged planned keyring");
        let expectation = recovered.source_expectation();
        let current = keyring();

        assert_eq!(expectation.transition_id(), transition_id().as_bytes());
        assert_eq!(expectation.owner_id(), owner_id().as_bytes());
        assert_eq!(expectation.audit_id(), audit_id().as_bytes());
        assert_eq!(
            expectation.expected_active_kid(),
            current.active_kid().as_str()
        );
        assert_eq!(expectation.expected_keyring_version(), 1);
        assert_eq!(expectation.expected_lifecycle_revision(), 2);
        assert_eq!(
            expectation.expected_lifecycle_updated_at_micros(),
            i64::try_from(ACTIVE_AT + 1).unwrap()
        );
        assert_eq!(
            expectation.result_kid(),
            recovered_keyring.active_kid().as_str()
        );
        assert_eq!(expectation.result_keyring_version(), 2);
        assert_eq!(
            expectation.source_at_micros(),
            i64::try_from(ROTATED_AT + 1).unwrap()
        );
        assert_eq!(expectation.credential_version(), 1);
        assert_eq!(expectation.account_revision(), 1);
        assert_eq!(expectation.password_credential_revision(), 1);
        assert_eq!(expectation.recovery_credential_revision(), 1);
        assert_eq!(
            recovered.encode().unwrap().expose_secret(),
            encoded.expose_secret()
        );

        let generated =
            PlannedRotationPreparationV1::from_current_keyring(planned_input(), &current)
                .expect("generated planned preparation");
        assert_eq!(
            generated.staged_keyring_bytes().len(),
            WITH_VERIFY_ONLY_LENGTH
        );
    }

    #[test]
    fn planned_rotation_metadata_rejects_corruption_mismatch_and_noncanonical_state() {
        let preparation = planned_preparation();
        let canonical = preparation
            .encoded_metadata()
            .expect("encode planned metadata")
            .expose_secret()
            .to_vec();
        let staged = preparation.staged_keyring_bytes().to_vec();

        for length in 0..canonical.len() {
            assert!(
                PlannedRotationMetadataV1::decode(SecretBytes::new(canonical[..length].to_vec()))
                    .is_err(),
                "truncation {length} must fail"
            );
        }
        let mut appended = canonical.clone();
        appended.push(0);
        assert!(PlannedRotationMetadataV1::decode(SecretBytes::new(appended)).is_err());

        let mut wrong_version = canonical.clone();
        wrong_version[8..10].copy_from_slice(&2_u16.to_be_bytes());
        refresh_metadata_checksum(&mut wrong_version);
        assert_eq!(
            PlannedRotationMetadataV1::decode(SecretBytes::new(wrong_version)).unwrap_err(),
            TransitionContractError::UnsupportedMetadataVersion
        );

        let mut wrong_kind = canonical.clone();
        wrong_kind[14] = INITIALIZE_METADATA_TAG;
        refresh_metadata_checksum(&mut wrong_kind);
        assert_eq!(
            PlannedRotationMetadataV1::decode(SecretBytes::new(wrong_kind)).unwrap_err(),
            TransitionContractError::UnsupportedMetadataKind
        );

        for (offset, value) in [
            (122_usize, 0_u64),
            (181, 1),
            (197, ROTATED_AT - 1),
            (241, 0),
            (249, i64::MAX as u64 + 1),
            (257, 0),
            (265, 0),
        ] {
            let mut invalid = canonical.clone();
            invalid[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
            refresh_metadata_checksum(&mut invalid);
            assert!(
                PlannedRotationMetadataV1::decode(SecretBytes::new(invalid)).is_err(),
                "semantic corruption at {offset} must fail"
            );
        }

        let metadata =
            PlannedRotationMetadataV1::decode(SecretBytes::new(canonical)).expect("metadata");
        let mut changed_stage = staged.clone();
        changed_stage[30] ^= 1;
        assert_eq!(
            metadata
                .validate_staged_keyring(SecretBytes::new(changed_stage))
                .unwrap_err(),
            TransitionContractError::InvalidPlannedRotationKeyring
        );

        let current = keyring();
        let unrelated_current =
            Keyring::from_test_seeds(1, ACTIVE_AT, RFC8032_SEED_TWO, None).expect("other current");
        let rotated = current
            .planned_rotation_from_test_seed(ROTATED_AT, RFC8032_SEED_TWO)
            .expect("rotation");
        assert_eq!(
            PlannedRotationPreparationV1::from_keyrings(
                planned_input(),
                &unrelated_current,
                rotated
            )
            .unwrap_err(),
            TransitionContractError::InvalidPlannedRotationKeyring
        );

        let with_overlap = Keyring::from_test_seeds(
            2,
            ROTATED_AT,
            RFC8032_SEED_TWO,
            Some((ACTIVE_AT, RFC8032_SEED_ONE)),
        )
        .expect("keyring with overlap");
        assert_eq!(
            PlannedRotationPreparationV1::from_current_keyring(planned_input(), &with_overlap)
                .unwrap_err(),
            TransitionContractError::InvalidPlannedRotationKeyring
        );

        let mut invalid_input = planned_input();
        invalid_input.expected_lifecycle_updated_at_micros =
            SourceTimestampMicros::new(0).expect("zero timestamp is representable");
        assert_eq!(
            PlannedRotationPreparationV1::from_current_keyring(invalid_input, &current)
                .unwrap_err(),
            TransitionContractError::InvalidMetadata
        );
    }

    #[test]
    fn planned_rotation_metadata_and_expectation_debug_are_redacted() {
        let preparation = planned_preparation();
        let metadata = PlannedRotationMetadataV1::decode(
            preparation.encoded_metadata().expect("metadata bytes"),
        )
        .expect("metadata");
        let debug = format!(
            "{preparation:?} {metadata:?} {:?}",
            metadata.source_expectation()
        );
        assert_eq!(
            debug,
            "PlannedRotationPreparationV1([REDACTED]) \
             PlannedRotationMetadataV1([REDACTED]) \
             PlannedRotationSourceExpectation([REDACTED])"
        );
        assert!(!debug.contains(keyring().active_kid().as_str()));
        assert!(!debug.contains(TRANSITION_UUID));
    }

    #[test]
    fn retire_metadata_round_trips_and_binds_current_and_staged_keyrings() {
        let preparation = retire_preparation();
        assert_eq!(
            preparation.transition_artifact(),
            TopLevelArtifactName::Transition {
                kind: TransitionKind::Retire,
                id: transition_id()
            }
        );
        let encoded = preparation
            .encoded_metadata()
            .expect("encode retire metadata");
        let staged = preparation.staged_keyring_bytes().to_vec();
        assert_eq!(encoded.expose_secret().len(), RETIRE_METADATA_BYTES);
        assert_eq!(encoded.expose_secret()[14], RETIRE_METADATA_TAG);
        assert_eq!(staged.len(), ACTIVE_ONLY_LENGTH);
        drop(preparation);

        let metadata = RetireMetadataV1::decode(SecretBytes::new(encoded.expose_secret().to_vec()))
            .expect("recover retire metadata");
        let current = retire_current_keyring();
        let current_bytes = current.encode().expose_secret().to_vec();
        let recovered_current = metadata
            .validate_current_keyring(SecretBytes::new(current_bytes))
            .expect("recover exact current keyring");
        let recovered_staged = metadata
            .validate_staged_keyring(SecretBytes::new(staged))
            .expect("recover exact staged keyring");
        let expectation = metadata.source_expectation();

        assert_eq!(recovered_current.version().get(), 2);
        assert!(recovered_current.verify_only_facts().is_some());
        assert_eq!(recovered_staged.version().get(), 3);
        assert!(recovered_staged.verify_only_facts().is_none());
        assert_eq!(
            recovered_staged.active_kid(),
            recovered_current.active_kid()
        );
        assert_eq!(
            recovered_staged.active_activated_at(),
            recovered_current.active_activated_at()
        );
        assert_eq!(expectation.transition_id(), transition_id().as_bytes());
        assert_eq!(expectation.owner_id(), owner_id().as_bytes());
        assert_eq!(expectation.audit_id(), audit_id().as_bytes());
        assert_eq!(
            expectation.expected_active_kid(),
            current.active_kid().as_str()
        );
        assert_eq!(expectation.expected_keyring_version(), 2);
        assert_eq!(expectation.expected_lifecycle_revision(), 4);
        assert_eq!(expectation.result_kid(), current.active_kid().as_str());
        assert_eq!(expectation.result_keyring_version(), 3);
        assert_eq!(expectation.source_at_micros(), RETIRE_AT as i64);
        assert_eq!(
            metadata.encode().unwrap().expose_secret(),
            encoded.expose_secret()
        );
    }

    #[test]
    fn retire_metadata_rejects_early_corrupt_unrelated_and_replayed_state() {
        let preparation = retire_preparation();
        let canonical = preparation
            .encoded_metadata()
            .expect("retire metadata")
            .expose_secret()
            .to_vec();
        let staged = preparation.staged_keyring_bytes().to_vec();
        let current = retire_current_keyring().encode().expose_secret().to_vec();

        for length in 0..canonical.len() {
            assert!(
                RetireMetadataV1::decode(SecretBytes::new(canonical[..length].to_vec())).is_err(),
                "truncation {length} must fail"
            );
        }
        let mut appended = canonical.clone();
        appended.push(0);
        assert!(RetireMetadataV1::decode(SecretBytes::new(appended)).is_err());

        let mut wrong_kind = canonical.clone();
        wrong_kind[14] = PLANNED_METADATA_TAG;
        refresh_metadata_checksum(&mut wrong_kind);
        assert_eq!(
            RetireMetadataV1::decode(SecretBytes::new(wrong_kind)).unwrap_err(),
            TransitionContractError::UnsupportedMetadataKind
        );

        for (offset, value) in [
            (181_usize, 0_u64),
            (205, 2),
            (285, 0),
            (293, 0),
            (301, 0),
            (309, 0),
        ] {
            let mut invalid = canonical.clone();
            invalid[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
            refresh_metadata_checksum(&mut invalid);
            assert!(
                RetireMetadataV1::decode(SecretBytes::new(invalid)).is_err(),
                "semantic corruption at {offset} must fail"
            );
        }

        let metadata =
            RetireMetadataV1::decode(SecretBytes::new(canonical)).expect("retire metadata");
        let mut changed_current = current;
        changed_current[30] ^= 1;
        assert_eq!(
            metadata
                .validate_current_keyring(SecretBytes::new(changed_current))
                .unwrap_err(),
            TransitionContractError::InvalidRetirementKeyring
        );
        let mut changed_staged = staged;
        changed_staged[30] ^= 1;
        assert_eq!(
            metadata
                .validate_staged_keyring(SecretBytes::new(changed_staged))
                .unwrap_err(),
            TransitionContractError::InvalidRetirementKeyring
        );

        let active_only = keyring();
        assert_eq!(
            RetirePreparationV1::from_current_keyring(retire_input(), &active_only).unwrap_err(),
            TransitionContractError::InvalidRetirementKeyring
        );
        let mut early = retire_input();
        early.source_at_micros =
            SourceTimestampMicros::new(RETIRE_AT - 1).expect("early timestamp");
        assert_eq!(
            RetirePreparationV1::from_current_keyring(early, &retire_current_keyring())
                .unwrap_err(),
            TransitionContractError::InvalidRetirementKeyring
        );
    }

    #[test]
    fn retire_metadata_and_expectation_debug_are_redacted() {
        let preparation = retire_preparation();
        let metadata =
            RetireMetadataV1::decode(preparation.encoded_metadata().expect("metadata bytes"))
                .expect("metadata");
        let debug = format!(
            "{preparation:?} {metadata:?} {:?}",
            metadata.source_expectation()
        );
        assert_eq!(
            debug,
            "RetirePreparationV1([REDACTED]) \
             RetireMetadataV1([REDACTED]) \
             RetireSourceExpectation([REDACTED])"
        );
        assert!(!debug.contains(retire_current_keyring().active_kid().as_str()));
        assert!(!debug.contains(TRANSITION_UUID));
    }

    #[test]
    fn initialization_metadata_has_stable_golden_shape_and_actual_byte_hash() {
        let metadata_v1 = metadata();
        let encoded = metadata_v1.encode().expect("encode metadata");
        let bytes = encoded.expose_secret();
        assert!(bytes.len() <= MAX_INITIALIZATION_METADATA_BYTES);
        assert_eq!(&bytes[..8], METADATA_MAGIC);
        assert_eq!(
            u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
            METADATA_FORMAT_VERSION
        );
        assert_eq!(
            u32::from_be_bytes(bytes[10..14].try_into().unwrap()) as usize,
            bytes.len()
        );
        assert_eq!(bytes[14], INITIALIZE_METADATA_TAG);
        assert_eq!(
            metadata_v1.legacy_policy_provenance.as_bytes(),
            NO_BLOCKLIST_CHECK_SENTINEL.as_bytes()
        );

        let staged = keyring().encode();
        let staged_bytes = staged.expose_secret().to_vec();
        assert_eq!(staged_bytes.len(), ACTIVE_ONLY_LENGTH);
        metadata_v1
            .validate_staged_keyring(SecretBytes::new(staged_bytes.clone()))
            .expect("validate staged keyring");
        let mut changed = staged_bytes.clone();
        changed[30] ^= 1;
        assert_eq!(
            metadata_v1
                .validate_staged_keyring(SecretBytes::new(changed.clone()))
                .unwrap_err(),
            TransitionContractError::InvalidInitializationKeyring
        );
        let mut invalid_keyring = metadata();
        invalid_keyring.staged_keyring_hash = Sha256::digest(&changed).into();
        assert_eq!(
            invalid_keyring
                .validate_staged_keyring(SecretBytes::new(changed))
                .unwrap_err(),
            TransitionContractError::InvalidInitializationKeyring
        );
        assert_eq!(
            metadata_v1
                .validate_staged_keyring(SecretBytes::new(staged_bytes[..169].to_vec()))
                .unwrap_err(),
            TransitionContractError::InvalidInitializationKeyring
        );

        let alternate = Keyring::from_test_seeds(1, ACTIVE_AT, [0x42; 32], None)
            .expect("alternate keyring")
            .encode();
        let mut cross_mismatch = metadata();
        cross_mismatch.staged_keyring_hash = Sha256::digest(alternate.expose_secret()).into();
        assert_eq!(
            cross_mismatch
                .validate_staged_keyring(alternate)
                .unwrap_err(),
            TransitionContractError::InvalidInitializationKeyring
        );

        let mut version_mismatch = metadata();
        version_mismatch.result_keyring_version = KeyringVersion::new(2).unwrap();
        assert_eq!(
            version_mismatch
                .validate_staged_keyring(SecretBytes::new(staged_bytes.clone()))
                .unwrap_err(),
            TransitionContractError::InvalidInitializationKeyring
        );

        let mut activation_mismatch = metadata();
        activation_mismatch.key_activated_at_micros =
            AuthTimestampMicros::new(ACTIVE_AT + 1).unwrap();
        assert_eq!(
            activation_mismatch
                .validate_staged_keyring(SecretBytes::new(staged_bytes))
                .unwrap_err(),
            TransitionContractError::InvalidInitializationKeyring
        );

        let digest: [u8; 32] = Sha256::digest(bytes).into();
        assert_eq!(
            digest,
            [
                85, 164, 118, 154, 121, 18, 63, 26, 12, 20, 173, 130, 158, 145, 169, 2, 238, 112,
                252, 183, 144, 208, 80, 237, 173, 57, 70, 239, 83, 10, 245, 49,
            ]
        );

        let decoded = InitializationMetadataV1::decode(SecretBytes::new(bytes.to_vec()))
            .expect("decode golden metadata");
        assert_eq!(
            decoded.encode().unwrap().expose_secret(),
            encoded.expose_secret()
        );
        assert!(
            decoded.matches_transition_artifact(TopLevelArtifactName::Transition {
                kind: TransitionKind::Initialize,
                id: transition_id(),
            })
        );
        assert!(
            !decoded.matches_transition_artifact(TopLevelArtifactName::Transition {
                kind: TransitionKind::Initialize,
                id: TransitionId::from_uuid(fixed_id(OTHER_UUID)).unwrap(),
            })
        );
        assert!(
            !decoded.matches_transition_artifact(TopLevelArtifactName::Transition {
                kind: TransitionKind::Planned,
                id: transition_id(),
            })
        );
    }

    #[test]
    fn initialization_metadata_rejects_all_truncation_append_and_header_corruption() {
        let encoded = metadata().encode().expect("encode metadata");
        let original = encoded.expose_secret();
        for length in 0..original.len() {
            assert!(
                InitializationMetadataV1::decode(SecretBytes::new(original[..length].to_vec()))
                    .is_err(),
                "truncation length {length}"
            );
        }

        let mut appended = original.to_vec();
        appended.push(0);
        assert_eq!(
            InitializationMetadataV1::decode(SecretBytes::new(appended)).unwrap_err(),
            TransitionContractError::InvalidMetadata
        );

        let mut oversized = vec![0_u8; MAX_INITIALIZATION_METADATA_BYTES + 1];
        oversized[..8].copy_from_slice(METADATA_MAGIC);
        assert_eq!(
            InitializationMetadataV1::decode(SecretBytes::new(oversized)).unwrap_err(),
            TransitionContractError::InvalidMetadata
        );

        for (offset, replacement, expected) in [
            (0, b'X', TransitionContractError::InvalidMetadata),
            (9, 2, TransitionContractError::UnsupportedMetadataVersion),
            (14, 2, TransitionContractError::UnsupportedMetadataKind),
        ] {
            let mut corrupted = original.to_vec();
            corrupted[offset] = replacement;
            assert_eq!(
                InitializationMetadataV1::decode(SecretBytes::new(corrupted)).unwrap_err(),
                expected
            );
        }
        let mut wrong_length = original.to_vec();
        wrong_length[10..14].copy_from_slice(&(original.len() as u32 - 1).to_be_bytes());
        assert_eq!(
            InitializationMetadataV1::decode(SecretBytes::new(wrong_length)).unwrap_err(),
            TransitionContractError::InvalidMetadata
        );
        let mut checksum_corrupt = original.to_vec();
        let checksum_offset = checksum_corrupt.len() - METADATA_CHECKSUM_BYTES;
        checksum_corrupt[checksum_offset] ^= 1;
        assert_eq!(
            InitializationMetadataV1::decode(SecretBytes::new(checksum_corrupt)).unwrap_err(),
            TransitionContractError::InvalidMetadata
        );
    }

    #[test]
    fn metadata_semantics_reject_invalid_ids_kid_version_timestamps_length_login_phc_and_salt_reuse()
     {
        let encoded = metadata().encode().expect("encode metadata");
        let original = encoded.expose_secret();
        for mutation in [
            MetadataMutation::Bytes(15, Uuid::nil().as_bytes().to_vec()),
            MetadataMutation::Bytes(31, Uuid::nil().as_bytes().to_vec()),
            MetadataMutation::Bytes(47, Uuid::nil().as_bytes().to_vec()),
            MetadataMutation::Byte(63, b'!'),
            MetadataMutation::Bytes(106, 2_u64.to_be_bytes().to_vec()),
            MetadataMutation::Bytes(114, (i64::MAX as u64 + 1).to_be_bytes().to_vec()),
            MetadataMutation::Bytes(122, (ACTIVE_AT - 1).to_be_bytes().to_vec()),
            MetadataMutation::Bytes(122, (i64::MAX as u64 + 1).to_be_bytes().to_vec()),
            MetadataMutation::Bytes(130, 169_u32.to_be_bytes().to_vec()),
            MetadataMutation::Byte(METADATA_FIXED_HEADER_BYTES, 2),
        ] {
            let corrupted = mutate_and_checksum(original, mutation);
            assert!(InitializationMetadataV1::decode(SecretBytes::new(corrupted)).is_err());
        }

        let password_length_offset =
            METADATA_FIXED_HEADER_BYTES + 1 + usize::from(original[METADATA_FIXED_HEADER_BYTES]);
        let password_length = u16::from_be_bytes(
            original[password_length_offset..password_length_offset + 2]
                .try_into()
                .unwrap(),
        ) as usize;
        let password_offset = password_length_offset + 2;
        let recovery_length_offset = password_offset + password_length;
        let recovery_length = u16::from_be_bytes(
            original[recovery_length_offset..recovery_length_offset + 2]
                .try_into()
                .unwrap(),
        ) as usize;
        let recovery_offset = recovery_length_offset + 2;

        let bad_password =
            mutate_and_checksum(original, MetadataMutation::Byte(password_offset, b'!'));
        assert_eq!(
            InitializationMetadataV1::decode(SecretBytes::new(bad_password)).unwrap_err(),
            TransitionContractError::InvalidMetadata
        );

        let mut same_salt = original.to_vec();
        let password = &original[password_offset..password_offset + password_length];
        let password_salt = phc_salt_range(password);
        let recovery = &original[recovery_offset..recovery_offset + recovery_length];
        let recovery_salt = phc_salt_range(recovery);
        let recovery_salt_absolute =
            recovery_offset + recovery_salt.start..recovery_offset + recovery_salt.end;
        same_salt[recovery_salt_absolute].copy_from_slice(&password[password_salt]);
        refresh_metadata_checksum(&mut same_salt);
        assert_eq!(
            InitializationMetadataV1::decode(SecretBytes::new(same_salt)).unwrap_err(),
            TransitionContractError::InvalidMetadata
        );

        let same_verifier = InitializationMetadataV1::from_keyring(
            InitializationMetadataInput {
                transition_id: transition_id(),
                owner_id: owner_id(),
                audit_id: audit_id(),
                source_at_micros: SourceTimestampMicros::new(ACTIVE_AT).unwrap(),
                login_id: LoginId::parse(b"owner_01").unwrap(),
                password_verifier: verifier(0x33),
                recovery_verifier: verifier(0x33),
            },
            &keyring(),
        );
        assert!(same_verifier.is_err());

        let verify_only = Keyring::from_test_seeds(
            1,
            ACTIVE_AT,
            RFC8032_SEED_ONE,
            Some((ACTIVE_AT - 1, [0x22; 32])),
        )
        .expect("verify-only keyring");
        assert_eq!(
            InitializationMetadataV1::from_keyring(
                InitializationMetadataInput {
                    transition_id: transition_id(),
                    owner_id: owner_id(),
                    audit_id: audit_id(),
                    source_at_micros: SourceTimestampMicros::new(ACTIVE_AT).unwrap(),
                    login_id: LoginId::parse(b"owner_01").unwrap(),
                    password_verifier: verifier(0x11),
                    recovery_verifier: verifier(0x22),
                },
                &verify_only,
            )
            .unwrap_err(),
            TransitionContractError::InvalidInitializationKeyring
        );
    }

    #[test]
    fn source_timestamp_is_bounded_and_not_before_key_activation() {
        assert!(SourceTimestampMicros::new(i64::MAX as u64).is_ok());
        assert_eq!(
            SourceTimestampMicros::new(i64::MAX as u64 + 1).unwrap_err(),
            TransitionContractError::InvalidMetadata
        );

        let input = |source_at_micros| InitializationMetadataInput {
            transition_id: transition_id(),
            owner_id: owner_id(),
            audit_id: audit_id(),
            source_at_micros,
            login_id: LoginId::parse(b"owner_01").unwrap(),
            password_verifier: verifier(0x11),
            recovery_verifier: verifier(0x22),
        };
        InitializationMetadataV1::from_keyring(
            input(SourceTimestampMicros::new(ACTIVE_AT).unwrap()),
            &keyring(),
        )
        .expect("equal activation and source timestamps are valid");
        assert_eq!(
            InitializationMetadataV1::from_keyring(
                input(SourceTimestampMicros::new(ACTIVE_AT - 1).unwrap()),
                &keyring(),
            )
            .unwrap_err(),
            TransitionContractError::InvalidMetadata
        );
        InitializationMetadataV1::from_keyring(
            input(SourceTimestampMicros::new(i64::MAX as u64).unwrap()),
            &keyring(),
        )
        .expect("maximum SQLite timestamp is valid");
    }

    #[test]
    fn decoder_preserves_canonical_legacy_policy_provenance_without_rewrite() {
        const HISTORICAL_VERSION: &[u8] = b"pov-blocklist-v0-4deb3704dc42b9a0";

        let encoded = metadata().encode().expect("encode metadata");
        let mut historical = encoded.expose_secret().to_vec();
        let mut offset = METADATA_FIXED_HEADER_BYTES;
        offset += 1 + usize::from(historical[offset]);
        let password_length = usize::from(u16::from_be_bytes(
            historical[offset..offset + 2].try_into().unwrap(),
        ));
        offset += 2 + password_length;
        let recovery_length = usize::from(u16::from_be_bytes(
            historical[offset..offset + 2].try_into().unwrap(),
        ));
        offset += 2 + recovery_length;
        let provenance_length = usize::from(historical[offset]);
        let provenance_end = offset + 1 + provenance_length;
        historical.splice(
            offset..provenance_end,
            std::iter::once(HISTORICAL_VERSION.len() as u8)
                .chain(HISTORICAL_VERSION.iter().copied()),
        );
        let total_length = u32::try_from(historical.len()).unwrap();
        historical[10..14].copy_from_slice(&total_length.to_be_bytes());
        refresh_metadata_checksum(&mut historical);

        let decoded =
            InitializationMetadataV1::decode(SecretBytes::new(historical.clone())).unwrap();
        assert_eq!(
            decoded.legacy_policy_provenance.as_bytes(),
            HISTORICAL_VERSION
        );
        assert!(
            !decoded
                .source_expectation()
                .uses_no_blocklist_check_policy()
        );
        assert_eq!(decoded.encode().unwrap().expose_secret(), historical);
    }

    #[test]
    fn sentinel_is_rollback_only_from_the_legacy_runtime_perspective() {
        const LEGACY_RUNTIME_CURRENT_MARKER: &[u8] = b"pov-blocklist-v1-4deb3704dc42b9a0";

        let metadata = metadata();
        let expectation = metadata.source_expectation();
        assert!(expectation.uses_no_blocklist_check_policy());
        assert!(
            expectation.matches_legacy_policy_provenance(NO_BLOCKLIST_CHECK_SENTINEL.as_bytes())
        );
        assert!(!expectation.matches_legacy_policy_provenance(LEGACY_RUNTIME_CURRENT_MARKER));
        assert!(metadata.sentinel_source_seed().is_some());
    }

    #[test]
    fn metadata_and_contract_debug_are_redacted() {
        let metadata = metadata();
        let input = InitializationMetadataInput {
            transition_id: transition_id(),
            owner_id: owner_id(),
            audit_id: audit_id(),
            source_at_micros: SourceTimestampMicros::new(ACTIVE_AT).unwrap(),
            login_id: LoginId::parse(b"secret_owner").unwrap(),
            password_verifier: verifier(0x11),
            recovery_verifier: verifier(0x22),
        };
        let rendered = format!(
            "{metadata:?} {:?} {input:?} {:?} {:?} {:?} {:?} {:?}",
            metadata.source_expectation(),
            transition_id(),
            owner_id(),
            audit_id(),
            LoginId::parse(b"secret_owner").unwrap(),
            LegacyPolicyProvenance::parse(b"secret-version-1").unwrap(),
        );
        for secret in [
            "secret_owner",
            "secret-version-1",
            TRANSITION_UUID,
            "$argon2id$",
        ] {
            assert!(!rendered.contains(secret), "{secret}");
        }
        assert!(rendered.contains("[REDACTED]"));
        assert!(
            !TransitionContractError::InvalidMetadata
                .to_string()
                .contains("secret")
        );
    }

    enum MetadataMutation {
        Byte(usize, u8),
        Bytes(usize, Vec<u8>),
    }

    fn mutate_and_checksum(original: &[u8], mutation: MetadataMutation) -> Vec<u8> {
        let mut bytes = original.to_vec();
        match mutation {
            MetadataMutation::Byte(offset, value) => bytes[offset] = value,
            MetadataMutation::Bytes(offset, value) => {
                bytes[offset..offset + value.len()].copy_from_slice(&value);
            }
        }
        refresh_metadata_checksum(&mut bytes);
        bytes
    }

    fn refresh_metadata_checksum(bytes: &mut [u8]) {
        let checksum_offset = bytes.len() - METADATA_CHECKSUM_BYTES;
        let checksum = Sha256::digest(&bytes[..checksum_offset]);
        bytes[checksum_offset..].copy_from_slice(&checksum);
    }

    fn phc_salt_range(phc: &[u8]) -> std::ops::Range<usize> {
        let mut dollar_offsets = phc
            .iter()
            .enumerate()
            .filter_map(|(index, byte)| (*byte == b'$').then_some(index));
        let _leading = dollar_offsets.next().unwrap();
        let _algorithm = dollar_offsets.next().unwrap();
        let _version = dollar_offsets.next().unwrap();
        let parameters = dollar_offsets.next().unwrap();
        let salt_end = dollar_offsets.next().unwrap();
        parameters + 1..salt_end
    }
}
