use std::{
    error::Error,
    ffi::{CStr, OsString},
    fmt, fs,
    io::{self, Write},
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::FileExt,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
use rustix::fs::{RenameFlags, renameat_with};
use rustix::{
    fs::{
        AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, Stat, flock, fstat, fsync, mkdirat,
        open, openat, statat, unlinkat,
    },
    io::{Errno, FdFlags, fcntl_getfd},
    process::geteuid,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
use pov_platform::ExtendedAclState;

use crate::storage::{
    AuthActiveLifecycleFacts, AuthConversationStoreBinding, AuthDatabaseLifecycleObservation,
    AuthDatabaseReconciliationObservation, AuthInitializationFinalLifecycleMutationOutcome,
    AuthInitializationSourceMatch, AuthInitializationSourceMutationOutcome,
    AuthPlannedRotationDatabaseObservation, AuthPlannedRotationFinalLifecycleMutationOutcome,
    AuthPlannedRotationSourceMatch, AuthPlannedRotationSourceMutationOutcome,
    AuthStorePoisonHandle, ConversationStore, SqliteStore, StoreDirectoryIdentity,
};
#[cfg(test)]
use crate::storage::{
    AuthInitializationFinalLifecycleMutationTestFault, AuthInitializationSourceMutationTestFault,
    AuthPlannedRotationFinalLifecycleMutationTestFault, AuthPlannedRotationSourceMutationTestFault,
};

use super::{
    SecretBytes,
    keyring::{ACTIVE_ONLY_LENGTH, Keyring, WITH_VERIFY_ONLY_LENGTH},
    transition::{
        ACTIVE_KEYRING_NAME, AUTH_MAINTENANCE_LOCK_NAME as AUTH_LOCK_FILE_NAME,
        InitializationMetadataV1, InitializationPreparationV1, MAX_INITIALIZATION_METADATA_BYTES,
        PlannedRotationMetadataV1, PlannedRotationPreparationV1, PlannedRotationSourceExpectation,
        ReservationEntryName, RetireMetadataV1, RetirePreparationV1, TopLevelArtifactName,
        TransitionId, TransitionKind,
    },
};

const STORE_DIRECTORY_NAME: &str = "stores";
const SECRET_DIRECTORY_NAME: &str = "secrets";
const OWNER_DIRECTORY_MODE: u32 = 0o700;
const OWNER_FILE_MODE: u32 = 0o600;
const MAX_SECRET_DIRECTORY_ENTRIES: usize = 32;
const MAX_SECRET_DIRECTORY_NAME_BYTES: usize = 8_192;
const MAX_RESERVATION_DIRECTORY_ENTRIES: usize = 8;
const MAX_RESERVATION_DIRECTORY_NAME_BYTES: usize = 2_048;

pub(crate) struct AuthInstanceLayout {
    parent_fd: OwnedFd,
    root_name: OsString,
    root_fd: OwnedFd,
    store_fd: OwnedFd,
    secret_fd: OwnedFd,
}

impl AuthInstanceLayout {
    pub(crate) fn open_or_create(root: impl AsRef<Path>) -> Result<Self, SecretFsError> {
        let absolute_root = absolute_path(root.as_ref())?;
        let prepared_root = prepare_instance_root(&absolute_root)?;
        let root_fd = openat(
            &prepared_root.parent_fd,
            &prepared_root.root_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(SecretFsError::errno)?;
        let root_identity = validate_directory_fd(&root_fd, DirectoryPurpose::InstanceRoot)?;
        ensure_cloexec(&root_fd)?;
        if root_identity != prepared_root.identity {
            return Err(SecretFsError::IdentityChanged);
        }
        revalidate_instance_root(&prepared_root.parent_fd, &root_fd, &prepared_root.root_name)?;

        let store_fd = open_or_create_child_directory(
            &root_fd,
            STORE_DIRECTORY_NAME,
            DirectoryPurpose::StoreDirectory,
        )?;
        let secret_fd = open_or_create_child_directory(
            &root_fd,
            SECRET_DIRECTORY_NAME,
            DirectoryPurpose::SecretDirectory,
        )?;

        Ok(Self {
            parent_fd: prepared_root.parent_fd,
            root_name: prepared_root.root_name,
            root_fd,
            store_fd,
            secret_fd,
        })
    }

    pub(crate) fn lock(self) -> Result<LockedAuthInstance, SecretFsError> {
        let lease = self.acquire_auth_lock()?;
        Ok(LockedAuthInstance {
            layout: self,
            _lease: lease,
        })
    }

    fn acquire_auth_lock(&self) -> Result<AuthMaintenanceLease, SecretFsError> {
        revalidate_instance_root(&self.parent_fd, &self.root_fd, &self.root_name)?;
        revalidate_child_directory(
            &self.root_fd,
            &self.store_fd,
            STORE_DIRECTORY_NAME,
            DirectoryPurpose::StoreDirectory,
        )?;
        revalidate_child_directory(
            &self.root_fd,
            &self.secret_fd,
            SECRET_DIRECTORY_NAME,
            DirectoryPurpose::SecretDirectory,
        )?;

        let (lock_fd, created) = open_or_create_lock_file(&self.secret_fd)?;
        let opened_identity = validate_lock_fd(&lock_fd)?;
        ensure_cloexec(&lock_fd)?;
        if created {
            fsync(&lock_fd).map_err(SecretFsError::errno)?;
            fsync(&self.secret_fd).map_err(SecretFsError::errno)?;
        }

        match flock(&lock_fd, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(error) if error == Errno::WOULDBLOCK || error == Errno::AGAIN => {
                return Err(SecretFsError::AlreadyLocked);
            }
            Err(error) => return Err(SecretFsError::errno(error)),
        }

        let path_identity = statat(
            &self.secret_fd,
            AUTH_LOCK_FILE_NAME,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(SecretFsError::errno)
        .and_then(|stat| validate_lock_stat(&stat))?;
        let second_fd_identity = validate_lock_fd(&lock_fd)?;
        if opened_identity != path_identity || opened_identity != second_fd_identity {
            return Err(SecretFsError::IdentityChanged);
        }
        revalidate_instance_root(&self.parent_fd, &self.root_fd, &self.root_name)?;
        revalidate_child_directory(
            &self.root_fd,
            &self.store_fd,
            STORE_DIRECTORY_NAME,
            DirectoryPurpose::StoreDirectory,
        )?;
        revalidate_child_directory(
            &self.root_fd,
            &self.secret_fd,
            SECRET_DIRECTORY_NAME,
            DirectoryPurpose::SecretDirectory,
        )?;

        Ok(AuthMaintenanceLease {
            lock_fd,
            identity: opened_identity,
        })
    }

    fn revalidate(&self) -> Result<FileIdentity, SecretFsError> {
        revalidate_instance_root(&self.parent_fd, &self.root_fd, &self.root_name)?;
        revalidate_child_directory(
            &self.root_fd,
            &self.store_fd,
            STORE_DIRECTORY_NAME,
            DirectoryPurpose::StoreDirectory,
        )?;
        revalidate_child_directory(
            &self.root_fd,
            &self.secret_fd,
            SECRET_DIRECTORY_NAME,
            DirectoryPurpose::SecretDirectory,
        )?;
        validate_directory_fd(&self.store_fd, DirectoryPurpose::StoreDirectory)
    }
}

impl fmt::Debug for AuthInstanceLayout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthInstanceLayout")
            .field("root_name", &"[REDACTED]")
            .field("parent_fd", &"[PINNED]")
            .field("root_fd", &"[PINNED]")
            .field("store_fd", &"[PINNED]")
            .field("secret_fd", &"[PINNED]")
            .finish()
    }
}

struct AuthMaintenanceLease {
    lock_fd: OwnedFd,
    identity: FileIdentity,
}

impl AuthMaintenanceLease {
    fn revalidate(&self, secret_fd: &OwnedFd) -> Result<(), SecretFsError> {
        let descriptor_identity = validate_lock_fd(&self.lock_fd)?;
        ensure_cloexec(&self.lock_fd)?;
        let path_identity = statat(secret_fd, AUTH_LOCK_FILE_NAME, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| {
                if error == Errno::NOENT {
                    SecretFsError::IdentityChanged
                } else {
                    SecretFsError::errno(error)
                }
            })
            .and_then(|stat| validate_lock_stat(&stat))?;
        if descriptor_identity != self.identity || path_identity != self.identity {
            return Err(SecretFsError::IdentityChanged);
        }
        Ok(())
    }
}

impl fmt::Debug for AuthMaintenanceLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AuthMaintenanceLease")
            .field(&"[HELD]")
            .finish()
    }
}

pub(crate) struct LockedAuthInstance {
    layout: AuthInstanceLayout,
    _lease: AuthMaintenanceLease,
}

impl LockedAuthInstance {
    pub(crate) fn bind_conversation<'a>(
        self,
        store: &'a SqliteStore<ConversationStore>,
    ) -> Result<AuthMaintenanceContext<'a>, AuthStoreBindingError> {
        let first_store_identity = store
            .auth_directory_identity()
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        let first_layout_identity = self.revalidate()?;
        if !first_store_identity.matches(
            first_layout_identity.device,
            first_layout_identity.inode,
            first_layout_identity.owner,
        ) {
            return Err(AuthStoreBindingError::ConversationStoreMismatch);
        }

        let second_store_identity = store
            .auth_directory_identity()
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        let second_layout_identity = self.revalidate()?;
        if first_store_identity != second_store_identity
            || !second_store_identity.matches(
                second_layout_identity.device,
                second_layout_identity.inode,
                second_layout_identity.owner,
            )
        {
            return Err(AuthStoreBindingError::ConversationStoreMismatch);
        }

        Ok(AuthMaintenanceContext {
            locked: self,
            conversation: store,
            store_identity: second_store_identity,
        })
    }

    fn revalidate(&self) -> Result<FileIdentity, SecretFsError> {
        let store_identity = self.layout.revalidate()?;
        self._lease.revalidate(&self.layout.secret_fd)?;
        Ok(store_identity)
    }

    fn capture_secret_artifacts(&self) -> Result<PinnedAuthArtifactSnapshot, SecretFsError> {
        self.revalidate()?;
        let inventory_fd = openat(
            &self.layout.secret_fd,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(SecretFsError::errno)?;
        let inventory_identity =
            validate_directory_fd(&inventory_fd, DirectoryPurpose::SecretDirectory)?;
        ensure_cloexec(&inventory_fd)?;
        let pinned_identity =
            validate_directory_fd(&self.layout.secret_fd, DirectoryPurpose::SecretDirectory)?;
        if inventory_identity != pinned_identity {
            return Err(SecretFsError::IdentityChanged);
        }

        let first_manifest = read_artifact_manifest(
            &inventory_fd,
            MAX_SECRET_DIRECTORY_ENTRIES,
            MAX_SECRET_DIRECTORY_NAME_BYTES,
        )?;
        let mut observations = Vec::with_capacity(first_manifest.entries.len());
        for manifest_entry in &first_manifest.entries {
            observations.push(capture_top_level_artifact(
                &inventory_fd,
                manifest_entry,
                self._lease.identity,
            )?);
        }
        let second_manifest = read_artifact_manifest(
            &inventory_fd,
            MAX_SECRET_DIRECTORY_ENTRIES,
            MAX_SECRET_DIRECTORY_NAME_BYTES,
        )?;
        if first_manifest != second_manifest {
            return Err(SecretFsError::ArtifactChanged);
        }

        let namespace = observe_top_level_namespace(&observations)?;
        if namespace.lock_count != 1 {
            return Err(SecretFsError::IdentityChanged);
        }
        self.revalidate()?;
        let directory_stat =
            validate_directory_artifact_fd(&inventory_fd, DirectoryPurpose::SecretDirectory)?;
        let pinned_stat = validate_directory_artifact_fd(
            &self.layout.secret_fd,
            DirectoryPurpose::SecretDirectory,
        )?;
        if directory_stat != pinned_stat {
            return Err(SecretFsError::ArtifactChanged);
        }
        Ok(PinnedAuthArtifactSnapshot {
            directory_fd: inventory_fd,
            directory_stat,
            manifest: second_manifest,
            observations,
            namespace,
        })
    }

    fn persist_initialization_preparation(
        &self,
        preparation: &InitializationPreparationV1,
        #[cfg(test)] fault: Option<AuthInitializationPrepareTestFault>,
    ) -> Result<AuthInitializationPersistenceOutcome, SecretFsError> {
        let artifact = preparation.transition_artifact();
        let reservation_name = artifact.format();
        if TopLevelArtifactName::parse(reservation_name.as_bytes()) != Ok(artifact) {
            return Err(SecretFsError::UnsafeAuthArtifact);
        }

        let immediate_namespace = self.capture_secret_artifacts()?;
        immediate_namespace.revalidate(&self.layout.secret_fd)?;
        self.revalidate()?;
        if !immediate_namespace.is_lock_only() {
            return Ok(AuthInitializationPersistenceOutcome::PreconditionNotClean);
        }

        mkdirat(
            &self.layout.secret_fd,
            reservation_name.as_str(),
            Mode::RWXU,
        )
        .map_err(map_creation_errno)?;
        let reservation_fd = openat(
            &self.layout.secret_fd,
            reservation_name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_artifact_errno)?;
        ensure_cloexec(&reservation_fd)?;
        let reservation_stat = validate_reservation_directory_fd(&reservation_fd)?;
        let reservation_path_stat = validate_reservation_directory_stat(
            &statat(
                &self.layout.secret_fd,
                reservation_name.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(map_artifact_errno)?,
        )?;
        if reservation_stat != reservation_path_stat {
            return Err(SecretFsError::ArtifactChanged);
        }
        fsync(&reservation_fd).map_err(SecretFsError::errno)?;
        fsync(&self.layout.secret_fd).map_err(SecretFsError::errno)?;
        self.revalidate()?;
        revalidate_created_reservation(
            &self.layout.secret_fd,
            &reservation_fd,
            reservation_name.as_str(),
            reservation_stat.identity,
        )?;
        #[cfg(test)]
        if fault == Some(AuthInitializationPrepareTestFault::Reservation) {
            return Err(SecretFsError::Io(io::ErrorKind::Other));
        }

        let encoded_metadata = preparation
            .encoded_metadata()
            .map_err(|_| SecretFsError::UnsafeAuthArtifact)?;
        persist_new_known_file(
            &reservation_fd,
            ReservationEntryName::Metadata.as_str(),
            KnownFilePurpose::Metadata,
            encoded_metadata.expose_secret(),
        )?;
        revalidate_created_reservation(
            &self.layout.secret_fd,
            &reservation_fd,
            reservation_name.as_str(),
            reservation_stat.identity,
        )?;
        #[cfg(test)]
        if fault == Some(AuthInitializationPrepareTestFault::Metadata) {
            return Err(SecretFsError::Io(io::ErrorKind::Other));
        }

        persist_new_known_file(
            &reservation_fd,
            ReservationEntryName::StagedKeyring.as_str(),
            KnownFilePurpose::StagedKeyring,
            preparation.staged_keyring_bytes(),
        )?;
        revalidate_created_reservation(
            &self.layout.secret_fd,
            &reservation_fd,
            reservation_name.as_str(),
            reservation_stat.identity,
        )?;
        #[cfg(test)]
        if fault == Some(AuthInitializationPrepareTestFault::Staged) {
            return Err(SecretFsError::Io(io::ErrorKind::Other));
        }

        persist_new_known_file(
            &reservation_fd,
            ReservationEntryName::Prepared.as_str(),
            KnownFilePurpose::Prepared,
            &[],
        )?;
        revalidate_created_reservation(
            &self.layout.secret_fd,
            &reservation_fd,
            reservation_name.as_str(),
            reservation_stat.identity,
        )?;
        #[cfg(test)]
        if fault == Some(AuthInitializationPrepareTestFault::Prepared) {
            return Err(SecretFsError::Io(io::ErrorKind::Other));
        }
        self.revalidate()?;
        Ok(AuthInitializationPersistenceOutcome::Persisted)
    }

    fn persist_planned_rotation_preparation(
        &self,
        preparation: &PlannedRotationPreparationV1,
        #[cfg(test)] fault: Option<AuthPlannedRotationPrepareTestFault>,
    ) -> Result<AuthPlannedRotationPersistenceOutcome, SecretFsError> {
        let artifact = preparation.transition_artifact();
        let reservation_name = artifact.format();
        if TopLevelArtifactName::parse(reservation_name.as_bytes()) != Ok(artifact) {
            return Err(SecretFsError::UnsafeAuthArtifact);
        }

        let immediate_namespace = self.capture_secret_artifacts()?;
        immediate_namespace.revalidate(&self.layout.secret_fd)?;
        self.revalidate()?;
        if !immediate_namespace.is_clean_active_namespace() {
            return Ok(AuthPlannedRotationPersistenceOutcome::PreconditionNotClean);
        }

        mkdirat(
            &self.layout.secret_fd,
            reservation_name.as_str(),
            Mode::RWXU,
        )
        .map_err(map_creation_errno)?;
        let reservation_fd = openat(
            &self.layout.secret_fd,
            reservation_name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_artifact_errno)?;
        ensure_cloexec(&reservation_fd)?;
        let reservation_stat = validate_reservation_directory_fd(&reservation_fd)?;
        let reservation_path_stat = validate_reservation_directory_stat(
            &statat(
                &self.layout.secret_fd,
                reservation_name.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(map_artifact_errno)?,
        )?;
        if reservation_stat != reservation_path_stat {
            return Err(SecretFsError::ArtifactChanged);
        }
        fsync(&reservation_fd).map_err(SecretFsError::errno)?;
        fsync(&self.layout.secret_fd).map_err(SecretFsError::errno)?;
        self.revalidate()?;
        revalidate_created_reservation(
            &self.layout.secret_fd,
            &reservation_fd,
            reservation_name.as_str(),
            reservation_stat.identity,
        )?;
        #[cfg(test)]
        if fault == Some(AuthPlannedRotationPrepareTestFault::Reservation) {
            return Err(SecretFsError::Io(io::ErrorKind::Other));
        }

        let encoded_metadata = preparation
            .encoded_metadata()
            .map_err(|_| SecretFsError::UnsafeAuthArtifact)?;
        persist_new_known_file(
            &reservation_fd,
            ReservationEntryName::Metadata.as_str(),
            KnownFilePurpose::Metadata,
            encoded_metadata.expose_secret(),
        )?;
        revalidate_created_reservation(
            &self.layout.secret_fd,
            &reservation_fd,
            reservation_name.as_str(),
            reservation_stat.identity,
        )?;
        #[cfg(test)]
        if fault == Some(AuthPlannedRotationPrepareTestFault::Metadata) {
            return Err(SecretFsError::Io(io::ErrorKind::Other));
        }

        persist_new_known_file(
            &reservation_fd,
            ReservationEntryName::StagedKeyring.as_str(),
            KnownFilePurpose::StagedKeyring,
            preparation.staged_keyring_bytes(),
        )?;
        revalidate_created_reservation(
            &self.layout.secret_fd,
            &reservation_fd,
            reservation_name.as_str(),
            reservation_stat.identity,
        )?;
        #[cfg(test)]
        if fault == Some(AuthPlannedRotationPrepareTestFault::Staged) {
            return Err(SecretFsError::Io(io::ErrorKind::Other));
        }

        persist_new_known_file(
            &reservation_fd,
            ReservationEntryName::Prepared.as_str(),
            KnownFilePurpose::Prepared,
            &[],
        )?;
        revalidate_created_reservation(
            &self.layout.secret_fd,
            &reservation_fd,
            reservation_name.as_str(),
            reservation_stat.identity,
        )?;
        #[cfg(test)]
        if fault == Some(AuthPlannedRotationPrepareTestFault::Prepared) {
            return Err(SecretFsError::Io(io::ErrorKind::Other));
        }
        self.revalidate()?;
        Ok(AuthPlannedRotationPersistenceOutcome::Persisted)
    }

    fn persist_retire_preparation(
        &self,
        preparation: &RetirePreparationV1,
        #[cfg(test)] fault: Option<AuthRetirePrepareTestFault>,
    ) -> Result<AuthRetirePersistenceOutcome, SecretFsError> {
        let artifact = preparation.transition_artifact();
        let reservation_name = artifact.format();
        if TopLevelArtifactName::parse(reservation_name.as_bytes()) != Ok(artifact) {
            return Err(SecretFsError::UnsafeAuthArtifact);
        }

        let immediate_namespace = self.capture_secret_artifacts()?;
        immediate_namespace.revalidate(&self.layout.secret_fd)?;
        self.revalidate()?;
        let ready = immediate_namespace.is_terminal_active_namespace()
            && immediate_namespace
                .active_file()
                .is_some_and(|active| active.content.expose().len() == WITH_VERIFY_ONLY_LENGTH);
        if !ready {
            return Ok(AuthRetirePersistenceOutcome::PreconditionNotReady);
        }

        mkdirat(
            &self.layout.secret_fd,
            reservation_name.as_str(),
            Mode::RWXU,
        )
        .map_err(map_creation_errno)?;
        let reservation_fd = openat(
            &self.layout.secret_fd,
            reservation_name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_artifact_errno)?;
        ensure_cloexec(&reservation_fd)?;
        let reservation_stat = validate_reservation_directory_fd(&reservation_fd)?;
        let reservation_path_stat = validate_reservation_directory_stat(
            &statat(
                &self.layout.secret_fd,
                reservation_name.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(map_artifact_errno)?,
        )?;
        if reservation_stat != reservation_path_stat {
            return Err(SecretFsError::ArtifactChanged);
        }
        fsync(&reservation_fd).map_err(SecretFsError::errno)?;
        fsync(&self.layout.secret_fd).map_err(SecretFsError::errno)?;
        self.revalidate()?;
        revalidate_created_reservation(
            &self.layout.secret_fd,
            &reservation_fd,
            reservation_name.as_str(),
            reservation_stat.identity,
        )?;
        #[cfg(test)]
        if fault == Some(AuthRetirePrepareTestFault::Reservation) {
            return Err(SecretFsError::Io(io::ErrorKind::Other));
        }

        let encoded_metadata = preparation
            .encoded_metadata()
            .map_err(|_| SecretFsError::UnsafeAuthArtifact)?;
        persist_new_known_file(
            &reservation_fd,
            ReservationEntryName::Metadata.as_str(),
            KnownFilePurpose::Metadata,
            encoded_metadata.expose_secret(),
        )?;
        revalidate_created_reservation(
            &self.layout.secret_fd,
            &reservation_fd,
            reservation_name.as_str(),
            reservation_stat.identity,
        )?;
        #[cfg(test)]
        if fault == Some(AuthRetirePrepareTestFault::Metadata) {
            return Err(SecretFsError::Io(io::ErrorKind::Other));
        }

        persist_new_known_file(
            &reservation_fd,
            ReservationEntryName::StagedKeyring.as_str(),
            KnownFilePurpose::StagedKeyring,
            preparation.staged_keyring_bytes(),
        )?;
        revalidate_created_reservation(
            &self.layout.secret_fd,
            &reservation_fd,
            reservation_name.as_str(),
            reservation_stat.identity,
        )?;
        #[cfg(test)]
        if fault == Some(AuthRetirePrepareTestFault::Staged) {
            return Err(SecretFsError::Io(io::ErrorKind::Other));
        }

        persist_new_known_file(
            &reservation_fd,
            ReservationEntryName::Prepared.as_str(),
            KnownFilePurpose::Prepared,
            &[],
        )?;
        revalidate_created_reservation(
            &self.layout.secret_fd,
            &reservation_fd,
            reservation_name.as_str(),
            reservation_stat.identity,
        )?;
        #[cfg(test)]
        if fault == Some(AuthRetirePrepareTestFault::Prepared) {
            return Err(SecretFsError::Io(io::ErrorKind::Other));
        }
        self.revalidate()?;
        Ok(AuthRetirePersistenceOutcome::Persisted)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AuthInitializationPersistenceOutcome {
    Persisted,
    PreconditionNotClean,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AuthPlannedRotationPersistenceOutcome {
    Persisted,
    PreconditionNotClean,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AuthRetirePersistenceOutcome {
    Persisted,
    PreconditionNotReady,
}

struct PinnedAuthArtifactSnapshot {
    directory_fd: OwnedFd,
    directory_stat: ArtifactStat,
    manifest: ArtifactManifest,
    observations: Vec<PinnedTopLevelArtifact>,
    namespace: TopLevelNamespaceObservation,
}

impl PinnedAuthArtifactSnapshot {
    fn revalidate(&self, pinned_secret_fd: &OwnedFd) -> Result<(), SecretFsError> {
        self.revalidate_inner(pinned_secret_fd, || {})
    }

    fn revalidate_inner(
        &self,
        pinned_secret_fd: &OwnedFd,
        after_observations: impl FnOnce(),
    ) -> Result<(), SecretFsError> {
        ensure_cloexec(&self.directory_fd)?;
        let held_stat =
            validate_directory_artifact_fd(&self.directory_fd, DirectoryPurpose::SecretDirectory)?;
        let pinned_stat =
            validate_directory_artifact_fd(pinned_secret_fd, DirectoryPurpose::SecretDirectory)?;
        if held_stat != self.directory_stat || pinned_stat != self.directory_stat {
            return Err(SecretFsError::ArtifactChanged);
        }

        let current_manifest = read_artifact_manifest(
            &self.directory_fd,
            MAX_SECRET_DIRECTORY_ENTRIES,
            MAX_SECRET_DIRECTORY_NAME_BYTES,
        )?;
        if current_manifest != self.manifest {
            return Err(SecretFsError::ArtifactChanged);
        }
        for observation in &self.observations {
            observation.revalidate(&self.directory_fd)?;
        }
        after_observations();
        let final_manifest = read_artifact_manifest(
            &self.directory_fd,
            MAX_SECRET_DIRECTORY_ENTRIES,
            MAX_SECRET_DIRECTORY_NAME_BYTES,
        )?;
        let final_stat =
            validate_directory_artifact_fd(&self.directory_fd, DirectoryPurpose::SecretDirectory)?;
        if final_manifest != self.manifest || final_stat != self.directory_stat {
            return Err(SecretFsError::ArtifactChanged);
        }
        Ok(())
    }

    #[cfg(test)]
    fn revalidate_with_checkpoint(
        &self,
        pinned_secret_fd: &OwnedFd,
        after_observations: impl FnOnce(),
    ) -> Result<(), SecretFsError> {
        self.revalidate_inner(pinned_secret_fd, after_observations)
    }

    fn is_lock_only(&self) -> bool {
        self.namespace.is_valid
            && self.namespace.lock_count == 1
            && self.observations.len() == 1
            && self
                .observations
                .iter()
                .all(|entry| entry.semantic_state() == RetainedArtifactState::MaintenanceLock)
    }

    fn revalidate_completed_cleanup_evidence(
        &self,
        pinned_secret_fd: &OwnedFd,
    ) -> Result<(), SecretFsError> {
        for observation in &self.observations {
            match observation {
                PinnedTopLevelArtifact::MaintenanceLock { raw_name, file }
                | PinnedTopLevelArtifact::ActiveKeyring { raw_name, file, .. } => {
                    file.revalidate(pinned_secret_fd, raw_name)?
                }
                PinnedTopLevelArtifact::Transition { directory, .. }
                | PinnedTopLevelArtifact::Cleanup { directory, .. } => {
                    let (kind, id) = match directory.artifact {
                        TopLevelArtifactName::Transition { kind, id }
                        | TopLevelArtifactName::Cleanup { kind, id } => (kind, id),
                        _ => return Err(SecretFsError::UnsafeAuthArtifact),
                    };
                    let transition_name = TopLevelArtifactName::Transition { kind, id }.format();
                    let cleanup_name = TopLevelArtifactName::Cleanup { kind, id }.format();
                    ensure_path_absent(pinned_secret_fd, transition_name.as_str())?;
                    ensure_path_absent(pinned_secret_fd, cleanup_name.as_str())?;
                    directory.revalidate_removed_empty()?;
                }
                PinnedTopLevelArtifact::InstallTemp { .. }
                | PinnedTopLevelArtifact::UnrecognizedPresent { .. } => {
                    return Err(SecretFsError::ArtifactChanged);
                }
            }
        }
        Ok(())
    }

    fn decode_initialization_metadata(&self) -> Option<InitializationMetadataV1> {
        let reservation = self.observations.iter().find_map(|entry| match entry {
            PinnedTopLevelArtifact::Transition { directory, .. }
            | PinnedTopLevelArtifact::Cleanup { directory, .. }
                if matches!(
                    directory.artifact,
                    TopLevelArtifactName::Transition {
                        kind: TransitionKind::Initialize,
                        ..
                    } | TopLevelArtifactName::Cleanup {
                        kind: TransitionKind::Initialize,
                        ..
                    }
                ) =>
            {
                Some(directory)
            }
            _ => None,
        })?;
        let file = reservation.entries.iter().find_map(|entry| match entry {
            PinnedReservationEntry::Metadata {
                file,
                codec: CodecObservation::Valid,
                ..
            } => Some(file),
            _ => None,
        })?;
        let mut copy = Zeroizing::new(Vec::with_capacity(file.content.expose().len()));
        copy.extend_from_slice(file.content.expose());
        InitializationMetadataV1::decode(SecretBytes::from_zeroizing(copy)).ok()
    }

    fn decode_planned_rotation_metadata(&self) -> Option<PlannedRotationMetadataV1> {
        let reservation = self.observations.iter().find_map(|entry| match entry {
            PinnedTopLevelArtifact::Transition { directory, .. }
            | PinnedTopLevelArtifact::Cleanup { directory, .. }
                if matches!(
                    directory.artifact,
                    TopLevelArtifactName::Transition {
                        kind: TransitionKind::Planned,
                        ..
                    } | TopLevelArtifactName::Cleanup {
                        kind: TransitionKind::Planned,
                        ..
                    }
                ) =>
            {
                Some(directory)
            }
            _ => None,
        })?;
        let file = reservation.entries.iter().find_map(|entry| match entry {
            PinnedReservationEntry::Metadata {
                file,
                codec: CodecObservation::Valid,
                ..
            } => Some(file),
            _ => None,
        })?;
        let mut copy = Zeroizing::new(Vec::with_capacity(file.content.expose().len()));
        copy.extend_from_slice(file.content.expose());
        PlannedRotationMetadataV1::decode(SecretBytes::from_zeroizing(copy)).ok()
    }

    fn decode_retire_metadata(&self) -> Option<RetireMetadataV1> {
        let reservation = self.observations.iter().find_map(|entry| match entry {
            PinnedTopLevelArtifact::Transition { directory, .. }
            | PinnedTopLevelArtifact::Cleanup { directory, .. }
                if matches!(
                    directory.artifact,
                    TopLevelArtifactName::Transition {
                        kind: TransitionKind::Retire,
                        ..
                    } | TopLevelArtifactName::Cleanup {
                        kind: TransitionKind::Retire,
                        ..
                    }
                ) =>
            {
                Some(directory)
            }
            _ => None,
        })?;
        let file = reservation.entries.iter().find_map(|entry| match entry {
            PinnedReservationEntry::Metadata {
                file,
                codec: CodecObservation::Valid,
                ..
            } => Some(file),
            _ => None,
        })?;
        let mut copy = Zeroizing::new(Vec::with_capacity(file.content.expose().len()));
        copy.extend_from_slice(file.content.expose());
        RetireMetadataV1::decode(SecretBytes::from_zeroizing(copy)).ok()
    }

    fn reconcile_planned_rotation(
        &self,
        database: AuthPlannedRotationDatabaseObservation,
        metadata: Option<&PlannedRotationMetadataV1>,
    ) -> AuthPlannedRotationReconciliation {
        if self.has_unrecognized_artifacts() {
            return AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::UnrecognizedArtifacts,
            );
        }
        if !self.namespace.is_valid {
            return AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::InconsistentDbFilesystem,
            );
        }
        let _lifecycle = match database.lifecycle {
            AuthDatabaseLifecycleObservation::Active(lifecycle)
                if self.active_matches_current_lifecycle(lifecycle)
                    && self.install_file().is_none()
                    && self.cleanup_directory().is_none() =>
            {
                lifecycle
            }
            AuthDatabaseLifecycleObservation::Active(lifecycle) => {
                return self.reconcile_planned_rotation_final_active(
                    database.source,
                    lifecycle,
                    metadata,
                );
            }
            AuthDatabaseLifecycleObservation::Transitioning(lifecycle) => {
                return self.reconcile_planned_rotation_transitioning(
                    database.source,
                    lifecycle,
                    metadata,
                );
            }
            AuthDatabaseLifecycleObservation::CleanUninitialized
            | AuthDatabaseLifecycleObservation::Initializing(_) => {
                return AuthPlannedRotationReconciliation::Blocked(
                    AuthPlannedRotationBlocker::UnsupportedLifecycleState,
                );
            }
        };
        let Some(reservation) = self.transition_directory() else {
            if database.source == AuthPlannedRotationSourceMatch::Canonical
                && metadata.is_none()
                && self.is_clean_active_namespace()
            {
                return AuthPlannedRotationReconciliation::CleanActive;
            }
            return AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::InconsistentDbFilesystem,
            );
        };
        if !matches!(
            reservation.artifact,
            TopLevelArtifactName::Transition {
                kind: TransitionKind::Planned,
                ..
            }
        ) {
            return AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::UnsupportedLifecycleState,
            );
        }
        let parts = RetainedReservationParts::from_directory(reservation);
        let phase = match (
            parts.metadata.map(|(_, codec)| codec),
            parts.staged.map(|(_, codec)| codec),
            parts.prepared,
        ) {
            (None, None, None) => AuthPlannedRotationPreSourcePhase::ReservationOnly,
            (Some(CodecObservation::Incomplete), None, None) => {
                AuthPlannedRotationPreSourcePhase::MetadataIncomplete
            }
            (Some(CodecObservation::Valid), None, None) => {
                AuthPlannedRotationPreSourcePhase::MetadataComplete
            }
            (Some(CodecObservation::Valid), Some(CodecObservation::Incomplete), None) => {
                AuthPlannedRotationPreSourcePhase::StagedIncomplete
            }
            (Some(CodecObservation::Valid), Some(CodecObservation::Valid), None)
                if reservation.linkage == SemanticLinkageObservation::Consistent =>
            {
                AuthPlannedRotationPreSourcePhase::StagedComplete
            }
            (Some(CodecObservation::Valid), Some(CodecObservation::Valid), Some(_))
                if reservation.linkage == SemanticLinkageObservation::Consistent =>
            {
                AuthPlannedRotationPreSourcePhase::Prepared
            }
            _ => {
                return AuthPlannedRotationReconciliation::Blocked(
                    AuthPlannedRotationBlocker::InconsistentDbFilesystem,
                );
            }
        };

        let metadata_complete = !matches!(
            phase,
            AuthPlannedRotationPreSourcePhase::ReservationOnly
                | AuthPlannedRotationPreSourcePhase::MetadataIncomplete
        );
        if metadata_complete {
            if database.source != AuthPlannedRotationSourceMatch::Exact
                || metadata.is_none()
                || !metadata.is_some_and(|metadata| self.active_matches_planned_metadata(metadata))
            {
                return AuthPlannedRotationReconciliation::Blocked(
                    AuthPlannedRotationBlocker::InconsistentDbFilesystem,
                );
            }
        } else if database.source != AuthPlannedRotationSourceMatch::Canonical || metadata.is_some()
        {
            return AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::InconsistentDbFilesystem,
            );
        }

        let recovery = if matches!(
            phase,
            AuthPlannedRotationPreSourcePhase::StagedComplete
                | AuthPlannedRotationPreSourcePhase::Prepared
        ) {
            AuthPlannedRotationRecovery::ResumeOrRollbackCandidate
        } else {
            AuthPlannedRotationRecovery::RollbackOnlyCandidate
        };
        AuthPlannedRotationReconciliation::PlannedPreSource { phase, recovery }
    }

    fn reconcile_retire(
        &self,
        database: AuthPlannedRotationDatabaseObservation,
        metadata: Option<&RetireMetadataV1>,
    ) -> AuthRetireReconciliation {
        if self.has_unrecognized_artifacts() {
            return AuthRetireReconciliation::Blocked(AuthRetireBlocker::UnrecognizedArtifacts);
        }
        if !self.namespace.is_valid {
            return AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem);
        }
        let lifecycle = match database.lifecycle {
            AuthDatabaseLifecycleObservation::Active(lifecycle)
                if self.active_matches_any_lifecycle(lifecycle)
                    && self.active_file().is_some_and(|active| {
                        active.content.expose().len() == WITH_VERIFY_ONLY_LENGTH
                    })
                    && self.install_file().is_none()
                    && self.cleanup_directory().is_none() =>
            {
                lifecycle
            }
            AuthDatabaseLifecycleObservation::Active(lifecycle) => {
                return self.reconcile_retire_final_active(database.source, lifecycle, metadata);
            }
            AuthDatabaseLifecycleObservation::Transitioning(lifecycle) => {
                return self.reconcile_retire_transitioning(database.source, lifecycle, metadata);
            }
            AuthDatabaseLifecycleObservation::CleanUninitialized
            | AuthDatabaseLifecycleObservation::Initializing(_) => {
                return AuthRetireReconciliation::Blocked(
                    AuthRetireBlocker::UnsupportedLifecycleState,
                );
            }
        };

        let Some(reservation) = self.transition_directory() else {
            if database.source != AuthPlannedRotationSourceMatch::Canonical
                || metadata.is_some()
                || !self.is_terminal_active_namespace()
            {
                return AuthRetireReconciliation::Blocked(
                    AuthRetireBlocker::InconsistentDbFilesystem,
                );
            }
            let Some(active) = self.active_file() else {
                return AuthRetireReconciliation::Blocked(
                    AuthRetireBlocker::InconsistentDbFilesystem,
                );
            };
            return match active.content.expose().len() {
                ACTIVE_ONLY_LENGTH => AuthRetireReconciliation::CleanActiveOnly,
                WITH_VERIFY_ONLY_LENGTH if self.active_matches_any_lifecycle(lifecycle) => {
                    AuthRetireReconciliation::ReadyToRetire
                }
                _ => AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem),
            };
        };
        if !matches!(
            reservation.artifact,
            TopLevelArtifactName::Transition {
                kind: TransitionKind::Retire,
                ..
            }
        ) {
            return AuthRetireReconciliation::Blocked(AuthRetireBlocker::UnsupportedLifecycleState);
        }
        let parts = RetainedReservationParts::from_directory(reservation);
        let phase = match (
            parts.metadata.map(|(_, codec)| codec),
            parts.staged.map(|(_, codec)| codec),
            parts.prepared,
        ) {
            (None, None, None) => AuthRetirePreSourcePhase::ReservationOnly,
            (Some(CodecObservation::Incomplete), None, None) => {
                AuthRetirePreSourcePhase::MetadataIncomplete
            }
            (Some(CodecObservation::Valid), None, None) => {
                AuthRetirePreSourcePhase::MetadataComplete
            }
            (Some(CodecObservation::Valid), Some(CodecObservation::Incomplete), None) => {
                AuthRetirePreSourcePhase::StagedIncomplete
            }
            (Some(CodecObservation::Valid), Some(CodecObservation::Valid), None)
                if reservation.linkage == SemanticLinkageObservation::Consistent =>
            {
                AuthRetirePreSourcePhase::StagedComplete
            }
            (Some(CodecObservation::Valid), Some(CodecObservation::Valid), Some(_))
                if reservation.linkage == SemanticLinkageObservation::Consistent =>
            {
                AuthRetirePreSourcePhase::Prepared
            }
            _ => {
                return AuthRetireReconciliation::Blocked(
                    AuthRetireBlocker::InconsistentDbFilesystem,
                );
            }
        };

        let metadata_complete = !matches!(
            phase,
            AuthRetirePreSourcePhase::ReservationOnly
                | AuthRetirePreSourcePhase::MetadataIncomplete
        );
        if metadata_complete {
            if database.source != AuthPlannedRotationSourceMatch::Exact
                || metadata.is_none()
                || !metadata.is_some_and(|metadata| self.active_matches_retire_metadata(metadata))
            {
                return AuthRetireReconciliation::Blocked(
                    AuthRetireBlocker::InconsistentDbFilesystem,
                );
            }
        } else if database.source != AuthPlannedRotationSourceMatch::Canonical || metadata.is_some()
        {
            return AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem);
        }

        let recovery = if matches!(
            phase,
            AuthRetirePreSourcePhase::StagedComplete | AuthRetirePreSourcePhase::Prepared
        ) {
            AuthRetireRecovery::ResumeOrRollbackCandidate
        } else {
            AuthRetireRecovery::RollbackOnlyCandidate
        };
        AuthRetireReconciliation::RetirePreSource { phase, recovery }
    }

    fn reconcile_retire_transitioning(
        &self,
        source: AuthPlannedRotationSourceMatch,
        lifecycle: crate::storage::AuthTransitioningLifecycleFacts,
        metadata: Option<&RetireMetadataV1>,
    ) -> AuthRetireReconciliation {
        let Some(metadata) = metadata else {
            return AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem);
        };
        let expectation = metadata.source_expectation();
        if source != AuthPlannedRotationSourceMatch::Exact
            || !expectation.matches_transitioning_lifecycle(
                lifecycle.state_revision,
                lifecycle.kind,
                lifecycle.transition_id,
                lifecycle.expected_kid,
                lifecycle.keyring_version,
                lifecycle.updated_at_micros,
            )
            || self.cleanup_directory().is_some()
        {
            return AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem);
        }
        let Some(reservation) = self.transition_directory() else {
            return AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem);
        };
        if !metadata.matches_reservation_artifact(reservation.artifact) {
            return AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem);
        }
        let parts = RetainedReservationParts::from_directory(reservation);
        let Some((staged, CodecObservation::Valid)) = parts.staged else {
            return AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem);
        };
        if !matches!(parts.metadata, Some((_, CodecObservation::Valid)))
            || parts.prepared.is_none()
            || reservation.linkage != SemanticLinkageObservation::Consistent
        {
            return AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem);
        }

        let Some(active) = self.active_file() else {
            return AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem);
        };
        let active_is_old = metadata
            .validate_current_keyring(SecretBytes::new(active.content.expose().to_vec()))
            .is_ok();
        let active_is_new = active.content.expose() == staged.content.expose()
            && metadata
                .validate_staged_keyring(SecretBytes::new(active.content.expose().to_vec()))
                .is_ok();
        match (active_is_old, active_is_new, self.install_file()) {
            (true, false, None) => AuthRetireReconciliation::RetireForwardOnly(
                AuthRetireForwardPhase::AwaitingInstallTemp,
            ),
            (true, false, Some(install)) => {
                let install_bytes = install.content.expose();
                let staged_bytes = staged.content.expose();
                if install_bytes == staged_bytes {
                    AuthRetireReconciliation::RetireForwardOnly(
                        AuthRetireForwardPhase::InstallTempExact,
                    )
                } else if install_bytes.len() < staged_bytes.len()
                    && staged_bytes.starts_with(install_bytes)
                {
                    AuthRetireReconciliation::RetireForwardOnly(
                        AuthRetireForwardPhase::InstallTempPrefix,
                    )
                } else {
                    AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem)
                }
            }
            (false, true, Some(install))
                if metadata
                    .validate_current_keyring(SecretBytes::new(install.content.expose().to_vec()))
                    .is_ok() =>
            {
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingOldActiveTempRemoval,
                )
            }
            (false, true, None) => AuthRetireReconciliation::RetireForwardOnly(
                AuthRetireForwardPhase::AwaitingFinalDbCas,
            ),
            _ => AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem),
        }
    }

    fn reconcile_retire_final_active(
        &self,
        source: AuthPlannedRotationSourceMatch,
        lifecycle: AuthActiveLifecycleFacts,
        metadata: Option<&RetireMetadataV1>,
    ) -> AuthRetireReconciliation {
        if self.install_file().is_some() {
            return AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem);
        }

        match (self.transition_directory(), self.cleanup_directory()) {
            (Some(reservation), None) => {
                let Some(metadata) = metadata else {
                    return AuthRetireReconciliation::Blocked(
                        AuthRetireBlocker::InconsistentDbFilesystem,
                    );
                };
                let expectation = metadata.source_expectation();
                let parts = RetainedReservationParts::from_directory(reservation);
                if source == AuthPlannedRotationSourceMatch::Exact
                    && expectation.matches_final_active_lifecycle(
                        lifecycle.state_revision,
                        lifecycle.expected_kid,
                        lifecycle.keyring_version,
                        lifecycle.updated_at_micros,
                    )
                    && metadata.matches_reservation_artifact(reservation.artifact)
                    && matches!(parts.metadata, Some((_, CodecObservation::Valid)))
                    && matches!(parts.staged, Some((_, CodecObservation::Valid)))
                    && parts.prepared.is_some()
                    && reservation.linkage == SemanticLinkageObservation::Consistent
                    && self.active_matches_retire_result_metadata(metadata)
                {
                    AuthRetireReconciliation::RetireForwardOnly(
                        AuthRetireForwardPhase::AwaitingCleanupRename,
                    )
                } else {
                    AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem)
                }
            }
            (None, Some(cleanup)) => {
                self.reconcile_retire_cleanup(source, lifecycle, metadata, cleanup)
            }
            (None, None)
                if source == AuthPlannedRotationSourceMatch::Canonical
                    && metadata.is_none()
                    && self.is_terminal_active_namespace()
                    && self.active_matches_retire_lifecycle(lifecycle) =>
            {
                AuthRetireReconciliation::CleanActiveOnly
            }
            _ => AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem),
        }
    }

    fn reconcile_retire_cleanup(
        &self,
        source: AuthPlannedRotationSourceMatch,
        lifecycle: AuthActiveLifecycleFacts,
        metadata: Option<&RetireMetadataV1>,
        cleanup: &PinnedReservationDirectory,
    ) -> AuthRetireReconciliation {
        let TopLevelArtifactName::Cleanup {
            kind: TransitionKind::Retire,
            ..
        } = cleanup.artifact
        else {
            return AuthRetireReconciliation::Blocked(AuthRetireBlocker::UnsupportedLifecycleState);
        };
        let parts = RetainedReservationParts::from_directory(cleanup);
        let exact_final = |metadata: &RetireMetadataV1| {
            metadata.matches_reservation_artifact(cleanup.artifact)
                && metadata
                    .source_expectation()
                    .matches_final_active_lifecycle(
                        lifecycle.state_revision,
                        lifecycle.expected_kid,
                        lifecycle.keyring_version,
                        lifecycle.updated_at_micros,
                    )
                && self.active_matches_retire_result_metadata(metadata)
        };
        match (parts.metadata, parts.staged, parts.prepared) {
            (Some((_, CodecObservation::Valid)), Some((_, CodecObservation::Valid)), Some(_))
                if source == AuthPlannedRotationSourceMatch::Exact
                    && metadata.is_some_and(exact_final)
                    && cleanup.linkage == SemanticLinkageObservation::Consistent =>
            {
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingCleanupStagedRemoval,
                )
            }
            (Some((_, CodecObservation::Valid)), None, Some(_))
                if source == AuthPlannedRotationSourceMatch::Exact
                    && metadata.is_some_and(exact_final) =>
            {
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingCleanupPreparedRemoval,
                )
            }
            (Some((_, CodecObservation::Valid)), None, None)
                if source == AuthPlannedRotationSourceMatch::Exact
                    && metadata.is_some_and(exact_final) =>
            {
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingCleanupMetadataRemoval,
                )
            }
            (None, None, None)
                if source == AuthPlannedRotationSourceMatch::Canonical
                    && metadata.is_none()
                    && self.active_matches_retire_lifecycle(lifecycle) =>
            {
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingCleanupDirectoryRemoval,
                )
            }
            _ => AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem),
        }
    }

    fn reconcile_planned_rotation_transitioning(
        &self,
        source: AuthPlannedRotationSourceMatch,
        lifecycle: crate::storage::AuthTransitioningLifecycleFacts,
        metadata: Option<&PlannedRotationMetadataV1>,
    ) -> AuthPlannedRotationReconciliation {
        let Some(metadata) = metadata else {
            return AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::InconsistentDbFilesystem,
            );
        };
        let expectation = metadata.source_expectation();
        if source != AuthPlannedRotationSourceMatch::Exact
            || !expectation.matches_transitioning_lifecycle(
                lifecycle.state_revision,
                lifecycle.kind,
                lifecycle.transition_id,
                lifecycle.expected_kid,
                lifecycle.keyring_version,
                lifecycle.updated_at_micros,
            )
            || self.cleanup_directory().is_some()
        {
            return AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::InconsistentDbFilesystem,
            );
        }
        let Some(reservation) = self.transition_directory() else {
            return AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::InconsistentDbFilesystem,
            );
        };
        if !metadata.matches_reservation_artifact(reservation.artifact) {
            return AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::InconsistentDbFilesystem,
            );
        }
        let parts = RetainedReservationParts::from_directory(reservation);
        let Some((staged, CodecObservation::Valid)) = parts.staged else {
            return AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::InconsistentDbFilesystem,
            );
        };
        if !matches!(parts.metadata, Some((_, CodecObservation::Valid)))
            || parts.prepared.is_none()
            || reservation.linkage != SemanticLinkageObservation::Consistent
        {
            return AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::InconsistentDbFilesystem,
            );
        }

        let Some(active) = self.active_file() else {
            return AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::InconsistentDbFilesystem,
            );
        };
        let active_is_old = self.active_matches_planned_expectation(expectation);
        let active_is_new = active.content.expose() == staged.content.expose()
            && metadata
                .validate_staged_keyring(SecretBytes::new(active.content.expose().to_vec()))
                .is_ok();
        match (active_is_old, active_is_new, self.install_file()) {
            (true, false, None) => AuthPlannedRotationReconciliation::PlannedForwardOnly(
                AuthPlannedRotationForwardPhase::AwaitingInstallTemp,
            ),
            (true, false, Some(install)) => {
                let install_bytes = install.content.expose();
                let staged_bytes = staged.content.expose();
                if install_bytes == staged_bytes {
                    AuthPlannedRotationReconciliation::PlannedForwardOnly(
                        AuthPlannedRotationForwardPhase::InstallTempExact,
                    )
                } else if install_bytes.len() < staged_bytes.len()
                    && staged_bytes.starts_with(install_bytes)
                {
                    AuthPlannedRotationReconciliation::PlannedForwardOnly(
                        AuthPlannedRotationForwardPhase::InstallTempPrefix,
                    )
                } else {
                    AuthPlannedRotationReconciliation::Blocked(
                        AuthPlannedRotationBlocker::InconsistentDbFilesystem,
                    )
                }
            }
            (false, true, Some(install))
                if known_file_matches_planned_expected_active(install, expectation) =>
            {
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingOldActiveTempRemoval,
                )
            }
            (false, true, None) => AuthPlannedRotationReconciliation::PlannedForwardOnly(
                AuthPlannedRotationForwardPhase::AwaitingFinalDbCas,
            ),
            _ => AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::InconsistentDbFilesystem,
            ),
        }
    }

    fn reconcile_planned_rotation_final_active(
        &self,
        source: AuthPlannedRotationSourceMatch,
        lifecycle: AuthActiveLifecycleFacts,
        metadata: Option<&PlannedRotationMetadataV1>,
    ) -> AuthPlannedRotationReconciliation {
        if self.install_file().is_some() {
            return AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::InconsistentDbFilesystem,
            );
        }

        match (self.transition_directory(), self.cleanup_directory()) {
            (Some(reservation), None) => {
                let Some(metadata) = metadata else {
                    return AuthPlannedRotationReconciliation::Blocked(
                        AuthPlannedRotationBlocker::InconsistentDbFilesystem,
                    );
                };
                let expectation = metadata.source_expectation();
                let parts = RetainedReservationParts::from_directory(reservation);
                if source == AuthPlannedRotationSourceMatch::Exact
                    && expectation.matches_final_active_lifecycle(
                        lifecycle.state_revision,
                        lifecycle.expected_kid,
                        lifecycle.keyring_version,
                        lifecycle.updated_at_micros,
                    )
                    && metadata.matches_reservation_artifact(reservation.artifact)
                    && matches!(parts.metadata, Some((_, CodecObservation::Valid)))
                    && matches!(parts.staged, Some((_, CodecObservation::Valid)))
                    && parts.prepared.is_some()
                    && reservation.linkage == SemanticLinkageObservation::Consistent
                    && self.active_matches_planned_result_metadata(metadata)
                {
                    AuthPlannedRotationReconciliation::PlannedForwardOnly(
                        AuthPlannedRotationForwardPhase::AwaitingCleanupRename,
                    )
                } else {
                    AuthPlannedRotationReconciliation::Blocked(
                        AuthPlannedRotationBlocker::InconsistentDbFilesystem,
                    )
                }
            }
            (None, Some(cleanup)) => {
                self.reconcile_planned_rotation_cleanup(source, lifecycle, metadata, cleanup)
            }
            (None, None)
                if source == AuthPlannedRotationSourceMatch::Canonical
                    && metadata.is_none()
                    && self.is_terminal_initialization_namespace()
                    && self.active_matches_planned_lifecycle(lifecycle) =>
            {
                AuthPlannedRotationReconciliation::PlannedRotationComplete
            }
            _ => AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::InconsistentDbFilesystem,
            ),
        }
    }

    fn reconcile_planned_rotation_cleanup(
        &self,
        source: AuthPlannedRotationSourceMatch,
        lifecycle: AuthActiveLifecycleFacts,
        metadata: Option<&PlannedRotationMetadataV1>,
        cleanup: &PinnedReservationDirectory,
    ) -> AuthPlannedRotationReconciliation {
        let TopLevelArtifactName::Cleanup {
            kind: TransitionKind::Planned,
            ..
        } = cleanup.artifact
        else {
            return AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::UnsupportedLifecycleState,
            );
        };
        let parts = RetainedReservationParts::from_directory(cleanup);
        match (parts.metadata, parts.staged, parts.prepared) {
            (Some((_, CodecObservation::Valid)), Some((_, CodecObservation::Valid)), Some(_))
                if source == AuthPlannedRotationSourceMatch::Exact
                    && metadata.is_some_and(|metadata| {
                        metadata.matches_reservation_artifact(cleanup.artifact)
                            && metadata
                                .source_expectation()
                                .matches_final_active_lifecycle(
                                    lifecycle.state_revision,
                                    lifecycle.expected_kid,
                                    lifecycle.keyring_version,
                                    lifecycle.updated_at_micros,
                                )
                            && self.active_matches_planned_result_metadata(metadata)
                    })
                    && cleanup.linkage == SemanticLinkageObservation::Consistent =>
            {
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingCleanupStagedRemoval,
                )
            }
            (Some((_, CodecObservation::Valid)), None, Some(_))
                if source == AuthPlannedRotationSourceMatch::Exact
                    && metadata.is_some_and(|metadata| {
                        metadata.matches_reservation_artifact(cleanup.artifact)
                            && metadata
                                .source_expectation()
                                .matches_final_active_lifecycle(
                                    lifecycle.state_revision,
                                    lifecycle.expected_kid,
                                    lifecycle.keyring_version,
                                    lifecycle.updated_at_micros,
                                )
                            && self.active_matches_planned_result_metadata(metadata)
                    }) =>
            {
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingCleanupPreparedRemoval,
                )
            }
            (Some((_, CodecObservation::Valid)), None, None)
                if source == AuthPlannedRotationSourceMatch::Exact
                    && metadata.is_some_and(|metadata| {
                        metadata.matches_reservation_artifact(cleanup.artifact)
                            && metadata
                                .source_expectation()
                                .matches_final_active_lifecycle(
                                    lifecycle.state_revision,
                                    lifecycle.expected_kid,
                                    lifecycle.keyring_version,
                                    lifecycle.updated_at_micros,
                                )
                            && self.active_matches_planned_result_metadata(metadata)
                    }) =>
            {
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingCleanupMetadataRemoval,
                )
            }
            (None, None, None)
                if source == AuthPlannedRotationSourceMatch::Canonical
                    && metadata.is_none()
                    && self.active_matches_planned_lifecycle(lifecycle) =>
            {
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingCleanupDirectoryRemoval,
                )
            }
            _ => AuthPlannedRotationReconciliation::Blocked(
                AuthPlannedRotationBlocker::InconsistentDbFilesystem,
            ),
        }
    }

    fn reconcile_initialization(
        &self,
        database: AuthDatabaseReconciliationObservation,
        metadata: Option<&InitializationMetadataV1>,
    ) -> AuthInitializationReconciliation {
        if self.has_unrecognized_artifacts() {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::UnrecognizedArtifacts,
            );
        }
        if !self.namespace.is_valid {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem,
            );
        }
        match database.lifecycle {
            AuthDatabaseLifecycleObservation::CleanUninitialized => {
                self.reconcile_pre_source(metadata)
            }
            AuthDatabaseLifecycleObservation::Initializing(_) => {
                self.reconcile_forward_only(database.source, metadata)
            }
            AuthDatabaseLifecycleObservation::Active(_) => {
                self.reconcile_active(database, metadata)
            }
            AuthDatabaseLifecycleObservation::Transitioning(_) => {
                AuthInitializationReconciliation::Blocked(
                    AuthInitializationBlocker::UnsupportedLifecycleState,
                )
            }
        }
    }

    fn reconcile_pre_source(
        &self,
        metadata: Option<&InitializationMetadataV1>,
    ) -> AuthInitializationReconciliation {
        if self.is_lock_only() {
            return AuthInitializationReconciliation::CleanUninitialized;
        }
        if self.active_file().is_some()
            || self.install_file().is_some()
            || self.cleanup_directory().is_some()
        {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem,
            );
        }
        let Some(reservation) = self.transition_directory() else {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem,
            );
        };
        if !matches!(
            reservation.artifact,
            TopLevelArtifactName::Transition {
                kind: TransitionKind::Initialize,
                ..
            }
        ) {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::UnsupportedLifecycleState,
            );
        }
        let parts = RetainedReservationParts::from_directory(reservation);
        let phase = match (
            parts.metadata.map(|(_, codec)| codec),
            parts.staged.map(|(_, codec)| codec),
            parts.prepared,
        ) {
            (None, None, None) => AuthInitializationPreSourcePhase::ReservationOnly,
            (Some(CodecObservation::Incomplete), None, None) => {
                AuthInitializationPreSourcePhase::MetadataIncomplete
            }
            (Some(CodecObservation::Valid), None, None) => {
                AuthInitializationPreSourcePhase::MetadataComplete
            }
            (Some(CodecObservation::Valid), Some(CodecObservation::Incomplete), None) => {
                AuthInitializationPreSourcePhase::StagedIncomplete
            }
            (Some(CodecObservation::Valid), Some(CodecObservation::Valid), None)
                if reservation.linkage == SemanticLinkageObservation::Consistent =>
            {
                AuthInitializationPreSourcePhase::StagedComplete
            }
            (Some(CodecObservation::Valid), Some(CodecObservation::Valid), Some(_))
                if reservation.linkage == SemanticLinkageObservation::Consistent =>
            {
                AuthInitializationPreSourcePhase::Prepared
            }
            _ => {
                return AuthInitializationReconciliation::Blocked(
                    AuthInitializationBlocker::InconsistentDbFilesystem,
                );
            }
        };
        let resumable_phase = matches!(
            phase,
            AuthInitializationPreSourcePhase::StagedComplete
                | AuthInitializationPreSourcePhase::Prepared
        );
        let sentinel_policy = metadata
            .map(InitializationMetadataV1::source_expectation)
            .is_some_and(|expectation| expectation.uses_no_blocklist_check_policy());
        let recovery = if resumable_phase && sentinel_policy {
            AuthInitializationRecovery::ResumeOrRollbackCandidate
        } else {
            AuthInitializationRecovery::RollbackOnlyCandidate
        };
        AuthInitializationReconciliation::InitializePreSource { phase, recovery }
    }

    fn reconcile_forward_only(
        &self,
        source: AuthInitializationSourceMatch,
        metadata: Option<&InitializationMetadataV1>,
    ) -> AuthInitializationReconciliation {
        if source != AuthInitializationSourceMatch::Exact
            || metadata.is_none()
            || self.cleanup_directory().is_some()
        {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem,
            );
        }
        let Some(reservation) = self.transition_directory() else {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem,
            );
        };
        if !matches!(
            reservation.artifact,
            TopLevelArtifactName::Transition {
                kind: TransitionKind::Initialize,
                ..
            }
        ) {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::UnsupportedLifecycleState,
            );
        }
        let parts = RetainedReservationParts::from_directory(reservation);
        let Some((staged, CodecObservation::Valid)) = parts.staged else {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem,
            );
        };
        if !matches!(parts.metadata, Some((_, CodecObservation::Valid)))
            || parts.prepared.is_none()
            || reservation.linkage != SemanticLinkageObservation::Consistent
        {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem,
            );
        }

        match (self.active_file(), self.install_file()) {
            (None, None) => AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::AwaitingInstallTemp,
            ),
            (None, Some(install)) => {
                let install_bytes = install.content.expose();
                let staged_bytes = staged.content.expose();
                if install_bytes == staged_bytes {
                    AuthInitializationReconciliation::InitializeForwardOnly(
                        AuthInitializationForwardPhase::InstallTempExact,
                    )
                } else if install_bytes.len() < staged_bytes.len()
                    && staged_bytes.starts_with(install_bytes)
                {
                    AuthInitializationReconciliation::InitializeForwardOnly(
                        AuthInitializationForwardPhase::InstallTempPrefix,
                    )
                } else {
                    AuthInitializationReconciliation::Blocked(
                        AuthInitializationBlocker::InconsistentDbFilesystem,
                    )
                }
            }
            (Some(active), None) if active.content.expose() == staged.content.expose() => {
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingFinalDbCas,
                )
            }
            (Some(_), None) | (Some(_), Some(_)) => AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem,
            ),
        }
    }

    fn reconcile_active(
        &self,
        database: AuthDatabaseReconciliationObservation,
        metadata: Option<&InitializationMetadataV1>,
    ) -> AuthInitializationReconciliation {
        let AuthDatabaseLifecycleObservation::Active(lifecycle) = database.lifecycle else {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem,
            );
        };
        if self.install_file().is_some() {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem,
            );
        }

        match (self.transition_directory(), self.cleanup_directory()) {
            (Some(_), None) => self.reconcile_awaiting_cleanup_rename(database.source, metadata),
            (None, Some(cleanup)) => {
                self.reconcile_cleanup_directory(database.source, lifecycle, metadata, cleanup)
            }
            (None, None) => {
                self.reconcile_initialization_terminal(database.source, lifecycle, metadata)
            }
            (Some(_), Some(_)) => AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem,
            ),
        }
    }

    fn reconcile_awaiting_cleanup_rename(
        &self,
        source: AuthInitializationSourceMatch,
        metadata: Option<&InitializationMetadataV1>,
    ) -> AuthInitializationReconciliation {
        if source != AuthInitializationSourceMatch::Exact || metadata.is_none() {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem,
            );
        }
        let Some(evidence) = self.initialization_active_key_evidence() else {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem,
            );
        };
        let Some(active) = self.active_file() else {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem,
            );
        };
        if active.content.expose() != evidence.staged.content.expose() {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem,
            );
        }
        AuthInitializationReconciliation::InitializeForwardOnly(
            AuthInitializationForwardPhase::AwaitingCleanupRename,
        )
    }

    fn reconcile_cleanup_directory(
        &self,
        source: AuthInitializationSourceMatch,
        lifecycle: AuthActiveLifecycleFacts,
        metadata: Option<&InitializationMetadataV1>,
        cleanup: &PinnedReservationDirectory,
    ) -> AuthInitializationReconciliation {
        let TopLevelArtifactName::Cleanup {
            kind: TransitionKind::Initialize,
            ..
        } = cleanup.artifact
        else {
            return AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::UnsupportedLifecycleState,
            );
        };
        let parts = RetainedReservationParts::from_directory(cleanup);
        match (parts.metadata, parts.staged, parts.prepared) {
            (Some((_, CodecObservation::Valid)), Some((_, CodecObservation::Valid)), Some(_))
                if source == AuthInitializationSourceMatch::Exact
                    && metadata.is_some_and(|metadata| {
                        self.active_matches_initialization_metadata(metadata)
                    })
                    && cleanup.linkage == SemanticLinkageObservation::Consistent =>
            {
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingCleanupStagedRemoval,
                )
            }
            (Some((_, CodecObservation::Valid)), None, Some(_))
                if source == AuthInitializationSourceMatch::Exact
                    && metadata.is_some_and(|metadata| {
                        self.active_matches_initialization_metadata(metadata)
                    }) =>
            {
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingCleanupPreparedRemoval,
                )
            }
            (Some((_, CodecObservation::Valid)), None, None)
                if source == AuthInitializationSourceMatch::Exact
                    && metadata.is_some_and(|metadata| {
                        self.active_matches_initialization_metadata(metadata)
                    }) =>
            {
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingCleanupMetadataRemoval,
                )
            }
            (None, None, None)
                if source == AuthInitializationSourceMatch::NotApplicable
                    && metadata.is_none()
                    && self.active_matches_initialization_lifecycle(lifecycle) =>
            {
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingCleanupDirectoryRemoval,
                )
            }
            _ => AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::InconsistentDbFilesystem,
            ),
        }
    }

    fn reconcile_initialization_terminal(
        &self,
        source: AuthInitializationSourceMatch,
        lifecycle: AuthActiveLifecycleFacts,
        metadata: Option<&InitializationMetadataV1>,
    ) -> AuthInitializationReconciliation {
        if source == AuthInitializationSourceMatch::NotApplicable
            && metadata.is_none()
            && self.is_terminal_initialization_namespace()
            && self.active_matches_initialization_lifecycle(lifecycle)
        {
            AuthInitializationReconciliation::InitializationComplete
        } else {
            AuthInitializationReconciliation::Blocked(
                AuthInitializationBlocker::UnsupportedLifecycleState,
            )
        }
    }

    fn active_matches_initialization_metadata(&self, metadata: &InitializationMetadataV1) -> bool {
        let Some(active) = self.active_file() else {
            return false;
        };
        active.content.expose().len() == ACTIVE_ONLY_LENGTH
            && metadata
                .validate_staged_keyring(SecretBytes::new(active.content.expose().to_vec()))
                .is_ok()
    }

    fn active_matches_initialization_lifecycle(&self, lifecycle: AuthActiveLifecycleFacts) -> bool {
        let Some(active) = self.active_file() else {
            return false;
        };
        if lifecycle.state_revision != 2
            || lifecycle.keyring_version.get() != 1
            || active.content.expose().len() != ACTIVE_ONLY_LENGTH
        {
            return false;
        }
        let Ok(keyring) = Keyring::decode(SecretBytes::new(active.content.expose().to_vec()))
        else {
            return false;
        };
        lifecycle.expected_kid.matches_key(keyring.active_kid())
            && lifecycle.keyring_version.matches_version(keyring.version())
            && lifecycle
                .updated_at_micros
                .is_at_or_after(keyring.active_activated_at())
    }

    fn active_matches_current_lifecycle(&self, lifecycle: AuthActiveLifecycleFacts) -> bool {
        let Some(active) = self.active_file() else {
            return false;
        };
        if active.content.expose().len() != ACTIVE_ONLY_LENGTH {
            return false;
        }
        let Ok(keyring) = Keyring::decode(SecretBytes::new(active.content.expose().to_vec()))
        else {
            return false;
        };
        lifecycle.expected_kid.matches_key(keyring.active_kid())
            && lifecycle.keyring_version.matches_version(keyring.version())
            && lifecycle
                .updated_at_micros
                .is_at_or_after(keyring.active_activated_at())
    }

    fn active_matches_planned_metadata(&self, metadata: &PlannedRotationMetadataV1) -> bool {
        self.active_matches_planned_expectation(metadata.source_expectation())
    }

    fn active_matches_planned_expectation(
        &self,
        expectation: PlannedRotationSourceExpectation<'_>,
    ) -> bool {
        let Some(active) = self.active_file() else {
            return false;
        };
        if active.content.expose().len() != ACTIVE_ONLY_LENGTH {
            return false;
        }
        let Ok(keyring) = Keyring::decode(SecretBytes::new(active.content.expose().to_vec()))
        else {
            return false;
        };
        keyring.active_kid().as_str() == expectation.expected_active_kid()
            && i64::try_from(keyring.version().get()).ok()
                == Some(expectation.expected_keyring_version())
            && i64::try_from(keyring.active_activated_at().get()).ok()
                == Some(expectation.expected_key_activated_at_micros())
    }

    fn active_matches_planned_result_metadata(&self, metadata: &PlannedRotationMetadataV1) -> bool {
        let Some(active) = self.active_file() else {
            return false;
        };
        active.content.expose().len() == WITH_VERIFY_ONLY_LENGTH
            && metadata
                .validate_staged_keyring(SecretBytes::new(active.content.expose().to_vec()))
                .is_ok()
    }

    fn active_matches_planned_lifecycle(&self, lifecycle: AuthActiveLifecycleFacts) -> bool {
        let Some(active) = self.active_file() else {
            return false;
        };
        if active.content.expose().len() != WITH_VERIFY_ONLY_LENGTH {
            return false;
        }
        let Ok(keyring) = Keyring::decode(SecretBytes::new(active.content.expose().to_vec()))
        else {
            return false;
        };
        lifecycle.expected_kid.matches_key(keyring.active_kid())
            && lifecycle.keyring_version.matches_version(keyring.version())
            && lifecycle
                .updated_at_micros
                .is_at_or_after(keyring.active_activated_at())
    }

    fn active_matches_any_lifecycle(&self, lifecycle: AuthActiveLifecycleFacts) -> bool {
        let Some(active) = self.active_file() else {
            return false;
        };
        let Ok(keyring) = Keyring::decode(SecretBytes::new(active.content.expose().to_vec()))
        else {
            return false;
        };
        lifecycle.expected_kid.matches_key(keyring.active_kid())
            && lifecycle.keyring_version.matches_version(keyring.version())
            && lifecycle
                .updated_at_micros
                .is_at_or_after(keyring.active_activated_at())
    }

    fn active_matches_retire_metadata(&self, metadata: &RetireMetadataV1) -> bool {
        let Some(active) = self.active_file() else {
            return false;
        };
        metadata
            .validate_current_keyring(SecretBytes::new(active.content.expose().to_vec()))
            .is_ok()
    }

    fn active_matches_retire_result_metadata(&self, metadata: &RetireMetadataV1) -> bool {
        let Some(active) = self.active_file() else {
            return false;
        };
        metadata
            .validate_staged_keyring(SecretBytes::new(active.content.expose().to_vec()))
            .is_ok()
    }

    fn active_matches_retire_lifecycle(&self, lifecycle: AuthActiveLifecycleFacts) -> bool {
        let Some(active) = self.active_file() else {
            return false;
        };
        if active.content.expose().len() != ACTIVE_ONLY_LENGTH {
            return false;
        }
        let Ok(keyring) = Keyring::decode(SecretBytes::new(active.content.expose().to_vec()))
        else {
            return false;
        };
        lifecycle.expected_kid.matches_key(keyring.active_kid())
            && lifecycle.keyring_version.matches_version(keyring.version())
            && lifecycle
                .updated_at_micros
                .is_at_or_after(keyring.active_activated_at())
    }

    fn is_terminal_initialization_namespace(&self) -> bool {
        self.namespace.is_valid
            && self.observations.len() == 2
            && self
                .observations
                .iter()
                .filter(|entry| matches!(entry, PinnedTopLevelArtifact::MaintenanceLock { .. }))
                .count()
                == 1
            && self
                .observations
                .iter()
                .filter(|entry| matches!(entry, PinnedTopLevelArtifact::ActiveKeyring { .. }))
                .count()
                == 1
    }

    fn is_clean_active_namespace(&self) -> bool {
        self.namespace.is_valid
            && self.observations.len() == 2
            && self
                .observations
                .iter()
                .filter(|entry| matches!(entry, PinnedTopLevelArtifact::MaintenanceLock { .. }))
                .count()
                == 1
            && self
                .observations
                .iter()
                .filter(|entry| {
                    matches!(
                        entry,
                        PinnedTopLevelArtifact::ActiveKeyring {
                            file,
                            codec: CodecObservation::Valid,
                            ..
                        } if file.content.expose().len() == ACTIVE_ONLY_LENGTH
                    )
                })
                .count()
                == 1
    }

    fn is_terminal_active_namespace(&self) -> bool {
        self.namespace.is_valid
            && self.observations.len() == 2
            && self
                .observations
                .iter()
                .filter(|entry| matches!(entry, PinnedTopLevelArtifact::MaintenanceLock { .. }))
                .count()
                == 1
            && self
                .observations
                .iter()
                .filter(|entry| {
                    matches!(
                        entry,
                        PinnedTopLevelArtifact::ActiveKeyring {
                            codec: CodecObservation::Valid,
                            ..
                        }
                    )
                })
                .count()
                == 1
    }

    fn matches_planned_preparation(
        &self,
        preparation: &PlannedRotationPreparationV1,
    ) -> Result<bool, SecretFsError> {
        let Some(reservation) = self.transition_directory() else {
            return Ok(false);
        };
        if reservation.artifact != preparation.transition_artifact() {
            return Ok(false);
        }
        let parts = RetainedReservationParts::from_directory(reservation);
        let Some((metadata, CodecObservation::Valid)) = parts.metadata else {
            return Ok(false);
        };
        let Some((staged, CodecObservation::Valid)) = parts.staged else {
            return Ok(false);
        };
        if parts.prepared.is_none() || reservation.linkage != SemanticLinkageObservation::Consistent
        {
            return Ok(false);
        }
        let encoded = preparation
            .encoded_metadata()
            .map_err(|_| SecretFsError::UnsafeAuthArtifact)?;
        Ok(metadata.content.expose() == encoded.expose_secret()
            && staged.content.expose() == preparation.staged_keyring_bytes())
    }

    fn matches_retire_preparation(
        &self,
        preparation: &RetirePreparationV1,
    ) -> Result<bool, SecretFsError> {
        let Some(reservation) = self.transition_directory() else {
            return Ok(false);
        };
        if reservation.artifact != preparation.transition_artifact() {
            return Ok(false);
        }
        let parts = RetainedReservationParts::from_directory(reservation);
        let Some((metadata, CodecObservation::Valid)) = parts.metadata else {
            return Ok(false);
        };
        let Some((staged, CodecObservation::Valid)) = parts.staged else {
            return Ok(false);
        };
        if parts.prepared.is_none() || reservation.linkage != SemanticLinkageObservation::Consistent
        {
            return Ok(false);
        }
        let encoded = preparation
            .encoded_metadata()
            .map_err(|_| SecretFsError::UnsafeAuthArtifact)?;
        Ok(metadata.content.expose() == encoded.expose_secret()
            && staged.content.expose() == preparation.staged_keyring_bytes())
    }

    fn active_file(&self) -> Option<&PinnedKnownFile> {
        self.observations.iter().find_map(|entry| match entry {
            PinnedTopLevelArtifact::ActiveKeyring { file, .. } => Some(file),
            _ => None,
        })
    }

    fn transition_directory(&self) -> Option<&PinnedReservationDirectory> {
        self.observations.iter().find_map(|entry| match entry {
            PinnedTopLevelArtifact::Transition { directory, .. } => Some(directory),
            _ => None,
        })
    }

    fn cleanup_directory(&self) -> Option<&PinnedReservationDirectory> {
        self.observations.iter().find_map(|entry| match entry {
            PinnedTopLevelArtifact::Cleanup { directory, .. } => Some(directory),
            _ => None,
        })
    }

    fn revalidate_pre_source_rollback_progress(
        &self,
        parent_fd: &OwnedFd,
        current: &Self,
    ) -> Result<(), SecretFsError> {
        let original = self
            .transition_directory()
            .ok_or(SecretFsError::ArtifactChanged)?;
        let current = current
            .transition_directory()
            .ok_or(SecretFsError::ArtifactChanged)?;
        original.revalidate_pre_source_rollback_progress(parent_fd, current)
    }

    fn revalidate_planned_rotation_rollback_progress(
        &self,
        parent_fd: &OwnedFd,
        current: &Self,
    ) -> Result<(), SecretFsError> {
        self.revalidate_pre_source_rollback_progress(parent_fd, current)?;
        let original_active = self.active_file().ok_or(SecretFsError::ArtifactChanged)?;
        let current_active = current
            .active_file()
            .ok_or(SecretFsError::ArtifactChanged)?;
        if original_active.stat != current_active.stat
            || original_active.content.expose() != current_active.content.expose()
            || original_active.content_sha256 != current_active.content_sha256
        {
            return Err(SecretFsError::ArtifactChanged);
        }
        let raw_name = RedactedBytes::new(ACTIVE_KEYRING_NAME.as_bytes().to_vec());
        original_active.revalidate(parent_fd, &raw_name)?;
        current_active.revalidate(parent_fd, &raw_name)
    }

    fn revalidate_pre_source_recovery_completion(
        &self,
        parent_fd: &OwnedFd,
        current: &Self,
        created_prepared: &PinnedKnownFile,
    ) -> Result<(), SecretFsError> {
        let original = self
            .transition_directory()
            .ok_or(SecretFsError::ArtifactChanged)?;
        let current = current
            .transition_directory()
            .ok_or(SecretFsError::ArtifactChanged)?;
        original.revalidate_pre_source_recovery_completion(parent_fd, current, created_prepared)
    }

    fn install_file(&self) -> Option<&PinnedKnownFile> {
        self.observations.iter().find_map(|entry| match entry {
            PinnedTopLevelArtifact::InstallTemp { file, .. } => Some(file),
            _ => None,
        })
    }

    fn has_unrecognized_artifacts(&self) -> bool {
        self.observations.iter().any(|entry| match entry {
            PinnedTopLevelArtifact::UnrecognizedPresent { .. } => true,
            PinnedTopLevelArtifact::Transition { directory, .. }
            | PinnedTopLevelArtifact::Cleanup { directory, .. } => directory
                .entries
                .iter()
                .any(|entry| matches!(entry, PinnedReservationEntry::UnrecognizedPresent { .. })),
            _ => false,
        })
    }

    fn initialization_active_key_evidence(&self) -> Option<InitializationActiveKeyEvidence<'_>> {
        let reservation = self.transition_directory()?;
        let transition_id = match reservation.artifact {
            TopLevelArtifactName::Transition {
                kind: TransitionKind::Initialize,
                id,
            } => id,
            _ => return None,
        };
        let parts = RetainedReservationParts::from_directory(reservation);
        let (staged, CodecObservation::Valid) = parts.staged? else {
            return None;
        };
        if !matches!(parts.metadata, Some((_, CodecObservation::Valid)))
            || parts.prepared.is_none()
            || reservation.linkage != SemanticLinkageObservation::Consistent
        {
            return None;
        }
        Some(InitializationActiveKeyEvidence {
            transition_id,
            staged,
        })
    }

    fn planned_rotation_active_key_evidence(&self) -> Option<PlannedRotationActiveKeyEvidence<'_>> {
        let reservation = self.transition_directory()?;
        let transition_id = match reservation.artifact {
            TopLevelArtifactName::Transition {
                kind: TransitionKind::Planned,
                id,
            } => id,
            _ => return None,
        };
        let parts = RetainedReservationParts::from_directory(reservation);
        let (staged, CodecObservation::Valid) = parts.staged? else {
            return None;
        };
        if !matches!(parts.metadata, Some((_, CodecObservation::Valid)))
            || parts.prepared.is_none()
            || reservation.linkage != SemanticLinkageObservation::Consistent
        {
            return None;
        }
        Some(PlannedRotationActiveKeyEvidence {
            transition_id,
            staged,
        })
    }

    fn retire_active_key_evidence(&self) -> Option<PlannedRotationActiveKeyEvidence<'_>> {
        let reservation = self.transition_directory()?;
        let transition_id = match reservation.artifact {
            TopLevelArtifactName::Transition {
                kind: TransitionKind::Retire,
                id,
            } => id,
            _ => return None,
        };
        let parts = RetainedReservationParts::from_directory(reservation);
        let (staged, CodecObservation::Valid) = parts.staged? else {
            return None;
        };
        if !matches!(parts.metadata, Some((_, CodecObservation::Valid)))
            || parts.prepared.is_none()
            || reservation.linkage != SemanticLinkageObservation::Consistent
        {
            return None;
        }
        Some(PlannedRotationActiveKeyEvidence {
            transition_id,
            staged,
        })
    }
}

struct InitializationActiveKeyEvidence<'a> {
    transition_id: TransitionId,
    staged: &'a PinnedKnownFile,
}

struct PlannedRotationActiveKeyEvidence<'a> {
    transition_id: TransitionId,
    staged: &'a PinnedKnownFile,
}

struct RetainedReservationParts<'a> {
    metadata: Option<(&'a PinnedKnownFile, CodecObservation)>,
    staged: Option<(&'a PinnedKnownFile, CodecObservation)>,
    prepared: Option<&'a PinnedKnownFile>,
}

impl<'a> RetainedReservationParts<'a> {
    fn from_directory(directory: &'a PinnedReservationDirectory) -> Self {
        let mut parts = Self {
            metadata: None,
            staged: None,
            prepared: None,
        };
        for entry in &directory.entries {
            match entry {
                PinnedReservationEntry::Metadata { file, codec, .. } => {
                    parts.metadata = Some((file, *codec));
                }
                PinnedReservationEntry::StagedKeyring { file, codec, .. } => {
                    parts.staged = Some((file, *codec));
                }
                PinnedReservationEntry::Prepared { file, .. } => parts.prepared = Some(file),
                PinnedReservationEntry::UnrecognizedPresent { .. } => {}
            }
        }
        parts
    }
}

impl fmt::Debug for PinnedAuthArtifactSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PinnedAuthArtifactSnapshot")
            .field(&"[REDACTED]")
            .finish()
    }
}

struct RedactedBytes(SecretBytes);

impl RedactedBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(SecretBytes::new(bytes))
    }

    fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(SecretBytes::from_zeroizing(bytes))
    }

    fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }

    fn with_c_str<T>(
        &self,
        operation: impl FnOnce(&CStr) -> Result<T, SecretFsError>,
    ) -> Result<T, SecretFsError> {
        let capacity = self
            .expose()
            .len()
            .checked_add(1)
            .ok_or(SecretFsError::ArtifactInventoryLimit)?;
        let mut nul_terminated = Zeroizing::new(Vec::with_capacity(capacity));
        nul_terminated.extend_from_slice(self.expose());
        nul_terminated.push(0);
        let name = CStr::from_bytes_with_nul(nul_terminated.as_slice())
            .map_err(|_| SecretFsError::UnsafeAuthArtifact)?;
        operation(name)
    }
}

impl PartialEq for RedactedBytes {
    fn eq(&self, other: &Self) -> bool {
        self.expose() == other.expose()
    }
}

impl Eq for RedactedBytes {}

impl fmt::Debug for RedactedBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RedactedBytes([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ArtifactStat {
    identity: FileIdentity,
    size: u64,
    modified_seconds: i128,
    modified_nanoseconds: i128,
    changed_seconds: i128,
    changed_nanoseconds: i128,
}

impl fmt::Debug for ArtifactStat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArtifactStat([REDACTED])")
    }
}

#[derive(Eq, PartialEq)]
struct ArtifactManifest {
    entries: Vec<ArtifactManifestEntry>,
}

impl fmt::Debug for ArtifactManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ArtifactManifest")
            .field(&"[REDACTED]")
            .finish()
    }
}

#[derive(Eq, PartialEq)]
struct ArtifactManifestEntry {
    raw_name: RedactedBytes,
    stat: ArtifactStat,
}

impl fmt::Debug for ArtifactManifestEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ArtifactManifestEntry")
            .field(&"[REDACTED]")
            .finish()
    }
}

struct PinnedKnownFile {
    file: fs::File,
    stat: ArtifactStat,
    content: RedactedBytes,
    content_sha256: [u8; 32],
    purpose: KnownFilePurpose,
}

impl PinnedKnownFile {
    fn revalidate(
        &self,
        parent_fd: &OwnedFd,
        raw_name: &RedactedBytes,
    ) -> Result<(), SecretFsError> {
        raw_name.with_c_str(|name| {
            ensure_cloexec(&self.file)?;
            let before = validate_known_file_fd(&self.file, self.purpose)?;
            let path_before = validate_known_file_stat(
                &statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
                self.purpose,
            )?;
            if before != self.stat || path_before != self.stat {
                return Err(SecretFsError::ArtifactChanged);
            }

            let first = read_file_positionally(&self.file, self.purpose.maximum_size())?;
            let second = read_file_positionally(&self.file, self.purpose.maximum_size())?;
            if first != second
                || first.expose() != self.content.expose()
                || <[u8; 32]>::from(Sha256::digest(first.expose())) != self.content_sha256
            {
                return Err(SecretFsError::ArtifactChanged);
            }

            let after = validate_known_file_fd(&self.file, self.purpose)?;
            let path_after = validate_known_file_stat(
                &statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
                self.purpose,
            )?;
            if after != self.stat || path_after != self.stat {
                return Err(SecretFsError::ArtifactChanged);
            }
            Ok(())
        })
    }

    fn revalidate_unlinked(&self) -> Result<(), SecretFsError> {
        ensure_cloexec(&self.file)?;
        let before = validate_unlinked_known_file_fd(&self.file, self.purpose, self.stat)?;
        let first = read_file_positionally(&self.file, self.purpose.maximum_size())?;
        let second = read_file_positionally(&self.file, self.purpose.maximum_size())?;
        if first != second
            || first.expose() != self.content.expose()
            || <[u8; 32]>::from(Sha256::digest(first.expose())) != self.content_sha256
        {
            return Err(SecretFsError::ArtifactChanged);
        }
        let after = validate_unlinked_known_file_fd(&self.file, self.purpose, self.stat)?;
        if before != after {
            return Err(SecretFsError::ArtifactChanged);
        }
        Ok(())
    }
}

impl fmt::Debug for PinnedKnownFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PinnedKnownFile")
            .field(&"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CodecObservation {
    Valid,
    Incomplete,
    Invalid,
}

struct PinnedReservationDirectory {
    artifact: TopLevelArtifactName,
    directory_fd: OwnedFd,
    stat: ArtifactStat,
    manifest: ArtifactManifest,
    entries: Vec<PinnedReservationEntry>,
    linkage: SemanticLinkageObservation,
}

impl PinnedReservationDirectory {
    fn revalidate(
        &self,
        parent_fd: &OwnedFd,
        raw_name: &RedactedBytes,
    ) -> Result<(), SecretFsError> {
        self.revalidate_inner(parent_fd, raw_name, || {})
    }

    fn revalidate_inner(
        &self,
        parent_fd: &OwnedFd,
        raw_name: &RedactedBytes,
        after_entries: impl FnOnce(),
    ) -> Result<(), SecretFsError> {
        raw_name.with_c_str(|name| {
            ensure_cloexec(&self.directory_fd)?;
            let held_stat = validate_reservation_directory_fd(&self.directory_fd)?;
            let path_stat = validate_reservation_directory_stat(
                &statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
            )?;
            if held_stat != self.stat || path_stat != self.stat {
                return Err(SecretFsError::ArtifactChanged);
            }

            let current_manifest = read_artifact_manifest(
                &self.directory_fd,
                MAX_RESERVATION_DIRECTORY_ENTRIES,
                MAX_RESERVATION_DIRECTORY_NAME_BYTES,
            )?;
            if current_manifest != self.manifest {
                return Err(SecretFsError::ArtifactChanged);
            }
            for entry in &self.entries {
                entry.revalidate(&self.directory_fd)?;
            }
            after_entries();
            let final_manifest = read_artifact_manifest(
                &self.directory_fd,
                MAX_RESERVATION_DIRECTORY_ENTRIES,
                MAX_RESERVATION_DIRECTORY_NAME_BYTES,
            )?;
            let final_stat = validate_reservation_directory_fd(&self.directory_fd)?;
            let final_path_stat = validate_reservation_directory_stat(
                &statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
            )?;
            if final_manifest != self.manifest
                || final_stat != self.stat
                || final_path_stat != self.stat
            {
                return Err(SecretFsError::ArtifactChanged);
            }
            Ok(())
        })
    }

    #[cfg(test)]
    fn revalidate_with_checkpoint(
        &self,
        parent_fd: &OwnedFd,
        raw_name: &RedactedBytes,
        after_entries: impl FnOnce(),
    ) -> Result<(), SecretFsError> {
        self.revalidate_inner(parent_fd, raw_name, after_entries)
    }

    fn semantic_state(&self) -> RetainedArtifactState {
        let mut state = match self.linkage {
            SemanticLinkageObservation::Invalid => RetainedArtifactState::Invalid,
            SemanticLinkageObservation::NotObservable | SemanticLinkageObservation::Consistent => {
                RetainedArtifactState::Complete
            }
        };
        for entry in &self.entries {
            state = state.combine(entry.semantic_state());
        }
        state
    }

    fn revalidate_after_rename(
        &self,
        parent_fd: &OwnedFd,
        new_name: &str,
    ) -> Result<(), SecretFsError> {
        ensure_cloexec(&self.directory_fd)?;
        let descriptor_stat = validate_reservation_directory_fd(&self.directory_fd)?;
        let path_stat = validate_reservation_directory_stat(
            &statat(parent_fd, new_name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
        )?;
        if descriptor_stat != path_stat
            || !same_directory_identity(descriptor_stat.identity, self.stat.identity)
        {
            return Err(SecretFsError::ArtifactChanged);
        }
        let manifest = read_artifact_manifest(
            &self.directory_fd,
            MAX_RESERVATION_DIRECTORY_ENTRIES,
            MAX_RESERVATION_DIRECTORY_NAME_BYTES,
        )?;
        if manifest != self.manifest {
            return Err(SecretFsError::ArtifactChanged);
        }
        for entry in &self.entries {
            entry.revalidate(&self.directory_fd)?;
        }
        let final_descriptor = validate_reservation_directory_fd(&self.directory_fd)?;
        let final_path = validate_reservation_directory_stat(
            &statat(parent_fd, new_name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
        )?;
        if final_descriptor != descriptor_stat || final_path != descriptor_stat {
            return Err(SecretFsError::ArtifactChanged);
        }
        Ok(())
    }

    fn revalidate_removed_empty(&self) -> Result<(), SecretFsError> {
        if !self.entries.is_empty() {
            for entry in &self.entries {
                match entry {
                    PinnedReservationEntry::Metadata { file, .. }
                    | PinnedReservationEntry::StagedKeyring { file, .. }
                    | PinnedReservationEntry::Prepared { file, .. } => {
                        file.revalidate_unlinked()?;
                    }
                    PinnedReservationEntry::UnrecognizedPresent { .. } => {
                        return Err(SecretFsError::ArtifactChanged);
                    }
                }
            }
        }
        ensure_cloexec(&self.directory_fd)?;
        let before = validate_unlinked_reservation_directory_fd(&self.directory_fd, self.stat)?;
        let manifest = read_artifact_manifest(
            &self.directory_fd,
            MAX_RESERVATION_DIRECTORY_ENTRIES,
            MAX_RESERVATION_DIRECTORY_NAME_BYTES,
        )?;
        let after = validate_unlinked_reservation_directory_fd(&self.directory_fd, self.stat)?;
        if !manifest.entries.is_empty() || before != after {
            return Err(SecretFsError::ArtifactChanged);
        }
        Ok(())
    }

    fn revalidate_pre_source_rollback_progress(
        &self,
        parent_fd: &OwnedFd,
        current: &Self,
    ) -> Result<(), SecretFsError> {
        if self.artifact != current.artifact {
            return Err(SecretFsError::ArtifactChanged);
        }
        let canonical_name = self.artifact.format();
        if TopLevelArtifactName::parse(canonical_name.as_bytes()) != Ok(self.artifact) {
            return Err(SecretFsError::UnsafeAuthArtifact);
        }
        let raw_name = RedactedBytes::new(canonical_name.as_bytes().to_vec());
        current.revalidate(parent_fd, &raw_name)?;

        let original_held = validate_reservation_directory_fd(&self.directory_fd)?;
        let current_held = validate_reservation_directory_fd(&current.directory_fd)?;
        if !same_directory_identity(original_held.identity, self.stat.identity)
            || !same_directory_identity(current_held.identity, self.stat.identity)
        {
            return Err(SecretFsError::ArtifactChanged);
        }

        for current_entry in &current.entries {
            let current_name = current_entry
                .known_name()
                .ok_or(SecretFsError::ArtifactChanged)?;
            let original_entry = self
                .entries
                .iter()
                .find(|entry| entry.known_name() == Some(current_name))
                .ok_or(SecretFsError::ArtifactChanged)?;
            if original_entry.raw_name() != current_entry.raw_name() {
                return Err(SecretFsError::ArtifactChanged);
            }
            original_entry
                .known_file()
                .ok_or(SecretFsError::ArtifactChanged)?
                .revalidate(&current.directory_fd, current_entry.raw_name())?;
        }

        for original_entry in &self.entries {
            let original_name = original_entry
                .known_name()
                .ok_or(SecretFsError::ArtifactChanged)?;
            if current
                .entries
                .iter()
                .any(|entry| entry.known_name() == Some(original_name))
            {
                continue;
            }
            original_entry
                .known_file()
                .ok_or(SecretFsError::ArtifactChanged)?
                .revalidate_unlinked()?;
        }

        let final_original = validate_reservation_directory_fd(&self.directory_fd)?;
        let final_current = validate_reservation_directory_fd(&current.directory_fd)?;
        if !same_directory_identity(final_original.identity, self.stat.identity)
            || !same_directory_identity(final_current.identity, self.stat.identity)
        {
            return Err(SecretFsError::ArtifactChanged);
        }
        current.revalidate(parent_fd, &raw_name)?;
        Ok(())
    }

    fn revalidate_pre_source_recovery_completion(
        &self,
        parent_fd: &OwnedFd,
        current: &Self,
        created_prepared: &PinnedKnownFile,
    ) -> Result<(), SecretFsError> {
        if self.artifact != current.artifact {
            return Err(SecretFsError::ArtifactChanged);
        }
        let canonical_name = self.artifact.format();
        if TopLevelArtifactName::parse(canonical_name.as_bytes()) != Ok(self.artifact) {
            return Err(SecretFsError::UnsafeAuthArtifact);
        }
        let raw_name = RedactedBytes::new(canonical_name.as_bytes().to_vec());
        current.revalidate(parent_fd, &raw_name)?;

        let original_held = validate_reservation_directory_fd(&self.directory_fd)?;
        let current_held = validate_reservation_directory_fd(&current.directory_fd)?;
        if !same_directory_identity(original_held.identity, self.stat.identity)
            || !same_directory_identity(current_held.identity, self.stat.identity)
        {
            return Err(SecretFsError::ArtifactChanged);
        }

        let original_parts = RetainedReservationParts::from_directory(self);
        let current_parts = RetainedReservationParts::from_directory(current);
        let (
            Some((original_metadata, CodecObservation::Valid)),
            Some((original_staged, CodecObservation::Valid)),
            None,
        ) = (
            original_parts.metadata,
            original_parts.staged,
            original_parts.prepared,
        )
        else {
            return Err(SecretFsError::ArtifactChanged);
        };
        let (
            Some((current_metadata, CodecObservation::Valid)),
            Some((current_staged, CodecObservation::Valid)),
            Some(current_prepared),
        ) = (
            current_parts.metadata,
            current_parts.staged,
            current_parts.prepared,
        )
        else {
            return Err(SecretFsError::ArtifactChanged);
        };
        if self.entries.len() != 2
            || current.entries.len() != 3
            || original_metadata.stat != current_metadata.stat
            || original_staged.stat != current_staged.stat
            || original_metadata.content.expose() != current_metadata.content.expose()
            || original_staged.content.expose() != current_staged.content.expose()
            || current_prepared.stat != created_prepared.stat
            || current_prepared.content.expose() != created_prepared.content.expose()
        {
            return Err(SecretFsError::ArtifactChanged);
        }

        let metadata_name =
            RedactedBytes::new(ReservationEntryName::Metadata.as_str().as_bytes().to_vec());
        let staged_name = RedactedBytes::new(
            ReservationEntryName::StagedKeyring
                .as_str()
                .as_bytes()
                .to_vec(),
        );
        let prepared_name =
            RedactedBytes::new(ReservationEntryName::Prepared.as_str().as_bytes().to_vec());
        original_metadata.revalidate(&current.directory_fd, &metadata_name)?;
        original_staged.revalidate(&current.directory_fd, &staged_name)?;
        created_prepared.revalidate(&current.directory_fd, &prepared_name)?;

        let final_original = validate_reservation_directory_fd(&self.directory_fd)?;
        let final_current = validate_reservation_directory_fd(&current.directory_fd)?;
        if !same_directory_identity(final_original.identity, self.stat.identity)
            || !same_directory_identity(final_current.identity, self.stat.identity)
        {
            return Err(SecretFsError::ArtifactChanged);
        }
        current.revalidate(parent_fd, &raw_name)?;
        created_prepared.revalidate(&current.directory_fd, &prepared_name)?;
        Ok(())
    }
}

impl fmt::Debug for PinnedReservationDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PinnedReservationDirectory")
            .field(&"[REDACTED]")
            .finish()
    }
}

enum PinnedReservationEntry {
    Metadata {
        raw_name: RedactedBytes,
        file: PinnedKnownFile,
        codec: CodecObservation,
    },
    StagedKeyring {
        raw_name: RedactedBytes,
        file: PinnedKnownFile,
        codec: CodecObservation,
    },
    Prepared {
        raw_name: RedactedBytes,
        file: PinnedKnownFile,
    },
    UnrecognizedPresent {
        raw_name: RedactedBytes,
        stat: ArtifactStat,
    },
}

impl PinnedReservationEntry {
    fn revalidate(&self, parent_fd: &OwnedFd) -> Result<(), SecretFsError> {
        match self {
            Self::Metadata { raw_name, file, .. }
            | Self::StagedKeyring { raw_name, file, .. }
            | Self::Prepared { raw_name, file } => file.revalidate(parent_fd, raw_name),
            Self::UnrecognizedPresent { .. } => Ok(()),
        }
    }

    fn raw_name(&self) -> &RedactedBytes {
        match self {
            Self::Metadata { raw_name, .. }
            | Self::StagedKeyring { raw_name, .. }
            | Self::Prepared { raw_name, .. }
            | Self::UnrecognizedPresent { raw_name, .. } => raw_name,
        }
    }

    fn known_name(&self) -> Option<ReservationEntryName> {
        match self {
            Self::Metadata { .. } => Some(ReservationEntryName::Metadata),
            Self::StagedKeyring { .. } => Some(ReservationEntryName::StagedKeyring),
            Self::Prepared { .. } => Some(ReservationEntryName::Prepared),
            Self::UnrecognizedPresent { .. } => None,
        }
    }

    fn known_file(&self) -> Option<&PinnedKnownFile> {
        match self {
            Self::Metadata { file, .. }
            | Self::StagedKeyring { file, .. }
            | Self::Prepared { file, .. } => Some(file),
            Self::UnrecognizedPresent { .. } => None,
        }
    }

    fn semantic_state(&self) -> RetainedArtifactState {
        match self {
            Self::Metadata { codec, .. } | Self::StagedKeyring { codec, .. } => {
                RetainedArtifactState::from_codec(*codec)
            }
            Self::Prepared { .. } => RetainedArtifactState::Complete,
            Self::UnrecognizedPresent { stat, .. } => {
                let _observed_type = stat.identity.file_type;
                RetainedArtifactState::Unrecognized
            }
        }
    }
}

impl fmt::Debug for PinnedReservationEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PinnedReservationEntry")
            .field(&"[REDACTED]")
            .finish()
    }
}

enum PinnedTopLevelArtifact {
    MaintenanceLock {
        raw_name: RedactedBytes,
        file: PinnedKnownFile,
    },
    ActiveKeyring {
        raw_name: RedactedBytes,
        file: PinnedKnownFile,
        codec: CodecObservation,
    },
    Transition {
        raw_name: RedactedBytes,
        directory: PinnedReservationDirectory,
    },
    Cleanup {
        raw_name: RedactedBytes,
        directory: PinnedReservationDirectory,
    },
    InstallTemp {
        raw_name: RedactedBytes,
        id: TransitionId,
        file: PinnedKnownFile,
        codec: CodecObservation,
    },
    UnrecognizedPresent {
        raw_name: RedactedBytes,
        stat: ArtifactStat,
    },
}

impl PinnedTopLevelArtifact {
    fn revalidate(&self, parent_fd: &OwnedFd) -> Result<(), SecretFsError> {
        match self {
            Self::MaintenanceLock { raw_name, file }
            | Self::ActiveKeyring { raw_name, file, .. }
            | Self::InstallTemp { raw_name, file, .. } => file.revalidate(parent_fd, raw_name),
            Self::Transition {
                raw_name,
                directory,
            }
            | Self::Cleanup {
                raw_name,
                directory,
            } => directory.revalidate(parent_fd, raw_name),
            Self::UnrecognizedPresent { .. } => Ok(()),
        }
    }

    fn semantic_state(&self) -> RetainedArtifactState {
        match self {
            Self::MaintenanceLock { .. } => RetainedArtifactState::MaintenanceLock,
            Self::ActiveKeyring { codec, .. } | Self::InstallTemp { codec, .. } => {
                RetainedArtifactState::from_codec(*codec)
            }
            Self::Transition { directory, .. } | Self::Cleanup { directory, .. } => {
                directory.semantic_state()
            }
            Self::UnrecognizedPresent { stat, .. } => {
                let _observed_type = stat.identity.file_type;
                RetainedArtifactState::Unrecognized
            }
        }
    }
}

impl fmt::Debug for PinnedTopLevelArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PinnedTopLevelArtifact")
            .field(&"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SemanticLinkageObservation {
    NotObservable,
    Consistent,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RetainedArtifactState {
    MaintenanceLock,
    Complete,
    Incomplete,
    Invalid,
    Unrecognized,
}

impl RetainedArtifactState {
    const fn from_codec(codec: CodecObservation) -> Self {
        match codec {
            CodecObservation::Valid => Self::Complete,
            CodecObservation::Incomplete => Self::Incomplete,
            CodecObservation::Invalid => Self::Invalid,
        }
    }

    fn combine(self, other: Self) -> Self {
        self.max(other)
    }
}

#[derive(Clone, Copy)]
struct TopLevelNamespaceObservation {
    lock_count: usize,
    is_valid: bool,
}

impl fmt::Debug for TopLevelNamespaceObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TopLevelNamespaceObservation")
            .field(&"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy)]
enum KnownFilePurpose {
    MaintenanceLock,
    ActiveKeyring,
    Metadata,
    StagedKeyring,
    Prepared,
    InstallTemp,
}

impl KnownFilePurpose {
    const fn maximum_size(self) -> usize {
        match self {
            Self::MaintenanceLock | Self::Prepared => 0,
            Self::ActiveKeyring | Self::StagedKeyring | Self::InstallTemp => {
                WITH_VERIFY_ONLY_LENGTH
            }
            Self::Metadata => MAX_INITIALIZATION_METADATA_BYTES,
        }
    }
}

fn read_artifact_manifest(
    directory_fd: &OwnedFd,
    maximum_entries: usize,
    maximum_name_bytes: usize,
) -> Result<ArtifactManifest, SecretFsError> {
    let expected_directory = artifact_stat_from_fd(directory_fd)?;
    let scan_fd = openat(
        directory_fd,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_artifact_errno)?;
    ensure_cloexec(&scan_fd)?;
    if artifact_stat_from_fd(&scan_fd)? != expected_directory {
        return Err(SecretFsError::ArtifactChanged);
    }

    let mut directory = Dir::new(scan_fd).map_err(SecretFsError::errno)?;
    let mut entries = Vec::new();
    let mut name_bytes = 0_usize;
    for entry in &mut directory {
        let entry = entry.map_err(SecretFsError::errno)?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        name_bytes = name_bytes
            .checked_add(name.to_bytes().len())
            .ok_or(SecretFsError::ArtifactInventoryLimit)?;
        if entries.len() >= maximum_entries || name_bytes > maximum_name_bytes {
            return Err(SecretFsError::ArtifactInventoryLimit);
        }
        let stat = statat(directory_fd, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(map_artifact_errno)
            .and_then(|stat| artifact_stat_from_stat(&stat))?;
        entries.push(ArtifactManifestEntry {
            raw_name: RedactedBytes::new(name.to_bytes().to_vec()),
            stat,
        });
    }
    entries.sort_by(|left, right| left.raw_name.expose().cmp(right.raw_name.expose()));
    if artifact_stat_from_fd(directory_fd)? != expected_directory {
        return Err(SecretFsError::ArtifactChanged);
    }
    Ok(ArtifactManifest { entries })
}

fn capture_top_level_artifact(
    parent_fd: &OwnedFd,
    manifest: &ArtifactManifestEntry,
    lock_identity: FileIdentity,
) -> Result<PinnedTopLevelArtifact, SecretFsError> {
    let raw_name = RedactedBytes::new(manifest.raw_name.expose().to_vec());
    let Ok(parsed_name) = TopLevelArtifactName::parse(raw_name.expose()) else {
        return Ok(PinnedTopLevelArtifact::UnrecognizedPresent {
            raw_name,
            stat: manifest.stat,
        });
    };

    match parsed_name {
        TopLevelArtifactName::MaintenanceLock => {
            let file = capture_known_file(
                parent_fd,
                &raw_name,
                manifest.stat,
                KnownFilePurpose::MaintenanceLock,
            )?;
            if file.stat.identity != lock_identity {
                return Err(SecretFsError::IdentityChanged);
            }
            Ok(PinnedTopLevelArtifact::MaintenanceLock { raw_name, file })
        }
        TopLevelArtifactName::ActiveKeyring => {
            let file = capture_known_file(
                parent_fd,
                &raw_name,
                manifest.stat,
                KnownFilePurpose::ActiveKeyring,
            )?;
            let codec = keyring_codec_observation(file.content.expose(), false);
            Ok(PinnedTopLevelArtifact::ActiveKeyring {
                raw_name,
                file,
                codec,
            })
        }
        artifact @ TopLevelArtifactName::Transition { .. } => {
            let directory =
                capture_reservation_directory(parent_fd, &raw_name, manifest.stat, artifact)?;
            Ok(PinnedTopLevelArtifact::Transition {
                raw_name,
                directory,
            })
        }
        artifact @ TopLevelArtifactName::Cleanup { .. } => {
            let directory =
                capture_reservation_directory(parent_fd, &raw_name, manifest.stat, artifact)?;
            Ok(PinnedTopLevelArtifact::Cleanup {
                raw_name,
                directory,
            })
        }
        TopLevelArtifactName::InstallTemp { id } => {
            let file = capture_known_file(
                parent_fd,
                &raw_name,
                manifest.stat,
                KnownFilePurpose::InstallTemp,
            )?;
            let codec = keyring_codec_observation(file.content.expose(), true);
            Ok(PinnedTopLevelArtifact::InstallTemp {
                raw_name,
                id,
                file,
                codec,
            })
        }
    }
}

fn capture_reservation_directory(
    parent_fd: &OwnedFd,
    raw_name: &RedactedBytes,
    manifest_stat: ArtifactStat,
    artifact: TopLevelArtifactName,
) -> Result<PinnedReservationDirectory, SecretFsError> {
    validate_reservation_directory_evidence(manifest_stat)?;
    raw_name.with_c_str(|name| {
        let directory_fd = openat(
            parent_fd,
            name,
            OFlags::RDONLY
                | OFlags::DIRECTORY
                | OFlags::NONBLOCK
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_artifact_errno)?;
        ensure_cloexec(&directory_fd)?;
        let descriptor_stat = validate_reservation_directory_fd(&directory_fd)?;
        let path_stat = validate_reservation_directory_stat(
            &statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
        )?;
        if descriptor_stat != manifest_stat || path_stat != manifest_stat {
            return Err(SecretFsError::ArtifactChanged);
        }

        let first_manifest = read_artifact_manifest(
            &directory_fd,
            MAX_RESERVATION_DIRECTORY_ENTRIES,
            MAX_RESERVATION_DIRECTORY_NAME_BYTES,
        )?;
        let mut entries = Vec::with_capacity(first_manifest.entries.len());
        for entry in &first_manifest.entries {
            entries.push(capture_reservation_entry(&directory_fd, entry, artifact)?);
        }
        let second_manifest = read_artifact_manifest(
            &directory_fd,
            MAX_RESERVATION_DIRECTORY_ENTRIES,
            MAX_RESERVATION_DIRECTORY_NAME_BYTES,
        )?;
        if first_manifest != second_manifest {
            return Err(SecretFsError::ArtifactChanged);
        }
        entries.sort_by(|left, right| left.raw_name().expose().cmp(right.raw_name().expose()));
        let linkage = observe_reservation_linkage(artifact, &entries);
        let final_stat = validate_reservation_directory_fd(&directory_fd)?;
        let final_path_stat = validate_reservation_directory_stat(
            &statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
        )?;
        if final_stat != manifest_stat || final_path_stat != manifest_stat {
            return Err(SecretFsError::ArtifactChanged);
        }
        Ok(PinnedReservationDirectory {
            artifact,
            directory_fd,
            stat: manifest_stat,
            manifest: second_manifest,
            entries,
            linkage,
        })
    })
}

fn capture_reservation_entry(
    parent_fd: &OwnedFd,
    manifest: &ArtifactManifestEntry,
    artifact: TopLevelArtifactName,
) -> Result<PinnedReservationEntry, SecretFsError> {
    let raw_name = RedactedBytes::new(manifest.raw_name.expose().to_vec());
    let Ok(parsed_name) = ReservationEntryName::parse(raw_name.expose()) else {
        return Ok(PinnedReservationEntry::UnrecognizedPresent {
            raw_name,
            stat: manifest.stat,
        });
    };
    match parsed_name {
        ReservationEntryName::Metadata => {
            let file = capture_known_file(
                parent_fd,
                &raw_name,
                manifest.stat,
                KnownFilePurpose::Metadata,
            )?;
            let codec = metadata_codec_observation(file.content.expose(), artifact);
            Ok(PinnedReservationEntry::Metadata {
                raw_name,
                file,
                codec,
            })
        }
        ReservationEntryName::StagedKeyring => {
            let file = capture_known_file(
                parent_fd,
                &raw_name,
                manifest.stat,
                KnownFilePurpose::StagedKeyring,
            )?;
            let codec = keyring_codec_observation(file.content.expose(), true);
            Ok(PinnedReservationEntry::StagedKeyring {
                raw_name,
                file,
                codec,
            })
        }
        ReservationEntryName::Prepared => {
            let file = capture_known_file(
                parent_fd,
                &raw_name,
                manifest.stat,
                KnownFilePurpose::Prepared,
            )?;
            Ok(PinnedReservationEntry::Prepared { raw_name, file })
        }
    }
}

fn capture_known_file(
    parent_fd: &OwnedFd,
    raw_name: &RedactedBytes,
    manifest_stat: ArtifactStat,
    purpose: KnownFilePurpose,
) -> Result<PinnedKnownFile, SecretFsError> {
    validate_known_file_evidence(manifest_stat, purpose)?;
    raw_name.with_c_str(|name| {
        let file_fd = openat(
            parent_fd,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_artifact_errno)?;
        ensure_cloexec(&file_fd)?;
        let file = fs::File::from(file_fd);
        let descriptor_before = validate_known_file_fd(&file, purpose)?;
        let path_before = validate_known_file_stat(
            &statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
            purpose,
        )?;
        if descriptor_before != manifest_stat || path_before != manifest_stat {
            return Err(SecretFsError::ArtifactChanged);
        }

        let first = read_file_positionally(&file, purpose.maximum_size())?;
        let second = read_file_positionally(&file, purpose.maximum_size())?;
        if first != second {
            return Err(SecretFsError::ArtifactChanged);
        }
        let descriptor_after = validate_known_file_fd(&file, purpose)?;
        let path_after = validate_known_file_stat(
            &statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
            purpose,
        )?;
        if descriptor_after != manifest_stat || path_after != manifest_stat {
            return Err(SecretFsError::ArtifactChanged);
        }
        let content_sha256 = Sha256::digest(first.expose()).into();
        Ok(PinnedKnownFile {
            file,
            stat: manifest_stat,
            content: first,
            content_sha256,
            purpose,
        })
    })
}

fn read_file_positionally(
    file: &fs::File,
    maximum_size: usize,
) -> Result<RedactedBytes, SecretFsError> {
    let capacity = maximum_size
        .checked_add(1)
        .ok_or(SecretFsError::ArtifactInventoryLimit)?;
    let mut output = Zeroizing::new(Vec::with_capacity(capacity));
    let mut offset = 0_u64;
    loop {
        let remaining = capacity
            .checked_sub(output.len())
            .ok_or(SecretFsError::ArtifactInventoryLimit)?;
        if remaining == 0 {
            return Err(SecretFsError::UnsafeAuthArtifact);
        }
        let mut buffer = Zeroizing::new([0_u8; 512]);
        let chunk_length = remaining.min(buffer.len());
        let count = file
            .read_at(&mut buffer[..chunk_length], offset)
            .map_err(|error| SecretFsError::io(&error))?;
        if count == 0 {
            break;
        }
        output.extend_from_slice(&buffer[..count]);
        offset = offset
            .checked_add(u64::try_from(count).map_err(|_| SecretFsError::ArtifactInventoryLimit)?)
            .ok_or(SecretFsError::ArtifactInventoryLimit)?;
    }
    Ok(RedactedBytes::from_zeroizing(output))
}

fn validate_known_file_stat(
    stat: &Stat,
    purpose: KnownFilePurpose,
) -> Result<ArtifactStat, SecretFsError> {
    let evidence = artifact_stat_from_stat(stat)?;
    validate_known_file_evidence(evidence, purpose)?;
    Ok(evidence)
}

fn validate_known_file_fd(
    fd: &fs::File,
    purpose: KnownFilePurpose,
) -> Result<ArtifactStat, SecretFsError> {
    let before = validate_known_file_stat(&fstat(fd).map_err(SecretFsError::errno)?, purpose)?;
    #[cfg(target_os = "macos")]
    ensure_no_extended_acl(fd, SecretFsError::UnsafeAuthArtifact)?;
    let after = validate_known_file_stat(&fstat(fd).map_err(SecretFsError::errno)?, purpose)?;
    if before != after {
        return Err(SecretFsError::ArtifactChanged);
    }
    Ok(after)
}

fn validate_unlinked_known_file_fd(
    fd: &fs::File,
    purpose: KnownFilePurpose,
    expected: ArtifactStat,
) -> Result<ArtifactStat, SecretFsError> {
    let before = artifact_stat_from_stat(&fstat(fd).map_err(SecretFsError::errno)?)?;
    if !same_file_node(before.identity, expected.identity)
        || before.identity.owner != expected.identity.owner
        || before.identity.mode != expected.identity.mode
        || before.identity.file_type != FileKind::Regular
        || before.identity.links != 0
        || before.size != expected.size
        || before.size
            > u64::try_from(purpose.maximum_size())
                .map_err(|_| SecretFsError::ArtifactInventoryLimit)?
    {
        return Err(SecretFsError::ArtifactChanged);
    }
    #[cfg(target_os = "macos")]
    ensure_no_extended_acl(fd, SecretFsError::UnsafeAuthArtifact)?;
    let after = artifact_stat_from_stat(&fstat(fd).map_err(SecretFsError::errno)?)?;
    if before != after {
        return Err(SecretFsError::ArtifactChanged);
    }
    Ok(after)
}

fn validate_known_file_evidence(
    evidence: ArtifactStat,
    purpose: KnownFilePurpose,
) -> Result<(), SecretFsError> {
    if evidence.identity.file_type != FileKind::Regular
        || evidence.identity.owner != geteuid().as_raw()
        || evidence.identity.mode != OWNER_FILE_MODE
        || evidence.identity.links != 1
        || evidence.size
            > u64::try_from(purpose.maximum_size())
                .map_err(|_| SecretFsError::ArtifactInventoryLimit)?
        || matches!(
            purpose,
            KnownFilePurpose::MaintenanceLock | KnownFilePurpose::Prepared
        ) && evidence.size != 0
    {
        return Err(SecretFsError::UnsafeAuthArtifact);
    }
    Ok(())
}

fn validate_reservation_directory_stat(stat: &Stat) -> Result<ArtifactStat, SecretFsError> {
    let evidence = artifact_stat_from_stat(stat)?;
    validate_reservation_directory_evidence(evidence)?;
    Ok(evidence)
}

fn validate_reservation_directory_fd(fd: &OwnedFd) -> Result<ArtifactStat, SecretFsError> {
    let before = validate_reservation_directory_stat(&fstat(fd).map_err(SecretFsError::errno)?)?;
    #[cfg(target_os = "macos")]
    ensure_no_extended_acl(fd, SecretFsError::UnsafeAuthArtifact)?;
    let after = validate_reservation_directory_stat(&fstat(fd).map_err(SecretFsError::errno)?)?;
    if before != after {
        return Err(SecretFsError::ArtifactChanged);
    }
    Ok(after)
}

fn validate_unlinked_reservation_directory_fd(
    fd: &OwnedFd,
    expected: ArtifactStat,
) -> Result<ArtifactStat, SecretFsError> {
    let before = artifact_stat_from_stat(&fstat(fd).map_err(SecretFsError::errno)?)?;
    if !same_file_node(before.identity, expected.identity)
        || before.identity.owner != expected.identity.owner
        || before.identity.mode != expected.identity.mode
        || before.identity.file_type != FileKind::Directory
    {
        return Err(SecretFsError::ArtifactChanged);
    }
    #[cfg(target_os = "macos")]
    ensure_no_extended_acl(fd, SecretFsError::UnsafeAuthArtifact)?;
    let after = artifact_stat_from_stat(&fstat(fd).map_err(SecretFsError::errno)?)?;
    if before != after {
        return Err(SecretFsError::ArtifactChanged);
    }
    Ok(after)
}

fn validate_reservation_directory_evidence(evidence: ArtifactStat) -> Result<(), SecretFsError> {
    if evidence.identity.file_type != FileKind::Directory
        || evidence.identity.owner != geteuid().as_raw()
        || evidence.identity.mode != OWNER_DIRECTORY_MODE
    {
        return Err(SecretFsError::UnsafeAuthArtifact);
    }
    Ok(())
}

fn validate_directory_artifact_fd(
    fd: &OwnedFd,
    purpose: DirectoryPurpose,
) -> Result<ArtifactStat, SecretFsError> {
    let before = fstat(fd).map_err(SecretFsError::errno)?;
    validate_directory_stat(&before, purpose)?;
    let before = artifact_stat_from_stat(&before)?;
    #[cfg(target_os = "macos")]
    ensure_no_extended_acl(fd, unsafe_directory_error(purpose))?;
    let after = fstat(fd).map_err(SecretFsError::errno)?;
    validate_directory_stat(&after, purpose)?;
    let after = artifact_stat_from_stat(&after)?;
    if before != after {
        return Err(SecretFsError::ArtifactChanged);
    }
    Ok(after)
}

fn artifact_stat_from_fd(fd: &OwnedFd) -> Result<ArtifactStat, SecretFsError> {
    let stat = fstat(fd).map_err(SecretFsError::errno)?;
    artifact_stat_from_stat(&stat)
}

fn artifact_stat_from_stat(stat: &Stat) -> Result<ArtifactStat, SecretFsError> {
    Ok(ArtifactStat {
        identity: file_identity_from_stat(stat),
        size: u64::try_from(stat.st_size).map_err(|_| SecretFsError::UnsafeAuthArtifact)?,
        modified_seconds: stat.st_mtime.into(),
        modified_nanoseconds: stat.st_mtime_nsec.into(),
        changed_seconds: stat.st_ctime.into(),
        changed_nanoseconds: stat.st_ctime_nsec.into(),
    })
}

fn keyring_codec_observation(bytes: &[u8], partial_is_incomplete: bool) -> CodecObservation {
    if bytes.len() == ACTIVE_ONLY_LENGTH || bytes.len() == WITH_VERIFY_ONLY_LENGTH {
        if Keyring::decode(SecretBytes::new(bytes.to_vec())).is_ok() {
            CodecObservation::Valid
        } else {
            CodecObservation::Invalid
        }
    } else if partial_is_incomplete {
        CodecObservation::Incomplete
    } else {
        CodecObservation::Invalid
    }
}

fn known_file_matches_planned_expected_active(
    file: &PinnedKnownFile,
    expectation: PlannedRotationSourceExpectation<'_>,
) -> bool {
    if file.content.expose().len() != ACTIVE_ONLY_LENGTH {
        return false;
    }
    let Ok(keyring) = Keyring::decode(SecretBytes::new(file.content.expose().to_vec())) else {
        return false;
    };
    keyring.active_kid().as_str() == expectation.expected_active_kid()
        && i64::try_from(keyring.version().get()).ok()
            == Some(expectation.expected_keyring_version())
        && i64::try_from(keyring.active_activated_at().get()).ok()
            == Some(expectation.expected_key_activated_at_micros())
}

fn metadata_codec_observation(bytes: &[u8], artifact: TopLevelArtifactName) -> CodecObservation {
    let valid = match artifact {
        TopLevelArtifactName::Transition {
            kind: TransitionKind::Initialize,
            ..
        }
        | TopLevelArtifactName::Cleanup {
            kind: TransitionKind::Initialize,
            ..
        } => InitializationMetadataV1::decode(SecretBytes::new(bytes.to_vec()))
            .is_ok_and(|metadata| metadata.matches_reservation_artifact(artifact)),
        TopLevelArtifactName::Transition {
            kind: TransitionKind::Planned,
            ..
        }
        | TopLevelArtifactName::Cleanup {
            kind: TransitionKind::Planned,
            ..
        } => PlannedRotationMetadataV1::decode(SecretBytes::new(bytes.to_vec()))
            .is_ok_and(|metadata| metadata.matches_reservation_artifact(artifact)),
        TopLevelArtifactName::Transition {
            kind: TransitionKind::Retire,
            ..
        }
        | TopLevelArtifactName::Cleanup {
            kind: TransitionKind::Retire,
            ..
        } => RetireMetadataV1::decode(SecretBytes::new(bytes.to_vec()))
            .is_ok_and(|metadata| metadata.matches_reservation_artifact(artifact)),
        _ => false,
    };
    if valid {
        CodecObservation::Valid
    } else if metadata_is_incomplete(bytes) {
        CodecObservation::Incomplete
    } else {
        CodecObservation::Invalid
    }
}

fn metadata_is_incomplete(bytes: &[u8]) -> bool {
    const HEADER_LENGTH: usize = 14;
    const MAGIC: &[u8; 8] = b"POVAUTHM";
    if bytes.len() < MAGIC.len() {
        return MAGIC.starts_with(bytes);
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return false;
    }
    if bytes.len() < HEADER_LENGTH {
        return true;
    }
    let encoded_length = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
    encoded_length <= MAX_INITIALIZATION_METADATA_BYTES && bytes.len() < encoded_length
}

fn observe_reservation_linkage(
    artifact: TopLevelArtifactName,
    entries: &[PinnedReservationEntry],
) -> SemanticLinkageObservation {
    let metadata = entries.iter().find_map(|entry| match entry {
        PinnedReservationEntry::Metadata { file, codec, .. } => Some((file, *codec)),
        _ => None,
    });
    let staged = entries.iter().find_map(|entry| match entry {
        PinnedReservationEntry::StagedKeyring { file, codec, .. } => Some((file, *codec)),
        _ => None,
    });
    let (Some((metadata_file, CodecObservation::Valid)), Some((staged_file, staged_codec))) =
        (metadata, staged)
    else {
        return SemanticLinkageObservation::NotObservable;
    };
    match staged_codec {
        CodecObservation::Incomplete => return SemanticLinkageObservation::NotObservable,
        CodecObservation::Invalid => return SemanticLinkageObservation::Invalid,
        CodecObservation::Valid => {}
    }
    let linked = match artifact {
        TopLevelArtifactName::Transition {
            kind: TransitionKind::Initialize,
            ..
        }
        | TopLevelArtifactName::Cleanup {
            kind: TransitionKind::Initialize,
            ..
        } => InitializationMetadataV1::decode(SecretBytes::new(
            metadata_file.content.expose().to_vec(),
        ))
        .is_ok_and(|metadata| {
            metadata.matches_reservation_artifact(artifact)
                && metadata
                    .validate_staged_keyring(SecretBytes::new(
                        staged_file.content.expose().to_vec(),
                    ))
                    .is_ok()
        }),
        TopLevelArtifactName::Transition {
            kind: TransitionKind::Planned,
            ..
        }
        | TopLevelArtifactName::Cleanup {
            kind: TransitionKind::Planned,
            ..
        } => PlannedRotationMetadataV1::decode(SecretBytes::new(
            metadata_file.content.expose().to_vec(),
        ))
        .is_ok_and(|metadata| {
            metadata.matches_reservation_artifact(artifact)
                && metadata
                    .validate_staged_keyring(SecretBytes::new(
                        staged_file.content.expose().to_vec(),
                    ))
                    .is_ok()
        }),
        TopLevelArtifactName::Transition {
            kind: TransitionKind::Retire,
            ..
        }
        | TopLevelArtifactName::Cleanup {
            kind: TransitionKind::Retire,
            ..
        } => RetireMetadataV1::decode(SecretBytes::new(metadata_file.content.expose().to_vec()))
            .is_ok_and(|metadata| {
                metadata.matches_reservation_artifact(artifact)
                    && metadata
                        .validate_staged_keyring(SecretBytes::new(
                            staged_file.content.expose().to_vec(),
                        ))
                        .is_ok()
            }),
        _ => false,
    };
    if linked {
        SemanticLinkageObservation::Consistent
    } else {
        SemanticLinkageObservation::Invalid
    }
}

fn observe_top_level_namespace(
    observations: &[PinnedTopLevelArtifact],
) -> Result<TopLevelNamespaceObservation, SecretFsError> {
    let lock_count = observations
        .iter()
        .filter(|entry| matches!(entry, PinnedTopLevelArtifact::MaintenanceLock { .. }))
        .count();
    let active_count = observations
        .iter()
        .filter(|entry| matches!(entry, PinnedTopLevelArtifact::ActiveKeyring { .. }))
        .count();
    let reservations: Vec<(TransitionKind, TransitionId)> = observations
        .iter()
        .filter_map(|entry| match entry {
            PinnedTopLevelArtifact::Transition { directory, .. }
            | PinnedTopLevelArtifact::Cleanup { directory, .. } => match directory.artifact {
                TopLevelArtifactName::Transition { kind, id }
                | TopLevelArtifactName::Cleanup { kind, id } => Some((kind, id)),
                _ => None,
            },
            _ => None,
        })
        .collect();
    let install_ids: Vec<TransitionId> = observations
        .iter()
        .filter_map(|entry| match entry {
            PinnedTopLevelArtifact::InstallTemp { id, .. } => Some(*id),
            _ => None,
        })
        .collect();
    let has_unrecognized = observations
        .iter()
        .any(|entry| matches!(entry, PinnedTopLevelArtifact::UnrecognizedPresent { .. }));
    let linkage_valid = match (reservations.as_slice(), install_ids.as_slice()) {
        ([], []) | ([_], []) => true,
        ([(_, reservation_id)], [install_id]) => reservation_id == install_id,
        _ => false,
    };
    Ok(TopLevelNamespaceObservation {
        lock_count,
        is_valid: lock_count == 1
            && active_count <= 1
            && reservations.len() <= 1
            && install_ids.len() <= 1
            && linkage_valid
            && !has_unrecognized,
    })
}

fn map_artifact_errno(error: Errno) -> SecretFsError {
    if matches!(error, Errno::NOENT | Errno::LOOP | Errno::NOTDIR) {
        SecretFsError::ArtifactChanged
    } else {
        SecretFsError::errno(error)
    }
}

fn map_creation_errno(error: Errno) -> SecretFsError {
    if matches!(
        error,
        Errno::EXIST | Errno::NOENT | Errno::LOOP | Errno::NOTDIR
    ) {
        SecretFsError::ArtifactChanged
    } else {
        SecretFsError::errno(error)
    }
}

fn persist_new_known_file(
    parent_fd: &OwnedFd,
    name: &str,
    purpose: KnownFilePurpose,
    bytes: &[u8],
) -> Result<PinnedKnownFile, SecretFsError> {
    if bytes.len() > purpose.maximum_size()
        || matches!(
            purpose,
            KnownFilePurpose::MaintenanceLock | KnownFilePurpose::Prepared
        ) && !bytes.is_empty()
    {
        return Err(SecretFsError::UnsafeAuthArtifact);
    }
    let file_fd = openat(
        parent_fd,
        name,
        OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NONBLOCK
            | OFlags::NOFOLLOW
            | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(map_creation_errno)?;
    ensure_cloexec(&file_fd)?;
    let mut file = fs::File::from(file_fd);
    let empty_stat = validate_known_file_fd(&file, purpose)?;
    let empty_path_stat = validate_known_file_stat(
        &statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
        purpose,
    )?;
    if empty_stat != empty_path_stat || empty_stat.size != 0 {
        return Err(SecretFsError::ArtifactChanged);
    }

    file.write_all(bytes)
        .map_err(|error| SecretFsError::io(&error))?;
    fsync(&file).map_err(SecretFsError::errno)?;
    let descriptor_stat = validate_known_file_fd(&file, purpose)?;
    let path_stat = validate_known_file_stat(
        &statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
        purpose,
    )?;
    let first_readback = read_file_positionally(&file, purpose.maximum_size())?;
    if descriptor_stat != path_stat || first_readback.expose() != bytes {
        return Err(SecretFsError::ArtifactChanged);
    }
    fsync(parent_fd).map_err(SecretFsError::errno)?;

    let final_descriptor_stat = validate_known_file_fd(&file, purpose)?;
    let final_path_stat = validate_known_file_stat(
        &statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
        purpose,
    )?;
    let final_readback = read_file_positionally(&file, purpose.maximum_size())?;
    if final_descriptor_stat != descriptor_stat
        || final_path_stat != descriptor_stat
        || final_readback.expose() != bytes
    {
        return Err(SecretFsError::ArtifactChanged);
    }
    let content_sha256 = Sha256::digest(final_readback.expose()).into();
    Ok(PinnedKnownFile {
        file,
        stat: final_descriptor_stat,
        content: final_readback,
        content_sha256,
        purpose,
    })
}

fn open_existing_known_file_for_update(
    parent_fd: &OwnedFd,
    name: &str,
    purpose: KnownFilePurpose,
    expected_stat: ArtifactStat,
    expected_bytes: &[u8],
) -> Result<fs::File, SecretFsError> {
    let file_fd = openat(
        parent_fd,
        name,
        OFlags::RDWR | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_artifact_errno)?;
    ensure_cloexec(&file_fd)?;
    let file = fs::File::from(file_fd);
    let descriptor_stat = validate_known_file_fd(&file, purpose)?;
    let path_stat = validate_known_file_stat(
        &statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
        purpose,
    )?;
    let first_readback = read_file_positionally(&file, purpose.maximum_size())?;
    let second_readback = read_file_positionally(&file, purpose.maximum_size())?;
    if descriptor_stat != expected_stat
        || path_stat != expected_stat
        || first_readback != second_readback
        || first_readback.expose() != expected_bytes
    {
        return Err(SecretFsError::ArtifactChanged);
    }
    Ok(file)
}

fn durabilize_existing_known_file(
    parent_fd: &OwnedFd,
    name: &str,
    purpose: KnownFilePurpose,
    expected_stat: ArtifactStat,
    expected_bytes: &[u8],
) -> Result<(), SecretFsError> {
    let file = open_existing_known_file_for_update(
        parent_fd,
        name,
        purpose,
        expected_stat,
        expected_bytes,
    )?;
    fsync(&file).map_err(SecretFsError::errno)?;
    fsync(parent_fd).map_err(SecretFsError::errno)?;
    let descriptor_stat = validate_known_file_fd(&file, purpose)?;
    let path_stat = validate_known_file_stat(
        &statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
        purpose,
    )?;
    let readback = read_file_positionally(&file, purpose.maximum_size())?;
    if descriptor_stat != expected_stat
        || path_stat != expected_stat
        || readback.expose() != expected_bytes
    {
        return Err(SecretFsError::ArtifactChanged);
    }
    Ok(())
}

fn remove_exact_known_file(
    parent_fd: &OwnedFd,
    name: &str,
    purpose: KnownFilePurpose,
    expected_stat: ArtifactStat,
    expected_bytes: &[u8],
    before_unlink: impl FnOnce(),
) -> Result<(), SecretFsError> {
    let retained = open_existing_known_file_for_update(
        parent_fd,
        name,
        purpose,
        expected_stat,
        expected_bytes,
    )?;
    before_unlink();
    unlinkat(parent_fd, name, AtFlags::empty()).map_err(map_artifact_errno)?;
    ensure_path_absent(parent_fd, name)?;
    let before =
        revalidate_exact_unlinked_known_file(&retained, purpose, expected_stat, expected_bytes)?;
    fsync(parent_fd).map_err(SecretFsError::errno)?;
    ensure_path_absent(parent_fd, name)?;
    let after =
        revalidate_exact_unlinked_known_file(&retained, purpose, expected_stat, expected_bytes)?;
    if before != after {
        return Err(SecretFsError::ArtifactChanged);
    }
    Ok(())
}

fn revalidate_exact_unlinked_known_file(
    file: &fs::File,
    purpose: KnownFilePurpose,
    expected_stat: ArtifactStat,
    expected_bytes: &[u8],
) -> Result<ArtifactStat, SecretFsError> {
    let before = validate_unlinked_known_file_fd(file, purpose, expected_stat)?;
    let first = read_file_positionally(file, purpose.maximum_size())?;
    let second = read_file_positionally(file, purpose.maximum_size())?;
    let expected_hash: [u8; 32] = Sha256::digest(expected_bytes).into();
    if first != second
        || first.expose() != expected_bytes
        || <[u8; 32]>::from(Sha256::digest(first.expose())) != expected_hash
    {
        return Err(SecretFsError::ArtifactChanged);
    }
    let after = validate_unlinked_known_file_fd(file, purpose, expected_stat)?;
    if before != after {
        return Err(SecretFsError::ArtifactChanged);
    }
    Ok(after)
}

fn rename_exact_reservation_to_cleanup_no_replace(
    parent_fd: &OwnedFd,
    transition_name: &str,
    cleanup_name: &str,
    reservation: &PinnedReservationDirectory,
) -> Result<(), SecretFsError> {
    let transition_raw = RedactedBytes::new(transition_name.as_bytes().to_vec());
    reservation.revalidate(parent_fd, &transition_raw)?;
    fsync(&reservation.directory_fd).map_err(SecretFsError::errno)?;
    fsync(parent_fd).map_err(SecretFsError::errno)?;
    ensure_path_absent(parent_fd, cleanup_name)?;
    reservation.revalidate(parent_fd, &transition_raw)?;
    ensure_path_absent(parent_fd, cleanup_name)?;

    rename_no_replace(parent_fd, transition_name, parent_fd, cleanup_name)?;
    ensure_path_absent(parent_fd, transition_name)?;
    reservation.revalidate_after_rename(parent_fd, cleanup_name)?;
    fsync(parent_fd).map_err(SecretFsError::errno)?;
    ensure_path_absent(parent_fd, transition_name)?;
    reservation.revalidate_after_rename(parent_fd, cleanup_name)?;
    Ok(())
}

fn remove_exact_empty_reservation_directory(
    parent_fd: &OwnedFd,
    reservation_name: &str,
    reservation: &PinnedReservationDirectory,
) -> Result<(), SecretFsError> {
    if !reservation.manifest.entries.is_empty() || !reservation.entries.is_empty() {
        return Err(SecretFsError::ArtifactChanged);
    }
    let reservation_raw = RedactedBytes::new(reservation_name.as_bytes().to_vec());
    reservation.revalidate(parent_fd, &reservation_raw)?;
    unlinkat(parent_fd, reservation_name, AtFlags::REMOVEDIR).map_err(map_artifact_errno)?;
    fsync(parent_fd).map_err(SecretFsError::errno)?;
    ensure_path_absent(parent_fd, reservation_name)?;
    reservation.revalidate_removed_empty()?;
    Ok(())
}

fn publish_install_temp_no_replace(
    parent_fd: &OwnedFd,
    install_name: &str,
    expected_stat: ArtifactStat,
    expected_bytes: &[u8],
    before_publish: impl FnOnce(),
) -> Result<(), SecretFsError> {
    let install = open_existing_known_file_for_update(
        parent_fd,
        install_name,
        KnownFilePurpose::InstallTemp,
        expected_stat,
        expected_bytes,
    )?;
    fsync(&install).map_err(SecretFsError::errno)?;
    fsync(parent_fd).map_err(SecretFsError::errno)?;
    let before_descriptor = validate_known_file_fd(&install, KnownFilePurpose::InstallTemp)?;
    let before_path = validate_known_file_stat(
        &statat(parent_fd, install_name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
        KnownFilePurpose::InstallTemp,
    )?;
    let before_readback =
        read_file_positionally(&install, KnownFilePurpose::InstallTemp.maximum_size())?;
    if before_descriptor != expected_stat
        || before_path != expected_stat
        || before_readback.expose() != expected_bytes
    {
        return Err(SecretFsError::ArtifactChanged);
    }
    ensure_path_absent(parent_fd, ACTIVE_KEYRING_NAME)?;

    before_publish();
    rename_no_replace(parent_fd, install_name, parent_fd, ACTIVE_KEYRING_NAME)?;
    fsync(parent_fd).map_err(SecretFsError::errno)?;

    ensure_path_absent(parent_fd, install_name)?;
    let active_descriptor = validate_known_file_fd(&install, KnownFilePurpose::ActiveKeyring)?;
    let active_path = validate_known_file_stat(
        &statat(parent_fd, ACTIVE_KEYRING_NAME, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(map_artifact_errno)?,
        KnownFilePurpose::ActiveKeyring,
    )?;
    let active_readback =
        read_file_positionally(&install, KnownFilePurpose::ActiveKeyring.maximum_size())?;
    if active_descriptor != active_path
        || !same_file_node(active_descriptor.identity, expected_stat.identity)
        || active_descriptor.size != expected_stat.size
        || active_readback.expose() != expected_bytes
    {
        return Err(SecretFsError::ArtifactChanged);
    }
    Ok(())
}

fn exchange_install_temp_with_active(
    parent_fd: &OwnedFd,
    install_name: &str,
    install_stat: ArtifactStat,
    staged_bytes: &[u8],
    active_stat: ArtifactStat,
    active_bytes: &[u8],
    before_exchange: impl FnOnce(),
) -> Result<(), SecretFsError> {
    let install = open_existing_known_file_for_update(
        parent_fd,
        install_name,
        KnownFilePurpose::InstallTemp,
        install_stat,
        staged_bytes,
    )?;
    let active = open_existing_known_file_for_update(
        parent_fd,
        ACTIVE_KEYRING_NAME,
        KnownFilePurpose::ActiveKeyring,
        active_stat,
        active_bytes,
    )?;
    fsync(&install).map_err(SecretFsError::errno)?;
    fsync(&active).map_err(SecretFsError::errno)?;
    fsync(parent_fd).map_err(SecretFsError::errno)?;

    let install_descriptor = validate_known_file_fd(&install, KnownFilePurpose::InstallTemp)?;
    let active_descriptor = validate_known_file_fd(&active, KnownFilePurpose::ActiveKeyring)?;
    let install_path = validate_known_file_stat(
        &statat(parent_fd, install_name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
        KnownFilePurpose::InstallTemp,
    )?;
    let active_path = validate_known_file_stat(
        &statat(parent_fd, ACTIVE_KEYRING_NAME, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(map_artifact_errno)?,
        KnownFilePurpose::ActiveKeyring,
    )?;
    let install_readback =
        read_file_positionally(&install, KnownFilePurpose::InstallTemp.maximum_size())?;
    let active_readback =
        read_file_positionally(&active, KnownFilePurpose::ActiveKeyring.maximum_size())?;
    if install_descriptor != install_stat
        || install_path != install_stat
        || active_descriptor != active_stat
        || active_path != active_stat
        || install_readback.expose() != staged_bytes
        || active_readback.expose() != active_bytes
    {
        return Err(SecretFsError::ArtifactChanged);
    }

    before_exchange();
    exchange_paths(parent_fd, install_name, parent_fd, ACTIVE_KEYRING_NAME)?;
    fsync(parent_fd).map_err(SecretFsError::errno)?;

    let new_active_path = validate_known_file_stat(
        &statat(parent_fd, ACTIVE_KEYRING_NAME, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(map_artifact_errno)?,
        KnownFilePurpose::ActiveKeyring,
    )?;
    let old_active_path = validate_known_file_stat(
        &statat(parent_fd, install_name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_artifact_errno)?,
        KnownFilePurpose::InstallTemp,
    )?;
    let new_active_descriptor = validate_known_file_fd(&install, KnownFilePurpose::ActiveKeyring)?;
    let old_active_descriptor = validate_known_file_fd(&active, KnownFilePurpose::InstallTemp)?;
    if new_active_descriptor != new_active_path
        || old_active_descriptor != old_active_path
        || !same_file_node(new_active_descriptor.identity, install_stat.identity)
        || !same_file_node(old_active_descriptor.identity, active_stat.identity)
        || read_file_positionally(&install, KnownFilePurpose::ActiveKeyring.maximum_size())?
            .expose()
            != staged_bytes
        || read_file_positionally(&active, KnownFilePurpose::InstallTemp.maximum_size())?.expose()
            != active_bytes
    {
        return Err(SecretFsError::ArtifactChanged);
    }
    Ok(())
}

fn ensure_path_absent(parent_fd: &OwnedFd, name: &str) -> Result<(), SecretFsError> {
    match statat(parent_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => Ok(()),
        Err(error) => Err(map_artifact_errno(error)),
        Ok(_) => Err(SecretFsError::ArtifactChanged),
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn exchange_paths(
    old_parent: &OwnedFd,
    old_name: &str,
    new_parent: &OwnedFd,
    new_name: &str,
) -> Result<(), SecretFsError> {
    renameat_with(
        old_parent,
        old_name,
        new_parent,
        new_name,
        RenameFlags::EXCHANGE,
    )
    .map_err(map_creation_errno)
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
fn exchange_paths(
    _old_parent: &OwnedFd,
    _old_name: &str,
    _new_parent: &OwnedFd,
    _new_name: &str,
) -> Result<(), SecretFsError> {
    Err(SecretFsError::Io(io::ErrorKind::Unsupported))
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
fn rename_no_replace(
    old_parent: &OwnedFd,
    old_name: &str,
    new_parent: &OwnedFd,
    new_name: &str,
) -> Result<(), SecretFsError> {
    renameat_with(
        old_parent,
        old_name,
        new_parent,
        new_name,
        RenameFlags::NOREPLACE,
    )
    .map_err(map_creation_errno)
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
)))]
fn rename_no_replace(
    _old_parent: &OwnedFd,
    _old_name: &str,
    _new_parent: &OwnedFd,
    _new_name: &str,
) -> Result<(), SecretFsError> {
    Err(SecretFsError::Io(io::ErrorKind::Unsupported))
}

fn revalidate_created_reservation(
    secret_fd: &OwnedFd,
    reservation_fd: &OwnedFd,
    reservation_name: &str,
    expected_identity: FileIdentity,
) -> Result<(), SecretFsError> {
    let descriptor_identity = validate_reservation_directory_fd(reservation_fd)?.identity;
    let path_identity = validate_reservation_directory_stat(
        &statat(secret_fd, reservation_name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(map_artifact_errno)?,
    )?
    .identity;
    if descriptor_identity != path_identity
        || !same_directory_identity(descriptor_identity, expected_identity)
    {
        return Err(SecretFsError::ArtifactChanged);
    }
    Ok(())
}

fn same_directory_identity(left: FileIdentity, right: FileIdentity) -> bool {
    left.device == right.device
        && left.inode == right.inode
        && left.owner == right.owner
        && left.mode == right.mode
        && left.file_type == FileKind::Directory
        && right.file_type == FileKind::Directory
}

impl fmt::Debug for LockedAuthInstance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("LockedAuthInstance")
            .field(&"[HELD]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthCleanInstanceState {
    Clean,
    Occupied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthInitializationPreSourcePhase {
    ReservationOnly,
    MetadataIncomplete,
    MetadataComplete,
    StagedIncomplete,
    StagedComplete,
    Prepared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthInitializationRecovery {
    RollbackOnlyCandidate,
    ResumeOrRollbackCandidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthInitializationForwardPhase {
    AwaitingInstallTemp,
    InstallTempPrefix,
    InstallTempExact,
    AwaitingFinalDbCas,
    AwaitingCleanupRename,
    AwaitingCleanupStagedRemoval,
    AwaitingCleanupPreparedRemoval,
    AwaitingCleanupMetadataRemoval,
    AwaitingCleanupDirectoryRemoval,
}

impl AuthInitializationForwardPhase {
    const fn is_cleanup(self) -> bool {
        matches!(
            self,
            Self::AwaitingCleanupRename
                | Self::AwaitingCleanupStagedRemoval
                | Self::AwaitingCleanupPreparedRemoval
                | Self::AwaitingCleanupMetadataRemoval
                | Self::AwaitingCleanupDirectoryRemoval
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthInitializationBlocker {
    UnrecognizedArtifacts,
    UnsupportedLifecycleState,
    InconsistentDbFilesystem,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthInitializationReconciliation {
    CleanUninitialized,
    InitializePreSource {
        phase: AuthInitializationPreSourcePhase,
        recovery: AuthInitializationRecovery,
    },
    InitializeForwardOnly(AuthInitializationForwardPhase),
    InitializationComplete,
    Blocked(AuthInitializationBlocker),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthPlannedRotationPreSourcePhase {
    ReservationOnly,
    MetadataIncomplete,
    MetadataComplete,
    StagedIncomplete,
    StagedComplete,
    Prepared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthPlannedRotationRecovery {
    RollbackOnlyCandidate,
    ResumeOrRollbackCandidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthPlannedRotationBlocker {
    UnrecognizedArtifacts,
    UnsupportedLifecycleState,
    InconsistentDbFilesystem,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthPlannedRotationForwardPhase {
    AwaitingInstallTemp,
    InstallTempPrefix,
    InstallTempExact,
    AwaitingOldActiveTempRemoval,
    AwaitingFinalDbCas,
    AwaitingCleanupRename,
    AwaitingCleanupStagedRemoval,
    AwaitingCleanupPreparedRemoval,
    AwaitingCleanupMetadataRemoval,
    AwaitingCleanupDirectoryRemoval,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthPlannedRotationReconciliation {
    CleanActive,
    PlannedPreSource {
        phase: AuthPlannedRotationPreSourcePhase,
        recovery: AuthPlannedRotationRecovery,
    },
    PlannedForwardOnly(AuthPlannedRotationForwardPhase),
    PlannedRotationComplete,
    Blocked(AuthPlannedRotationBlocker),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthPlannedRotationPrepareOutcome {
    Prepared,
    AlreadyPrepared,
    PreconditionNotClean(AuthPlannedRotationReconciliation),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthPlannedRotationRollbackOutcome {
    RolledBack,
    AlreadyClean,
    NotRollbackable(AuthPlannedRotationReconciliation),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthPlannedRotationSourceOutcome {
    Committed,
    AlreadyCommitted,
    ConfirmedNotCommitted,
    NotPrepared(AuthPlannedRotationReconciliation),
    PreconditionChanged,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthPlannedRotationActiveKeyInstallOutcome {
    InstalledAwaitingFinalDbCas,
    AlreadyAwaitingFinalDbCas,
    NotInstallable(AuthPlannedRotationReconciliation),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthPlannedRotationFinalLifecycleOutcome {
    ActivatedAwaitingCleanup,
    AlreadyActivatedAwaitingCleanup,
    ConfirmedNotActivated,
    NotActivatable(AuthPlannedRotationReconciliation),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthPlannedRotationCleanupOutcome {
    Completed,
    AlreadyCompleted,
    NotCleanable(AuthPlannedRotationReconciliation),
}

pub(crate) type AuthRetirePreSourcePhase = AuthPlannedRotationPreSourcePhase;
pub(crate) type AuthRetireRecovery = AuthPlannedRotationRecovery;
pub(crate) type AuthRetireBlocker = AuthPlannedRotationBlocker;
pub(crate) type AuthRetireForwardPhase = AuthPlannedRotationForwardPhase;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthRetireReconciliation {
    CleanActiveOnly,
    ReadyToRetire,
    RetirePreSource {
        phase: AuthRetirePreSourcePhase,
        recovery: AuthRetireRecovery,
    },
    RetireForwardOnly(AuthRetireForwardPhase),
    Blocked(AuthRetireBlocker),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthRetirePrepareOutcome {
    Prepared,
    AlreadyPrepared,
    PreconditionNotReady(AuthRetireReconciliation),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthRetireRollbackOutcome {
    RolledBack,
    AlreadyReady,
    NotRollbackable(AuthRetireReconciliation),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthRetireSourceOutcome {
    Committed,
    AlreadyCommitted,
    ConfirmedNotCommitted,
    NotPrepared(AuthRetireReconciliation),
    PreconditionChanged,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthRetireActiveKeyInstallOutcome {
    InstalledAwaitingFinalDbCas,
    AlreadyAwaitingFinalDbCas,
    NotInstallable(AuthRetireReconciliation),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthRetireFinalLifecycleOutcome {
    ActivatedAwaitingCleanup,
    AlreadyActivatedAwaitingCleanup,
    ConfirmedNotActivated,
    NotActivatable(AuthRetireReconciliation),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthRetireCleanupOutcome {
    Completed,
    AlreadyCompleted,
    NotCleanable(AuthRetireReconciliation),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthInitializationPrepareOutcome {
    Prepared,
    PreconditionNotClean(AuthInitializationReconciliation),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthInitializationRollbackOutcome {
    RolledBack,
    AlreadyClean,
    NotRollbackable(AuthInitializationReconciliation),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthInitializationPreSourceRecoveryOutcome {
    Prepared,
    AlreadyPrepared,
    NotRecoverable(AuthInitializationReconciliation),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthInitializationSourceOutcome {
    Committed,
    AlreadyCommitted,
    ConfirmedNotCommitted,
    LegacyPrepared,
    NotPrepared(AuthInitializationReconciliation),
    PreconditionChanged,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthInitializationActiveKeyInstallOutcome {
    InstalledAwaitingFinalDbCas,
    AlreadyAwaitingFinalDbCas,
    NotInstallable(AuthInitializationReconciliation),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthInitializationFinalLifecycleOutcome {
    ActivatedAwaitingCleanup,
    AlreadyActivatedAwaitingCleanup,
    ConfirmedNotActivated,
    NotActivatable(AuthInitializationReconciliation),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthInitializationCleanupOutcome {
    Completed,
    AlreadyCompleted,
    NotCleanable(AuthInitializationReconciliation),
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthInitializationPrepareTestFault {
    Reservation,
    Metadata,
    Staged,
    Prepared,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthPlannedRotationPrepareTestFault {
    Reservation,
    Metadata,
    Staged,
    Prepared,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthRetirePrepareTestFault {
    Reservation,
    Metadata,
    Staged,
    Prepared,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthPlannedRotationRollbackTestFault {
    Prepared,
    Staged,
    Metadata,
    Directory,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthRetireRollbackTestFault {
    Prepared,
    Staged,
    Metadata,
    Directory,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthInitializationRollbackTestFault {
    Prepared,
    Staged,
    Metadata,
    Directory,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthInitializationPreSourceRecoveryTestFault {
    Metadata,
    Staged,
    Prepared,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthInitializationSourceDurabilityTestFault {
    Metadata,
    Staged,
    Prepared,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthPlannedRotationSourceDurabilityTestFault {
    Metadata,
    Staged,
    Prepared,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthPlannedRotationActiveKeyInstallTestFault {
    PrefixRemoved,
    InstallTempDurable,
    ExchangeDurable,
    OldActiveTempRemoved,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthPlannedRotationCleanupTestFault {
    Rename,
    Staged,
    Prepared,
    Metadata,
    Directory,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthInitializationActiveKeyInstallTestFault {
    PrefixRemoved,
    InstallTempDurable,
    PublishDurable,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthInitializationCleanupTestFault {
    Rename,
    Staged,
    Prepared,
    Metadata,
    Directory,
}

impl fmt::Debug for AuthInitializationPrepareOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prepared => formatter.write_str("AuthInitializationPrepareOutcome::Prepared"),
            Self::PreconditionNotClean(_) => formatter
                .write_str("AuthInitializationPrepareOutcome::PreconditionNotClean([REDACTED])"),
        }
    }
}

impl fmt::Debug for AuthPlannedRotationPrepareOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Prepared => "AuthPlannedRotationPrepareOutcome::Prepared",
            Self::AlreadyPrepared => "AuthPlannedRotationPrepareOutcome::AlreadyPrepared",
            Self::PreconditionNotClean(_) => {
                "AuthPlannedRotationPrepareOutcome::PreconditionNotClean([REDACTED])"
            }
        })
    }
}

impl fmt::Debug for AuthPlannedRotationRollbackOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RolledBack => "AuthPlannedRotationRollbackOutcome::RolledBack",
            Self::AlreadyClean => "AuthPlannedRotationRollbackOutcome::AlreadyClean",
            Self::NotRollbackable(_) => {
                "AuthPlannedRotationRollbackOutcome::NotRollbackable([REDACTED])"
            }
        })
    }
}

impl fmt::Debug for AuthRetirePrepareOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Prepared => "AuthRetirePrepareOutcome::Prepared",
            Self::AlreadyPrepared => "AuthRetirePrepareOutcome::AlreadyPrepared",
            Self::PreconditionNotReady(_) => {
                "AuthRetirePrepareOutcome::PreconditionNotReady([REDACTED])"
            }
        })
    }
}

impl fmt::Debug for AuthRetireRollbackOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RolledBack => "AuthRetireRollbackOutcome::RolledBack",
            Self::AlreadyReady => "AuthRetireRollbackOutcome::AlreadyReady",
            Self::NotRollbackable(_) => "AuthRetireRollbackOutcome::NotRollbackable([REDACTED])",
        })
    }
}

impl fmt::Debug for AuthRetireSourceOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Committed => "AuthRetireSourceOutcome::Committed",
            Self::AlreadyCommitted => "AuthRetireSourceOutcome::AlreadyCommitted",
            Self::ConfirmedNotCommitted => "AuthRetireSourceOutcome::ConfirmedNotCommitted",
            Self::NotPrepared(_) => "AuthRetireSourceOutcome::NotPrepared([REDACTED])",
            Self::PreconditionChanged => "AuthRetireSourceOutcome::PreconditionChanged",
        })
    }
}

impl fmt::Debug for AuthRetireActiveKeyInstallOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InstalledAwaitingFinalDbCas => {
                "AuthRetireActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas"
            }
            Self::AlreadyAwaitingFinalDbCas => {
                "AuthRetireActiveKeyInstallOutcome::AlreadyAwaitingFinalDbCas"
            }
            Self::NotInstallable(_) => {
                "AuthRetireActiveKeyInstallOutcome::NotInstallable([REDACTED])"
            }
        })
    }
}

impl fmt::Debug for AuthRetireFinalLifecycleOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ActivatedAwaitingCleanup => {
                "AuthRetireFinalLifecycleOutcome::ActivatedAwaitingCleanup"
            }
            Self::AlreadyActivatedAwaitingCleanup => {
                "AuthRetireFinalLifecycleOutcome::AlreadyActivatedAwaitingCleanup"
            }
            Self::ConfirmedNotActivated => "AuthRetireFinalLifecycleOutcome::ConfirmedNotActivated",
            Self::NotActivatable(_) => {
                "AuthRetireFinalLifecycleOutcome::NotActivatable([REDACTED])"
            }
        })
    }
}

impl fmt::Debug for AuthRetireCleanupOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Completed => "AuthRetireCleanupOutcome::Completed",
            Self::AlreadyCompleted => "AuthRetireCleanupOutcome::AlreadyCompleted",
            Self::NotCleanable(_) => "AuthRetireCleanupOutcome::NotCleanable([REDACTED])",
        })
    }
}

impl fmt::Debug for AuthPlannedRotationSourceOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Committed => "AuthPlannedRotationSourceOutcome::Committed",
            Self::AlreadyCommitted => "AuthPlannedRotationSourceOutcome::AlreadyCommitted",
            Self::ConfirmedNotCommitted => {
                "AuthPlannedRotationSourceOutcome::ConfirmedNotCommitted"
            }
            Self::NotPrepared(_) => "AuthPlannedRotationSourceOutcome::NotPrepared([REDACTED])",
            Self::PreconditionChanged => "AuthPlannedRotationSourceOutcome::PreconditionChanged",
        })
    }
}

impl fmt::Debug for AuthPlannedRotationActiveKeyInstallOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InstalledAwaitingFinalDbCas => {
                "AuthPlannedRotationActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas"
            }
            Self::AlreadyAwaitingFinalDbCas => {
                "AuthPlannedRotationActiveKeyInstallOutcome::AlreadyAwaitingFinalDbCas"
            }
            Self::NotInstallable(_) => {
                "AuthPlannedRotationActiveKeyInstallOutcome::NotInstallable([REDACTED])"
            }
        })
    }
}

impl fmt::Debug for AuthPlannedRotationFinalLifecycleOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ActivatedAwaitingCleanup => {
                "AuthPlannedRotationFinalLifecycleOutcome::ActivatedAwaitingCleanup"
            }
            Self::AlreadyActivatedAwaitingCleanup => {
                "AuthPlannedRotationFinalLifecycleOutcome::AlreadyActivatedAwaitingCleanup"
            }
            Self::ConfirmedNotActivated => {
                "AuthPlannedRotationFinalLifecycleOutcome::ConfirmedNotActivated"
            }
            Self::NotActivatable(_) => {
                "AuthPlannedRotationFinalLifecycleOutcome::NotActivatable([REDACTED])"
            }
        })
    }
}

impl fmt::Debug for AuthPlannedRotationCleanupOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Completed => "AuthPlannedRotationCleanupOutcome::Completed",
            Self::AlreadyCompleted => "AuthPlannedRotationCleanupOutcome::AlreadyCompleted",
            Self::NotCleanable(_) => "AuthPlannedRotationCleanupOutcome::NotCleanable([REDACTED])",
        })
    }
}

impl fmt::Debug for AuthInitializationRollbackOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RolledBack => "AuthInitializationRollbackOutcome::RolledBack",
            Self::AlreadyClean => "AuthInitializationRollbackOutcome::AlreadyClean",
            Self::NotRollbackable(_) => {
                "AuthInitializationRollbackOutcome::NotRollbackable([REDACTED])"
            }
        })
    }
}

impl fmt::Debug for AuthInitializationPreSourceRecoveryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Prepared => "AuthInitializationPreSourceRecoveryOutcome::Prepared",
            Self::AlreadyPrepared => "AuthInitializationPreSourceRecoveryOutcome::AlreadyPrepared",
            Self::NotRecoverable(_) => {
                "AuthInitializationPreSourceRecoveryOutcome::NotRecoverable([REDACTED])"
            }
        })
    }
}

impl fmt::Debug for AuthInitializationSourceOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Committed => "AuthInitializationSourceOutcome::Committed",
            Self::AlreadyCommitted => "AuthInitializationSourceOutcome::AlreadyCommitted",
            Self::ConfirmedNotCommitted => "AuthInitializationSourceOutcome::ConfirmedNotCommitted",
            Self::LegacyPrepared => "AuthInitializationSourceOutcome::LegacyPrepared",
            Self::NotPrepared(_) => "AuthInitializationSourceOutcome::NotPrepared([REDACTED])",
            Self::PreconditionChanged => "AuthInitializationSourceOutcome::PreconditionChanged",
        })
    }
}

impl fmt::Debug for AuthInitializationActiveKeyInstallOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InstalledAwaitingFinalDbCas => {
                "AuthInitializationActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas"
            }
            Self::AlreadyAwaitingFinalDbCas => {
                "AuthInitializationActiveKeyInstallOutcome::AlreadyAwaitingFinalDbCas"
            }
            Self::NotInstallable(_) => {
                "AuthInitializationActiveKeyInstallOutcome::NotInstallable([REDACTED])"
            }
        })
    }
}

impl fmt::Debug for AuthInitializationFinalLifecycleOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ActivatedAwaitingCleanup => {
                "AuthInitializationFinalLifecycleOutcome::ActivatedAwaitingCleanup"
            }
            Self::AlreadyActivatedAwaitingCleanup => {
                "AuthInitializationFinalLifecycleOutcome::AlreadyActivatedAwaitingCleanup"
            }
            Self::ConfirmedNotActivated => {
                "AuthInitializationFinalLifecycleOutcome::ConfirmedNotActivated"
            }
            Self::NotActivatable(_) => {
                "AuthInitializationFinalLifecycleOutcome::NotActivatable([REDACTED])"
            }
        })
    }
}

impl fmt::Debug for AuthInitializationCleanupOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Completed => "AuthInitializationCleanupOutcome::Completed",
            Self::AlreadyCompleted => "AuthInitializationCleanupOutcome::AlreadyCompleted",
            Self::NotCleanable(_) => "AuthInitializationCleanupOutcome::NotCleanable([REDACTED])",
        })
    }
}

pub(crate) struct AuthMaintenanceContext<'a> {
    locked: LockedAuthInstance,
    conversation: &'a SqliteStore<ConversationStore>,
    store_identity: crate::storage::StoreDirectoryIdentity,
}

impl AuthMaintenanceContext<'_> {
    pub(crate) fn revalidate_conversation(&self) -> Result<(), AuthStoreBindingError> {
        let store_identity = self
            .conversation
            .auth_directory_identity()
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        let layout_identity = self.locked.revalidate()?;
        if store_identity != self.store_identity
            || !store_identity.matches(
                layout_identity.device,
                layout_identity.inode,
                layout_identity.owner,
            )
        {
            return Err(AuthStoreBindingError::ConversationStoreMismatch);
        }
        Ok(())
    }

    pub(super) fn into_owned(self) -> Result<OwnedAuthMaintenanceContext, AuthStoreBindingError> {
        self.revalidate_conversation()?;
        let conversation = self
            .conversation
            .auth_maintenance_binding()
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        let store_identity = conversation
            .directory_identity()
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        let layout_identity = self.locked.revalidate()?;
        if store_identity != self.store_identity
            || !store_identity.matches(
                layout_identity.device,
                layout_identity.inode,
                layout_identity.owner,
            )
        {
            return Err(AuthStoreBindingError::ConversationStoreMismatch);
        }
        Ok(OwnedAuthMaintenanceContext {
            locked: self.locked,
            conversation,
            store_identity,
        })
    }
}

impl fmt::Debug for AuthMaintenanceContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthMaintenanceContext")
            .field("lock", &"[HELD]")
            .field("conversation_store", &"[BOUND]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthStoreBindingError {
    Filesystem(SecretFsError),
    ConversationStoreUnavailable,
    ConversationStoreMismatch,
    ConversationStoreChanged,
}

impl From<SecretFsError> for AuthStoreBindingError {
    fn from(error: SecretFsError) -> Self {
        Self::Filesystem(error)
    }
}

impl fmt::Display for AuthStoreBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Filesystem(_) => "authentication filesystem binding failed",
            Self::ConversationStoreUnavailable => {
                "authentication conversation store is unavailable"
            }
            Self::ConversationStoreMismatch => {
                "authentication conversation store belongs to another instance"
            }
            Self::ConversationStoreChanged => {
                "authentication conversation store changed during inspection"
            }
        })
    }
}

impl Error for AuthStoreBindingError {}

fn retain_initialization_cleanup_evidence(
    retained_artifacts: &mut Option<PinnedAuthArtifactSnapshot>,
    retained_metadata: &mut Option<InitializationMetadataV1>,
    retained_database: &mut Option<AuthDatabaseReconciliationObservation>,
    artifacts: PinnedAuthArtifactSnapshot,
    metadata: Option<InitializationMetadataV1>,
    database: AuthDatabaseReconciliationObservation,
) -> Result<(), AuthStoreBindingError> {
    if retained_artifacts.is_some() {
        return Ok(());
    }
    let metadata = metadata.ok_or(AuthStoreBindingError::Filesystem(
        SecretFsError::UnsafeAuthArtifact,
    ))?;
    if database.source != AuthInitializationSourceMatch::Exact
        || database.source_fingerprint.is_none()
    {
        return Err(AuthStoreBindingError::ConversationStoreChanged);
    }
    *retained_artifacts = Some(artifacts);
    *retained_metadata = Some(metadata);
    *retained_database = Some(database);
    Ok(())
}

fn retain_planned_rotation_cleanup_evidence(
    retained_artifacts: &mut Option<PinnedAuthArtifactSnapshot>,
    retained_metadata: &mut Option<PlannedRotationMetadataV1>,
    retained_database: &mut Option<AuthPlannedRotationDatabaseObservation>,
    artifacts: PinnedAuthArtifactSnapshot,
    metadata: Option<PlannedRotationMetadataV1>,
    database: AuthPlannedRotationDatabaseObservation,
) -> Result<(), AuthStoreBindingError> {
    if retained_artifacts.is_some() {
        return Ok(());
    }
    let metadata = metadata.ok_or(AuthStoreBindingError::Filesystem(
        SecretFsError::UnsafeAuthArtifact,
    ))?;
    if database.source != AuthPlannedRotationSourceMatch::Exact
        || database.source_fingerprint.is_none()
    {
        return Err(AuthStoreBindingError::ConversationStoreChanged);
    }
    *retained_artifacts = Some(artifacts);
    *retained_metadata = Some(metadata);
    *retained_database = Some(database);
    Ok(())
}

fn retain_retire_cleanup_evidence(
    retained_artifacts: &mut Option<PinnedAuthArtifactSnapshot>,
    retained_metadata: &mut Option<RetireMetadataV1>,
    retained_database: &mut Option<AuthPlannedRotationDatabaseObservation>,
    artifacts: PinnedAuthArtifactSnapshot,
    metadata: Option<RetireMetadataV1>,
    database: AuthPlannedRotationDatabaseObservation,
) -> Result<(), AuthStoreBindingError> {
    if retained_artifacts.is_some() {
        return Ok(());
    }
    let metadata = metadata.ok_or(AuthStoreBindingError::Filesystem(
        SecretFsError::UnsafeAuthArtifact,
    ))?;
    if database.source != AuthPlannedRotationSourceMatch::Exact
        || database.source_fingerprint.is_none()
    {
        return Err(AuthStoreBindingError::ConversationStoreChanged);
    }
    *retained_artifacts = Some(artifacts);
    *retained_metadata = Some(metadata);
    *retained_database = Some(database);
    Ok(())
}

pub(super) struct OwnedAuthMaintenanceContext {
    locked: LockedAuthInstance,
    conversation: AuthConversationStoreBinding,
    store_identity: StoreDirectoryIdentity,
}

impl OwnedAuthMaintenanceContext {
    pub(super) fn revalidate(&self) -> Result<(), AuthStoreBindingError> {
        let store_identity = self
            .conversation
            .directory_identity()
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        let layout_identity = self.locked.revalidate()?;
        if store_identity != self.store_identity
            || !store_identity.matches(
                layout_identity.device,
                layout_identity.inode,
                layout_identity.owner,
            )
        {
            return Err(AuthStoreBindingError::ConversationStoreMismatch);
        }
        Ok(())
    }

    pub(super) fn inspect_clean_instance(
        &self,
    ) -> Result<AuthCleanInstanceState, AuthStoreBindingError> {
        Ok(match self.inspect_initialization_reconciliation()? {
            AuthInitializationReconciliation::CleanUninitialized => AuthCleanInstanceState::Clean,
            _ => AuthCleanInstanceState::Occupied,
        })
    }

    pub(super) fn into_listener_lease(self) -> Result<AuthListenerLease, AuthStoreBindingError> {
        let reconciliation = self.inspect_retire_reconciliation()?;
        if !matches!(
            reconciliation,
            AuthRetireReconciliation::ReadyToRetire | AuthRetireReconciliation::CleanActiveOnly
        ) {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::UnsafeAuthArtifact,
            ));
        }

        let artifacts = self.locked.capture_secret_artifacts()?;
        if artifacts.has_unrecognized_artifacts()
            || !artifacts.namespace.is_valid
            || !artifacts.is_terminal_active_namespace()
        {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::UnsafeAuthArtifact,
            ));
        }
        let active = artifacts
            .active_file()
            .ok_or(AuthStoreBindingError::Filesystem(
                SecretFsError::UnsafeAuthArtifact,
            ))?;
        let keyring = Keyring::decode(SecretBytes::new(active.content.expose().to_vec()))
            .map_err(|_| AuthStoreBindingError::Filesystem(SecretFsError::UnsafeAuthArtifact))?;
        let database = self
            .conversation
            .inspect_auth_retire(None)
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        let AuthDatabaseLifecycleObservation::Active(lifecycle) = database.lifecycle else {
            return Err(AuthStoreBindingError::ConversationStoreChanged);
        };
        if database.source != AuthPlannedRotationSourceMatch::Canonical
            || !lifecycle.expected_kid.matches_key(keyring.active_kid())
            || !lifecycle.keyring_version.matches_version(keyring.version())
            || !lifecycle
                .updated_at_micros
                .is_at_or_after(keyring.active_activated_at())
        {
            return Err(AuthStoreBindingError::ConversationStoreChanged);
        }
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        Ok(AuthListenerLease {
            locked: self.locked,
            conversation: self.conversation,
            store_identity: self.store_identity,
            keyring,
        })
    }

    pub(super) fn inspect_initialization_reconciliation(
        &self,
    ) -> Result<AuthInitializationReconciliation, AuthStoreBindingError> {
        self.inspect_initialization_reconciliation_inner(|| {}, || {})
    }

    pub(super) fn inspect_planned_rotation_reconciliation(
        &self,
    ) -> Result<AuthPlannedRotationReconciliation, AuthStoreBindingError> {
        self.inspect_planned_rotation_reconciliation_inner(|| {}, || {})
    }

    pub(super) fn inspect_retire_reconciliation(
        &self,
    ) -> Result<AuthRetireReconciliation, AuthStoreBindingError> {
        self.inspect_retire_reconciliation_inner(|| {}, || {})
    }

    pub(super) fn prepare_planned_rotation(
        &self,
        preparation: &PlannedRotationPreparationV1,
    ) -> Result<AuthPlannedRotationPrepareOutcome, AuthStoreBindingError> {
        self.prepare_planned_rotation_inner(
            preparation,
            #[cfg(test)]
            None,
            || {},
        )
    }

    pub(super) fn prepare_retire(
        &self,
        preparation: &RetirePreparationV1,
    ) -> Result<AuthRetirePrepareOutcome, AuthStoreBindingError> {
        self.prepare_retire_inner(
            preparation,
            #[cfg(test)]
            None,
            || {},
        )
    }

    pub(super) fn rollback_planned_rotation_pre_source(
        &self,
    ) -> Result<AuthPlannedRotationRollbackOutcome, AuthStoreBindingError> {
        self.rollback_planned_rotation_pre_source_inner(
            #[cfg(test)]
            None,
            || {},
            || {},
            || {},
        )
    }

    pub(super) fn rollback_retire_pre_source(
        &self,
    ) -> Result<AuthRetireRollbackOutcome, AuthStoreBindingError> {
        self.rollback_retire_pre_source_inner(
            #[cfg(test)]
            None,
            || {},
            || {},
            || {},
        )
    }

    pub(super) fn prepare_initialization(
        &self,
        preparation: &InitializationPreparationV1,
    ) -> Result<AuthInitializationPrepareOutcome, AuthStoreBindingError> {
        self.prepare_initialization_inner(
            preparation,
            #[cfg(test)]
            None,
            || {},
        )
    }

    pub(super) fn recover_initialization_pre_source(
        &self,
    ) -> Result<AuthInitializationPreSourceRecoveryOutcome, AuthStoreBindingError> {
        self.recover_initialization_pre_source_inner(
            #[cfg(test)]
            None,
            || {},
            || {},
        )
    }

    #[cfg(test)]
    pub(super) fn recover_initialization_pre_source_with_test_control(
        &self,
        fault: Option<AuthInitializationPreSourceRecoveryTestFault>,
        before_mutation: impl FnOnce(),
        after_recovery: impl FnOnce(),
    ) -> Result<AuthInitializationPreSourceRecoveryOutcome, AuthStoreBindingError> {
        self.recover_initialization_pre_source_inner(fault, before_mutation, after_recovery)
    }

    fn recover_initialization_pre_source_inner<BeforeMutation, AfterRecovery>(
        &self,
        #[cfg(test)] fault: Option<AuthInitializationPreSourceRecoveryTestFault>,
        before_mutation: BeforeMutation,
        after_recovery: AfterRecovery,
    ) -> Result<AuthInitializationPreSourceRecoveryOutcome, AuthStoreBindingError>
    where
        BeforeMutation: FnOnce(),
        AfterRecovery: FnOnce(),
    {
        let (artifacts, reconciliation) = self.capture_stable_initialization_reconciliation()?;
        let phase = match reconciliation {
            AuthInitializationReconciliation::InitializePreSource {
                phase:
                    phase @ (AuthInitializationPreSourcePhase::StagedComplete
                    | AuthInitializationPreSourcePhase::Prepared),
                recovery: AuthInitializationRecovery::ResumeOrRollbackCandidate,
            } => phase,
            _ => {
                return Ok(AuthInitializationPreSourceRecoveryOutcome::NotRecoverable(
                    reconciliation,
                ));
            }
        };
        let metadata =
            artifacts
                .decode_initialization_metadata()
                .ok_or(AuthStoreBindingError::Filesystem(
                    SecretFsError::UnsafeAuthArtifact,
                ))?;
        if metadata.sentinel_source_seed().is_none() {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::UnsafeAuthArtifact,
            ));
        }

        before_mutation();
        let (verified_artifacts, verified_reconciliation) =
            self.capture_stable_initialization_reconciliation()?;
        if verified_reconciliation != reconciliation {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        }
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        verified_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;

        let reservation =
            artifacts
                .transition_directory()
                .ok_or(AuthStoreBindingError::Filesystem(
                    SecretFsError::ArtifactChanged,
                ))?;
        let transition_artifact = match reservation.artifact {
            TopLevelArtifactName::Transition {
                kind: TransitionKind::Initialize,
                id,
            } => TopLevelArtifactName::Transition {
                kind: TransitionKind::Initialize,
                id,
            },
            _ => {
                return Err(AuthStoreBindingError::Filesystem(
                    SecretFsError::ArtifactChanged,
                ));
            }
        };
        let transition_name = transition_artifact.format();
        if TopLevelArtifactName::parse(transition_name.as_bytes()) != Ok(transition_artifact) {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::UnsafeAuthArtifact,
            ));
        }
        let parts = RetainedReservationParts::from_directory(reservation);
        let (metadata_file, CodecObservation::Valid) = parts.metadata.ok_or(
            AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
        )?
        else {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        };
        let (staged_file, CodecObservation::Valid) = parts.staged.ok_or(
            AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
        )?
        else {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        };

        durabilize_existing_known_file(
            &reservation.directory_fd,
            ReservationEntryName::Metadata.as_str(),
            KnownFilePurpose::Metadata,
            metadata_file.stat,
            metadata_file.content.expose(),
        )?;
        self.verify_unchanged_pre_source_recovery_phase(&artifacts, reconciliation)?;
        #[cfg(test)]
        if fault == Some(AuthInitializationPreSourceRecoveryTestFault::Metadata) {
            return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                io::ErrorKind::Other,
            )));
        }

        durabilize_existing_known_file(
            &reservation.directory_fd,
            ReservationEntryName::StagedKeyring.as_str(),
            KnownFilePurpose::StagedKeyring,
            staged_file.stat,
            staged_file.content.expose(),
        )?;
        self.verify_unchanged_pre_source_recovery_phase(&artifacts, reconciliation)?;
        #[cfg(test)]
        if fault == Some(AuthInitializationPreSourceRecoveryTestFault::Staged) {
            return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                io::ErrorKind::Other,
            )));
        }

        let created_prepared = if phase == AuthInitializationPreSourcePhase::Prepared {
            let prepared = parts.prepared.ok_or(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ))?;
            durabilize_existing_known_file(
                &reservation.directory_fd,
                ReservationEntryName::Prepared.as_str(),
                KnownFilePurpose::Prepared,
                prepared.stat,
                prepared.content.expose(),
            )?;
            None
        } else {
            Some(persist_new_known_file(
                &reservation.directory_fd,
                ReservationEntryName::Prepared.as_str(),
                KnownFilePurpose::Prepared,
                &[],
            )?)
        };
        revalidate_created_reservation(
            &self.locked.layout.secret_fd,
            &reservation.directory_fd,
            transition_name.as_str(),
            reservation.stat.identity,
        )?;
        after_recovery();

        let expected = AuthInitializationReconciliation::InitializePreSource {
            phase: AuthInitializationPreSourcePhase::Prepared,
            recovery: AuthInitializationRecovery::ResumeOrRollbackCandidate,
        };
        let (final_artifacts, final_reconciliation) =
            self.capture_stable_initialization_reconciliation()?;
        if final_reconciliation != expected {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        }
        if let Some(created_prepared) = created_prepared.as_ref() {
            artifacts.revalidate_pre_source_recovery_completion(
                &self.locked.layout.secret_fd,
                &final_artifacts,
                created_prepared,
            )?;
        } else {
            artifacts.revalidate(&self.locked.layout.secret_fd)?;
            final_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        }
        self.revalidate()?;

        let (readback_artifacts, readback) = self.capture_stable_initialization_reconciliation()?;
        if readback != expected {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        }
        if let Some(created_prepared) = created_prepared.as_ref() {
            artifacts.revalidate_pre_source_recovery_completion(
                &self.locked.layout.secret_fd,
                &readback_artifacts,
                created_prepared,
            )?;
        } else {
            artifacts.revalidate(&self.locked.layout.secret_fd)?;
            readback_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        }
        self.revalidate()?;
        #[cfg(test)]
        if fault == Some(AuthInitializationPreSourceRecoveryTestFault::Prepared) {
            return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                io::ErrorKind::Other,
            )));
        }

        Ok(if created_prepared.is_some() {
            AuthInitializationPreSourceRecoveryOutcome::Prepared
        } else {
            AuthInitializationPreSourceRecoveryOutcome::AlreadyPrepared
        })
    }

    fn verify_unchanged_pre_source_recovery_phase(
        &self,
        artifacts: &PinnedAuthArtifactSnapshot,
        expected: AuthInitializationReconciliation,
    ) -> Result<(), AuthStoreBindingError> {
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        let (current_artifacts, current) = self.capture_stable_initialization_reconciliation()?;
        if current != expected {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        }
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        current_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()
    }

    fn durabilize_prepared_initialization_evidence(
        &self,
        artifacts: &PinnedAuthArtifactSnapshot,
        #[cfg(test)] fault: Option<AuthInitializationSourceDurabilityTestFault>,
    ) -> Result<(), AuthStoreBindingError> {
        let reservation =
            artifacts
                .transition_directory()
                .ok_or(AuthStoreBindingError::Filesystem(
                    SecretFsError::ArtifactChanged,
                ))?;
        let transition_name = reservation.artifact.format();
        if !matches!(
            reservation.artifact,
            TopLevelArtifactName::Transition {
                kind: TransitionKind::Initialize,
                ..
            }
        ) || TopLevelArtifactName::parse(transition_name.as_bytes()) != Ok(reservation.artifact)
        {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::UnsafeAuthArtifact,
            ));
        }
        let parts = RetainedReservationParts::from_directory(reservation);
        let (metadata, CodecObservation::Valid) = parts.metadata.ok_or(
            AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
        )?
        else {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        };
        let (staged, CodecObservation::Valid) = parts.staged.ok_or(
            AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
        )?
        else {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        };
        let prepared = parts.prepared.ok_or(AuthStoreBindingError::Filesystem(
            SecretFsError::ArtifactChanged,
        ))?;

        for (name, purpose, file) in [
            (
                ReservationEntryName::Metadata.as_str(),
                KnownFilePurpose::Metadata,
                metadata,
            ),
            (
                ReservationEntryName::StagedKeyring.as_str(),
                KnownFilePurpose::StagedKeyring,
                staged,
            ),
            (
                ReservationEntryName::Prepared.as_str(),
                KnownFilePurpose::Prepared,
                prepared,
            ),
        ] {
            durabilize_existing_known_file(
                &reservation.directory_fd,
                name,
                purpose,
                file.stat,
                file.content.expose(),
            )?;
            artifacts.revalidate(&self.locked.layout.secret_fd)?;
            self.revalidate()?;
            #[cfg(test)]
            if matches!(
                (fault, purpose),
                (
                    Some(AuthInitializationSourceDurabilityTestFault::Metadata),
                    KnownFilePurpose::Metadata
                ) | (
                    Some(AuthInitializationSourceDurabilityTestFault::Staged),
                    KnownFilePurpose::StagedKeyring
                ) | (
                    Some(AuthInitializationSourceDurabilityTestFault::Prepared),
                    KnownFilePurpose::Prepared
                )
            ) {
                return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                    io::ErrorKind::Other,
                )));
            }
        }
        revalidate_created_reservation(
            &self.locked.layout.secret_fd,
            &reservation.directory_fd,
            transition_name.as_str(),
            reservation.stat.identity,
        )?;
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()
    }

    fn durabilize_prepared_planned_rotation_evidence(
        &self,
        artifacts: &PinnedAuthArtifactSnapshot,
        #[cfg(test)] fault: Option<AuthPlannedRotationSourceDurabilityTestFault>,
    ) -> Result<(), AuthStoreBindingError> {
        let reservation =
            artifacts
                .transition_directory()
                .ok_or(AuthStoreBindingError::Filesystem(
                    SecretFsError::ArtifactChanged,
                ))?;
        let transition_name = reservation.artifact.format();
        if !matches!(
            reservation.artifact,
            TopLevelArtifactName::Transition {
                kind: TransitionKind::Planned,
                ..
            }
        ) || TopLevelArtifactName::parse(transition_name.as_bytes()) != Ok(reservation.artifact)
        {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::UnsafeAuthArtifact,
            ));
        }
        let parts = RetainedReservationParts::from_directory(reservation);
        let (metadata, CodecObservation::Valid) = parts.metadata.ok_or(
            AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
        )?
        else {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        };
        let (staged, CodecObservation::Valid) = parts.staged.ok_or(
            AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
        )?
        else {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        };
        let prepared = parts.prepared.ok_or(AuthStoreBindingError::Filesystem(
            SecretFsError::ArtifactChanged,
        ))?;

        for (name, purpose, file) in [
            (
                ReservationEntryName::Metadata.as_str(),
                KnownFilePurpose::Metadata,
                metadata,
            ),
            (
                ReservationEntryName::StagedKeyring.as_str(),
                KnownFilePurpose::StagedKeyring,
                staged,
            ),
            (
                ReservationEntryName::Prepared.as_str(),
                KnownFilePurpose::Prepared,
                prepared,
            ),
        ] {
            durabilize_existing_known_file(
                &reservation.directory_fd,
                name,
                purpose,
                file.stat,
                file.content.expose(),
            )?;
            artifacts.revalidate(&self.locked.layout.secret_fd)?;
            self.revalidate()?;
            #[cfg(test)]
            if matches!(
                (fault, purpose),
                (
                    Some(AuthPlannedRotationSourceDurabilityTestFault::Metadata),
                    KnownFilePurpose::Metadata
                ) | (
                    Some(AuthPlannedRotationSourceDurabilityTestFault::Staged),
                    KnownFilePurpose::StagedKeyring
                ) | (
                    Some(AuthPlannedRotationSourceDurabilityTestFault::Prepared),
                    KnownFilePurpose::Prepared
                )
            ) {
                return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                    io::ErrorKind::Other,
                )));
            }
        }
        revalidate_created_reservation(
            &self.locked.layout.secret_fd,
            &reservation.directory_fd,
            transition_name.as_str(),
            reservation.stat.identity,
        )?;
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()
    }

    fn durabilize_prepared_retire_evidence(
        &self,
        artifacts: &PinnedAuthArtifactSnapshot,
        #[cfg(test)] fault: Option<AuthPlannedRotationSourceDurabilityTestFault>,
    ) -> Result<(), AuthStoreBindingError> {
        let reservation =
            artifacts
                .transition_directory()
                .ok_or(AuthStoreBindingError::Filesystem(
                    SecretFsError::ArtifactChanged,
                ))?;
        let transition_name = reservation.artifact.format();
        if !matches!(
            reservation.artifact,
            TopLevelArtifactName::Transition {
                kind: TransitionKind::Retire,
                ..
            }
        ) || TopLevelArtifactName::parse(transition_name.as_bytes()) != Ok(reservation.artifact)
        {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::UnsafeAuthArtifact,
            ));
        }
        let parts = RetainedReservationParts::from_directory(reservation);
        let (metadata, CodecObservation::Valid) = parts.metadata.ok_or(
            AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
        )?
        else {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        };
        let (staged, CodecObservation::Valid) = parts.staged.ok_or(
            AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
        )?
        else {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        };
        let prepared = parts.prepared.ok_or(AuthStoreBindingError::Filesystem(
            SecretFsError::ArtifactChanged,
        ))?;

        for (name, purpose, file) in [
            (
                ReservationEntryName::Metadata.as_str(),
                KnownFilePurpose::Metadata,
                metadata,
            ),
            (
                ReservationEntryName::StagedKeyring.as_str(),
                KnownFilePurpose::StagedKeyring,
                staged,
            ),
            (
                ReservationEntryName::Prepared.as_str(),
                KnownFilePurpose::Prepared,
                prepared,
            ),
        ] {
            durabilize_existing_known_file(
                &reservation.directory_fd,
                name,
                purpose,
                file.stat,
                file.content.expose(),
            )?;
            artifacts.revalidate(&self.locked.layout.secret_fd)?;
            self.revalidate()?;
            #[cfg(test)]
            if matches!(
                (fault, purpose),
                (
                    Some(AuthPlannedRotationSourceDurabilityTestFault::Metadata),
                    KnownFilePurpose::Metadata
                ) | (
                    Some(AuthPlannedRotationSourceDurabilityTestFault::Staged),
                    KnownFilePurpose::StagedKeyring
                ) | (
                    Some(AuthPlannedRotationSourceDurabilityTestFault::Prepared),
                    KnownFilePurpose::Prepared
                )
            ) {
                return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                    io::ErrorKind::Other,
                )));
            }
        }
        revalidate_created_reservation(
            &self.locked.layout.secret_fd,
            &reservation.directory_fd,
            transition_name.as_str(),
            reservation.stat.identity,
        )?;
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()
    }

    pub(super) fn rollback_initialization_pre_source(
        &self,
    ) -> Result<AuthInitializationRollbackOutcome, AuthStoreBindingError> {
        self.rollback_initialization_pre_source_inner(
            #[cfg(test)]
            None,
            || {},
            || {},
        )
    }

    #[cfg(test)]
    pub(super) fn rollback_initialization_pre_source_with_test_control(
        &self,
        fault: Option<AuthInitializationRollbackTestFault>,
        before_mutation: impl FnOnce(),
        after_rollback: impl FnOnce(),
    ) -> Result<AuthInitializationRollbackOutcome, AuthStoreBindingError> {
        self.rollback_initialization_pre_source_inner(fault, before_mutation, after_rollback)
    }

    fn rollback_initialization_pre_source_inner<BeforeMutation, AfterRollback>(
        &self,
        #[cfg(test)] fault: Option<AuthInitializationRollbackTestFault>,
        before_mutation: BeforeMutation,
        after_rollback: AfterRollback,
    ) -> Result<AuthInitializationRollbackOutcome, AuthStoreBindingError>
    where
        BeforeMutation: FnOnce(),
        AfterRollback: FnOnce(),
    {
        let mut before_mutation = Some(before_mutation);
        let mut after_rollback = Some(after_rollback);
        let mut filesystem_mutated = false;
        let mut rollback_evidence: Option<PinnedAuthArtifactSnapshot> = None;
        let mut expected_reconciliation = None;

        for _ in 0..5 {
            let (artifacts, reconciliation) =
                self.capture_stable_initialization_reconciliation()?;
            if expected_reconciliation
                .take()
                .is_some_and(|expected| expected != reconciliation)
            {
                return Err(AuthStoreBindingError::Filesystem(
                    SecretFsError::ArtifactChanged,
                ));
            }
            let (phase, recovery) = match reconciliation {
                AuthInitializationReconciliation::CleanUninitialized => {
                    if !filesystem_mutated {
                        return Ok(AuthInitializationRollbackOutcome::AlreadyClean);
                    }

                    after_rollback
                        .take()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?();
                    let rollback_evidence =
                        rollback_evidence
                            .as_ref()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    rollback_evidence
                        .revalidate_completed_cleanup_evidence(&self.locked.layout.secret_fd)?;
                    let (post_artifacts, postcondition) =
                        self.capture_stable_initialization_reconciliation()?;
                    if postcondition != AuthInitializationReconciliation::CleanUninitialized {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    post_artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    rollback_evidence
                        .revalidate_completed_cleanup_evidence(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    return Ok(AuthInitializationRollbackOutcome::RolledBack);
                }
                AuthInitializationReconciliation::InitializePreSource { phase, recovery } => {
                    (phase, recovery)
                }
                _ => {
                    if filesystem_mutated {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    return Ok(AuthInitializationRollbackOutcome::NotRollbackable(
                        reconciliation,
                    ));
                }
            };

            let artifacts = if !filesystem_mutated {
                rollback_evidence = Some(artifacts);
                before_mutation
                    .take()
                    .ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ))?();
                let (verified_artifacts, verified_reconciliation) =
                    self.capture_stable_initialization_reconciliation()?;
                if verified_reconciliation != reconciliation {
                    return Err(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ));
                }
                rollback_evidence
                    .as_ref()
                    .ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ))?
                    .revalidate_pre_source_rollback_progress(
                        &self.locked.layout.secret_fd,
                        &verified_artifacts,
                    )?;
                verified_artifacts
            } else {
                rollback_evidence
                    .as_ref()
                    .ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ))?
                    .revalidate_pre_source_rollback_progress(
                        &self.locked.layout.secret_fd,
                        &artifacts,
                    )?;
                artifacts
            };

            let reservation =
                artifacts
                    .transition_directory()
                    .ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ))?;
            let transition_artifact = match reservation.artifact {
                TopLevelArtifactName::Transition {
                    kind: TransitionKind::Initialize,
                    id,
                } => TopLevelArtifactName::Transition {
                    kind: TransitionKind::Initialize,
                    id,
                },
                _ => {
                    return Err(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ));
                }
            };
            let transition_name = transition_artifact.format();
            if TopLevelArtifactName::parse(transition_name.as_bytes()) != Ok(transition_artifact) {
                return Err(AuthStoreBindingError::Filesystem(
                    SecretFsError::UnsafeAuthArtifact,
                ));
            }
            let parts = RetainedReservationParts::from_directory(reservation);
            artifacts.revalidate(&self.locked.layout.secret_fd)?;
            self.revalidate()?;

            match phase {
                AuthInitializationPreSourcePhase::Prepared => {
                    let prepared = parts.prepared.ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ))?;
                    remove_exact_known_file(
                        &reservation.directory_fd,
                        ReservationEntryName::Prepared.as_str(),
                        KnownFilePurpose::Prepared,
                        prepared.stat,
                        prepared.content.expose(),
                        || {},
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault == Some(AuthInitializationRollbackTestFault::Prepared) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    expected_reconciliation =
                        Some(AuthInitializationReconciliation::InitializePreSource {
                            phase: AuthInitializationPreSourcePhase::StagedComplete,
                            recovery,
                        });
                }
                AuthInitializationPreSourcePhase::StagedIncomplete
                | AuthInitializationPreSourcePhase::StagedComplete => {
                    let staged = parts.staged.map(|(file, _)| file).ok_or(
                        AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
                    )?;
                    remove_exact_known_file(
                        &reservation.directory_fd,
                        ReservationEntryName::StagedKeyring.as_str(),
                        KnownFilePurpose::StagedKeyring,
                        staged.stat,
                        staged.content.expose(),
                        || {},
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault == Some(AuthInitializationRollbackTestFault::Staged) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    expected_reconciliation =
                        Some(AuthInitializationReconciliation::InitializePreSource {
                            phase: AuthInitializationPreSourcePhase::MetadataComplete,
                            recovery: AuthInitializationRecovery::RollbackOnlyCandidate,
                        });
                }
                AuthInitializationPreSourcePhase::MetadataIncomplete
                | AuthInitializationPreSourcePhase::MetadataComplete => {
                    let metadata = parts.metadata.map(|(file, _)| file).ok_or(
                        AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
                    )?;
                    remove_exact_known_file(
                        &reservation.directory_fd,
                        ReservationEntryName::Metadata.as_str(),
                        KnownFilePurpose::Metadata,
                        metadata.stat,
                        metadata.content.expose(),
                        || {},
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault == Some(AuthInitializationRollbackTestFault::Metadata) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    expected_reconciliation =
                        Some(AuthInitializationReconciliation::InitializePreSource {
                            phase: AuthInitializationPreSourcePhase::ReservationOnly,
                            recovery: AuthInitializationRecovery::RollbackOnlyCandidate,
                        });
                }
                AuthInitializationPreSourcePhase::ReservationOnly => {
                    remove_exact_empty_reservation_directory(
                        &self.locked.layout.secret_fd,
                        transition_name.as_str(),
                        reservation,
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault == Some(AuthInitializationRollbackTestFault::Directory) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    expected_reconciliation =
                        Some(AuthInitializationReconciliation::CleanUninitialized);
                }
            }
        }

        Err(AuthStoreBindingError::Filesystem(
            SecretFsError::ArtifactChanged,
        ))
    }

    pub(super) fn commit_initialization_source(
        &self,
    ) -> Result<AuthInitializationSourceOutcome, AuthStoreBindingError> {
        self.commit_initialization_source_inner(
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            || {},
            || {},
        )
    }

    #[cfg(test)]
    pub(super) fn commit_initialization_source_with_test_control(
        &self,
        mutation_fault: Option<AuthInitializationSourceMutationTestFault>,
        durability_fault: Option<AuthInitializationSourceDurabilityTestFault>,
        before_source_mutation: impl FnOnce(),
        after_source_mutation: impl FnOnce(),
    ) -> Result<AuthInitializationSourceOutcome, AuthStoreBindingError> {
        self.commit_initialization_source_inner(
            mutation_fault,
            durability_fault,
            before_source_mutation,
            after_source_mutation,
        )
    }

    fn commit_initialization_source_inner<BeforeSourceMutation, AfterSourceMutation>(
        &self,
        #[cfg(test)] mutation_fault: Option<AuthInitializationSourceMutationTestFault>,
        #[cfg(test)] durability_fault: Option<AuthInitializationSourceDurabilityTestFault>,
        before_source_mutation: BeforeSourceMutation,
        after_source_mutation: AfterSourceMutation,
    ) -> Result<AuthInitializationSourceOutcome, AuthStoreBindingError>
    where
        BeforeSourceMutation: FnOnce(),
        AfterSourceMutation: FnOnce(),
    {
        self.revalidate()?;
        let artifacts = self.locked.capture_secret_artifacts()?;
        let metadata = artifacts.decode_initialization_metadata();
        let expectation = metadata
            .as_ref()
            .map(InitializationMetadataV1::source_expectation);
        let database_a = self
            .conversation
            .inspect_auth_reconciliation(expectation)
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        let database_b = self
            .conversation
            .inspect_auth_reconciliation(expectation)
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        if database_a != database_b {
            return Err(AuthStoreBindingError::ConversationStoreChanged);
        }
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;

        let reconciliation = artifacts.reconcile_initialization(database_a, metadata.as_ref());
        match reconciliation {
            AuthInitializationReconciliation::InitializePreSource {
                phase: AuthInitializationPreSourcePhase::Prepared,
                recovery: AuthInitializationRecovery::RollbackOnlyCandidate,
            } => return Ok(AuthInitializationSourceOutcome::LegacyPrepared),
            AuthInitializationReconciliation::InitializePreSource {
                phase: AuthInitializationPreSourcePhase::Prepared,
                recovery: AuthInitializationRecovery::ResumeOrRollbackCandidate,
            } => {}
            AuthInitializationReconciliation::InitializeForwardOnly(_)
            | AuthInitializationReconciliation::InitializationComplete => {
                return Ok(AuthInitializationSourceOutcome::AlreadyCommitted);
            }
            _ => {
                return Ok(AuthInitializationSourceOutcome::NotPrepared(reconciliation));
            }
        }

        let seed = metadata
            .as_ref()
            .and_then(InitializationMetadataV1::sentinel_source_seed)
            .ok_or(AuthStoreBindingError::Filesystem(
                SecretFsError::UnsafeAuthArtifact,
            ))?;
        self.durabilize_prepared_initialization_evidence(
            &artifacts,
            #[cfg(test)]
            durability_fault,
        )?;
        let (durable_artifacts, durable_reconciliation) =
            self.capture_stable_initialization_reconciliation()?;
        if durable_reconciliation != reconciliation {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        }
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        durable_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        before_source_mutation();
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        #[cfg(test)]
        let mutation = match mutation_fault {
            Some(fault) => self
                .conversation
                .commit_initialization_source_with_test_fault(seed, fault),
            None => self.conversation.commit_initialization_source(seed),
        };
        #[cfg(not(test))]
        let mutation = self.conversation.commit_initialization_source(seed);
        let mutation = mutation.map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        after_source_mutation();
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;

        Ok(match mutation {
            AuthInitializationSourceMutationOutcome::Committed => {
                AuthInitializationSourceOutcome::Committed
            }
            AuthInitializationSourceMutationOutcome::AlreadyCommitted => {
                AuthInitializationSourceOutcome::AlreadyCommitted
            }
            AuthInitializationSourceMutationOutcome::ConfirmedNotCommitted => {
                AuthInitializationSourceOutcome::ConfirmedNotCommitted
            }
            AuthInitializationSourceMutationOutcome::PreconditionChanged => {
                AuthInitializationSourceOutcome::PreconditionChanged
            }
        })
    }

    pub(super) fn install_initialization_active_key(
        &self,
    ) -> Result<AuthInitializationActiveKeyInstallOutcome, AuthStoreBindingError> {
        self.install_initialization_active_key_inner(
            #[cfg(test)]
            None,
            || {},
            || {},
        )
    }

    #[cfg(test)]
    pub(super) fn install_initialization_active_key_with_test_control(
        &self,
        fault: Option<AuthInitializationActiveKeyInstallTestFault>,
        before_publish: impl FnOnce(),
        after_publish: impl FnOnce(),
    ) -> Result<AuthInitializationActiveKeyInstallOutcome, AuthStoreBindingError> {
        self.install_initialization_active_key_inner(fault, before_publish, after_publish)
    }

    fn install_initialization_active_key_inner<BeforePublish, AfterPublish>(
        &self,
        #[cfg(test)] fault: Option<AuthInitializationActiveKeyInstallTestFault>,
        before_publish: BeforePublish,
        after_publish: AfterPublish,
    ) -> Result<AuthInitializationActiveKeyInstallOutcome, AuthStoreBindingError>
    where
        BeforePublish: FnOnce(),
        AfterPublish: FnOnce(),
    {
        let mut before_publish = Some(before_publish);
        let mut after_publish = Some(after_publish);
        let mut filesystem_mutated = false;

        for _ in 0..4 {
            let (artifacts, reconciliation) =
                self.capture_stable_initialization_reconciliation()?;
            let phase = match reconciliation {
                AuthInitializationReconciliation::InitializeForwardOnly(phase) => phase,
                _ => {
                    if filesystem_mutated {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    return Ok(AuthInitializationActiveKeyInstallOutcome::NotInstallable(
                        reconciliation,
                    ));
                }
            };
            if phase.is_cleanup() {
                if filesystem_mutated {
                    return Err(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ));
                }
                return Ok(AuthInitializationActiveKeyInstallOutcome::NotInstallable(
                    reconciliation,
                ));
            }
            let evidence = artifacts.initialization_active_key_evidence().ok_or(
                AuthStoreBindingError::Filesystem(SecretFsError::UnsafeAuthArtifact),
            )?;
            let install_name = TopLevelArtifactName::InstallTemp {
                id: evidence.transition_id,
            }
            .format();
            if TopLevelArtifactName::parse(install_name.as_bytes())
                != Ok(TopLevelArtifactName::InstallTemp {
                    id: evidence.transition_id,
                })
            {
                return Err(AuthStoreBindingError::Filesystem(
                    SecretFsError::UnsafeAuthArtifact,
                ));
            }
            artifacts.revalidate(&self.locked.layout.secret_fd)?;
            self.revalidate()?;

            match phase {
                AuthInitializationForwardPhase::AwaitingInstallTemp => {
                    persist_new_known_file(
                        &self.locked.layout.secret_fd,
                        install_name.as_str(),
                        KnownFilePurpose::InstallTemp,
                        evidence.staged.content.expose(),
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault
                        == Some(AuthInitializationActiveKeyInstallTestFault::InstallTempDurable)
                    {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthInitializationForwardPhase::InstallTempPrefix => {
                    let install =
                        artifacts
                            .install_file()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let install_bytes = install.content.expose();
                    let staged_bytes = evidence.staged.content.expose();
                    if install_bytes.len() >= staged_bytes.len()
                        || !staged_bytes.starts_with(install_bytes)
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    remove_exact_known_file(
                        &self.locked.layout.secret_fd,
                        install_name.as_str(),
                        KnownFilePurpose::InstallTemp,
                        install.stat,
                        install_bytes,
                        || {},
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault == Some(AuthInitializationActiveKeyInstallTestFault::PrefixRemoved) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthInitializationForwardPhase::InstallTempExact => {
                    let install =
                        artifacts
                            .install_file()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    durabilize_existing_known_file(
                        &self.locked.layout.secret_fd,
                        install_name.as_str(),
                        KnownFilePurpose::InstallTemp,
                        install.stat,
                        evidence.staged.content.expose(),
                    )?;

                    let (publish_artifacts, publish_reconciliation) =
                        self.capture_stable_initialization_reconciliation()?;
                    if publish_reconciliation
                        != AuthInitializationReconciliation::InitializeForwardOnly(
                            AuthInitializationForwardPhase::InstallTempExact,
                        )
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    let Some(publish_evidence) =
                        publish_artifacts.initialization_active_key_evidence()
                    else {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::UnsafeAuthArtifact,
                        ));
                    };
                    let publish_install = publish_artifacts.install_file().ok_or(
                        AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
                    )?;
                    publish_artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    publish_install_temp_no_replace(
                        &self.locked.layout.secret_fd,
                        install_name.as_str(),
                        publish_install.stat,
                        publish_evidence.staged.content.expose(),
                        before_publish
                            .take()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?,
                    )?;
                    #[cfg(test)]
                    if fault == Some(AuthInitializationActiveKeyInstallTestFault::PublishDurable) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    after_publish
                        .take()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?();
                    let (_, postcondition) = self.capture_stable_initialization_reconciliation()?;
                    if postcondition
                        != AuthInitializationReconciliation::InitializeForwardOnly(
                            AuthInitializationForwardPhase::AwaitingFinalDbCas,
                        )
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    return Ok(
                        AuthInitializationActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas,
                    );
                }
                AuthInitializationForwardPhase::AwaitingFinalDbCas => {
                    let active =
                        artifacts
                            .active_file()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    durabilize_existing_known_file(
                        &self.locked.layout.secret_fd,
                        ACTIVE_KEYRING_NAME,
                        KnownFilePurpose::ActiveKeyring,
                        active.stat,
                        evidence.staged.content.expose(),
                    )?;
                    let (_, postcondition) = self.capture_stable_initialization_reconciliation()?;
                    if postcondition
                        != AuthInitializationReconciliation::InitializeForwardOnly(
                            AuthInitializationForwardPhase::AwaitingFinalDbCas,
                        )
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    return Ok(
                        AuthInitializationActiveKeyInstallOutcome::AlreadyAwaitingFinalDbCas,
                    );
                }
                AuthInitializationForwardPhase::AwaitingCleanupRename
                | AuthInitializationForwardPhase::AwaitingCleanupStagedRemoval
                | AuthInitializationForwardPhase::AwaitingCleanupPreparedRemoval
                | AuthInitializationForwardPhase::AwaitingCleanupMetadataRemoval
                | AuthInitializationForwardPhase::AwaitingCleanupDirectoryRemoval => {
                    return Err(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ));
                }
            }
        }
        Err(AuthStoreBindingError::Filesystem(
            SecretFsError::ArtifactChanged,
        ))
    }

    pub(super) fn commit_initialization_final_lifecycle(
        &self,
    ) -> Result<AuthInitializationFinalLifecycleOutcome, AuthStoreBindingError> {
        self.commit_initialization_final_lifecycle_inner(
            #[cfg(test)]
            None,
            || {},
            || {},
        )
    }

    #[cfg(test)]
    pub(super) fn commit_initialization_final_lifecycle_with_test_control(
        &self,
        fault: Option<AuthInitializationFinalLifecycleMutationTestFault>,
        before_mutation: impl FnOnce(),
        after_mutation: impl FnOnce(),
    ) -> Result<AuthInitializationFinalLifecycleOutcome, AuthStoreBindingError> {
        self.commit_initialization_final_lifecycle_inner(fault, before_mutation, after_mutation)
    }

    fn commit_initialization_final_lifecycle_inner<BeforeMutation, AfterMutation>(
        &self,
        #[cfg(test)] fault: Option<AuthInitializationFinalLifecycleMutationTestFault>,
        before_mutation: BeforeMutation,
        after_mutation: AfterMutation,
    ) -> Result<AuthInitializationFinalLifecycleOutcome, AuthStoreBindingError>
    where
        BeforeMutation: FnOnce(),
        AfterMutation: FnOnce(),
    {
        let (artifacts, reconciliation) = self.capture_stable_initialization_reconciliation()?;
        let expected_phase = match reconciliation {
            AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::AwaitingFinalDbCas,
            ) => AuthInitializationForwardPhase::AwaitingFinalDbCas,
            AuthInitializationReconciliation::InitializeForwardOnly(
                AuthInitializationForwardPhase::AwaitingCleanupRename,
            ) => AuthInitializationForwardPhase::AwaitingCleanupRename,
            _ => {
                return Ok(AuthInitializationFinalLifecycleOutcome::NotActivatable(
                    reconciliation,
                ));
            }
        };
        let evidence = artifacts.initialization_active_key_evidence().ok_or(
            AuthStoreBindingError::Filesystem(SecretFsError::UnsafeAuthArtifact),
        )?;
        let active = artifacts
            .active_file()
            .ok_or(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ))?;
        durabilize_existing_known_file(
            &self.locked.layout.secret_fd,
            ACTIVE_KEYRING_NAME,
            KnownFilePurpose::ActiveKeyring,
            active.stat,
            evidence.staged.content.expose(),
        )?;

        let (cas_artifacts, cas_reconciliation) =
            self.capture_stable_initialization_reconciliation()?;
        if cas_reconciliation
            != AuthInitializationReconciliation::InitializeForwardOnly(expected_phase)
        {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        }
        if expected_phase == AuthInitializationForwardPhase::AwaitingCleanupRename {
            return Ok(AuthInitializationFinalLifecycleOutcome::AlreadyActivatedAwaitingCleanup);
        }
        let metadata = cas_artifacts.decode_initialization_metadata().ok_or(
            AuthStoreBindingError::Filesystem(SecretFsError::UnsafeAuthArtifact),
        )?;
        let expectation = metadata.source_expectation();

        before_mutation();
        cas_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        #[cfg(test)]
        let mutation = match fault {
            Some(fault) => self
                .conversation
                .commit_initialization_final_lifecycle_with_test_fault(expectation, fault),
            None => self
                .conversation
                .commit_initialization_final_lifecycle(expectation),
        };
        #[cfg(not(test))]
        let mutation = self
            .conversation
            .commit_initialization_final_lifecycle(expectation);
        let mutation = mutation.map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        after_mutation();
        cas_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;

        let (_, postcondition) = self.capture_stable_initialization_reconciliation()?;
        match mutation {
            AuthInitializationFinalLifecycleMutationOutcome::Committed => {
                if postcondition
                    != AuthInitializationReconciliation::InitializeForwardOnly(
                        AuthInitializationForwardPhase::AwaitingCleanupRename,
                    )
                {
                    return Err(AuthStoreBindingError::ConversationStoreChanged);
                }
                Ok(AuthInitializationFinalLifecycleOutcome::ActivatedAwaitingCleanup)
            }
            AuthInitializationFinalLifecycleMutationOutcome::AlreadyCommitted => {
                if postcondition
                    != AuthInitializationReconciliation::InitializeForwardOnly(
                        AuthInitializationForwardPhase::AwaitingCleanupRename,
                    )
                {
                    return Err(AuthStoreBindingError::ConversationStoreChanged);
                }
                Ok(AuthInitializationFinalLifecycleOutcome::AlreadyActivatedAwaitingCleanup)
            }
            AuthInitializationFinalLifecycleMutationOutcome::ConfirmedNotCommitted => {
                if postcondition
                    != AuthInitializationReconciliation::InitializeForwardOnly(
                        AuthInitializationForwardPhase::AwaitingFinalDbCas,
                    )
                {
                    return Err(AuthStoreBindingError::ConversationStoreChanged);
                }
                Ok(AuthInitializationFinalLifecycleOutcome::ConfirmedNotActivated)
            }
            AuthInitializationFinalLifecycleMutationOutcome::PreconditionChanged => {
                Err(AuthStoreBindingError::ConversationStoreChanged)
            }
        }
    }

    pub(super) fn cleanup_initialization(
        &self,
    ) -> Result<AuthInitializationCleanupOutcome, AuthStoreBindingError> {
        self.cleanup_initialization_inner(
            #[cfg(test)]
            None,
            || {},
            || {},
        )
    }

    #[cfg(test)]
    pub(super) fn cleanup_initialization_with_test_control(
        &self,
        fault: Option<AuthInitializationCleanupTestFault>,
        before_rename: impl FnOnce(),
        after_cleanup: impl FnOnce(),
    ) -> Result<AuthInitializationCleanupOutcome, AuthStoreBindingError> {
        self.cleanup_initialization_inner(fault, before_rename, after_cleanup)
    }

    fn cleanup_initialization_inner<BeforeRename, AfterCleanup>(
        &self,
        #[cfg(test)] fault: Option<AuthInitializationCleanupTestFault>,
        before_rename: BeforeRename,
        after_cleanup: AfterCleanup,
    ) -> Result<AuthInitializationCleanupOutcome, AuthStoreBindingError>
    where
        BeforeRename: FnOnce(),
        AfterCleanup: FnOnce(),
    {
        let mut before_rename = Some(before_rename);
        let mut after_cleanup = Some(after_cleanup);
        let mut retained_artifacts = None;
        let mut retained_metadata = None;
        let mut retained_database = None;
        let mut filesystem_mutated = false;

        for _ in 0..7 {
            let (artifacts, reconciliation, database) =
                self.capture_stable_initialization_reconciliation_observed()?;
            if let (Some(metadata), Some(expected_database)) =
                (retained_metadata.as_ref(), retained_database)
            {
                self.revalidate_retained_initialization_source(
                    &artifacts,
                    metadata,
                    expected_database,
                )?;
            }
            let captured_metadata = artifacts.decode_initialization_metadata();
            if matches!(
                reconciliation,
                AuthInitializationReconciliation::InitializeForwardOnly(phase)
                    if phase.is_cleanup()
                        && phase
                            != AuthInitializationForwardPhase::AwaitingCleanupDirectoryRemoval
            ) && retained_metadata.is_none()
            {
                let metadata =
                    captured_metadata
                        .as_ref()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::UnsafeAuthArtifact,
                        ))?;
                self.revalidate_retained_initialization_source(&artifacts, metadata, database)?;
            }

            match reconciliation {
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingCleanupRename,
                ) => {
                    let reservation = artifacts.transition_directory().ok_or(
                        AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
                    )?;
                    let (kind, id) = match reservation.artifact {
                        TopLevelArtifactName::Transition {
                            kind: TransitionKind::Initialize,
                            id,
                        } => (TransitionKind::Initialize, id),
                        _ => {
                            return Err(AuthStoreBindingError::Filesystem(
                                SecretFsError::UnsafeAuthArtifact,
                            ));
                        }
                    };
                    let transition_artifact = TopLevelArtifactName::Transition { kind, id };
                    let cleanup_artifact = TopLevelArtifactName::Cleanup { kind, id };
                    let transition_name = transition_artifact.format();
                    let cleanup_name = cleanup_artifact.format();
                    if TopLevelArtifactName::parse(transition_name.as_bytes())
                        != Ok(transition_artifact)
                        || TopLevelArtifactName::parse(cleanup_name.as_bytes())
                            != Ok(cleanup_artifact)
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::UnsafeAuthArtifact,
                        ));
                    }
                    before_rename
                        .take()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?();
                    let metadata =
                        captured_metadata
                            .as_ref()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::UnsafeAuthArtifact,
                            ))?;
                    self.revalidate_retained_initialization_source(&artifacts, metadata, database)?;
                    artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    rename_exact_reservation_to_cleanup_no_replace(
                        &self.locked.layout.secret_fd,
                        transition_name.as_str(),
                        cleanup_name.as_str(),
                        reservation,
                    )?;
                    filesystem_mutated = true;
                    retain_initialization_cleanup_evidence(
                        &mut retained_artifacts,
                        &mut retained_metadata,
                        &mut retained_database,
                        artifacts,
                        captured_metadata,
                        database,
                    )?;
                    #[cfg(test)]
                    if fault == Some(AuthInitializationCleanupTestFault::Rename) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingCleanupStagedRemoval,
                ) => {
                    let cleanup =
                        artifacts
                            .cleanup_directory()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let parts = RetainedReservationParts::from_directory(cleanup);
                    let (staged, CodecObservation::Valid) = parts.staged.ok_or(
                        AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
                    )?
                    else {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    };
                    artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    remove_exact_known_file(
                        &cleanup.directory_fd,
                        ReservationEntryName::StagedKeyring.as_str(),
                        KnownFilePurpose::StagedKeyring,
                        staged.stat,
                        staged.content.expose(),
                        || {},
                    )?;
                    filesystem_mutated = true;
                    retain_initialization_cleanup_evidence(
                        &mut retained_artifacts,
                        &mut retained_metadata,
                        &mut retained_database,
                        artifacts,
                        captured_metadata,
                        database,
                    )?;
                    #[cfg(test)]
                    if fault == Some(AuthInitializationCleanupTestFault::Staged) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingCleanupPreparedRemoval,
                ) => {
                    let cleanup =
                        artifacts
                            .cleanup_directory()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let prepared = RetainedReservationParts::from_directory(cleanup)
                        .prepared
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?;
                    artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    remove_exact_known_file(
                        &cleanup.directory_fd,
                        ReservationEntryName::Prepared.as_str(),
                        KnownFilePurpose::Prepared,
                        prepared.stat,
                        prepared.content.expose(),
                        || {},
                    )?;
                    filesystem_mutated = true;
                    retain_initialization_cleanup_evidence(
                        &mut retained_artifacts,
                        &mut retained_metadata,
                        &mut retained_database,
                        artifacts,
                        captured_metadata,
                        database,
                    )?;
                    #[cfg(test)]
                    if fault == Some(AuthInitializationCleanupTestFault::Prepared) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingCleanupMetadataRemoval,
                ) => {
                    let cleanup =
                        artifacts
                            .cleanup_directory()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let (metadata_file, CodecObservation::Valid) =
                        RetainedReservationParts::from_directory(cleanup)
                            .metadata
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?
                    else {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    };
                    artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    remove_exact_known_file(
                        &cleanup.directory_fd,
                        ReservationEntryName::Metadata.as_str(),
                        KnownFilePurpose::Metadata,
                        metadata_file.stat,
                        metadata_file.content.expose(),
                        || {},
                    )?;
                    filesystem_mutated = true;
                    retain_initialization_cleanup_evidence(
                        &mut retained_artifacts,
                        &mut retained_metadata,
                        &mut retained_database,
                        artifacts,
                        captured_metadata,
                        database,
                    )?;
                    #[cfg(test)]
                    if fault == Some(AuthInitializationCleanupTestFault::Metadata) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthInitializationReconciliation::InitializeForwardOnly(
                    AuthInitializationForwardPhase::AwaitingCleanupDirectoryRemoval,
                ) => {
                    let cleanup =
                        artifacts
                            .cleanup_directory()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let (kind, id) = match cleanup.artifact {
                        TopLevelArtifactName::Cleanup {
                            kind: TransitionKind::Initialize,
                            id,
                        } => (TransitionKind::Initialize, id),
                        _ => {
                            return Err(AuthStoreBindingError::Filesystem(
                                SecretFsError::UnsafeAuthArtifact,
                            ));
                        }
                    };
                    let cleanup_artifact = TopLevelArtifactName::Cleanup { kind, id };
                    let cleanup_name = cleanup_artifact.format();
                    if TopLevelArtifactName::parse(cleanup_name.as_bytes()) != Ok(cleanup_artifact)
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::UnsafeAuthArtifact,
                        ));
                    }
                    artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    remove_exact_empty_reservation_directory(
                        &self.locked.layout.secret_fd,
                        cleanup_name.as_str(),
                        cleanup,
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault == Some(AuthInitializationCleanupTestFault::Directory) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthInitializationReconciliation::InitializationComplete => {
                    let active =
                        artifacts
                            .active_file()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    durabilize_existing_known_file(
                        &self.locked.layout.secret_fd,
                        ACTIVE_KEYRING_NAME,
                        KnownFilePurpose::ActiveKeyring,
                        active.stat,
                        active.content.expose(),
                    )?;
                    if !filesystem_mutated {
                        let (_, postcondition) =
                            self.capture_stable_initialization_reconciliation()?;
                        if postcondition != AuthInitializationReconciliation::InitializationComplete
                        {
                            return Err(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ));
                        }
                        return Ok(AuthInitializationCleanupOutcome::AlreadyCompleted);
                    }

                    after_cleanup
                        .take()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?();
                    let (terminal_artifacts, terminal_reconciliation, _) =
                        self.capture_stable_initialization_reconciliation_observed()?;
                    if terminal_reconciliation
                        != AuthInitializationReconciliation::InitializationComplete
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    if let (Some(metadata), Some(expected_database)) =
                        (retained_metadata.as_ref(), retained_database)
                    {
                        self.revalidate_retained_initialization_source(
                            &terminal_artifacts,
                            metadata,
                            expected_database,
                        )?;
                    }
                    if let Some(retained) = retained_artifacts.as_ref() {
                        retained
                            .revalidate_completed_cleanup_evidence(&self.locked.layout.secret_fd)?;
                    }
                    terminal_artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    return Ok(AuthInitializationCleanupOutcome::Completed);
                }
                _ => {
                    if filesystem_mutated {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    return Ok(AuthInitializationCleanupOutcome::NotCleanable(
                        reconciliation,
                    ));
                }
            }
        }
        Err(AuthStoreBindingError::Filesystem(
            SecretFsError::ArtifactChanged,
        ))
    }

    fn revalidate_retained_initialization_source(
        &self,
        artifacts: &PinnedAuthArtifactSnapshot,
        metadata: &InitializationMetadataV1,
        expected: AuthDatabaseReconciliationObservation,
    ) -> Result<(), AuthStoreBindingError> {
        self.revalidate()?;
        let expectation = metadata.source_expectation();
        let database_a = self
            .conversation
            .inspect_auth_reconciliation(Some(expectation))
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        let database_b = self
            .conversation
            .inspect_auth_reconciliation(Some(expectation))
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        if database_a != database_b
            || database_a != expected
            || database_a.source != AuthInitializationSourceMatch::Exact
            || database_a.source_fingerprint.is_none()
        {
            return Err(AuthStoreBindingError::ConversationStoreChanged);
        }
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        Ok(())
    }

    fn capture_stable_planned_rotation_reconciliation(
        &self,
    ) -> Result<
        (
            PinnedAuthArtifactSnapshot,
            AuthPlannedRotationReconciliation,
            AuthPlannedRotationDatabaseObservation,
        ),
        AuthStoreBindingError,
    > {
        self.revalidate()?;
        let artifacts = self.locked.capture_secret_artifacts()?;
        let metadata = artifacts.decode_planned_rotation_metadata();
        let expectation = metadata
            .as_ref()
            .map(PlannedRotationMetadataV1::source_expectation);
        let database_a = self
            .conversation
            .inspect_auth_planned_rotation(expectation)
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        let database_b = self
            .conversation
            .inspect_auth_planned_rotation(expectation)
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        if database_a != database_b {
            return Err(AuthStoreBindingError::ConversationStoreChanged);
        }
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        let reconciliation = artifacts.reconcile_planned_rotation(database_a, metadata.as_ref());
        Ok((artifacts, reconciliation, database_a))
    }

    fn capture_stable_retire_reconciliation(
        &self,
    ) -> Result<
        (
            PinnedAuthArtifactSnapshot,
            AuthRetireReconciliation,
            AuthPlannedRotationDatabaseObservation,
        ),
        AuthStoreBindingError,
    > {
        self.revalidate()?;
        let artifacts = self.locked.capture_secret_artifacts()?;
        let metadata = artifacts.decode_retire_metadata();
        let expectation = metadata.as_ref().map(RetireMetadataV1::source_expectation);
        let database_a = self
            .conversation
            .inspect_auth_retire(expectation)
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        let database_b = self
            .conversation
            .inspect_auth_retire(expectation)
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        if database_a != database_b {
            return Err(AuthStoreBindingError::ConversationStoreChanged);
        }
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        let reconciliation = artifacts.reconcile_retire(database_a, metadata.as_ref());
        Ok((artifacts, reconciliation, database_a))
    }

    fn capture_planned_rotation_preparation_precondition(
        &self,
        preparation: &PlannedRotationPreparationV1,
    ) -> Result<(PinnedAuthArtifactSnapshot, bool), AuthStoreBindingError> {
        self.revalidate()?;
        let artifacts = self.locked.capture_secret_artifacts()?;
        let expectation = preparation.source_expectation();
        let database_a = self
            .conversation
            .inspect_auth_planned_rotation(Some(expectation))
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        let database_b = self
            .conversation
            .inspect_auth_planned_rotation(Some(expectation))
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        if database_a != database_b {
            return Err(AuthStoreBindingError::ConversationStoreChanged);
        }
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        let exact = matches!(
            database_a.lifecycle,
            AuthDatabaseLifecycleObservation::Active(lifecycle)
                if artifacts.active_matches_current_lifecycle(lifecycle)
        ) && database_a.source == AuthPlannedRotationSourceMatch::Exact
            && database_a.source_fingerprint.is_some()
            && artifacts.is_clean_active_namespace()
            && artifacts.active_matches_planned_expectation(expectation);
        Ok((artifacts, exact))
    }

    fn capture_retire_preparation_precondition(
        &self,
        preparation: &RetirePreparationV1,
    ) -> Result<(PinnedAuthArtifactSnapshot, bool), AuthStoreBindingError> {
        self.revalidate()?;
        let artifacts = self.locked.capture_secret_artifacts()?;
        let expectation = preparation.source_expectation();
        let database_a = self
            .conversation
            .inspect_auth_retire(Some(expectation))
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        let database_b = self
            .conversation
            .inspect_auth_retire(Some(expectation))
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        if database_a != database_b {
            return Err(AuthStoreBindingError::ConversationStoreChanged);
        }
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        let active = artifacts.active_file();
        let exact = matches!(
            database_a.lifecycle,
            AuthDatabaseLifecycleObservation::Active(lifecycle)
                if artifacts.active_matches_any_lifecycle(lifecycle)
        ) && database_a.source == AuthPlannedRotationSourceMatch::Exact
            && database_a.source_fingerprint.is_some()
            && artifacts.is_terminal_active_namespace()
            && active
                .is_some_and(|active| preparation.matches_current_keyring(active.content.expose()));
        Ok((artifacts, exact))
    }

    fn planned_rotation_database_unchanged(
        expected: AuthPlannedRotationDatabaseObservation,
        current: AuthPlannedRotationDatabaseObservation,
    ) -> bool {
        expected.lifecycle == current.lifecycle
            && expected.source_fingerprint.is_some()
            && expected.source_fingerprint == current.source_fingerprint
            && matches!(
                current.source,
                AuthPlannedRotationSourceMatch::Canonical | AuthPlannedRotationSourceMatch::Exact
            )
    }

    #[cfg(test)]
    pub(super) fn prepare_planned_rotation_with_test_control(
        &self,
        preparation: &PlannedRotationPreparationV1,
        fault: Option<AuthPlannedRotationPrepareTestFault>,
        after_outer_precondition: impl FnOnce(),
    ) -> Result<AuthPlannedRotationPrepareOutcome, AuthStoreBindingError> {
        self.prepare_planned_rotation_inner(preparation, fault, after_outer_precondition)
    }

    fn prepare_planned_rotation_inner<AfterOuterPrecondition>(
        &self,
        preparation: &PlannedRotationPreparationV1,
        #[cfg(test)] fault: Option<AuthPlannedRotationPrepareTestFault>,
        after_outer_precondition: AfterOuterPrecondition,
    ) -> Result<AuthPlannedRotationPrepareOutcome, AuthStoreBindingError>
    where
        AfterOuterPrecondition: FnOnce(),
    {
        let (existing, reconciliation, _) =
            self.capture_stable_planned_rotation_reconciliation()?;
        if reconciliation
            == (AuthPlannedRotationReconciliation::PlannedPreSource {
                phase: AuthPlannedRotationPreSourcePhase::Prepared,
                recovery: AuthPlannedRotationRecovery::ResumeOrRollbackCandidate,
            })
            && existing.matches_planned_preparation(preparation)?
        {
            return Ok(AuthPlannedRotationPrepareOutcome::AlreadyPrepared);
        }
        if reconciliation != AuthPlannedRotationReconciliation::CleanActive {
            return Ok(AuthPlannedRotationPrepareOutcome::PreconditionNotClean(
                reconciliation,
            ));
        }

        let (outer_artifacts, exact_outer) =
            self.capture_planned_rotation_preparation_precondition(preparation)?;
        if !exact_outer {
            return Ok(AuthPlannedRotationPrepareOutcome::PreconditionNotClean(
                AuthPlannedRotationReconciliation::Blocked(
                    AuthPlannedRotationBlocker::InconsistentDbFilesystem,
                ),
            ));
        }
        after_outer_precondition();

        let (verified_artifacts, exact_verified) =
            self.capture_planned_rotation_preparation_precondition(preparation)?;
        if !exact_verified {
            return Ok(AuthPlannedRotationPrepareOutcome::PreconditionNotClean(
                AuthPlannedRotationReconciliation::Blocked(
                    AuthPlannedRotationBlocker::InconsistentDbFilesystem,
                ),
            ));
        }
        outer_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        verified_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;

        let persistence = self.locked.persist_planned_rotation_preparation(
            preparation,
            #[cfg(test)]
            fault,
        )?;
        if persistence == AuthPlannedRotationPersistenceOutcome::PreconditionNotClean {
            let (_, observed, _) = self.capture_stable_planned_rotation_reconciliation()?;
            if observed == AuthPlannedRotationReconciliation::CleanActive {
                return Err(AuthStoreBindingError::Filesystem(
                    SecretFsError::ArtifactChanged,
                ));
            }
            return Ok(AuthPlannedRotationPrepareOutcome::PreconditionNotClean(
                observed,
            ));
        }
        let (readback_artifacts, readback, _) =
            self.capture_stable_planned_rotation_reconciliation()?;
        let expected = AuthPlannedRotationReconciliation::PlannedPreSource {
            phase: AuthPlannedRotationPreSourcePhase::Prepared,
            recovery: AuthPlannedRotationRecovery::ResumeOrRollbackCandidate,
        };
        if readback != expected || !readback_artifacts.matches_planned_preparation(preparation)? {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        }
        self.revalidate()?;
        Ok(AuthPlannedRotationPrepareOutcome::Prepared)
    }

    #[cfg(test)]
    pub(super) fn prepare_retire_with_test_control(
        &self,
        preparation: &RetirePreparationV1,
        fault: Option<AuthRetirePrepareTestFault>,
        after_outer_precondition: impl FnOnce(),
    ) -> Result<AuthRetirePrepareOutcome, AuthStoreBindingError> {
        self.prepare_retire_inner(preparation, fault, after_outer_precondition)
    }

    fn prepare_retire_inner<AfterOuterPrecondition>(
        &self,
        preparation: &RetirePreparationV1,
        #[cfg(test)] fault: Option<AuthRetirePrepareTestFault>,
        after_outer_precondition: AfterOuterPrecondition,
    ) -> Result<AuthRetirePrepareOutcome, AuthStoreBindingError>
    where
        AfterOuterPrecondition: FnOnce(),
    {
        let (existing, reconciliation, _) = self.capture_stable_retire_reconciliation()?;
        if reconciliation
            == (AuthRetireReconciliation::RetirePreSource {
                phase: AuthRetirePreSourcePhase::Prepared,
                recovery: AuthRetireRecovery::ResumeOrRollbackCandidate,
            })
            && existing.matches_retire_preparation(preparation)?
        {
            return Ok(AuthRetirePrepareOutcome::AlreadyPrepared);
        }
        if reconciliation != AuthRetireReconciliation::ReadyToRetire {
            return Ok(AuthRetirePrepareOutcome::PreconditionNotReady(
                reconciliation,
            ));
        }

        let (outer_artifacts, exact_outer) =
            self.capture_retire_preparation_precondition(preparation)?;
        if !exact_outer {
            return Ok(AuthRetirePrepareOutcome::PreconditionNotReady(
                AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem),
            ));
        }
        after_outer_precondition();

        let (verified_artifacts, exact_verified) =
            self.capture_retire_preparation_precondition(preparation)?;
        if !exact_verified {
            return Ok(AuthRetirePrepareOutcome::PreconditionNotReady(
                AuthRetireReconciliation::Blocked(AuthRetireBlocker::InconsistentDbFilesystem),
            ));
        }
        outer_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        verified_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;

        let persistence = self.locked.persist_retire_preparation(
            preparation,
            #[cfg(test)]
            fault,
        )?;
        if persistence == AuthRetirePersistenceOutcome::PreconditionNotReady {
            let (_, observed, _) = self.capture_stable_retire_reconciliation()?;
            if observed == AuthRetireReconciliation::ReadyToRetire {
                return Err(AuthStoreBindingError::Filesystem(
                    SecretFsError::ArtifactChanged,
                ));
            }
            return Ok(AuthRetirePrepareOutcome::PreconditionNotReady(observed));
        }
        let (readback_artifacts, readback, _) = self.capture_stable_retire_reconciliation()?;
        let expected = AuthRetireReconciliation::RetirePreSource {
            phase: AuthRetirePreSourcePhase::Prepared,
            recovery: AuthRetireRecovery::ResumeOrRollbackCandidate,
        };
        if readback != expected || !readback_artifacts.matches_retire_preparation(preparation)? {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        }
        self.revalidate()?;
        Ok(AuthRetirePrepareOutcome::Prepared)
    }

    #[cfg(test)]
    pub(super) fn rollback_planned_rotation_pre_source_with_test_control(
        &self,
        fault: Option<AuthPlannedRotationRollbackTestFault>,
        before_mutation: impl FnOnce(),
        after_first_mutation: impl FnOnce(),
        after_rollback: impl FnOnce(),
    ) -> Result<AuthPlannedRotationRollbackOutcome, AuthStoreBindingError> {
        self.rollback_planned_rotation_pre_source_inner(
            fault,
            before_mutation,
            after_first_mutation,
            after_rollback,
        )
    }

    fn rollback_planned_rotation_pre_source_inner<
        BeforeMutation,
        AfterFirstMutation,
        AfterRollback,
    >(
        &self,
        #[cfg(test)] fault: Option<AuthPlannedRotationRollbackTestFault>,
        before_mutation: BeforeMutation,
        after_first_mutation: AfterFirstMutation,
        after_rollback: AfterRollback,
    ) -> Result<AuthPlannedRotationRollbackOutcome, AuthStoreBindingError>
    where
        BeforeMutation: FnOnce(),
        AfterFirstMutation: FnOnce(),
        AfterRollback: FnOnce(),
    {
        let mut before_mutation = Some(before_mutation);
        let mut after_first_mutation = Some(after_first_mutation);
        let mut after_rollback = Some(after_rollback);
        let mut filesystem_mutated = false;
        let mut rollback_evidence: Option<PinnedAuthArtifactSnapshot> = None;
        let mut database_evidence: Option<AuthPlannedRotationDatabaseObservation> = None;
        let mut expected_reconciliation = None;

        for _ in 0..5 {
            let (artifacts, reconciliation, database) =
                self.capture_stable_planned_rotation_reconciliation()?;
            if expected_reconciliation
                .take()
                .is_some_and(|expected| expected != reconciliation)
            {
                return Err(AuthStoreBindingError::Filesystem(
                    SecretFsError::ArtifactChanged,
                ));
            }
            if let Some(expected_database) = database_evidence
                && !Self::planned_rotation_database_unchanged(expected_database, database)
            {
                if filesystem_mutated {
                    return Err(AuthStoreBindingError::ConversationStoreChanged);
                }
                return Ok(AuthPlannedRotationRollbackOutcome::NotRollbackable(
                    reconciliation,
                ));
            }

            let (phase, recovery) = match reconciliation {
                AuthPlannedRotationReconciliation::CleanActive => {
                    if !filesystem_mutated {
                        return Ok(AuthPlannedRotationRollbackOutcome::AlreadyClean);
                    }
                    after_rollback
                        .take()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?();
                    let rollback_evidence =
                        rollback_evidence
                            .as_ref()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    rollback_evidence
                        .revalidate_completed_cleanup_evidence(&self.locked.layout.secret_fd)?;
                    let (terminal_artifacts, terminal, terminal_database) =
                        self.capture_stable_planned_rotation_reconciliation()?;
                    if terminal != AuthPlannedRotationReconciliation::CleanActive
                        || !Self::planned_rotation_database_unchanged(
                            database_evidence
                                .ok_or(AuthStoreBindingError::ConversationStoreChanged)?,
                            terminal_database,
                        )
                    {
                        return Err(AuthStoreBindingError::ConversationStoreChanged);
                    }
                    terminal_artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    rollback_evidence
                        .revalidate_completed_cleanup_evidence(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    return Ok(AuthPlannedRotationRollbackOutcome::RolledBack);
                }
                AuthPlannedRotationReconciliation::PlannedPreSource { phase, recovery } => {
                    (phase, recovery)
                }
                _ => {
                    if filesystem_mutated {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    return Ok(AuthPlannedRotationRollbackOutcome::NotRollbackable(
                        reconciliation,
                    ));
                }
            };

            let artifacts = if !filesystem_mutated {
                database_evidence = Some(database);
                rollback_evidence = Some(artifacts);
                before_mutation
                    .take()
                    .ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ))?();
                let (verified_artifacts, verified, verified_database) =
                    self.capture_stable_planned_rotation_reconciliation()?;
                if verified != reconciliation
                    || !Self::planned_rotation_database_unchanged(database, verified_database)
                {
                    return Ok(AuthPlannedRotationRollbackOutcome::NotRollbackable(
                        verified,
                    ));
                }
                rollback_evidence
                    .as_ref()
                    .ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ))?
                    .revalidate_planned_rotation_rollback_progress(
                        &self.locked.layout.secret_fd,
                        &verified_artifacts,
                    )?;
                verified_artifacts
            } else {
                rollback_evidence
                    .as_ref()
                    .ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ))?
                    .revalidate_planned_rotation_rollback_progress(
                        &self.locked.layout.secret_fd,
                        &artifacts,
                    )?;
                artifacts
            };

            let reservation =
                artifacts
                    .transition_directory()
                    .ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ))?;
            let transition_artifact = match reservation.artifact {
                TopLevelArtifactName::Transition {
                    kind: TransitionKind::Planned,
                    id,
                } => TopLevelArtifactName::Transition {
                    kind: TransitionKind::Planned,
                    id,
                },
                _ => {
                    return Err(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ));
                }
            };
            let transition_name = transition_artifact.format();
            if TopLevelArtifactName::parse(transition_name.as_bytes()) != Ok(transition_artifact) {
                return Err(AuthStoreBindingError::Filesystem(
                    SecretFsError::UnsafeAuthArtifact,
                ));
            }
            let parts = RetainedReservationParts::from_directory(reservation);
            artifacts.revalidate(&self.locked.layout.secret_fd)?;
            self.revalidate()?;

            match phase {
                AuthPlannedRotationPreSourcePhase::Prepared => {
                    let prepared = parts.prepared.ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ))?;
                    remove_exact_known_file(
                        &reservation.directory_fd,
                        ReservationEntryName::Prepared.as_str(),
                        KnownFilePurpose::Prepared,
                        prepared.stat,
                        prepared.content.expose(),
                        || {},
                    )?;
                    if !filesystem_mutated {
                        filesystem_mutated = true;
                        after_first_mutation
                            .take()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?();
                    }
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationRollbackTestFault::Prepared) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    expected_reconciliation =
                        Some(AuthPlannedRotationReconciliation::PlannedPreSource {
                            phase: AuthPlannedRotationPreSourcePhase::StagedComplete,
                            recovery,
                        });
                }
                AuthPlannedRotationPreSourcePhase::StagedIncomplete
                | AuthPlannedRotationPreSourcePhase::StagedComplete => {
                    let staged = parts.staged.map(|(file, _)| file).ok_or(
                        AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
                    )?;
                    remove_exact_known_file(
                        &reservation.directory_fd,
                        ReservationEntryName::StagedKeyring.as_str(),
                        KnownFilePurpose::StagedKeyring,
                        staged.stat,
                        staged.content.expose(),
                        || {},
                    )?;
                    if !filesystem_mutated {
                        filesystem_mutated = true;
                        after_first_mutation
                            .take()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?();
                    }
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationRollbackTestFault::Staged) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    expected_reconciliation =
                        Some(AuthPlannedRotationReconciliation::PlannedPreSource {
                            phase: AuthPlannedRotationPreSourcePhase::MetadataComplete,
                            recovery: AuthPlannedRotationRecovery::RollbackOnlyCandidate,
                        });
                }
                AuthPlannedRotationPreSourcePhase::MetadataIncomplete
                | AuthPlannedRotationPreSourcePhase::MetadataComplete => {
                    let metadata = parts.metadata.map(|(file, _)| file).ok_or(
                        AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
                    )?;
                    remove_exact_known_file(
                        &reservation.directory_fd,
                        ReservationEntryName::Metadata.as_str(),
                        KnownFilePurpose::Metadata,
                        metadata.stat,
                        metadata.content.expose(),
                        || {},
                    )?;
                    if !filesystem_mutated {
                        filesystem_mutated = true;
                        after_first_mutation
                            .take()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?();
                    }
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationRollbackTestFault::Metadata) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    expected_reconciliation =
                        Some(AuthPlannedRotationReconciliation::PlannedPreSource {
                            phase: AuthPlannedRotationPreSourcePhase::ReservationOnly,
                            recovery: AuthPlannedRotationRecovery::RollbackOnlyCandidate,
                        });
                }
                AuthPlannedRotationPreSourcePhase::ReservationOnly => {
                    remove_exact_empty_reservation_directory(
                        &self.locked.layout.secret_fd,
                        transition_name.as_str(),
                        reservation,
                    )?;
                    if !filesystem_mutated {
                        filesystem_mutated = true;
                        after_first_mutation
                            .take()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?();
                    }
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationRollbackTestFault::Directory) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    expected_reconciliation = Some(AuthPlannedRotationReconciliation::CleanActive);
                }
            }
        }

        Err(AuthStoreBindingError::Filesystem(
            SecretFsError::ArtifactChanged,
        ))
    }

    #[cfg(test)]
    pub(super) fn rollback_retire_pre_source_with_test_control(
        &self,
        fault: Option<AuthRetireRollbackTestFault>,
        before_mutation: impl FnOnce(),
        after_first_mutation: impl FnOnce(),
        after_rollback: impl FnOnce(),
    ) -> Result<AuthRetireRollbackOutcome, AuthStoreBindingError> {
        self.rollback_retire_pre_source_inner(
            fault,
            before_mutation,
            after_first_mutation,
            after_rollback,
        )
    }

    fn rollback_retire_pre_source_inner<BeforeMutation, AfterFirstMutation, AfterRollback>(
        &self,
        #[cfg(test)] fault: Option<AuthRetireRollbackTestFault>,
        before_mutation: BeforeMutation,
        after_first_mutation: AfterFirstMutation,
        after_rollback: AfterRollback,
    ) -> Result<AuthRetireRollbackOutcome, AuthStoreBindingError>
    where
        BeforeMutation: FnOnce(),
        AfterFirstMutation: FnOnce(),
        AfterRollback: FnOnce(),
    {
        let mut before_mutation = Some(before_mutation);
        let mut after_first_mutation = Some(after_first_mutation);
        let mut after_rollback = Some(after_rollback);
        let mut filesystem_mutated = false;
        let mut rollback_evidence: Option<PinnedAuthArtifactSnapshot> = None;
        let mut database_evidence: Option<AuthPlannedRotationDatabaseObservation> = None;
        let mut expected_reconciliation = None;

        for _ in 0..5 {
            let (artifacts, reconciliation, database) =
                self.capture_stable_retire_reconciliation()?;
            if expected_reconciliation
                .take()
                .is_some_and(|expected| expected != reconciliation)
            {
                return Err(AuthStoreBindingError::Filesystem(
                    SecretFsError::ArtifactChanged,
                ));
            }
            if let Some(expected_database) = database_evidence
                && !Self::planned_rotation_database_unchanged(expected_database, database)
            {
                if filesystem_mutated {
                    return Err(AuthStoreBindingError::ConversationStoreChanged);
                }
                return Ok(AuthRetireRollbackOutcome::NotRollbackable(reconciliation));
            }

            let (phase, recovery) = match reconciliation {
                AuthRetireReconciliation::ReadyToRetire => {
                    if !filesystem_mutated {
                        return Ok(AuthRetireRollbackOutcome::AlreadyReady);
                    }
                    after_rollback
                        .take()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?();
                    let rollback_evidence =
                        rollback_evidence
                            .as_ref()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    rollback_evidence
                        .revalidate_completed_cleanup_evidence(&self.locked.layout.secret_fd)?;
                    let (terminal_artifacts, terminal, terminal_database) =
                        self.capture_stable_retire_reconciliation()?;
                    if terminal != AuthRetireReconciliation::ReadyToRetire
                        || !Self::planned_rotation_database_unchanged(
                            database_evidence
                                .ok_or(AuthStoreBindingError::ConversationStoreChanged)?,
                            terminal_database,
                        )
                    {
                        return Err(AuthStoreBindingError::ConversationStoreChanged);
                    }
                    terminal_artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    rollback_evidence
                        .revalidate_completed_cleanup_evidence(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    return Ok(AuthRetireRollbackOutcome::RolledBack);
                }
                AuthRetireReconciliation::RetirePreSource { phase, recovery } => (phase, recovery),
                _ => {
                    if filesystem_mutated {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    return Ok(AuthRetireRollbackOutcome::NotRollbackable(reconciliation));
                }
            };

            let artifacts = if !filesystem_mutated {
                database_evidence = Some(database);
                rollback_evidence = Some(artifacts);
                before_mutation
                    .take()
                    .ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ))?();
                let (verified_artifacts, verified, verified_database) =
                    self.capture_stable_retire_reconciliation()?;
                if verified != reconciliation
                    || !Self::planned_rotation_database_unchanged(database, verified_database)
                {
                    return Ok(AuthRetireRollbackOutcome::NotRollbackable(verified));
                }
                rollback_evidence
                    .as_ref()
                    .ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ))?
                    .revalidate_planned_rotation_rollback_progress(
                        &self.locked.layout.secret_fd,
                        &verified_artifacts,
                    )?;
                verified_artifacts
            } else {
                rollback_evidence
                    .as_ref()
                    .ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ))?
                    .revalidate_planned_rotation_rollback_progress(
                        &self.locked.layout.secret_fd,
                        &artifacts,
                    )?;
                artifacts
            };

            let reservation =
                artifacts
                    .transition_directory()
                    .ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ))?;
            let transition_artifact = match reservation.artifact {
                TopLevelArtifactName::Transition {
                    kind: TransitionKind::Retire,
                    id,
                } => TopLevelArtifactName::Transition {
                    kind: TransitionKind::Retire,
                    id,
                },
                _ => {
                    return Err(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ));
                }
            };
            let transition_name = transition_artifact.format();
            if TopLevelArtifactName::parse(transition_name.as_bytes()) != Ok(transition_artifact) {
                return Err(AuthStoreBindingError::Filesystem(
                    SecretFsError::UnsafeAuthArtifact,
                ));
            }
            let parts = RetainedReservationParts::from_directory(reservation);
            artifacts.revalidate(&self.locked.layout.secret_fd)?;
            self.revalidate()?;

            match phase {
                AuthRetirePreSourcePhase::Prepared => {
                    let prepared = parts.prepared.ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ))?;
                    remove_exact_known_file(
                        &reservation.directory_fd,
                        ReservationEntryName::Prepared.as_str(),
                        KnownFilePurpose::Prepared,
                        prepared.stat,
                        prepared.content.expose(),
                        || {},
                    )?;
                    if !filesystem_mutated {
                        filesystem_mutated = true;
                        after_first_mutation
                            .take()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?();
                    }
                    #[cfg(test)]
                    if fault == Some(AuthRetireRollbackTestFault::Prepared) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    expected_reconciliation = Some(AuthRetireReconciliation::RetirePreSource {
                        phase: AuthRetirePreSourcePhase::StagedComplete,
                        recovery,
                    });
                }
                AuthRetirePreSourcePhase::StagedIncomplete
                | AuthRetirePreSourcePhase::StagedComplete => {
                    let staged = parts.staged.map(|(file, _)| file).ok_or(
                        AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
                    )?;
                    remove_exact_known_file(
                        &reservation.directory_fd,
                        ReservationEntryName::StagedKeyring.as_str(),
                        KnownFilePurpose::StagedKeyring,
                        staged.stat,
                        staged.content.expose(),
                        || {},
                    )?;
                    if !filesystem_mutated {
                        filesystem_mutated = true;
                        after_first_mutation
                            .take()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?();
                    }
                    #[cfg(test)]
                    if fault == Some(AuthRetireRollbackTestFault::Staged) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    expected_reconciliation = Some(AuthRetireReconciliation::RetirePreSource {
                        phase: AuthRetirePreSourcePhase::MetadataComplete,
                        recovery: AuthRetireRecovery::RollbackOnlyCandidate,
                    });
                }
                AuthRetirePreSourcePhase::MetadataIncomplete
                | AuthRetirePreSourcePhase::MetadataComplete => {
                    let metadata = parts.metadata.map(|(file, _)| file).ok_or(
                        AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
                    )?;
                    remove_exact_known_file(
                        &reservation.directory_fd,
                        ReservationEntryName::Metadata.as_str(),
                        KnownFilePurpose::Metadata,
                        metadata.stat,
                        metadata.content.expose(),
                        || {},
                    )?;
                    if !filesystem_mutated {
                        filesystem_mutated = true;
                        after_first_mutation
                            .take()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?();
                    }
                    #[cfg(test)]
                    if fault == Some(AuthRetireRollbackTestFault::Metadata) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    expected_reconciliation = Some(AuthRetireReconciliation::RetirePreSource {
                        phase: AuthRetirePreSourcePhase::ReservationOnly,
                        recovery: AuthRetireRecovery::RollbackOnlyCandidate,
                    });
                }
                AuthRetirePreSourcePhase::ReservationOnly => {
                    remove_exact_empty_reservation_directory(
                        &self.locked.layout.secret_fd,
                        transition_name.as_str(),
                        reservation,
                    )?;
                    if !filesystem_mutated {
                        filesystem_mutated = true;
                        after_first_mutation
                            .take()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?();
                    }
                    #[cfg(test)]
                    if fault == Some(AuthRetireRollbackTestFault::Directory) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    expected_reconciliation = Some(AuthRetireReconciliation::ReadyToRetire);
                }
            }
        }

        Err(AuthStoreBindingError::Filesystem(
            SecretFsError::ArtifactChanged,
        ))
    }

    pub(super) fn commit_planned_rotation_source(
        &self,
    ) -> Result<AuthPlannedRotationSourceOutcome, AuthStoreBindingError> {
        self.commit_planned_rotation_source_inner(
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            || {},
            || {},
        )
    }

    #[cfg(test)]
    pub(super) fn commit_planned_rotation_source_with_test_control(
        &self,
        mutation_fault: Option<AuthPlannedRotationSourceMutationTestFault>,
        durability_fault: Option<AuthPlannedRotationSourceDurabilityTestFault>,
        before_source_mutation: impl FnOnce(),
        after_source_mutation: impl FnOnce(),
    ) -> Result<AuthPlannedRotationSourceOutcome, AuthStoreBindingError> {
        self.commit_planned_rotation_source_inner(
            mutation_fault,
            durability_fault,
            before_source_mutation,
            after_source_mutation,
        )
    }

    fn commit_planned_rotation_source_inner<BeforeSourceMutation, AfterSourceMutation>(
        &self,
        #[cfg(test)] mutation_fault: Option<AuthPlannedRotationSourceMutationTestFault>,
        #[cfg(test)] durability_fault: Option<AuthPlannedRotationSourceDurabilityTestFault>,
        before_source_mutation: BeforeSourceMutation,
        after_source_mutation: AfterSourceMutation,
    ) -> Result<AuthPlannedRotationSourceOutcome, AuthStoreBindingError>
    where
        BeforeSourceMutation: FnOnce(),
        AfterSourceMutation: FnOnce(),
    {
        let (artifacts, reconciliation, _) =
            self.capture_stable_planned_rotation_reconciliation()?;
        match reconciliation {
            AuthPlannedRotationReconciliation::PlannedPreSource {
                phase: AuthPlannedRotationPreSourcePhase::Prepared,
                recovery: AuthPlannedRotationRecovery::ResumeOrRollbackCandidate,
            } => {}
            AuthPlannedRotationReconciliation::PlannedForwardOnly(_) => {
                return Ok(AuthPlannedRotationSourceOutcome::AlreadyCommitted);
            }
            _ => {
                return Ok(AuthPlannedRotationSourceOutcome::NotPrepared(
                    reconciliation,
                ));
            }
        }

        let metadata = artifacts.decode_planned_rotation_metadata().ok_or(
            AuthStoreBindingError::Filesystem(SecretFsError::UnsafeAuthArtifact),
        )?;
        let expectation = metadata.source_expectation();
        self.durabilize_prepared_planned_rotation_evidence(
            &artifacts,
            #[cfg(test)]
            durability_fault,
        )?;
        let (durable_artifacts, durable_reconciliation, _) =
            self.capture_stable_planned_rotation_reconciliation()?;
        if durable_reconciliation != reconciliation {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        }
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        durable_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        before_source_mutation();
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;

        #[cfg(test)]
        let mutation = match mutation_fault {
            Some(fault) => self
                .conversation
                .commit_planned_rotation_source_with_test_fault(expectation, fault),
            None => self
                .conversation
                .commit_planned_rotation_source(expectation),
        };
        #[cfg(not(test))]
        let mutation = self
            .conversation
            .commit_planned_rotation_source(expectation);
        let mutation = mutation.map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        after_source_mutation();
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;

        Ok(match mutation {
            AuthPlannedRotationSourceMutationOutcome::Committed => {
                AuthPlannedRotationSourceOutcome::Committed
            }
            AuthPlannedRotationSourceMutationOutcome::AlreadyCommitted => {
                AuthPlannedRotationSourceOutcome::AlreadyCommitted
            }
            AuthPlannedRotationSourceMutationOutcome::ConfirmedNotCommitted => {
                AuthPlannedRotationSourceOutcome::ConfirmedNotCommitted
            }
            AuthPlannedRotationSourceMutationOutcome::PreconditionChanged => {
                AuthPlannedRotationSourceOutcome::PreconditionChanged
            }
        })
    }

    pub(super) fn commit_retire_source(
        &self,
    ) -> Result<AuthRetireSourceOutcome, AuthStoreBindingError> {
        self.commit_retire_source_inner(
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
            || {},
            || {},
        )
    }

    #[cfg(test)]
    pub(super) fn commit_retire_source_with_test_control(
        &self,
        mutation_fault: Option<AuthPlannedRotationSourceMutationTestFault>,
        durability_fault: Option<AuthPlannedRotationSourceDurabilityTestFault>,
        before_source_mutation: impl FnOnce(),
        after_source_mutation: impl FnOnce(),
    ) -> Result<AuthRetireSourceOutcome, AuthStoreBindingError> {
        self.commit_retire_source_inner(
            mutation_fault,
            durability_fault,
            before_source_mutation,
            after_source_mutation,
        )
    }

    fn commit_retire_source_inner<BeforeSourceMutation, AfterSourceMutation>(
        &self,
        #[cfg(test)] mutation_fault: Option<AuthPlannedRotationSourceMutationTestFault>,
        #[cfg(test)] durability_fault: Option<AuthPlannedRotationSourceDurabilityTestFault>,
        before_source_mutation: BeforeSourceMutation,
        after_source_mutation: AfterSourceMutation,
    ) -> Result<AuthRetireSourceOutcome, AuthStoreBindingError>
    where
        BeforeSourceMutation: FnOnce(),
        AfterSourceMutation: FnOnce(),
    {
        let (artifacts, reconciliation, _) = self.capture_stable_retire_reconciliation()?;
        match reconciliation {
            AuthRetireReconciliation::RetirePreSource {
                phase: AuthRetirePreSourcePhase::Prepared,
                recovery: AuthRetireRecovery::ResumeOrRollbackCandidate,
            } => {}
            AuthRetireReconciliation::RetireForwardOnly(_) => {
                return Ok(AuthRetireSourceOutcome::AlreadyCommitted);
            }
            _ => return Ok(AuthRetireSourceOutcome::NotPrepared(reconciliation)),
        }

        let metadata =
            artifacts
                .decode_retire_metadata()
                .ok_or(AuthStoreBindingError::Filesystem(
                    SecretFsError::UnsafeAuthArtifact,
                ))?;
        let expectation = metadata.source_expectation();
        self.durabilize_prepared_retire_evidence(
            &artifacts,
            #[cfg(test)]
            durability_fault,
        )?;
        let (durable_artifacts, durable_reconciliation, _) =
            self.capture_stable_retire_reconciliation()?;
        if durable_reconciliation != reconciliation {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        }
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        durable_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        before_source_mutation();
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;

        #[cfg(test)]
        let mutation = match mutation_fault {
            Some(fault) => self
                .conversation
                .commit_retire_source_with_test_fault(expectation, fault),
            None => self.conversation.commit_retire_source(expectation),
        };
        #[cfg(not(test))]
        let mutation = self.conversation.commit_retire_source(expectation);
        let mutation = mutation.map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        after_source_mutation();
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;

        Ok(match mutation {
            AuthPlannedRotationSourceMutationOutcome::Committed => {
                AuthRetireSourceOutcome::Committed
            }
            AuthPlannedRotationSourceMutationOutcome::AlreadyCommitted => {
                AuthRetireSourceOutcome::AlreadyCommitted
            }
            AuthPlannedRotationSourceMutationOutcome::ConfirmedNotCommitted => {
                AuthRetireSourceOutcome::ConfirmedNotCommitted
            }
            AuthPlannedRotationSourceMutationOutcome::PreconditionChanged => {
                AuthRetireSourceOutcome::PreconditionChanged
            }
        })
    }

    pub(super) fn install_planned_rotation_active_key(
        &self,
    ) -> Result<AuthPlannedRotationActiveKeyInstallOutcome, AuthStoreBindingError> {
        self.install_planned_rotation_active_key_inner(
            #[cfg(test)]
            None,
            || {},
            || {},
            || {},
        )
    }

    #[cfg(test)]
    pub(super) fn install_planned_rotation_active_key_with_test_control(
        &self,
        fault: Option<AuthPlannedRotationActiveKeyInstallTestFault>,
        before_exchange: impl FnOnce(),
        after_exchange: impl FnOnce(),
        after_old_active_removal: impl FnOnce(),
    ) -> Result<AuthPlannedRotationActiveKeyInstallOutcome, AuthStoreBindingError> {
        self.install_planned_rotation_active_key_inner(
            fault,
            before_exchange,
            after_exchange,
            after_old_active_removal,
        )
    }

    fn install_planned_rotation_active_key_inner<
        BeforeExchange,
        AfterExchange,
        AfterOldActiveRemoval,
    >(
        &self,
        #[cfg(test)] fault: Option<AuthPlannedRotationActiveKeyInstallTestFault>,
        before_exchange: BeforeExchange,
        after_exchange: AfterExchange,
        after_old_active_removal: AfterOldActiveRemoval,
    ) -> Result<AuthPlannedRotationActiveKeyInstallOutcome, AuthStoreBindingError>
    where
        BeforeExchange: FnOnce(),
        AfterExchange: FnOnce(),
        AfterOldActiveRemoval: FnOnce(),
    {
        let mut before_exchange = Some(before_exchange);
        let mut after_exchange = Some(after_exchange);
        let mut after_old_active_removal = Some(after_old_active_removal);
        let mut filesystem_mutated = false;

        for _ in 0..6 {
            let (artifacts, reconciliation, _) =
                self.capture_stable_planned_rotation_reconciliation()?;
            let phase = match reconciliation {
                AuthPlannedRotationReconciliation::PlannedForwardOnly(phase) => phase,
                _ => {
                    if filesystem_mutated {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    return Ok(AuthPlannedRotationActiveKeyInstallOutcome::NotInstallable(
                        reconciliation,
                    ));
                }
            };
            if matches!(
                phase,
                AuthPlannedRotationForwardPhase::AwaitingCleanupRename
                    | AuthPlannedRotationForwardPhase::AwaitingCleanupStagedRemoval
                    | AuthPlannedRotationForwardPhase::AwaitingCleanupPreparedRemoval
                    | AuthPlannedRotationForwardPhase::AwaitingCleanupMetadataRemoval
                    | AuthPlannedRotationForwardPhase::AwaitingCleanupDirectoryRemoval
            ) {
                if filesystem_mutated {
                    return Err(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ));
                }
                return Ok(AuthPlannedRotationActiveKeyInstallOutcome::NotInstallable(
                    reconciliation,
                ));
            }
            let evidence = artifacts.planned_rotation_active_key_evidence().ok_or(
                AuthStoreBindingError::Filesystem(SecretFsError::UnsafeAuthArtifact),
            )?;
            let metadata = artifacts.decode_planned_rotation_metadata().ok_or(
                AuthStoreBindingError::Filesystem(SecretFsError::UnsafeAuthArtifact),
            )?;
            let expectation = metadata.source_expectation();
            let install_name = TopLevelArtifactName::InstallTemp {
                id: evidence.transition_id,
            }
            .format();
            if TopLevelArtifactName::parse(install_name.as_bytes())
                != Ok(TopLevelArtifactName::InstallTemp {
                    id: evidence.transition_id,
                })
            {
                return Err(AuthStoreBindingError::Filesystem(
                    SecretFsError::UnsafeAuthArtifact,
                ));
            }
            artifacts.revalidate(&self.locked.layout.secret_fd)?;
            self.revalidate()?;

            match phase {
                AuthPlannedRotationForwardPhase::AwaitingInstallTemp => {
                    persist_new_known_file(
                        &self.locked.layout.secret_fd,
                        install_name.as_str(),
                        KnownFilePurpose::InstallTemp,
                        evidence.staged.content.expose(),
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault
                        == Some(AuthPlannedRotationActiveKeyInstallTestFault::InstallTempDurable)
                    {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthPlannedRotationForwardPhase::InstallTempPrefix => {
                    let install =
                        artifacts
                            .install_file()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let install_bytes = install.content.expose();
                    let staged_bytes = evidence.staged.content.expose();
                    if install_bytes.len() >= staged_bytes.len()
                        || !staged_bytes.starts_with(install_bytes)
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    remove_exact_known_file(
                        &self.locked.layout.secret_fd,
                        install_name.as_str(),
                        KnownFilePurpose::InstallTemp,
                        install.stat,
                        install_bytes,
                        || {},
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationActiveKeyInstallTestFault::PrefixRemoved) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthPlannedRotationForwardPhase::InstallTempExact => {
                    let install =
                        artifacts
                            .install_file()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let active =
                        artifacts
                            .active_file()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    if !known_file_matches_planned_expected_active(active, expectation) {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    durabilize_existing_known_file(
                        &self.locked.layout.secret_fd,
                        install_name.as_str(),
                        KnownFilePurpose::InstallTemp,
                        install.stat,
                        evidence.staged.content.expose(),
                    )?;
                    durabilize_existing_known_file(
                        &self.locked.layout.secret_fd,
                        ACTIVE_KEYRING_NAME,
                        KnownFilePurpose::ActiveKeyring,
                        active.stat,
                        active.content.expose(),
                    )?;

                    let (exchange_artifacts, exchange_reconciliation, _) =
                        self.capture_stable_planned_rotation_reconciliation()?;
                    if exchange_reconciliation
                        != AuthPlannedRotationReconciliation::PlannedForwardOnly(
                            AuthPlannedRotationForwardPhase::InstallTempExact,
                        )
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    let exchange_evidence = exchange_artifacts
                        .planned_rotation_active_key_evidence()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::UnsafeAuthArtifact,
                        ))?;
                    let exchange_install = exchange_artifacts.install_file().ok_or(
                        AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
                    )?;
                    let exchange_active = exchange_artifacts.active_file().ok_or(
                        AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
                    )?;
                    exchange_artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    exchange_install_temp_with_active(
                        &self.locked.layout.secret_fd,
                        install_name.as_str(),
                        exchange_install.stat,
                        exchange_evidence.staged.content.expose(),
                        exchange_active.stat,
                        exchange_active.content.expose(),
                        before_exchange
                            .take()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?,
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationActiveKeyInstallTestFault::ExchangeDurable)
                    {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    after_exchange
                        .take()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?();
                }
                AuthPlannedRotationForwardPhase::AwaitingOldActiveTempRemoval => {
                    let install =
                        artifacts
                            .install_file()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    if !known_file_matches_planned_expected_active(install, expectation) {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    remove_exact_known_file(
                        &self.locked.layout.secret_fd,
                        install_name.as_str(),
                        KnownFilePurpose::InstallTemp,
                        install.stat,
                        install.content.expose(),
                        || {},
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault
                        == Some(AuthPlannedRotationActiveKeyInstallTestFault::OldActiveTempRemoved)
                    {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    after_old_active_removal
                        .take()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?();
                }
                AuthPlannedRotationForwardPhase::AwaitingFinalDbCas => {
                    let active =
                        artifacts
                            .active_file()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    durabilize_existing_known_file(
                        &self.locked.layout.secret_fd,
                        ACTIVE_KEYRING_NAME,
                        KnownFilePurpose::ActiveKeyring,
                        active.stat,
                        evidence.staged.content.expose(),
                    )?;
                    let (_, postcondition, _) =
                        self.capture_stable_planned_rotation_reconciliation()?;
                    if postcondition
                        != AuthPlannedRotationReconciliation::PlannedForwardOnly(
                            AuthPlannedRotationForwardPhase::AwaitingFinalDbCas,
                        )
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    return Ok(if filesystem_mutated {
                        AuthPlannedRotationActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas
                    } else {
                        AuthPlannedRotationActiveKeyInstallOutcome::AlreadyAwaitingFinalDbCas
                    });
                }
                AuthPlannedRotationForwardPhase::AwaitingCleanupRename
                | AuthPlannedRotationForwardPhase::AwaitingCleanupStagedRemoval
                | AuthPlannedRotationForwardPhase::AwaitingCleanupPreparedRemoval
                | AuthPlannedRotationForwardPhase::AwaitingCleanupMetadataRemoval
                | AuthPlannedRotationForwardPhase::AwaitingCleanupDirectoryRemoval => {
                    return Err(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ));
                }
            }
        }
        Err(AuthStoreBindingError::Filesystem(
            SecretFsError::ArtifactChanged,
        ))
    }

    pub(super) fn install_retire_active_key(
        &self,
    ) -> Result<AuthRetireActiveKeyInstallOutcome, AuthStoreBindingError> {
        self.install_retire_active_key_inner(
            #[cfg(test)]
            None,
            || {},
            || {},
            || {},
        )
    }

    #[cfg(test)]
    pub(super) fn install_retire_active_key_with_test_control(
        &self,
        fault: Option<AuthPlannedRotationActiveKeyInstallTestFault>,
        before_exchange: impl FnOnce(),
        after_exchange: impl FnOnce(),
        after_old_active_removal: impl FnOnce(),
    ) -> Result<AuthRetireActiveKeyInstallOutcome, AuthStoreBindingError> {
        self.install_retire_active_key_inner(
            fault,
            before_exchange,
            after_exchange,
            after_old_active_removal,
        )
    }

    fn install_retire_active_key_inner<BeforeExchange, AfterExchange, AfterOldActiveRemoval>(
        &self,
        #[cfg(test)] fault: Option<AuthPlannedRotationActiveKeyInstallTestFault>,
        before_exchange: BeforeExchange,
        after_exchange: AfterExchange,
        after_old_active_removal: AfterOldActiveRemoval,
    ) -> Result<AuthRetireActiveKeyInstallOutcome, AuthStoreBindingError>
    where
        BeforeExchange: FnOnce(),
        AfterExchange: FnOnce(),
        AfterOldActiveRemoval: FnOnce(),
    {
        let mut before_exchange = Some(before_exchange);
        let mut after_exchange = Some(after_exchange);
        let mut after_old_active_removal = Some(after_old_active_removal);
        let mut filesystem_mutated = false;

        for _ in 0..6 {
            let (artifacts, reconciliation, _) = self.capture_stable_retire_reconciliation()?;
            let phase = match reconciliation {
                AuthRetireReconciliation::RetireForwardOnly(phase) => phase,
                _ => {
                    if filesystem_mutated {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    return Ok(AuthRetireActiveKeyInstallOutcome::NotInstallable(
                        reconciliation,
                    ));
                }
            };
            if matches!(
                phase,
                AuthRetireForwardPhase::AwaitingCleanupRename
                    | AuthRetireForwardPhase::AwaitingCleanupStagedRemoval
                    | AuthRetireForwardPhase::AwaitingCleanupPreparedRemoval
                    | AuthRetireForwardPhase::AwaitingCleanupMetadataRemoval
                    | AuthRetireForwardPhase::AwaitingCleanupDirectoryRemoval
            ) {
                if filesystem_mutated {
                    return Err(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ));
                }
                return Ok(AuthRetireActiveKeyInstallOutcome::NotInstallable(
                    reconciliation,
                ));
            }
            let evidence =
                artifacts
                    .retire_active_key_evidence()
                    .ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::UnsafeAuthArtifact,
                    ))?;
            let metadata =
                artifacts
                    .decode_retire_metadata()
                    .ok_or(AuthStoreBindingError::Filesystem(
                        SecretFsError::UnsafeAuthArtifact,
                    ))?;
            let install_name = TopLevelArtifactName::InstallTemp {
                id: evidence.transition_id,
            }
            .format();
            if TopLevelArtifactName::parse(install_name.as_bytes())
                != Ok(TopLevelArtifactName::InstallTemp {
                    id: evidence.transition_id,
                })
            {
                return Err(AuthStoreBindingError::Filesystem(
                    SecretFsError::UnsafeAuthArtifact,
                ));
            }
            artifacts.revalidate(&self.locked.layout.secret_fd)?;
            self.revalidate()?;

            match phase {
                AuthRetireForwardPhase::AwaitingInstallTemp => {
                    persist_new_known_file(
                        &self.locked.layout.secret_fd,
                        install_name.as_str(),
                        KnownFilePurpose::InstallTemp,
                        evidence.staged.content.expose(),
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault
                        == Some(AuthPlannedRotationActiveKeyInstallTestFault::InstallTempDurable)
                    {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthRetireForwardPhase::InstallTempPrefix => {
                    let install =
                        artifacts
                            .install_file()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let install_bytes = install.content.expose();
                    let staged_bytes = evidence.staged.content.expose();
                    if install_bytes.len() >= staged_bytes.len()
                        || !staged_bytes.starts_with(install_bytes)
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    remove_exact_known_file(
                        &self.locked.layout.secret_fd,
                        install_name.as_str(),
                        KnownFilePurpose::InstallTemp,
                        install.stat,
                        install_bytes,
                        || {},
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationActiveKeyInstallTestFault::PrefixRemoved) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthRetireForwardPhase::InstallTempExact => {
                    let install =
                        artifacts
                            .install_file()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let active =
                        artifacts
                            .active_file()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    if metadata
                        .validate_current_keyring(SecretBytes::new(
                            active.content.expose().to_vec(),
                        ))
                        .is_err()
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    durabilize_existing_known_file(
                        &self.locked.layout.secret_fd,
                        install_name.as_str(),
                        KnownFilePurpose::InstallTemp,
                        install.stat,
                        evidence.staged.content.expose(),
                    )?;
                    durabilize_existing_known_file(
                        &self.locked.layout.secret_fd,
                        ACTIVE_KEYRING_NAME,
                        KnownFilePurpose::ActiveKeyring,
                        active.stat,
                        active.content.expose(),
                    )?;

                    let (exchange_artifacts, exchange_reconciliation, _) =
                        self.capture_stable_retire_reconciliation()?;
                    if exchange_reconciliation
                        != AuthRetireReconciliation::RetireForwardOnly(
                            AuthRetireForwardPhase::InstallTempExact,
                        )
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    let exchange_evidence = exchange_artifacts.retire_active_key_evidence().ok_or(
                        AuthStoreBindingError::Filesystem(SecretFsError::UnsafeAuthArtifact),
                    )?;
                    let exchange_install = exchange_artifacts.install_file().ok_or(
                        AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
                    )?;
                    let exchange_active = exchange_artifacts.active_file().ok_or(
                        AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
                    )?;
                    exchange_artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    exchange_install_temp_with_active(
                        &self.locked.layout.secret_fd,
                        install_name.as_str(),
                        exchange_install.stat,
                        exchange_evidence.staged.content.expose(),
                        exchange_active.stat,
                        exchange_active.content.expose(),
                        before_exchange
                            .take()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?,
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationActiveKeyInstallTestFault::ExchangeDurable)
                    {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    after_exchange
                        .take()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?();
                }
                AuthRetireForwardPhase::AwaitingOldActiveTempRemoval => {
                    let install =
                        artifacts
                            .install_file()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    if metadata
                        .validate_current_keyring(SecretBytes::new(
                            install.content.expose().to_vec(),
                        ))
                        .is_err()
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    remove_exact_known_file(
                        &self.locked.layout.secret_fd,
                        install_name.as_str(),
                        KnownFilePurpose::InstallTemp,
                        install.stat,
                        install.content.expose(),
                        || {},
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault
                        == Some(AuthPlannedRotationActiveKeyInstallTestFault::OldActiveTempRemoved)
                    {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                    after_old_active_removal
                        .take()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?();
                }
                AuthRetireForwardPhase::AwaitingFinalDbCas => {
                    let active =
                        artifacts
                            .active_file()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    durabilize_existing_known_file(
                        &self.locked.layout.secret_fd,
                        ACTIVE_KEYRING_NAME,
                        KnownFilePurpose::ActiveKeyring,
                        active.stat,
                        evidence.staged.content.expose(),
                    )?;
                    let (_, postcondition, _) = self.capture_stable_retire_reconciliation()?;
                    if postcondition
                        != AuthRetireReconciliation::RetireForwardOnly(
                            AuthRetireForwardPhase::AwaitingFinalDbCas,
                        )
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    return Ok(if filesystem_mutated {
                        AuthRetireActiveKeyInstallOutcome::InstalledAwaitingFinalDbCas
                    } else {
                        AuthRetireActiveKeyInstallOutcome::AlreadyAwaitingFinalDbCas
                    });
                }
                AuthRetireForwardPhase::AwaitingCleanupRename
                | AuthRetireForwardPhase::AwaitingCleanupStagedRemoval
                | AuthRetireForwardPhase::AwaitingCleanupPreparedRemoval
                | AuthRetireForwardPhase::AwaitingCleanupMetadataRemoval
                | AuthRetireForwardPhase::AwaitingCleanupDirectoryRemoval => {
                    return Err(AuthStoreBindingError::Filesystem(
                        SecretFsError::ArtifactChanged,
                    ));
                }
            }
        }
        Err(AuthStoreBindingError::Filesystem(
            SecretFsError::ArtifactChanged,
        ))
    }

    pub(super) fn commit_planned_rotation_final_lifecycle(
        &self,
    ) -> Result<AuthPlannedRotationFinalLifecycleOutcome, AuthStoreBindingError> {
        self.commit_planned_rotation_final_lifecycle_inner(
            #[cfg(test)]
            None,
            || {},
            || {},
        )
    }

    #[cfg(test)]
    pub(super) fn commit_planned_rotation_final_lifecycle_with_test_control(
        &self,
        fault: Option<AuthPlannedRotationFinalLifecycleMutationTestFault>,
        before_mutation: impl FnOnce(),
        after_mutation: impl FnOnce(),
    ) -> Result<AuthPlannedRotationFinalLifecycleOutcome, AuthStoreBindingError> {
        self.commit_planned_rotation_final_lifecycle_inner(fault, before_mutation, after_mutation)
    }

    fn commit_planned_rotation_final_lifecycle_inner<BeforeMutation, AfterMutation>(
        &self,
        #[cfg(test)] fault: Option<AuthPlannedRotationFinalLifecycleMutationTestFault>,
        before_mutation: BeforeMutation,
        after_mutation: AfterMutation,
    ) -> Result<AuthPlannedRotationFinalLifecycleOutcome, AuthStoreBindingError>
    where
        BeforeMutation: FnOnce(),
        AfterMutation: FnOnce(),
    {
        let (artifacts, reconciliation, _) =
            self.capture_stable_planned_rotation_reconciliation()?;
        let expected_phase = match reconciliation {
            AuthPlannedRotationReconciliation::PlannedForwardOnly(
                AuthPlannedRotationForwardPhase::AwaitingFinalDbCas,
            ) => AuthPlannedRotationForwardPhase::AwaitingFinalDbCas,
            AuthPlannedRotationReconciliation::PlannedForwardOnly(
                AuthPlannedRotationForwardPhase::AwaitingCleanupRename,
            ) => AuthPlannedRotationForwardPhase::AwaitingCleanupRename,
            _ => {
                return Ok(AuthPlannedRotationFinalLifecycleOutcome::NotActivatable(
                    reconciliation,
                ));
            }
        };
        let evidence = artifacts.planned_rotation_active_key_evidence().ok_or(
            AuthStoreBindingError::Filesystem(SecretFsError::UnsafeAuthArtifact),
        )?;
        let active = artifacts
            .active_file()
            .ok_or(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ))?;
        durabilize_existing_known_file(
            &self.locked.layout.secret_fd,
            ACTIVE_KEYRING_NAME,
            KnownFilePurpose::ActiveKeyring,
            active.stat,
            evidence.staged.content.expose(),
        )?;
        self.durabilize_prepared_planned_rotation_evidence(
            &artifacts,
            #[cfg(test)]
            None,
        )?;

        let (cas_artifacts, cas_reconciliation, _) =
            self.capture_stable_planned_rotation_reconciliation()?;
        if cas_reconciliation
            != AuthPlannedRotationReconciliation::PlannedForwardOnly(expected_phase)
        {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        }
        if expected_phase == AuthPlannedRotationForwardPhase::AwaitingCleanupRename {
            return Ok(AuthPlannedRotationFinalLifecycleOutcome::AlreadyActivatedAwaitingCleanup);
        }
        let metadata = cas_artifacts.decode_planned_rotation_metadata().ok_or(
            AuthStoreBindingError::Filesystem(SecretFsError::UnsafeAuthArtifact),
        )?;
        let expectation = metadata.source_expectation();

        before_mutation();
        cas_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        #[cfg(test)]
        let mutation = match fault {
            Some(fault) => self
                .conversation
                .commit_planned_rotation_final_lifecycle_with_test_fault(expectation, fault),
            None => self
                .conversation
                .commit_planned_rotation_final_lifecycle(expectation),
        };
        #[cfg(not(test))]
        let mutation = self
            .conversation
            .commit_planned_rotation_final_lifecycle(expectation);
        let mutation = mutation.map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        after_mutation();
        cas_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;

        let (_, postcondition, _) = self.capture_stable_planned_rotation_reconciliation()?;
        match mutation {
            AuthPlannedRotationFinalLifecycleMutationOutcome::Committed => {
                if postcondition
                    != AuthPlannedRotationReconciliation::PlannedForwardOnly(
                        AuthPlannedRotationForwardPhase::AwaitingCleanupRename,
                    )
                {
                    return Err(AuthStoreBindingError::ConversationStoreChanged);
                }
                Ok(AuthPlannedRotationFinalLifecycleOutcome::ActivatedAwaitingCleanup)
            }
            AuthPlannedRotationFinalLifecycleMutationOutcome::AlreadyCommitted => {
                if postcondition
                    != AuthPlannedRotationReconciliation::PlannedForwardOnly(
                        AuthPlannedRotationForwardPhase::AwaitingCleanupRename,
                    )
                {
                    return Err(AuthStoreBindingError::ConversationStoreChanged);
                }
                Ok(AuthPlannedRotationFinalLifecycleOutcome::AlreadyActivatedAwaitingCleanup)
            }
            AuthPlannedRotationFinalLifecycleMutationOutcome::ConfirmedNotCommitted => {
                if postcondition
                    != AuthPlannedRotationReconciliation::PlannedForwardOnly(
                        AuthPlannedRotationForwardPhase::AwaitingFinalDbCas,
                    )
                {
                    return Err(AuthStoreBindingError::ConversationStoreChanged);
                }
                Ok(AuthPlannedRotationFinalLifecycleOutcome::ConfirmedNotActivated)
            }
            AuthPlannedRotationFinalLifecycleMutationOutcome::PreconditionChanged => {
                Err(AuthStoreBindingError::ConversationStoreChanged)
            }
        }
    }

    pub(super) fn commit_retire_final_lifecycle(
        &self,
    ) -> Result<AuthRetireFinalLifecycleOutcome, AuthStoreBindingError> {
        self.commit_retire_final_lifecycle_inner(
            #[cfg(test)]
            None,
            || {},
            || {},
        )
    }

    #[cfg(test)]
    pub(super) fn commit_retire_final_lifecycle_with_test_control(
        &self,
        fault: Option<AuthPlannedRotationFinalLifecycleMutationTestFault>,
        before_mutation: impl FnOnce(),
        after_mutation: impl FnOnce(),
    ) -> Result<AuthRetireFinalLifecycleOutcome, AuthStoreBindingError> {
        self.commit_retire_final_lifecycle_inner(fault, before_mutation, after_mutation)
    }

    fn commit_retire_final_lifecycle_inner<BeforeMutation, AfterMutation>(
        &self,
        #[cfg(test)] fault: Option<AuthPlannedRotationFinalLifecycleMutationTestFault>,
        before_mutation: BeforeMutation,
        after_mutation: AfterMutation,
    ) -> Result<AuthRetireFinalLifecycleOutcome, AuthStoreBindingError>
    where
        BeforeMutation: FnOnce(),
        AfterMutation: FnOnce(),
    {
        let (artifacts, reconciliation, _) = self.capture_stable_retire_reconciliation()?;
        let expected_phase = match reconciliation {
            AuthRetireReconciliation::RetireForwardOnly(
                AuthRetireForwardPhase::AwaitingFinalDbCas,
            ) => AuthRetireForwardPhase::AwaitingFinalDbCas,
            AuthRetireReconciliation::RetireForwardOnly(
                AuthRetireForwardPhase::AwaitingCleanupRename,
            ) => AuthRetireForwardPhase::AwaitingCleanupRename,
            _ => {
                return Ok(AuthRetireFinalLifecycleOutcome::NotActivatable(
                    reconciliation,
                ));
            }
        };
        let evidence =
            artifacts
                .retire_active_key_evidence()
                .ok_or(AuthStoreBindingError::Filesystem(
                    SecretFsError::UnsafeAuthArtifact,
                ))?;
        let active = artifacts
            .active_file()
            .ok_or(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ))?;
        durabilize_existing_known_file(
            &self.locked.layout.secret_fd,
            ACTIVE_KEYRING_NAME,
            KnownFilePurpose::ActiveKeyring,
            active.stat,
            evidence.staged.content.expose(),
        )?;
        self.durabilize_prepared_retire_evidence(
            &artifacts,
            #[cfg(test)]
            None,
        )?;

        let (cas_artifacts, cas_reconciliation, _) = self.capture_stable_retire_reconciliation()?;
        if cas_reconciliation != AuthRetireReconciliation::RetireForwardOnly(expected_phase) {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        }
        if expected_phase == AuthRetireForwardPhase::AwaitingCleanupRename {
            return Ok(AuthRetireFinalLifecycleOutcome::AlreadyActivatedAwaitingCleanup);
        }
        let metadata =
            cas_artifacts
                .decode_retire_metadata()
                .ok_or(AuthStoreBindingError::Filesystem(
                    SecretFsError::UnsafeAuthArtifact,
                ))?;
        let expectation = metadata.source_expectation();

        before_mutation();
        cas_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        #[cfg(test)]
        let mutation = match fault {
            Some(fault) => self
                .conversation
                .commit_retire_final_lifecycle_with_test_fault(expectation, fault),
            None => self.conversation.commit_retire_final_lifecycle(expectation),
        };
        #[cfg(not(test))]
        let mutation = self.conversation.commit_retire_final_lifecycle(expectation);
        let mutation = mutation.map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        after_mutation();
        cas_artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;

        let (_, postcondition, _) = self.capture_stable_retire_reconciliation()?;
        match mutation {
            AuthPlannedRotationFinalLifecycleMutationOutcome::Committed => {
                if postcondition
                    != AuthRetireReconciliation::RetireForwardOnly(
                        AuthRetireForwardPhase::AwaitingCleanupRename,
                    )
                {
                    return Err(AuthStoreBindingError::ConversationStoreChanged);
                }
                Ok(AuthRetireFinalLifecycleOutcome::ActivatedAwaitingCleanup)
            }
            AuthPlannedRotationFinalLifecycleMutationOutcome::AlreadyCommitted => {
                if postcondition
                    != AuthRetireReconciliation::RetireForwardOnly(
                        AuthRetireForwardPhase::AwaitingCleanupRename,
                    )
                {
                    return Err(AuthStoreBindingError::ConversationStoreChanged);
                }
                Ok(AuthRetireFinalLifecycleOutcome::AlreadyActivatedAwaitingCleanup)
            }
            AuthPlannedRotationFinalLifecycleMutationOutcome::ConfirmedNotCommitted => {
                if postcondition
                    != AuthRetireReconciliation::RetireForwardOnly(
                        AuthRetireForwardPhase::AwaitingFinalDbCas,
                    )
                {
                    return Err(AuthStoreBindingError::ConversationStoreChanged);
                }
                Ok(AuthRetireFinalLifecycleOutcome::ConfirmedNotActivated)
            }
            AuthPlannedRotationFinalLifecycleMutationOutcome::PreconditionChanged => {
                Err(AuthStoreBindingError::ConversationStoreChanged)
            }
        }
    }

    pub(super) fn cleanup_planned_rotation(
        &self,
    ) -> Result<AuthPlannedRotationCleanupOutcome, AuthStoreBindingError> {
        self.cleanup_planned_rotation_inner(
            #[cfg(test)]
            None,
            || {},
            || {},
        )
    }

    #[cfg(test)]
    pub(super) fn cleanup_planned_rotation_with_test_control(
        &self,
        fault: Option<AuthPlannedRotationCleanupTestFault>,
        before_rename: impl FnOnce(),
        after_cleanup: impl FnOnce(),
    ) -> Result<AuthPlannedRotationCleanupOutcome, AuthStoreBindingError> {
        self.cleanup_planned_rotation_inner(fault, before_rename, after_cleanup)
    }

    fn cleanup_planned_rotation_inner<BeforeRename, AfterCleanup>(
        &self,
        #[cfg(test)] fault: Option<AuthPlannedRotationCleanupTestFault>,
        before_rename: BeforeRename,
        after_cleanup: AfterCleanup,
    ) -> Result<AuthPlannedRotationCleanupOutcome, AuthStoreBindingError>
    where
        BeforeRename: FnOnce(),
        AfterCleanup: FnOnce(),
    {
        let mut before_rename = Some(before_rename);
        let mut after_cleanup = Some(after_cleanup);
        let mut retained_artifacts = None;
        let mut retained_metadata = None;
        let mut retained_database = None;
        let mut filesystem_mutated = false;

        for _ in 0..7 {
            let (artifacts, reconciliation, database) =
                self.capture_stable_planned_rotation_reconciliation()?;
            if let (Some(metadata), Some(expected_database)) =
                (retained_metadata.as_ref(), retained_database)
            {
                self.revalidate_retained_planned_rotation_source(
                    &artifacts,
                    metadata,
                    expected_database,
                )?;
            }
            let captured_metadata = artifacts.decode_planned_rotation_metadata();
            if matches!(
                reconciliation,
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingCleanupRename
                        | AuthPlannedRotationForwardPhase::AwaitingCleanupStagedRemoval
                        | AuthPlannedRotationForwardPhase::AwaitingCleanupPreparedRemoval
                        | AuthPlannedRotationForwardPhase::AwaitingCleanupMetadataRemoval
                )
            ) && retained_metadata.is_none()
            {
                let metadata =
                    captured_metadata
                        .as_ref()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::UnsafeAuthArtifact,
                        ))?;
                self.revalidate_retained_planned_rotation_source(&artifacts, metadata, database)?;
            }

            match reconciliation {
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingCleanupRename,
                ) => {
                    let reservation = artifacts.transition_directory().ok_or(
                        AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
                    )?;
                    let (kind, id) = match reservation.artifact {
                        TopLevelArtifactName::Transition {
                            kind: TransitionKind::Planned,
                            id,
                        } => (TransitionKind::Planned, id),
                        _ => {
                            return Err(AuthStoreBindingError::Filesystem(
                                SecretFsError::UnsafeAuthArtifact,
                            ));
                        }
                    };
                    let transition_artifact = TopLevelArtifactName::Transition { kind, id };
                    let cleanup_artifact = TopLevelArtifactName::Cleanup { kind, id };
                    let transition_name = transition_artifact.format();
                    let cleanup_name = cleanup_artifact.format();
                    if TopLevelArtifactName::parse(transition_name.as_bytes())
                        != Ok(transition_artifact)
                        || TopLevelArtifactName::parse(cleanup_name.as_bytes())
                            != Ok(cleanup_artifact)
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::UnsafeAuthArtifact,
                        ));
                    }
                    before_rename
                        .take()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?();
                    let metadata =
                        captured_metadata
                            .as_ref()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::UnsafeAuthArtifact,
                            ))?;
                    self.revalidate_retained_planned_rotation_source(
                        &artifacts, metadata, database,
                    )?;
                    artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    rename_exact_reservation_to_cleanup_no_replace(
                        &self.locked.layout.secret_fd,
                        transition_name.as_str(),
                        cleanup_name.as_str(),
                        reservation,
                    )?;
                    filesystem_mutated = true;
                    retain_planned_rotation_cleanup_evidence(
                        &mut retained_artifacts,
                        &mut retained_metadata,
                        &mut retained_database,
                        artifacts,
                        captured_metadata,
                        database,
                    )?;
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationCleanupTestFault::Rename) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingCleanupStagedRemoval,
                ) => {
                    let cleanup =
                        artifacts
                            .cleanup_directory()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let (staged, CodecObservation::Valid) =
                        RetainedReservationParts::from_directory(cleanup)
                            .staged
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?
                    else {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    };
                    artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    remove_exact_known_file(
                        &cleanup.directory_fd,
                        ReservationEntryName::StagedKeyring.as_str(),
                        KnownFilePurpose::StagedKeyring,
                        staged.stat,
                        staged.content.expose(),
                        || {},
                    )?;
                    filesystem_mutated = true;
                    retain_planned_rotation_cleanup_evidence(
                        &mut retained_artifacts,
                        &mut retained_metadata,
                        &mut retained_database,
                        artifacts,
                        captured_metadata,
                        database,
                    )?;
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationCleanupTestFault::Staged) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingCleanupPreparedRemoval,
                ) => {
                    let cleanup =
                        artifacts
                            .cleanup_directory()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let prepared = RetainedReservationParts::from_directory(cleanup)
                        .prepared
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?;
                    artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    remove_exact_known_file(
                        &cleanup.directory_fd,
                        ReservationEntryName::Prepared.as_str(),
                        KnownFilePurpose::Prepared,
                        prepared.stat,
                        prepared.content.expose(),
                        || {},
                    )?;
                    filesystem_mutated = true;
                    retain_planned_rotation_cleanup_evidence(
                        &mut retained_artifacts,
                        &mut retained_metadata,
                        &mut retained_database,
                        artifacts,
                        captured_metadata,
                        database,
                    )?;
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationCleanupTestFault::Prepared) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingCleanupMetadataRemoval,
                ) => {
                    let cleanup =
                        artifacts
                            .cleanup_directory()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let (metadata_file, CodecObservation::Valid) =
                        RetainedReservationParts::from_directory(cleanup)
                            .metadata
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?
                    else {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    };
                    artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    remove_exact_known_file(
                        &cleanup.directory_fd,
                        ReservationEntryName::Metadata.as_str(),
                        KnownFilePurpose::Metadata,
                        metadata_file.stat,
                        metadata_file.content.expose(),
                        || {},
                    )?;
                    filesystem_mutated = true;
                    retain_planned_rotation_cleanup_evidence(
                        &mut retained_artifacts,
                        &mut retained_metadata,
                        &mut retained_database,
                        artifacts,
                        captured_metadata,
                        database,
                    )?;
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationCleanupTestFault::Metadata) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthPlannedRotationReconciliation::PlannedForwardOnly(
                    AuthPlannedRotationForwardPhase::AwaitingCleanupDirectoryRemoval,
                ) => {
                    let cleanup =
                        artifacts
                            .cleanup_directory()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let (kind, id) = match cleanup.artifact {
                        TopLevelArtifactName::Cleanup {
                            kind: TransitionKind::Planned,
                            id,
                        } => (TransitionKind::Planned, id),
                        _ => {
                            return Err(AuthStoreBindingError::Filesystem(
                                SecretFsError::UnsafeAuthArtifact,
                            ));
                        }
                    };
                    let cleanup_artifact = TopLevelArtifactName::Cleanup { kind, id };
                    let cleanup_name = cleanup_artifact.format();
                    if TopLevelArtifactName::parse(cleanup_name.as_bytes()) != Ok(cleanup_artifact)
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::UnsafeAuthArtifact,
                        ));
                    }
                    artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    remove_exact_empty_reservation_directory(
                        &self.locked.layout.secret_fd,
                        cleanup_name.as_str(),
                        cleanup,
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationCleanupTestFault::Directory) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthPlannedRotationReconciliation::PlannedRotationComplete => {
                    let active =
                        artifacts
                            .active_file()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    durabilize_existing_known_file(
                        &self.locked.layout.secret_fd,
                        ACTIVE_KEYRING_NAME,
                        KnownFilePurpose::ActiveKeyring,
                        active.stat,
                        active.content.expose(),
                    )?;
                    if !filesystem_mutated {
                        let (_, postcondition, _) =
                            self.capture_stable_planned_rotation_reconciliation()?;
                        if postcondition
                            != AuthPlannedRotationReconciliation::PlannedRotationComplete
                        {
                            return Err(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ));
                        }
                        return Ok(AuthPlannedRotationCleanupOutcome::AlreadyCompleted);
                    }

                    after_cleanup
                        .take()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?();
                    let (terminal_artifacts, terminal_reconciliation, _) =
                        self.capture_stable_planned_rotation_reconciliation()?;
                    if terminal_reconciliation
                        != AuthPlannedRotationReconciliation::PlannedRotationComplete
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    if let (Some(metadata), Some(expected_database)) =
                        (retained_metadata.as_ref(), retained_database)
                    {
                        self.revalidate_retained_planned_rotation_source(
                            &terminal_artifacts,
                            metadata,
                            expected_database,
                        )?;
                    }
                    if let Some(retained) = retained_artifacts.as_ref() {
                        retained
                            .revalidate_completed_cleanup_evidence(&self.locked.layout.secret_fd)?;
                    }
                    terminal_artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    return Ok(AuthPlannedRotationCleanupOutcome::Completed);
                }
                _ => {
                    if filesystem_mutated {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    return Ok(AuthPlannedRotationCleanupOutcome::NotCleanable(
                        reconciliation,
                    ));
                }
            }
        }
        Err(AuthStoreBindingError::Filesystem(
            SecretFsError::ArtifactChanged,
        ))
    }

    pub(super) fn cleanup_retire(&self) -> Result<AuthRetireCleanupOutcome, AuthStoreBindingError> {
        self.cleanup_retire_inner(
            #[cfg(test)]
            None,
            || {},
            || {},
        )
    }

    #[cfg(test)]
    pub(super) fn cleanup_retire_with_test_control(
        &self,
        fault: Option<AuthPlannedRotationCleanupTestFault>,
        before_rename: impl FnOnce(),
        after_cleanup: impl FnOnce(),
    ) -> Result<AuthRetireCleanupOutcome, AuthStoreBindingError> {
        self.cleanup_retire_inner(fault, before_rename, after_cleanup)
    }

    fn cleanup_retire_inner<BeforeRename, AfterCleanup>(
        &self,
        #[cfg(test)] fault: Option<AuthPlannedRotationCleanupTestFault>,
        before_rename: BeforeRename,
        after_cleanup: AfterCleanup,
    ) -> Result<AuthRetireCleanupOutcome, AuthStoreBindingError>
    where
        BeforeRename: FnOnce(),
        AfterCleanup: FnOnce(),
    {
        let mut before_rename = Some(before_rename);
        let mut after_cleanup = Some(after_cleanup);
        let mut retained_artifacts = None;
        let mut retained_metadata = None;
        let mut retained_database = None;
        let mut filesystem_mutated = false;

        for _ in 0..7 {
            let (artifacts, reconciliation, database) =
                self.capture_stable_retire_reconciliation()?;
            if let (Some(metadata), Some(expected_database)) =
                (retained_metadata.as_ref(), retained_database)
            {
                self.revalidate_retained_retire_source(&artifacts, metadata, expected_database)?;
            }
            let captured_metadata = artifacts.decode_retire_metadata();
            if matches!(
                reconciliation,
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingCleanupRename
                        | AuthRetireForwardPhase::AwaitingCleanupStagedRemoval
                        | AuthRetireForwardPhase::AwaitingCleanupPreparedRemoval
                        | AuthRetireForwardPhase::AwaitingCleanupMetadataRemoval
                )
            ) && retained_metadata.is_none()
            {
                let metadata =
                    captured_metadata
                        .as_ref()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::UnsafeAuthArtifact,
                        ))?;
                self.revalidate_retained_retire_source(&artifacts, metadata, database)?;
            }

            match reconciliation {
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingCleanupRename,
                ) => {
                    let reservation = artifacts.transition_directory().ok_or(
                        AuthStoreBindingError::Filesystem(SecretFsError::ArtifactChanged),
                    )?;
                    let id = match reservation.artifact {
                        TopLevelArtifactName::Transition {
                            kind: TransitionKind::Retire,
                            id,
                        } => id,
                        _ => {
                            return Err(AuthStoreBindingError::Filesystem(
                                SecretFsError::UnsafeAuthArtifact,
                            ));
                        }
                    };
                    let transition_artifact = TopLevelArtifactName::Transition {
                        kind: TransitionKind::Retire,
                        id,
                    };
                    let cleanup_artifact = TopLevelArtifactName::Cleanup {
                        kind: TransitionKind::Retire,
                        id,
                    };
                    let transition_name = transition_artifact.format();
                    let cleanup_name = cleanup_artifact.format();
                    if TopLevelArtifactName::parse(transition_name.as_bytes())
                        != Ok(transition_artifact)
                        || TopLevelArtifactName::parse(cleanup_name.as_bytes())
                            != Ok(cleanup_artifact)
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::UnsafeAuthArtifact,
                        ));
                    }
                    before_rename
                        .take()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?();
                    let metadata =
                        captured_metadata
                            .as_ref()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::UnsafeAuthArtifact,
                            ))?;
                    self.revalidate_retained_retire_source(&artifacts, metadata, database)?;
                    artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    rename_exact_reservation_to_cleanup_no_replace(
                        &self.locked.layout.secret_fd,
                        transition_name.as_str(),
                        cleanup_name.as_str(),
                        reservation,
                    )?;
                    filesystem_mutated = true;
                    retain_retire_cleanup_evidence(
                        &mut retained_artifacts,
                        &mut retained_metadata,
                        &mut retained_database,
                        artifacts,
                        captured_metadata,
                        database,
                    )?;
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationCleanupTestFault::Rename) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingCleanupStagedRemoval,
                ) => {
                    let cleanup =
                        artifacts
                            .cleanup_directory()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let (staged, CodecObservation::Valid) =
                        RetainedReservationParts::from_directory(cleanup)
                            .staged
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?
                    else {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    };
                    artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    remove_exact_known_file(
                        &cleanup.directory_fd,
                        ReservationEntryName::StagedKeyring.as_str(),
                        KnownFilePurpose::StagedKeyring,
                        staged.stat,
                        staged.content.expose(),
                        || {},
                    )?;
                    filesystem_mutated = true;
                    retain_retire_cleanup_evidence(
                        &mut retained_artifacts,
                        &mut retained_metadata,
                        &mut retained_database,
                        artifacts,
                        captured_metadata,
                        database,
                    )?;
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationCleanupTestFault::Staged) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingCleanupPreparedRemoval,
                ) => {
                    let cleanup =
                        artifacts
                            .cleanup_directory()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let prepared = RetainedReservationParts::from_directory(cleanup)
                        .prepared
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?;
                    artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    remove_exact_known_file(
                        &cleanup.directory_fd,
                        ReservationEntryName::Prepared.as_str(),
                        KnownFilePurpose::Prepared,
                        prepared.stat,
                        prepared.content.expose(),
                        || {},
                    )?;
                    filesystem_mutated = true;
                    retain_retire_cleanup_evidence(
                        &mut retained_artifacts,
                        &mut retained_metadata,
                        &mut retained_database,
                        artifacts,
                        captured_metadata,
                        database,
                    )?;
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationCleanupTestFault::Prepared) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingCleanupMetadataRemoval,
                ) => {
                    let cleanup =
                        artifacts
                            .cleanup_directory()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let (metadata_file, CodecObservation::Valid) =
                        RetainedReservationParts::from_directory(cleanup)
                            .metadata
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?
                    else {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    };
                    artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    remove_exact_known_file(
                        &cleanup.directory_fd,
                        ReservationEntryName::Metadata.as_str(),
                        KnownFilePurpose::Metadata,
                        metadata_file.stat,
                        metadata_file.content.expose(),
                        || {},
                    )?;
                    filesystem_mutated = true;
                    retain_retire_cleanup_evidence(
                        &mut retained_artifacts,
                        &mut retained_metadata,
                        &mut retained_database,
                        artifacts,
                        captured_metadata,
                        database,
                    )?;
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationCleanupTestFault::Metadata) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthRetireReconciliation::RetireForwardOnly(
                    AuthRetireForwardPhase::AwaitingCleanupDirectoryRemoval,
                ) => {
                    let cleanup =
                        artifacts
                            .cleanup_directory()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    let id = match cleanup.artifact {
                        TopLevelArtifactName::Cleanup {
                            kind: TransitionKind::Retire,
                            id,
                        } => id,
                        _ => {
                            return Err(AuthStoreBindingError::Filesystem(
                                SecretFsError::UnsafeAuthArtifact,
                            ));
                        }
                    };
                    let cleanup_artifact = TopLevelArtifactName::Cleanup {
                        kind: TransitionKind::Retire,
                        id,
                    };
                    let cleanup_name = cleanup_artifact.format();
                    if TopLevelArtifactName::parse(cleanup_name.as_bytes()) != Ok(cleanup_artifact)
                    {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::UnsafeAuthArtifact,
                        ));
                    }
                    artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    remove_exact_empty_reservation_directory(
                        &self.locked.layout.secret_fd,
                        cleanup_name.as_str(),
                        cleanup,
                    )?;
                    filesystem_mutated = true;
                    #[cfg(test)]
                    if fault == Some(AuthPlannedRotationCleanupTestFault::Directory) {
                        return Err(AuthStoreBindingError::Filesystem(SecretFsError::Io(
                            io::ErrorKind::Other,
                        )));
                    }
                }
                AuthRetireReconciliation::CleanActiveOnly => {
                    let active =
                        artifacts
                            .active_file()
                            .ok_or(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ))?;
                    durabilize_existing_known_file(
                        &self.locked.layout.secret_fd,
                        ACTIVE_KEYRING_NAME,
                        KnownFilePurpose::ActiveKeyring,
                        active.stat,
                        active.content.expose(),
                    )?;
                    if !filesystem_mutated {
                        let (_, postcondition, _) = self.capture_stable_retire_reconciliation()?;
                        if postcondition != AuthRetireReconciliation::CleanActiveOnly {
                            return Err(AuthStoreBindingError::Filesystem(
                                SecretFsError::ArtifactChanged,
                            ));
                        }
                        return Ok(AuthRetireCleanupOutcome::AlreadyCompleted);
                    }

                    after_cleanup
                        .take()
                        .ok_or(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ))?();
                    let (terminal_artifacts, terminal_reconciliation, _) =
                        self.capture_stable_retire_reconciliation()?;
                    if terminal_reconciliation != AuthRetireReconciliation::CleanActiveOnly {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    if let (Some(metadata), Some(expected_database)) =
                        (retained_metadata.as_ref(), retained_database)
                    {
                        self.revalidate_retained_retire_source(
                            &terminal_artifacts,
                            metadata,
                            expected_database,
                        )?;
                    }
                    if let Some(retained) = retained_artifacts.as_ref() {
                        retained
                            .revalidate_completed_cleanup_evidence(&self.locked.layout.secret_fd)?;
                    }
                    terminal_artifacts.revalidate(&self.locked.layout.secret_fd)?;
                    self.revalidate()?;
                    return Ok(AuthRetireCleanupOutcome::Completed);
                }
                _ => {
                    if filesystem_mutated {
                        return Err(AuthStoreBindingError::Filesystem(
                            SecretFsError::ArtifactChanged,
                        ));
                    }
                    return Ok(AuthRetireCleanupOutcome::NotCleanable(reconciliation));
                }
            }
        }
        Err(AuthStoreBindingError::Filesystem(
            SecretFsError::ArtifactChanged,
        ))
    }

    fn revalidate_retained_planned_rotation_source(
        &self,
        artifacts: &PinnedAuthArtifactSnapshot,
        metadata: &PlannedRotationMetadataV1,
        expected: AuthPlannedRotationDatabaseObservation,
    ) -> Result<(), AuthStoreBindingError> {
        self.revalidate()?;
        let expectation = metadata.source_expectation();
        let database_a = self
            .conversation
            .inspect_auth_planned_rotation(Some(expectation))
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        let database_b = self
            .conversation
            .inspect_auth_planned_rotation(Some(expectation))
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        if database_a != database_b
            || database_a != expected
            || database_a.source != AuthPlannedRotationSourceMatch::Exact
            || database_a.source_fingerprint.is_none()
        {
            return Err(AuthStoreBindingError::ConversationStoreChanged);
        }
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        Ok(())
    }

    fn revalidate_retained_retire_source(
        &self,
        artifacts: &PinnedAuthArtifactSnapshot,
        metadata: &RetireMetadataV1,
        expected: AuthPlannedRotationDatabaseObservation,
    ) -> Result<(), AuthStoreBindingError> {
        self.revalidate()?;
        let expectation = metadata.source_expectation();
        let database_a = self
            .conversation
            .inspect_auth_retire(Some(expectation))
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        let database_b = self
            .conversation
            .inspect_auth_retire(Some(expectation))
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        if database_a != database_b
            || database_a != expected
            || database_a.source != AuthPlannedRotationSourceMatch::Exact
            || database_a.source_fingerprint.is_none()
        {
            return Err(AuthStoreBindingError::ConversationStoreChanged);
        }
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        Ok(())
    }

    fn capture_stable_initialization_reconciliation(
        &self,
    ) -> Result<(PinnedAuthArtifactSnapshot, AuthInitializationReconciliation), AuthStoreBindingError>
    {
        let (artifacts, reconciliation, _) =
            self.capture_stable_initialization_reconciliation_observed()?;
        Ok((artifacts, reconciliation))
    }

    fn capture_stable_initialization_reconciliation_observed(
        &self,
    ) -> Result<
        (
            PinnedAuthArtifactSnapshot,
            AuthInitializationReconciliation,
            AuthDatabaseReconciliationObservation,
        ),
        AuthStoreBindingError,
    > {
        self.revalidate()?;
        let artifacts = self.locked.capture_secret_artifacts()?;
        let metadata = artifacts.decode_initialization_metadata();
        let expectation = metadata
            .as_ref()
            .map(InitializationMetadataV1::source_expectation);
        let database_a = self
            .conversation
            .inspect_auth_reconciliation(expectation)
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        let database_b = self
            .conversation
            .inspect_auth_reconciliation(expectation)
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        if database_a != database_b {
            return Err(AuthStoreBindingError::ConversationStoreChanged);
        }
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        let reconciliation = artifacts.reconcile_initialization(database_a, metadata.as_ref());
        Ok((artifacts, reconciliation, database_a))
    }

    #[cfg(test)]
    pub(super) fn prepare_initialization_with_test_control(
        &self,
        preparation: &InitializationPreparationV1,
        fault: Option<AuthInitializationPrepareTestFault>,
        after_outer_precondition: impl FnOnce(),
    ) -> Result<AuthInitializationPrepareOutcome, AuthStoreBindingError> {
        self.prepare_initialization_inner(preparation, fault, after_outer_precondition)
    }

    fn prepare_initialization_inner<AfterOuterPrecondition>(
        &self,
        preparation: &InitializationPreparationV1,
        #[cfg(test)] fault: Option<AuthInitializationPrepareTestFault>,
        after_outer_precondition: AfterOuterPrecondition,
    ) -> Result<AuthInitializationPrepareOutcome, AuthStoreBindingError>
    where
        AfterOuterPrecondition: FnOnce(),
    {
        let precondition = self.inspect_initialization_reconciliation()?;
        if precondition != AuthInitializationReconciliation::CleanUninitialized {
            return Ok(AuthInitializationPrepareOutcome::PreconditionNotClean(
                precondition,
            ));
        }
        after_outer_precondition();

        let persistence = self.locked.persist_initialization_preparation(
            preparation,
            #[cfg(test)]
            fault,
        )?;
        if persistence == AuthInitializationPersistenceOutcome::PreconditionNotClean {
            let observed = self.inspect_initialization_reconciliation()?;
            if observed == AuthInitializationReconciliation::CleanUninitialized {
                return Err(AuthStoreBindingError::Filesystem(
                    SecretFsError::ArtifactChanged,
                ));
            }
            return Ok(AuthInitializationPrepareOutcome::PreconditionNotClean(
                observed,
            ));
        }
        let readback = self.inspect_initialization_reconciliation()?;
        if readback
            != (AuthInitializationReconciliation::InitializePreSource {
                phase: AuthInitializationPreSourcePhase::Prepared,
                recovery: AuthInitializationRecovery::ResumeOrRollbackCandidate,
            })
        {
            return Err(AuthStoreBindingError::Filesystem(
                SecretFsError::ArtifactChanged,
            ));
        }
        Ok(AuthInitializationPrepareOutcome::Prepared)
    }

    #[cfg(test)]
    pub(super) fn inspect_initialization_reconciliation_with_checkpoints<
        AfterFilesystemB,
        AfterDatabaseB,
    >(
        &self,
        after_filesystem_b: AfterFilesystemB,
        after_database_b: AfterDatabaseB,
    ) -> Result<AuthInitializationReconciliation, AuthStoreBindingError>
    where
        AfterFilesystemB: FnOnce(),
        AfterDatabaseB: FnOnce(),
    {
        self.inspect_initialization_reconciliation_inner(after_filesystem_b, after_database_b)
    }

    #[cfg(test)]
    pub(super) fn inspect_planned_rotation_reconciliation_with_checkpoints<
        AfterFilesystemB,
        AfterDatabaseB,
    >(
        &self,
        after_filesystem_b: AfterFilesystemB,
        after_database_b: AfterDatabaseB,
    ) -> Result<AuthPlannedRotationReconciliation, AuthStoreBindingError>
    where
        AfterFilesystemB: FnOnce(),
        AfterDatabaseB: FnOnce(),
    {
        self.inspect_planned_rotation_reconciliation_inner(after_filesystem_b, after_database_b)
    }

    fn inspect_planned_rotation_reconciliation_inner<AfterFilesystemB, AfterDatabaseB>(
        &self,
        after_filesystem_b: AfterFilesystemB,
        after_database_b: AfterDatabaseB,
    ) -> Result<AuthPlannedRotationReconciliation, AuthStoreBindingError>
    where
        AfterFilesystemB: FnOnce(),
        AfterDatabaseB: FnOnce(),
    {
        self.revalidate()?;
        let artifacts = self.locked.capture_secret_artifacts()?;
        let metadata = artifacts.decode_planned_rotation_metadata();
        let expectation = metadata
            .as_ref()
            .map(PlannedRotationMetadataV1::source_expectation);
        let database_a = self
            .conversation
            .inspect_auth_planned_rotation(expectation)
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        after_filesystem_b();
        let database_b = self
            .conversation
            .inspect_auth_planned_rotation(expectation)
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        if database_a != database_b {
            return Err(AuthStoreBindingError::ConversationStoreChanged);
        }
        after_database_b();
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        Ok(artifacts.reconcile_planned_rotation(database_a, metadata.as_ref()))
    }

    #[cfg(test)]
    pub(super) fn inspect_retire_reconciliation_with_checkpoints<AfterFilesystemB, AfterDatabaseB>(
        &self,
        after_filesystem_b: AfterFilesystemB,
        after_database_b: AfterDatabaseB,
    ) -> Result<AuthRetireReconciliation, AuthStoreBindingError>
    where
        AfterFilesystemB: FnOnce(),
        AfterDatabaseB: FnOnce(),
    {
        self.inspect_retire_reconciliation_inner(after_filesystem_b, after_database_b)
    }

    fn inspect_retire_reconciliation_inner<AfterFilesystemB, AfterDatabaseB>(
        &self,
        after_filesystem_b: AfterFilesystemB,
        after_database_b: AfterDatabaseB,
    ) -> Result<AuthRetireReconciliation, AuthStoreBindingError>
    where
        AfterFilesystemB: FnOnce(),
        AfterDatabaseB: FnOnce(),
    {
        self.revalidate()?;
        let artifacts = self.locked.capture_secret_artifacts()?;
        let metadata = artifacts.decode_retire_metadata();
        let expectation = metadata.as_ref().map(RetireMetadataV1::source_expectation);
        let database_a = self
            .conversation
            .inspect_auth_retire(expectation)
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        after_filesystem_b();
        let database_b = self
            .conversation
            .inspect_auth_retire(expectation)
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        if database_a != database_b {
            return Err(AuthStoreBindingError::ConversationStoreChanged);
        }
        after_database_b();
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        Ok(artifacts.reconcile_retire(database_a, metadata.as_ref()))
    }

    fn inspect_initialization_reconciliation_inner<AfterFilesystemB, AfterDatabaseB>(
        &self,
        after_filesystem_b: AfterFilesystemB,
        after_database_b: AfterDatabaseB,
    ) -> Result<AuthInitializationReconciliation, AuthStoreBindingError>
    where
        AfterFilesystemB: FnOnce(),
        AfterDatabaseB: FnOnce(),
    {
        self.revalidate()?;
        let artifacts = self.locked.capture_secret_artifacts()?;
        let metadata = artifacts.decode_initialization_metadata();
        let expectation = metadata
            .as_ref()
            .map(InitializationMetadataV1::source_expectation);
        let database_a = self
            .conversation
            .inspect_auth_reconciliation(expectation)
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        after_filesystem_b();
        let database_b = self
            .conversation
            .inspect_auth_reconciliation(expectation)
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        if database_a != database_b {
            return Err(AuthStoreBindingError::ConversationStoreChanged);
        }
        after_database_b();
        artifacts.revalidate(&self.locked.layout.secret_fd)?;
        self.revalidate()?;
        Ok(artifacts.reconcile_initialization(database_a, metadata.as_ref()))
    }

    pub(super) fn poison(&self) {
        self.conversation.poison();
    }

    pub(super) fn poison_handle(&self) -> AuthStorePoisonHandle {
        self.conversation.poison_handle()
    }
}

pub(super) struct AuthListenerLease {
    locked: LockedAuthInstance,
    conversation: AuthConversationStoreBinding,
    store_identity: StoreDirectoryIdentity,
    keyring: Keyring,
}

impl AuthListenerLease {
    pub(super) fn revalidate(&self) -> Result<(), AuthStoreBindingError> {
        let store_identity = self
            .conversation
            .directory_identity()
            .map_err(|_| AuthStoreBindingError::ConversationStoreUnavailable)?;
        let layout_identity = self.locked.revalidate()?;
        if store_identity != self.store_identity
            || !store_identity.matches(
                layout_identity.device,
                layout_identity.inode,
                layout_identity.owner,
            )
        {
            return Err(AuthStoreBindingError::ConversationStoreMismatch);
        }
        Ok(())
    }

    pub(super) const fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    pub(super) fn poison(&self) {
        self.conversation.poison();
    }
}

impl fmt::Debug for AuthListenerLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthListenerLease")
            .field("lock", &"[HELD]")
            .field("conversation_store", &"[BOUND]")
            .field("keyring", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for OwnedAuthMaintenanceContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedAuthMaintenanceContext")
            .field("lock", &"[HELD]")
            .field("conversation_store", &"[BOUND]")
            .finish()
    }
}

fn absolute_path(path: &Path) -> Result<PathBuf, SecretFsError> {
    if path.as_os_str().is_empty() {
        return Err(SecretFsError::UnsafeRoot);
    }
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(std::env::current_dir()
            .map_err(|error| SecretFsError::io(&error))?
            .join(path))
    }
}

struct PreparedInstanceRoot {
    parent_fd: OwnedFd,
    root_name: OsString,
    identity: FileIdentity,
}

fn prepare_instance_root(path: &Path) -> Result<PreparedInstanceRoot, SecretFsError> {
    let parent_path = path.parent().ok_or(SecretFsError::UnsafeRoot)?;
    let root_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or(SecretFsError::UnsafeRoot)?
        .to_owned();
    let canonical_parent =
        fs::canonicalize(parent_path).map_err(|error| SecretFsError::io(&error))?;
    let parent_fd = open(
        &canonical_parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(SecretFsError::errno)?;
    ensure_cloexec(&parent_fd)?;
    let parent_identity = fstat(&parent_fd)
        .map_err(SecretFsError::errno)
        .map(|stat| file_identity_from_stat(&stat))?;
    let current_parent = fs::metadata(parent_path).map_err(|error| SecretFsError::io(&error))?;
    if !same_file_node(
        file_identity_from_metadata(&current_parent),
        parent_identity,
    ) {
        return Err(SecretFsError::IdentityChanged);
    }

    let identity = match statat(&parent_fd, &root_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => validate_directory_stat(&stat, DirectoryPurpose::InstanceRoot)?,
        Err(error) if error == Errno::NOENT => {
            match mkdirat(&parent_fd, &root_name, Mode::RWXU) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(error) => return Err(SecretFsError::errno(error)),
            }
            fsync(&parent_fd).map_err(SecretFsError::errno)?;
            statat(&parent_fd, &root_name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(SecretFsError::errno)
                .and_then(|stat| validate_directory_stat(&stat, DirectoryPurpose::InstanceRoot))?
        }
        Err(error) => return Err(SecretFsError::errno(error)),
    };
    let current_parent = fs::metadata(parent_path).map_err(|error| SecretFsError::io(&error))?;
    if !same_file_node(
        file_identity_from_metadata(&current_parent),
        parent_identity,
    ) {
        return Err(SecretFsError::IdentityChanged);
    }

    Ok(PreparedInstanceRoot {
        parent_fd,
        root_name,
        identity,
    })
}

fn revalidate_instance_root(
    parent_fd: &OwnedFd,
    root_fd: &OwnedFd,
    root_name: &OsString,
) -> Result<(), SecretFsError> {
    let fd_identity = validate_directory_fd(root_fd, DirectoryPurpose::InstanceRoot)?;
    let path_identity = statat(parent_fd, root_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| {
            if error == Errno::NOENT {
                SecretFsError::IdentityChanged
            } else {
                SecretFsError::errno(error)
            }
        })
        .and_then(|stat| validate_directory_stat(&stat, DirectoryPurpose::InstanceRoot))?;
    if fd_identity != path_identity {
        return Err(SecretFsError::IdentityChanged);
    }
    Ok(())
}

fn open_or_create_child_directory(
    root_fd: &OwnedFd,
    name: &'static str,
    purpose: DirectoryPurpose,
) -> Result<OwnedFd, SecretFsError> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let directory = match openat(root_fd, name, flags, Mode::empty()) {
        Ok(directory) => directory,
        Err(error) if error == Errno::NOENT => {
            match mkdirat(root_fd, name, Mode::RWXU) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(error) => return Err(SecretFsError::errno(error)),
            }
            fsync(root_fd).map_err(SecretFsError::errno)?;
            openat(root_fd, name, flags, Mode::empty()).map_err(SecretFsError::errno)?
        }
        Err(error) => return Err(SecretFsError::errno(error)),
    };
    validate_directory_fd(&directory, purpose)?;
    ensure_cloexec(&directory)?;
    revalidate_child_directory(root_fd, &directory, name, purpose)?;
    Ok(directory)
}

fn revalidate_child_directory(
    root_fd: &OwnedFd,
    directory_fd: &OwnedFd,
    name: &'static str,
    purpose: DirectoryPurpose,
) -> Result<(), SecretFsError> {
    let fd_identity = validate_directory_fd(directory_fd, purpose)?;
    let path_identity = statat(root_fd, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(SecretFsError::errno)
        .and_then(|stat| validate_directory_stat(&stat, purpose))?;
    if fd_identity != path_identity {
        return Err(SecretFsError::IdentityChanged);
    }
    Ok(())
}

fn validate_directory_fd(
    fd: &OwnedFd,
    purpose: DirectoryPurpose,
) -> Result<FileIdentity, SecretFsError> {
    let before = fstat(fd).map_err(SecretFsError::errno)?;
    let identity = validate_directory_stat(&before, purpose)?;
    let before = artifact_stat_from_stat(&before)?;
    #[cfg(target_os = "macos")]
    ensure_no_extended_acl(fd, unsafe_directory_error(purpose))?;
    let after = fstat(fd).map_err(SecretFsError::errno)?;
    validate_directory_stat(&after, purpose)?;
    let after = artifact_stat_from_stat(&after)?;
    if before != after {
        return Err(SecretFsError::IdentityChanged);
    }
    Ok(identity)
}

fn validate_directory_stat(
    stat: &Stat,
    purpose: DirectoryPurpose,
) -> Result<FileIdentity, SecretFsError> {
    let identity = file_identity_from_stat(stat);
    if identity.file_type != FileKind::Directory
        || identity.owner != geteuid().as_raw()
        || identity.mode != OWNER_DIRECTORY_MODE
    {
        return Err(unsafe_directory_error(purpose));
    }
    Ok(identity)
}

const fn unsafe_directory_error(purpose: DirectoryPurpose) -> SecretFsError {
    match purpose {
        DirectoryPurpose::InstanceRoot => SecretFsError::UnsafeRoot,
        DirectoryPurpose::StoreDirectory => SecretFsError::UnsafeStoreDirectory,
        DirectoryPurpose::SecretDirectory => SecretFsError::UnsafeSecretDirectory,
    }
}

fn open_or_create_lock_file(secret_fd: &OwnedFd) -> Result<(OwnedFd, bool), SecretFsError> {
    let create_flags =
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match openat(
        secret_fd,
        AUTH_LOCK_FILE_NAME,
        create_flags,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(file) => Ok((file, true)),
        Err(error) if error == Errno::EXIST => {
            let file = openat(
                secret_fd,
                AUTH_LOCK_FILE_NAME,
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(SecretFsError::errno)?;
            Ok((file, false))
        }
        Err(error) => Err(SecretFsError::errno(error)),
    }
}

fn validate_lock_fd(fd: &OwnedFd) -> Result<FileIdentity, SecretFsError> {
    let before = fstat(fd).map_err(SecretFsError::errno)?;
    let identity = validate_lock_stat(&before)?;
    let before = artifact_stat_from_stat(&before)?;
    #[cfg(target_os = "macos")]
    ensure_no_extended_acl(fd, SecretFsError::UnsafeLockFile)?;
    let after = fstat(fd).map_err(SecretFsError::errno)?;
    validate_lock_stat(&after)?;
    let after = artifact_stat_from_stat(&after)?;
    if before != after {
        return Err(SecretFsError::IdentityChanged);
    }
    Ok(identity)
}

fn validate_lock_stat(stat: &Stat) -> Result<FileIdentity, SecretFsError> {
    let identity = file_identity_from_stat(stat);
    if identity.file_type != FileKind::Regular
        || identity.owner != geteuid().as_raw()
        || identity.mode != OWNER_FILE_MODE
        || identity.links != 1
        || stat.st_size != 0
    {
        return Err(SecretFsError::UnsafeLockFile);
    }
    Ok(identity)
}

fn ensure_cloexec(fd: impl AsFd) -> Result<(), SecretFsError> {
    let flags = fcntl_getfd(fd).map_err(SecretFsError::errno)?;
    if !flags.contains(FdFlags::CLOEXEC) {
        return Err(SecretFsError::CloseOnExecMissing);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn ensure_no_extended_acl(
    fd: impl AsFd,
    present_error: SecretFsError,
) -> Result<(), SecretFsError> {
    match pov_platform::extended_acl_state(fd.as_fd()) {
        Ok(ExtendedAclState::Absent) => Ok(()),
        Ok(ExtendedAclState::Present) => Err(present_error),
        Err(error) => Err(SecretFsError::Io(error.kind())),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryPurpose {
    InstanceRoot,
    StoreDirectory,
    SecretDirectory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileKind {
    Directory,
    Regular,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
    file_type: FileKind,
}

fn same_file_node(left: FileIdentity, right: FileIdentity) -> bool {
    left.device == right.device && left.inode == right.inode
}

fn file_identity_from_metadata(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.permissions().mode() & 0o7777,
        links: metadata.nlink(),
        file_type: if metadata.is_dir() {
            FileKind::Directory
        } else if metadata.is_file() {
            FileKind::Regular
        } else {
            FileKind::Other
        },
    }
}

fn file_identity_from_stat(stat: &Stat) -> FileIdentity {
    let file_type = match FileType::from_raw_mode(stat.st_mode) {
        FileType::Directory => FileKind::Directory,
        FileType::RegularFile => FileKind::Regular,
        _ => FileKind::Other,
    };
    FileIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino,
        owner: stat.st_uid,
        mode: (stat.st_mode as u32) & 0o7777,
        links: stat.st_nlink as u64,
        file_type,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecretFsError {
    UnsafeRoot,
    UnsafeStoreDirectory,
    UnsafeSecretDirectory,
    UnsafeLockFile,
    IdentityChanged,
    CloseOnExecMissing,
    AlreadyLocked,
    ArtifactInventoryLimit,
    UnsafeAuthArtifact,
    ArtifactChanged,
    Io(io::ErrorKind),
}

impl SecretFsError {
    fn io(error: &io::Error) -> Self {
        Self::Io(error.kind())
    }

    fn errno(error: Errno) -> Self {
        Self::Io(error.kind())
    }
}

impl fmt::Display for SecretFsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafeRoot => "authentication instance root is unsafe",
            Self::UnsafeStoreDirectory => "authentication store directory is unsafe",
            Self::UnsafeSecretDirectory => "authentication secret directory is unsafe",
            Self::UnsafeLockFile => "authentication maintenance lock file is unsafe",
            Self::IdentityChanged => "authentication filesystem identity changed",
            Self::CloseOnExecMissing => "authentication filesystem descriptor is inheritable",
            Self::AlreadyLocked => "authentication maintenance is already active",
            Self::ArtifactInventoryLimit => {
                "authentication secret artifact inventory exceeded its limit"
            }
            Self::UnsafeAuthArtifact => "authentication secret artifact is unsafe",
            Self::ArtifactChanged => "authentication secret artifact changed during inspection",
            Self::Io(_) => "authentication filesystem operation failed",
        })
    }
}

impl Error for SecretFsError {}

#[cfg(test)]
pub(super) fn raw_filename_creation_is_unavailable(error: &io::Error) -> bool {
    // Native macOS/APFS rejects raw non-UTF-8 path bytes with EILSEQ before an
    // artifact exists. Managed runners may reject the same operation earlier.
    matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput
    ) || error.raw_os_error() == Some(Errno::ILSEQ.raw_os_error())
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        ffi::OsString,
        fs,
        io::{self, Write},
        os::{
            fd::AsRawFd,
            unix::ffi::OsStringExt,
            unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink},
            unix::net::UnixListener,
        },
        path::{Path, PathBuf},
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use base64ct::{Base64Unpadded, Encoding};
    use rustix::{
        io::{Errno, FdFlags, fcntl_getfd},
        process::{Pid, Signal, kill_process},
    };
    use tempfile::tempdir;
    use uuid::Uuid;

    use crate::{
        auth::{
            SecretBytes, ValidatedVerifier,
            keyring::Keyring,
            transition::{
                AuditId, AuthOwnerId, InitializationMetadataInput, InitializationMetadataV1,
                LoginId, SourceTimestampMicros, TransitionId,
            },
        },
        storage::StoreSet,
    };

    use super::{
        AUTH_LOCK_FILE_NAME, ArtifactManifestEntry, AuthInstanceLayout, AuthStoreBindingError,
        CodecObservation, FileKind, KnownFilePurpose, OWNER_DIRECTORY_MODE, OWNER_FILE_MODE,
        PinnedReservationEntry, PinnedTopLevelArtifact, RedactedBytes, SECRET_DIRECTORY_NAME,
        STORE_DIRECTORY_NAME, SecretFsError, SemanticLinkageObservation, TopLevelArtifactName,
        capture_known_file, raw_filename_creation_is_unavailable, read_artifact_manifest,
        remove_exact_known_file,
    };

    const HELPER_ROOT_ENV: &str = "POV_AUTH_SECRET_FS_TEST_ROOT";
    const HELPER_MODE_ENV: &str = "POV_AUTH_SECRET_FS_TEST_MODE";
    const HELPER_READY_FILE: &str = "secret-fs-helper-ready";
    const HELPER_PID_FILE: &str = "secret-fs-grandchild-pid";
    const ACTIVE_KEYRING_FILE: &str = "auth-keyring.v1";
    const INITIALIZE_ONE: &str = ".auth-transition-initialize-00000000-0000-4000-8000-000000000001";
    const INITIALIZE_TWO: &str = ".auth-transition-initialize-00000000-0000-4000-8000-000000000002";
    const INSTALL_ONE: &str = ".auth-keyring-install-00000000-0000-4000-8000-000000000001.tmp";
    const INSTALL_TWO: &str = ".auth-keyring-install-00000000-0000-4000-8000-000000000002.tmp";

    fn owner_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("owner-only file");
        fs::set_permissions(path, fs::Permissions::from_mode(OWNER_FILE_MODE))
            .expect("owner-only file mode");
    }

    fn owner_directory(path: &Path) {
        fs::create_dir(path).expect("owner-only directory");
        fs::set_permissions(path, fs::Permissions::from_mode(OWNER_DIRECTORY_MODE))
            .expect("owner-only directory mode");
    }

    fn synthetic_verifier(fill: u8) -> ValidatedVerifier {
        let salt = Base64Unpadded::encode_string(&[fill; 16]);
        let output = Base64Unpadded::encode_string(&[fill; 32]);
        ValidatedVerifier::parse(SecretBytes::new(
            format!("$argon2id$v=19$m=65536,t=3,p=4${salt}${output}").into_bytes(),
        ))
        .expect("canonical synthetic verifier")
    }

    fn initialization_metadata(keyring: &Keyring) -> SecretBytes {
        let transition_id = TransitionId::from_uuid(
            Uuid::parse_str("00000000-0000-4000-8000-000000000001").expect("fixed transition UUID"),
        )
        .expect("transition ID");
        InitializationMetadataV1::from_keyring(
            InitializationMetadataInput {
                transition_id,
                owner_id: AuthOwnerId::from_uuid(
                    Uuid::parse_str("01234567-89ab-4cde-8fab-0123456789ab")
                        .expect("fixed owner UUID"),
                )
                .expect("owner ID"),
                audit_id: AuditId::from_uuid(
                    Uuid::parse_str("fedcba98-7654-4321-8abc-fedcba987654")
                        .expect("fixed audit UUID"),
                )
                .expect("audit ID"),
                source_at_micros: SourceTimestampMicros::new(1_700_000_000_000_001)
                    .expect("source timestamp"),
                login_id: LoginId::parse(b"owner_01").expect("login ID"),
                password_verifier: synthetic_verifier(0x11),
                recovery_verifier: synthetic_verifier(0x22),
            },
            keyring,
        )
        .expect("initialization metadata")
        .encode()
        .expect("encoded initialization metadata")
    }

    #[cfg(target_os = "macos")]
    fn add_extended_acl(path: &Path) {
        let mode_before = fs::symlink_metadata(path)
            .expect("ACL target metadata")
            .permissions()
            .mode()
            & 0o7777;
        assert!(matches!(
            mode_before,
            OWNER_FILE_MODE | OWNER_DIRECTORY_MODE
        ));
        let output = Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(path)
            .output()
            .expect("run macOS chmod ACL command");
        assert!(
            output.status.success(),
            "macOS chmod ACL command failed with status {:?}",
            output.status.code()
        );
        assert_eq!(
            fs::symlink_metadata(path)
                .expect("ACL target metadata after chmod")
                .permissions()
                .mode()
                & 0o7777,
            mode_before,
            "extended ACL must not rely on a traditional-mode mismatch"
        );
    }

    fn secret_root(root: &Path) -> PathBuf {
        root.join(SECRET_DIRECTORY_NAME)
    }

    fn try_bind_unix_listener(path: &Path) -> Option<UnixListener> {
        match UnixListener::bind(path) {
            Ok(socket) => Some(socket),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput
                ) =>
            {
                // Managed macOS runners may deny socket creation, while a long
                // temporary path can exceed the platform `sun_path` bound.
                None
            }
            Err(error) => panic!("unexpected socket creation error: {error}"),
        }
    }

    fn try_create_fifo(path: &Path) -> bool {
        match Command::new("mkfifo").env("LC_ALL", "C").arg(path).output() {
            Ok(output) if output.status.success() => true,
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
                if [
                    "operation not permitted",
                    "permission denied",
                    "not supported",
                    "operation unsupported",
                ]
                .iter()
                .any(|message| stderr.contains(message))
                {
                    false
                } else {
                    panic!(
                        "unexpected FIFO creation exit status: {:?}",
                        output.status.code()
                    );
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                false
            }
            Err(error) => panic!("unexpected FIFO creation error: {error}"),
        }
    }

    fn find_manifest_entry<'a>(
        entries: &'a [ArtifactManifestEntry],
        raw_name: &[u8],
    ) -> &'a ArtifactManifestEntry {
        entries
            .iter()
            .find(|entry| entry.raw_name.expose() == raw_name)
            .expect("manifest entry")
    }

    #[test]
    fn exact_unlink_detects_hardlink_inserted_after_precheck() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let layout = AuthInstanceLayout::open_or_create(&root).expect("layout");
        let victim = root.join(SECRET_DIRECTORY_NAME).join("victim");
        let alias = root.join(SECRET_DIRECTORY_NAME).join("alias");
        owner_file(&victim, b"retained secret");
        let manifest = read_artifact_manifest(&layout.secret_fd, 8, 128).expect("manifest");
        let entry = find_manifest_entry(&manifest.entries, b"victim");
        let raw_name = RedactedBytes::new(b"victim".to_vec());
        let captured = capture_known_file(
            &layout.secret_fd,
            &raw_name,
            entry.stat,
            KnownFilePurpose::Metadata,
        )
        .expect("captured victim");

        assert_eq!(
            remove_exact_known_file(
                &layout.secret_fd,
                "victim",
                KnownFilePurpose::Metadata,
                captured.stat,
                captured.content.expose(),
                || fs::hard_link(&victim, &alias).expect("raced hard link"),
            )
            .unwrap_err(),
            SecretFsError::ArtifactChanged
        );
        assert!(!victim.exists());
        assert_eq!(
            fs::read(&alias).expect("hard-linked evidence retained"),
            b"retained secret"
        );
    }

    #[test]
    fn raw_filename_creation_unavailable_recognizes_ilseq_without_hiding_unrelated_errors() {
        let ilseq = io::Error::from_raw_os_error(Errno::ILSEQ.raw_os_error());
        assert!(raw_filename_creation_is_unavailable(&ilseq));

        let unrelated = io::Error::from_raw_os_error(Errno::NOENT.raw_os_error());
        assert!(!raw_filename_creation_is_unavailable(&unrelated));
    }

    #[test]
    fn raw_non_utf8_artifact_name_is_occupied_without_normalization() {
        let raw_name = b"artifact-\xff";
        let retained_name = RedactedBytes::new(raw_name.to_vec());
        assert_eq!(retained_name.expose(), raw_name);
        assert!(TopLevelArtifactName::parse(retained_name.expose()).is_err());
        assert!(!format!("{retained_name:?}").contains("artifact"));

        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let locked = AuthInstanceLayout::open_or_create(&root)
            .expect("layout")
            .lock()
            .expect("locked layout");
        let artifact = root
            .join(SECRET_DIRECTORY_NAME)
            .join(OsString::from_vec(raw_name.to_vec()));
        match fs::write(&artifact, b"synthetic") {
            Ok(()) => {}
            Err(error) if raw_filename_creation_is_unavailable(&error) => {
                return;
            }
            Err(error) => panic!("unexpected raw artifact error: {error}"),
        }

        let snapshot = locked
            .capture_secret_artifacts()
            .expect("artifact snapshot");
        assert!(!snapshot.is_lock_only());
        assert!(snapshot.observations.iter().any(|entry| matches!(
            entry,
            PinnedTopLevelArtifact::UnrecognizedPresent { raw_name: observed, .. }
                if observed.expose() == raw_name
        )));
        assert_eq!(fs::read(artifact).expect("artifact retained"), b"synthetic");
    }

    #[test]
    fn typed_inventory_preserves_codec_progress_unknown_entries_and_redacted_bytes() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let locked = AuthInstanceLayout::open_or_create(&root)
            .expect("layout")
            .lock()
            .expect("locked layout");
        let secrets = secret_root(&root);

        let keyring = Keyring::from_test_seeds(1, 10, [0x31; 32], None)
            .expect("synthetic active keyring")
            .encode();
        owner_file(&secrets.join(ACTIVE_KEYRING_FILE), keyring.expose_secret());
        let reservation = secrets.join(INITIALIZE_ONE);
        owner_directory(&reservation);
        owner_file(&reservation.join("metadata"), b"POV");
        owner_file(&reservation.join("staged-keyring"), &[0_u8; 261]);
        owner_file(&reservation.join("prepared"), b"");
        fs::write(reservation.join("unknown-file"), b"nested-marker").expect("unknown nested file");
        fs::create_dir(reservation.join("unknown-directory")).expect("unknown nested directory");
        owner_file(&secrets.join(INSTALL_ONE), b"partial-temp");
        owner_file(&secrets.join(INSTALL_TWO), &[0_u8; 261]);
        fs::write(secrets.join(".unknown-top"), b"top-marker").expect("unknown top-level file");

        let snapshot = locked
            .capture_secret_artifacts()
            .expect("typed artifact snapshot");
        snapshot
            .revalidate(&locked.layout.secret_fd)
            .expect("stable same-FD revalidation");
        assert!(!snapshot.is_lock_only());
        assert!(!snapshot.namespace.is_valid);

        assert!(snapshot.observations.iter().any(|entry| matches!(
            entry,
            PinnedTopLevelArtifact::ActiveKeyring {
                codec: CodecObservation::Valid,
                ..
            }
        )));
        assert!(snapshot.observations.iter().any(|entry| matches!(
            entry,
            PinnedTopLevelArtifact::InstallTemp {
                codec: CodecObservation::Incomplete,
                ..
            }
        )));
        assert!(snapshot.observations.iter().any(|entry| matches!(
            entry,
            PinnedTopLevelArtifact::InstallTemp {
                codec: CodecObservation::Invalid,
                ..
            }
        )));
        let reservation = snapshot
            .observations
            .iter()
            .find_map(|entry| match entry {
                PinnedTopLevelArtifact::Transition { directory, .. } => Some(directory),
                _ => None,
            })
            .expect("transition observation");
        assert_eq!(
            reservation.linkage,
            SemanticLinkageObservation::NotObservable
        );
        assert!(reservation.entries.iter().any(|entry| matches!(
            entry,
            PinnedReservationEntry::Metadata {
                codec: CodecObservation::Incomplete,
                ..
            }
        )));
        assert!(reservation.entries.iter().any(|entry| matches!(
            entry,
            PinnedReservationEntry::StagedKeyring {
                codec: CodecObservation::Invalid,
                ..
            }
        )));
        assert!(
            reservation
                .entries
                .iter()
                .any(|entry| matches!(entry, PinnedReservationEntry::Prepared { .. }))
        );
        let unknown_kinds: Vec<FileKind> = reservation
            .entries
            .iter()
            .filter_map(|entry| match entry {
                PinnedReservationEntry::UnrecognizedPresent { stat, .. } => {
                    Some(stat.identity.file_type)
                }
                _ => None,
            })
            .collect();
        assert!(unknown_kinds.contains(&FileKind::Regular));
        assert!(unknown_kinds.contains(&FileKind::Directory));
        assert!(snapshot.observations.iter().any(|entry| matches!(
            entry,
            PinnedTopLevelArtifact::UnrecognizedPresent { stat, .. }
                if stat.identity.file_type == FileKind::Regular
        )));

        let rendered = format!(
            "{snapshot:?} {:?} {:?}",
            snapshot.manifest, snapshot.observations
        );
        for forbidden in [
            "auth-keyring",
            "unknown-file",
            "nested-marker",
            "top-marker",
            "00000000-0000-4000",
        ] {
            assert!(!rendered.contains(forbidden));
        }
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn reservation_linkage_preserves_partial_staged_phase_and_rejects_actual_mismatch() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let locked = AuthInstanceLayout::open_or_create(&root)
            .expect("layout")
            .lock()
            .expect("locked layout");
        let reservation = secret_root(&root).join(INITIALIZE_ONE);
        owner_directory(&reservation);

        let expected_keyring = Keyring::from_test_seeds(1, 1_700_000_000_000_000, [0x31; 32], None)
            .expect("expected staged keyring");
        let metadata = initialization_metadata(&expected_keyring);
        let staged = expected_keyring.encode();
        owner_file(&reservation.join("metadata"), metadata.expose_secret());
        owner_file(
            &reservation.join("staged-keyring"),
            &staged.expose_secret()[..32],
        );

        let partial = locked
            .capture_secret_artifacts()
            .expect("partial staged snapshot");
        let partial_reservation = partial
            .observations
            .iter()
            .find_map(|entry| match entry {
                PinnedTopLevelArtifact::Transition { directory, .. } => Some(directory),
                _ => None,
            })
            .expect("transition observation");
        assert_eq!(
            partial_reservation.linkage,
            SemanticLinkageObservation::NotObservable
        );
        assert_eq!(
            partial_reservation.semantic_state(),
            super::RetainedArtifactState::Incomplete
        );
        drop(partial);

        let mismatched_keyring =
            Keyring::from_test_seeds(1, 1_700_000_000_000_000, [0x42; 32], None)
                .expect("mismatched staged keyring")
                .encode();
        owner_file(
            &reservation.join("staged-keyring"),
            mismatched_keyring.expose_secret(),
        );
        let mismatched = locked
            .capture_secret_artifacts()
            .expect("mismatched staged snapshot");
        let mismatched_reservation = mismatched
            .observations
            .iter()
            .find_map(|entry| match entry {
                PinnedTopLevelArtifact::Transition { directory, .. } => Some(directory),
                _ => None,
            })
            .expect("transition observation");
        assert_eq!(
            mismatched_reservation.linkage,
            SemanticLinkageObservation::Invalid
        );
        assert_eq!(
            mismatched_reservation.semantic_state(),
            super::RetainedArtifactState::Invalid
        );
    }

    #[test]
    fn known_artifact_shapes_and_size_bounds_fail_without_mutation() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let locked = AuthInstanceLayout::open_or_create(&root)
            .expect("layout")
            .lock()
            .expect("locked layout");
        let secrets = secret_root(&root);
        let active = secrets.join(ACTIVE_KEYRING_FILE);
        let external = directory.path().join("external");
        owner_file(&external, b"external-canary");

        symlink(&external, &active).expect("known symlink");
        assert_eq!(
            locked.capture_secret_artifacts().unwrap_err(),
            SecretFsError::UnsafeAuthArtifact
        );
        assert!(
            fs::symlink_metadata(&active)
                .expect("symlink retained")
                .file_type()
                .is_symlink()
        );
        fs::remove_file(&active).expect("remove known symlink");

        if let Some(socket) = try_bind_unix_listener(&active) {
            assert_eq!(
                locked.capture_secret_artifacts().unwrap_err(),
                SecretFsError::UnsafeAuthArtifact
            );
            drop(socket);
            assert!(
                fs::symlink_metadata(&active)
                    .expect("socket retained")
                    .file_type()
                    .is_socket()
            );
            fs::remove_file(&active).expect("remove known socket");
        }

        if try_create_fifo(&active) {
            fs::set_permissions(&active, fs::Permissions::from_mode(OWNER_FILE_MODE))
                .expect("fifo mode");
            assert_eq!(
                locked.capture_secret_artifacts().unwrap_err(),
                SecretFsError::UnsafeAuthArtifact
            );
            assert!(active.exists());
            fs::remove_file(&active).expect("remove known FIFO");
        }

        owner_file(&active, b"");
        let alias = directory.path().join("active-alias");
        fs::hard_link(&active, &alias).expect("known hard link");
        assert_eq!(
            locked.capture_secret_artifacts().unwrap_err(),
            SecretFsError::UnsafeAuthArtifact
        );
        assert_eq!(
            fs::symlink_metadata(&active)
                .expect("hard-linked artifact retained")
                .nlink(),
            2
        );
        fs::remove_file(&alias).expect("remove hard-link alias");
        fs::remove_file(&active).expect("remove hard-linked artifact");

        owner_file(&active, b"");
        fs::set_permissions(&active, fs::Permissions::from_mode(0o640)).expect("wrong file mode");
        assert_eq!(
            locked.capture_secret_artifacts().unwrap_err(),
            SecretFsError::UnsafeAuthArtifact
        );
        assert_eq!(
            fs::symlink_metadata(&active)
                .expect("wrong-mode artifact retained")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        fs::remove_file(&active).expect("remove wrong-mode artifact");

        owner_file(&active, b"");
        fs::set_permissions(&active, fs::Permissions::from_mode(0o1600))
            .expect("special-bit file mode");
        assert_eq!(
            locked.capture_secret_artifacts().unwrap_err(),
            SecretFsError::UnsafeAuthArtifact
        );
        assert_eq!(
            fs::symlink_metadata(&active)
                .expect("special-bit artifact retained")
                .permissions()
                .mode()
                & 0o7777,
            0o1600
        );
        fs::remove_file(&active).expect("remove special-bit artifact");

        owner_file(&active, &[0_u8; 262]);
        assert_eq!(
            locked.capture_secret_artifacts().unwrap_err(),
            SecretFsError::UnsafeAuthArtifact
        );
        assert_eq!(fs::metadata(&active).expect("oversize retained").len(), 262);
        fs::remove_file(&active).expect("remove oversized active keyring");

        let transition = secrets.join(INITIALIZE_ONE);
        owner_file(&transition, b"wrong type");
        assert_eq!(
            locked.capture_secret_artifacts().unwrap_err(),
            SecretFsError::UnsafeAuthArtifact
        );
        assert!(transition.is_file());
        fs::remove_file(&transition).expect("remove wrong-type transition");

        owner_directory(&transition);
        owner_file(&transition.join("prepared"), b"x");
        assert_eq!(
            locked.capture_secret_artifacts().unwrap_err(),
            SecretFsError::UnsafeAuthArtifact
        );
        assert_eq!(
            fs::read(transition.join("prepared")).expect("prepared retained"),
            b"x"
        );
        fs::remove_dir_all(&transition).expect("remove unsafe reservation");

        owner_directory(&transition);
        owner_file(&transition.join("metadata"), &[0_u8; 513]);
        assert_eq!(
            locked.capture_secret_artifacts().unwrap_err(),
            SecretFsError::UnsafeAuthArtifact
        );
        fs::remove_dir_all(&transition).expect("remove oversized metadata reservation");

        owner_directory(&transition);
        owner_file(&transition.join("staged-keyring"), &[0_u8; 262]);
        assert_eq!(
            locked.capture_secret_artifacts().unwrap_err(),
            SecretFsError::UnsafeAuthArtifact
        );
        fs::remove_dir_all(&transition).expect("remove oversized staged reservation");

        owner_file(&secrets.join(INSTALL_ONE), &[0_u8; 262]);
        assert_eq!(
            locked.capture_secret_artifacts().unwrap_err(),
            SecretFsError::UnsafeAuthArtifact
        );
        assert_eq!(
            fs::read(&external).expect("external canary retained"),
            b"external-canary"
        );
    }

    #[test]
    fn unknown_special_files_are_preserved_as_unrecognized_occupied_entries() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let locked = AuthInstanceLayout::open_or_create(&root)
            .expect("layout")
            .lock()
            .expect("locked layout");
        let secrets = secret_root(&root);
        let external = directory.path().join("external");
        owner_file(&external, b"external");
        symlink(&external, secrets.join("unknown-link")).expect("unknown symlink");
        let socket = try_bind_unix_listener(&secrets.join("unknown-socket"));
        let fifo = secrets.join("unknown-fifo");
        let fifo_created = try_create_fifo(&fifo);

        let snapshot = locked
            .capture_secret_artifacts()
            .expect("unknown special-file snapshot");
        assert!(!snapshot.is_lock_only());
        let unknown_count = snapshot
            .observations
            .iter()
            .filter(|entry| matches!(entry, PinnedTopLevelArtifact::UnrecognizedPresent { .. }))
            .count();
        assert_eq!(
            unknown_count,
            1 + usize::from(socket.is_some()) + usize::from(fifo_created)
        );
        snapshot
            .revalidate(&locked.layout.secret_fd)
            .expect("unknown special files remain stable");
        assert_eq!(fs::read(&external).expect("external retained"), b"external");
        drop(socket);
    }

    #[test]
    fn namespace_cardinality_orphan_and_id_linkage_are_typed_invalid() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let locked = AuthInstanceLayout::open_or_create(&root)
            .expect("layout")
            .lock()
            .expect("locked layout");
        let secrets = secret_root(&root);

        owner_file(&secrets.join(INSTALL_ONE), b"partial");
        let orphan = locked
            .capture_secret_artifacts()
            .expect("orphan install observation");
        assert!(!orphan.namespace.is_valid);
        drop(orphan);
        fs::remove_file(secrets.join(INSTALL_ONE)).expect("remove orphan temp");

        owner_directory(&secrets.join(INITIALIZE_ONE));
        owner_directory(&secrets.join(INITIALIZE_TWO));
        let multiple = locked
            .capture_secret_artifacts()
            .expect("multiple reservation observation");
        assert!(!multiple.namespace.is_valid);
        drop(multiple);
        fs::remove_dir(secrets.join(INITIALIZE_TWO)).expect("remove second reservation");

        owner_file(&secrets.join(INSTALL_TWO), b"partial");
        let mismatched = locked
            .capture_secret_artifacts()
            .expect("mismatched ID observation");
        assert!(!mismatched.namespace.is_valid);
        drop(mismatched);
        fs::remove_file(secrets.join(INSTALL_TWO)).expect("remove mismatched temp");

        owner_file(&secrets.join(INSTALL_ONE), b"partial");
        owner_file(&secrets.join(ACTIVE_KEYRING_FILE), &[0_u8; 170]);
        let matched = locked
            .capture_secret_artifacts()
            .expect("matched namespace observation");
        assert!(matched.namespace.is_valid);
        assert!(!matched.is_lock_only());
        assert!(matched.observations.iter().any(|entry| matches!(
            entry,
            PinnedTopLevelArtifact::ActiveKeyring {
                codec: CodecObservation::Invalid,
                ..
            }
        )));
    }

    #[test]
    fn manifest_open_and_post_capture_races_are_detected_on_pinned_descriptors() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let locked = AuthInstanceLayout::open_or_create(&root)
            .expect("layout")
            .lock()
            .expect("locked layout");
        let secrets = secret_root(&root);
        let active = secrets.join(ACTIVE_KEYRING_FILE);

        owner_file(&active, b"manifest");
        let manifest = read_artifact_manifest(
            &locked.layout.secret_fd,
            super::MAX_SECRET_DIRECTORY_ENTRIES,
            super::MAX_SECRET_DIRECTORY_NAME_BYTES,
        )
        .expect("stale manifest");
        let stale = find_manifest_entry(&manifest.entries, ACTIVE_KEYRING_FILE.as_bytes());
        let moved = secrets.join("moved-active");
        fs::rename(&active, &moved).expect("move manifest inode");
        owner_file(&active, b"manifest");
        assert_eq!(
            capture_known_file(
                &locked.layout.secret_fd,
                &stale.raw_name,
                stale.stat,
                KnownFilePurpose::ActiveKeyring,
            )
            .unwrap_err(),
            SecretFsError::ArtifactChanged
        );
        assert_eq!(fs::read(&moved).expect("old inode retained"), b"manifest");
        fs::remove_file(&moved).expect("remove moved inode");
        fs::remove_file(&active).expect("remove replacement inode");

        owner_file(&active, b"aaaaaaaa");
        let inode = fs::metadata(&active).expect("active metadata").ino();
        let same_inode = locked
            .capture_secret_artifacts()
            .expect("same-inode snapshot");
        owner_file(&active, b"bbbbbbbb");
        assert_eq!(
            fs::metadata(&active).expect("mutated metadata").ino(),
            inode
        );
        assert_eq!(
            same_inode.revalidate(&locked.layout.secret_fd).unwrap_err(),
            SecretFsError::ArtifactChanged
        );
        assert_eq!(fs::read(&active).expect("mutation retained"), b"bbbbbbbb");
        drop(same_inode);
        fs::remove_file(&active).expect("remove same-inode artifact");

        owner_file(&active, b"replacement");
        let replaced = locked
            .capture_secret_artifacts()
            .expect("replacement snapshot");
        let moved = secrets.join("post-db-active");
        fs::rename(&active, &moved).expect("move captured inode");
        owner_file(&active, b"replacement");
        assert_eq!(
            replaced.revalidate(&locked.layout.secret_fd).unwrap_err(),
            SecretFsError::ArtifactChanged
        );
        assert!(active.exists());
        assert!(moved.exists());
        drop(replaced);
        fs::remove_file(&active).expect("remove replacement");
        fs::remove_file(&moved).expect("remove captured inode");

        let reservation = secrets.join(INITIALIZE_ONE);
        owner_directory(&reservation);
        let nested = locked
            .capture_secret_artifacts()
            .expect("nested manifest snapshot");
        fs::write(reservation.join("late-entry"), b"late").expect("late nested entry");
        assert_eq!(
            nested.revalidate(&locked.layout.secret_fd).unwrap_err(),
            SecretFsError::ArtifactChanged
        );
        assert_eq!(
            fs::read(reservation.join("late-entry")).expect("late entry retained"),
            b"late"
        );
        drop(nested);
        fs::remove_dir_all(&reservation).expect("remove nested reservation");

        let install = secrets.join(INSTALL_ONE);
        owner_file(&install, b"small");
        let growing = locked.capture_secret_artifacts().expect("growth snapshot");
        let mut writer = fs::OpenOptions::new()
            .append(true)
            .open(&install)
            .expect("open install for growth");
        writer.write_all(&[0x55; 300]).expect("grow install");
        writer.sync_all().expect("sync growth");
        drop(writer);
        assert_eq!(
            growing.revalidate(&locked.layout.secret_fd).unwrap_err(),
            SecretFsError::ArtifactChanged
        );
        assert!(fs::metadata(&install).expect("grown temp retained").len() > 261);
    }

    #[test]
    fn final_parent_path_and_top_manifest_checks_close_post_observation_races() {
        let reservation_fixture = tempdir().expect("reservation race fixture");
        let reservation_root = reservation_fixture.path().join("instance");
        let reservation_locked = AuthInstanceLayout::open_or_create(&reservation_root)
            .expect("reservation layout")
            .lock()
            .expect("reservation lock");
        let secrets = secret_root(&reservation_root);
        let reservation = secrets.join(INITIALIZE_ONE);
        let moved_reservation = secrets.join("moved-reservation");
        owner_directory(&reservation);
        let reservation_snapshot = reservation_locked
            .capture_secret_artifacts()
            .expect("reservation snapshot");
        let (raw_name, pinned_reservation) = reservation_snapshot
            .observations
            .iter()
            .find_map(|entry| match entry {
                PinnedTopLevelArtifact::Transition {
                    raw_name,
                    directory,
                } => Some((raw_name, directory)),
                _ => None,
            })
            .expect("reservation observation");
        assert_eq!(
            pinned_reservation
                .revalidate_with_checkpoint(&reservation_locked.layout.secret_fd, raw_name, || {
                    fs::rename(&reservation, &moved_reservation)
                        .expect("move observed reservation");
                    owner_directory(&reservation);
                },)
                .unwrap_err(),
            SecretFsError::ArtifactChanged
        );
        assert!(reservation.is_dir());
        assert!(moved_reservation.is_dir());

        let manifest_fixture = tempdir().expect("manifest race fixture");
        let manifest_root = manifest_fixture.path().join("instance");
        let manifest_locked = AuthInstanceLayout::open_or_create(&manifest_root)
            .expect("manifest layout")
            .lock()
            .expect("manifest lock");
        let manifest_snapshot = manifest_locked
            .capture_secret_artifacts()
            .expect("top-level manifest snapshot");
        let late_artifact = secret_root(&manifest_root).join(".late-artifact");
        assert_eq!(
            manifest_snapshot
                .revalidate_with_checkpoint(&manifest_locked.layout.secret_fd, || {
                    owner_file(&late_artifact, b"late");
                })
                .unwrap_err(),
            SecretFsError::ArtifactChanged
        );
        assert_eq!(
            fs::read(&late_artifact).expect("late artifact retained"),
            b"late"
        );
    }

    #[test]
    fn fresh_layout_and_persistent_lock_are_owner_only_pinned_and_redacted() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let layout = AuthInstanceLayout::open_or_create(&root).expect("fresh layout");
        let expected_directories = [
            root.clone(),
            root.join(STORE_DIRECTORY_NAME),
            root.join(SECRET_DIRECTORY_NAME),
        ];
        for path in expected_directories {
            let metadata = fs::symlink_metadata(&path).expect("directory metadata");
            assert!(metadata.is_dir());
            assert_eq!(metadata.permissions().mode() & 0o777, OWNER_DIRECTORY_MODE);
        }

        let rendered_layout = format!("{layout:?}");
        assert!(!rendered_layout.contains(root.to_string_lossy().as_ref()));
        assert!(rendered_layout.contains("[REDACTED]"));

        let lease = layout.acquire_auth_lock().expect("first lease");
        let lock_path = root.join(SECRET_DIRECTORY_NAME).join(AUTH_LOCK_FILE_NAME);
        let lock_metadata = fs::symlink_metadata(&lock_path).expect("lock metadata");
        assert!(lock_metadata.is_file());
        assert_eq!(lock_metadata.permissions().mode() & 0o777, OWNER_FILE_MODE);
        assert_eq!(lock_metadata.nlink(), 1);
        assert!(
            fcntl_getfd(&lease.lock_fd)
                .expect("lock descriptor flags")
                .contains(FdFlags::CLOEXEC)
        );
        assert!(!format!("{lease:?}").contains(root.to_string_lossy().as_ref()));
        drop(lease);

        layout.acquire_auth_lock().expect("persistent lock reopens");
        assert!(lock_path.exists());
    }

    #[test]
    fn unsafe_existing_root_is_rejected_without_chmod_or_cleanup() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("unsafe root mode");

        assert_eq!(
            AuthInstanceLayout::open_or_create(&root).unwrap_err(),
            SecretFsError::UnsafeRoot
        );
        assert_eq!(
            fs::symlink_metadata(&root)
                .expect("root retained")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_extended_acls_are_rejected_on_instance_directories_and_lock_fd() {
        let root_fixture = tempdir().expect("root ACL fixture");
        let root = root_fixture.path().join("instance");
        owner_directory(&root);
        add_extended_acl(&root);
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root).unwrap_err(),
            SecretFsError::UnsafeRoot
        );

        let retained_root_fixture = tempdir().expect("retained root ACL fixture");
        let retained_root = retained_root_fixture.path().join("instance");
        let retained_root_layout =
            AuthInstanceLayout::open_or_create(&retained_root).expect("retained root layout");
        add_extended_acl(&retained_root);
        assert_eq!(
            retained_root_layout.revalidate().unwrap_err(),
            SecretFsError::UnsafeRoot
        );

        let initial_store_fixture = tempdir().expect("initial store ACL fixture");
        let initial_store_root = initial_store_fixture.path().join("instance");
        owner_directory(&initial_store_root);
        owner_directory(&initial_store_root.join(STORE_DIRECTORY_NAME));
        add_extended_acl(&initial_store_root.join(STORE_DIRECTORY_NAME));
        assert_eq!(
            AuthInstanceLayout::open_or_create(&initial_store_root).unwrap_err(),
            SecretFsError::UnsafeStoreDirectory
        );

        let store_fixture = tempdir().expect("store ACL fixture");
        let store_root = store_fixture.path().join("instance");
        let store_layout = AuthInstanceLayout::open_or_create(&store_root).expect("store layout");
        add_extended_acl(&store_root.join(STORE_DIRECTORY_NAME));
        assert_eq!(
            store_layout.revalidate().unwrap_err(),
            SecretFsError::UnsafeStoreDirectory
        );

        let initial_secret_fixture = tempdir().expect("initial secret ACL fixture");
        let initial_secret_root = initial_secret_fixture.path().join("instance");
        owner_directory(&initial_secret_root);
        owner_directory(&initial_secret_root.join(STORE_DIRECTORY_NAME));
        owner_directory(&secret_root(&initial_secret_root));
        add_extended_acl(&secret_root(&initial_secret_root));
        assert_eq!(
            AuthInstanceLayout::open_or_create(&initial_secret_root).unwrap_err(),
            SecretFsError::UnsafeSecretDirectory
        );

        let secret_fixture = tempdir().expect("secret ACL fixture");
        let secret_root_path = secret_fixture.path().join("instance");
        let secret_layout =
            AuthInstanceLayout::open_or_create(&secret_root_path).expect("secret layout");
        add_extended_acl(&secret_root(&secret_root_path));
        assert_eq!(
            secret_layout.revalidate().unwrap_err(),
            SecretFsError::UnsafeSecretDirectory
        );

        let initial_lock_fixture = tempdir().expect("initial lock ACL fixture");
        let initial_lock_root = initial_lock_fixture.path().join("instance");
        let initial_lock_layout =
            AuthInstanceLayout::open_or_create(&initial_lock_root).expect("initial lock layout");
        initial_lock_layout
            .acquire_auth_lock()
            .expect("create persistent lock");
        add_extended_acl(&secret_root(&initial_lock_root).join(AUTH_LOCK_FILE_NAME));
        assert_eq!(
            initial_lock_layout.acquire_auth_lock().unwrap_err(),
            SecretFsError::UnsafeLockFile
        );

        let lock_fixture = tempdir().expect("lock ACL fixture");
        let lock_root = lock_fixture.path().join("instance");
        let locked = AuthInstanceLayout::open_or_create(&lock_root)
            .expect("lock layout")
            .lock()
            .expect("lock");
        add_extended_acl(&secret_root(&lock_root).join(AUTH_LOCK_FILE_NAME));
        assert_eq!(
            locked.revalidate().unwrap_err(),
            SecretFsError::UnsafeLockFile
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_extended_acls_are_rejected_on_known_and_reservation_artifact_fds() {
        let initial_fixture = tempdir().expect("initial artifact ACL fixture");
        let initial_root = initial_fixture.path().join("instance");
        let initial_locked = AuthInstanceLayout::open_or_create(&initial_root)
            .expect("initial layout")
            .lock()
            .expect("initial lock");
        let active = secret_root(&initial_root).join(ACTIVE_KEYRING_FILE);
        owner_file(&active, b"partial");
        add_extended_acl(&active);
        assert_eq!(
            initial_locked.capture_secret_artifacts().unwrap_err(),
            SecretFsError::UnsafeAuthArtifact
        );

        let initial_directory_fixture = tempdir().expect("initial directory ACL fixture");
        let initial_directory_root = initial_directory_fixture.path().join("instance");
        let initial_directory_locked = AuthInstanceLayout::open_or_create(&initial_directory_root)
            .expect("initial directory layout")
            .lock()
            .expect("initial directory lock");
        let initial_reservation = secret_root(&initial_directory_root).join(INITIALIZE_ONE);
        owner_directory(&initial_reservation);
        add_extended_acl(&initial_reservation);
        assert_eq!(
            initial_directory_locked
                .capture_secret_artifacts()
                .unwrap_err(),
            SecretFsError::UnsafeAuthArtifact
        );

        let retained_file_fixture = tempdir().expect("retained file ACL fixture");
        let retained_file_root = retained_file_fixture.path().join("instance");
        let retained_file_locked = AuthInstanceLayout::open_or_create(&retained_file_root)
            .expect("retained file layout")
            .lock()
            .expect("retained file lock");
        let retained_active = secret_root(&retained_file_root).join(ACTIVE_KEYRING_FILE);
        owner_file(&retained_active, b"partial");
        let retained_file_snapshot = retained_file_locked
            .capture_secret_artifacts()
            .expect("retained file snapshot");
        add_extended_acl(&retained_active);
        let (raw_name, file) = retained_file_snapshot
            .observations
            .iter()
            .find_map(|entry| match entry {
                PinnedTopLevelArtifact::ActiveKeyring { raw_name, file, .. } => {
                    Some((raw_name, file))
                }
                _ => None,
            })
            .expect("active observation");
        assert_eq!(
            file.revalidate(&retained_file_locked.layout.secret_fd, raw_name)
                .unwrap_err(),
            SecretFsError::UnsafeAuthArtifact
        );

        let retained_directory_fixture = tempdir().expect("retained directory ACL fixture");
        let retained_directory_root = retained_directory_fixture.path().join("instance");
        let retained_directory_locked =
            AuthInstanceLayout::open_or_create(&retained_directory_root)
                .expect("retained directory layout")
                .lock()
                .expect("retained directory lock");
        let reservation = secret_root(&retained_directory_root).join(INITIALIZE_ONE);
        owner_directory(&reservation);
        let retained_directory_snapshot = retained_directory_locked
            .capture_secret_artifacts()
            .expect("retained directory snapshot");
        add_extended_acl(&reservation);
        let (raw_name, directory) = retained_directory_snapshot
            .observations
            .iter()
            .find_map(|entry| match entry {
                PinnedTopLevelArtifact::Transition {
                    raw_name,
                    directory,
                } => Some((raw_name, directory)),
                _ => None,
            })
            .expect("reservation observation");
        assert_eq!(
            directory
                .revalidate(&retained_directory_locked.layout.secret_fd, raw_name)
                .unwrap_err(),
            SecretFsError::UnsafeAuthArtifact
        );
    }

    #[test]
    fn root_symlink_and_non_directory_are_rejected_without_following_or_removing() {
        let directory = tempdir().expect("temporary parent");
        let target = directory.path().join("target");
        fs::create_dir(&target).expect("target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).expect("target mode");
        let root_link = directory.path().join("root-link");
        symlink(&target, &root_link).expect("root symlink");
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root_link).unwrap_err(),
            SecretFsError::UnsafeRoot
        );
        assert!(
            fs::symlink_metadata(&root_link)
                .expect("root link retained")
                .file_type()
                .is_symlink()
        );

        let root_file = directory.path().join("root-file");
        fs::write(&root_file, b"synthetic").expect("root file");
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root_file).unwrap_err(),
            SecretFsError::UnsafeRoot
        );
        assert_eq!(
            fs::read(&root_file).expect("root file retained"),
            b"synthetic"
        );
    }

    #[test]
    fn unsafe_child_directories_are_rejected_without_repair() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");

        let stores = root.join(STORE_DIRECTORY_NAME);
        fs::create_dir(&stores).expect("stores");
        fs::set_permissions(&stores, fs::Permissions::from_mode(0o755)).expect("stores mode");
        assert!(AuthInstanceLayout::open_or_create(&root).is_err());
        assert_eq!(
            fs::symlink_metadata(&stores)
                .expect("stores retained")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );

        fs::remove_dir(&stores).expect("remove synthetic stores");
        let external = directory.path().join("external");
        fs::create_dir(&external).expect("external");
        fs::set_permissions(&external, fs::Permissions::from_mode(0o700)).expect("external mode");
        symlink(&external, root.join(SECRET_DIRECTORY_NAME)).expect("secret symlink");
        assert!(AuthInstanceLayout::open_or_create(&root).is_err());
        assert!(
            fs::symlink_metadata(root.join(SECRET_DIRECTORY_NAME))
                .expect("secret link retained")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn unsafe_lock_artifacts_are_rejected_without_mutation() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let layout = AuthInstanceLayout::open_or_create(&root).expect("layout");
        let lock_path = root.join(SECRET_DIRECTORY_NAME).join(AUTH_LOCK_FILE_NAME);
        let external = directory.path().join("external");
        fs::write(&external, b"external").expect("external file");

        symlink(&external, &lock_path).expect("lock symlink");
        assert!(layout.acquire_auth_lock().is_err());
        assert!(
            fs::symlink_metadata(&lock_path)
                .expect("lock symlink retained")
                .file_type()
                .is_symlink()
        );
        fs::remove_file(&lock_path).expect("remove synthetic symlink");

        fs::write(&lock_path, b"").expect("lock file");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).expect("unsafe mode");
        assert_eq!(
            layout.acquire_auth_lock().unwrap_err(),
            SecretFsError::UnsafeLockFile
        );
        assert_eq!(
            fs::symlink_metadata(&lock_path)
                .expect("lock retained")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        fs::remove_file(&lock_path).expect("remove synthetic lock");

        fs::write(&lock_path, b"not empty").expect("non-empty lock file");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).expect("lock mode");
        assert_eq!(
            layout.acquire_auth_lock().unwrap_err(),
            SecretFsError::UnsafeLockFile
        );
        assert_eq!(
            fs::read(&lock_path).expect("non-empty lock retained"),
            b"not empty"
        );
        fs::remove_file(&lock_path).expect("remove non-empty lock");

        fs::create_dir(&lock_path).expect("lock directory");
        assert!(layout.acquire_auth_lock().is_err());
        assert!(lock_path.is_dir());
        fs::remove_dir(&lock_path).expect("remove synthetic lock directory");

        fs::write(&lock_path, b"").expect("lock file");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).expect("lock mode");
        let alias = directory.path().join("lock-alias");
        fs::hard_link(&lock_path, &alias).expect("hard link");
        assert_eq!(
            layout.acquire_auth_lock().unwrap_err(),
            SecretFsError::UnsafeLockFile
        );
        assert_eq!(
            fs::symlink_metadata(&lock_path)
                .expect("hard-linked lock retained")
                .nlink(),
            2
        );
        assert_eq!(fs::read(&external).expect("external retained"), b"external");
    }

    #[test]
    fn lock_contention_is_nonblocking_and_release_allows_reacquisition() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let first_layout = AuthInstanceLayout::open_or_create(&root).expect("first layout");
        let second_layout = AuthInstanceLayout::open_or_create(&root).expect("second layout");
        let first_lease = first_layout.acquire_auth_lock().expect("first lease");

        assert_eq!(
            second_layout.acquire_auth_lock().unwrap_err(),
            SecretFsError::AlreadyLocked
        );
        drop(first_lease);
        second_layout.acquire_auth_lock().expect("lock released");
    }

    #[tokio::test]
    async fn locked_instance_binds_matching_conversation_store_for_its_full_lifetime() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let layout = AuthInstanceLayout::open_or_create(&root).expect("layout");
        let contender = AuthInstanceLayout::open_or_create(&root).expect("contender");
        let stores = StoreSet::open(root.join(STORE_DIRECTORY_NAME))
            .await
            .expect("stores");

        let context = layout
            .lock()
            .expect("locked instance")
            .bind_conversation(&stores.conversation)
            .expect("matching conversation store");
        context
            .revalidate_conversation()
            .expect("binding remains valid");
        let rendered = format!("{context:?}");
        assert!(!rendered.contains(root.to_string_lossy().as_ref()));
        assert!(rendered.contains("[HELD]"));
        assert!(rendered.contains("[BOUND]"));

        assert_eq!(contender.lock().unwrap_err(), SecretFsError::AlreadyLocked);
        drop(context);
        AuthInstanceLayout::open_or_create(&root)
            .expect("released layout")
            .lock()
            .expect("context drop releases lock");
    }

    #[tokio::test]
    async fn cross_instance_conversation_store_is_rejected_without_leaking_paths() {
        let directory = tempdir().expect("temporary parent");
        let first_root = directory.path().join("first-instance");
        let second_root = directory.path().join("second-instance");
        let layout = AuthInstanceLayout::open_or_create(&first_root).expect("first layout");
        AuthInstanceLayout::open_or_create(&second_root).expect("second layout");
        let stores = StoreSet::open(second_root.join(STORE_DIRECTORY_NAME))
            .await
            .expect("second stores");

        let error = layout
            .lock()
            .expect("first lock")
            .bind_conversation(&stores.conversation)
            .unwrap_err();
        assert_eq!(error, AuthStoreBindingError::ConversationStoreMismatch);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(first_root.to_string_lossy().as_ref()));
        assert!(!rendered.contains(second_root.to_string_lossy().as_ref()));

        AuthInstanceLayout::open_or_create(&first_root)
            .expect("first layout reopens")
            .lock()
            .expect("failed bind releases the lock");
    }

    #[tokio::test]
    async fn replaced_store_directory_invalidates_binding_but_context_keeps_lock() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let store_root = root.join(STORE_DIRECTORY_NAME);
        let moved_store_root = root.join("moved-stores");
        let layout = AuthInstanceLayout::open_or_create(&root).expect("layout");
        let stores = StoreSet::open(&store_root).await.expect("stores");
        let conversation_file_name = stores.conversation.file_name();
        let context = layout
            .lock()
            .expect("locked instance")
            .bind_conversation(&stores.conversation)
            .expect("initial binding");

        fs::rename(&store_root, &moved_store_root).expect("move original stores");
        fs::create_dir(&store_root).expect("replacement stores");
        fs::set_permissions(
            &store_root,
            fs::Permissions::from_mode(OWNER_DIRECTORY_MODE),
        )
        .expect("replacement mode");
        fs::rename(
            moved_store_root.join(conversation_file_name),
            store_root.join(conversation_file_name),
        )
        .expect("move same database inode under replacement directory");

        let error = context.revalidate_conversation().unwrap_err();
        assert!(matches!(
            error,
            AuthStoreBindingError::ConversationStoreUnavailable
                | AuthStoreBindingError::Filesystem(SecretFsError::IdentityChanged)
        ));
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(root.to_string_lossy().as_ref()));

        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("replacement layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );
        drop(context);
        AuthInstanceLayout::open_or_create(&root)
            .expect("replacement layout after drop")
            .lock()
            .expect("context drop releases replacement-visible lock");
    }

    #[tokio::test]
    async fn same_directory_database_replacement_cannot_rebind_context() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let store_root = root.join(STORE_DIRECTORY_NAME);
        let layout = AuthInstanceLayout::open_or_create(&root).expect("layout");
        let stores = StoreSet::open(&store_root).await.expect("stores");
        let database_path = store_root.join(stores.conversation.file_name());
        let moved_database_path = store_root.join("moved-conversation.sqlite3");
        let context = layout
            .lock()
            .expect("locked instance")
            .bind_conversation(&stores.conversation)
            .expect("initial binding");

        fs::rename(&database_path, &moved_database_path).expect("move bound database");
        fs::copy(&moved_database_path, &database_path).expect("replacement database inode");

        let error = context.revalidate_conversation().unwrap_err();
        assert_eq!(error, AuthStoreBindingError::ConversationStoreUnavailable);
        assert!(
            !format!("{error:?} {error}").contains(root.to_string_lossy().as_ref()),
            "binding error must not disclose the database path"
        );
        assert_eq!(
            AuthInstanceLayout::open_or_create(&root)
                .expect("contending layout")
                .lock()
                .unwrap_err(),
            SecretFsError::AlreadyLocked
        );
    }

    #[test]
    fn renamed_and_replaced_root_cannot_split_store_and_lock_instances() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let moved_root = directory.path().join("moved-instance");
        let original_layout = AuthInstanceLayout::open_or_create(&root).expect("original layout");

        fs::rename(&root, &moved_root).expect("rename original root");
        let replacement_layout =
            AuthInstanceLayout::open_or_create(&root).expect("replacement layout");
        let replacement_lease = replacement_layout
            .acquire_auth_lock()
            .expect("replacement lock");

        assert_eq!(
            original_layout.acquire_auth_lock().unwrap_err(),
            SecretFsError::IdentityChanged
        );
        assert!(
            !moved_root
                .join(SECRET_DIRECTORY_NAME)
                .join(AUTH_LOCK_FILE_NAME)
                .exists(),
            "stale layout must not create a lock under the renamed root"
        );
        drop(replacement_lease);
    }

    #[test]
    fn child_process_observes_contention_and_holder_crash_releases_the_lock() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let layout = AuthInstanceLayout::open_or_create(&root).expect("layout");
        let lease = layout.acquire_auth_lock().expect("parent lease");
        let status = helper_command(&root, "expect_busy")
            .status()
            .expect("contention helper");
        assert!(status.success());
        drop(lease);

        let ready = root.join(HELPER_READY_FILE);
        let mut holder = helper_command(&root, "hold")
            .spawn()
            .expect("holder helper");
        wait_for_file(&ready);
        holder.kill().expect("kill holder");
        holder.wait().expect("reap holder");
        fs::remove_file(&ready).expect("remove ready marker");
        layout
            .acquire_auth_lock()
            .expect("kernel releases crashed holder lock");
    }

    #[test]
    fn exec_child_cannot_retain_the_lock_after_holder_exit() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let layout = AuthInstanceLayout::open_or_create(&root).expect("layout");
        let status = helper_command(&root, "spawn_exec_and_exit")
            .status()
            .expect("exec helper");
        assert!(status.success());

        let pid_text =
            fs::read_to_string(root.join(HELPER_PID_FILE)).expect("grandchild pid marker");
        let pid_raw: i32 = pid_text.parse().expect("grandchild pid");
        let pid = Pid::from_raw(pid_raw).expect("positive grandchild pid");
        let acquisition = layout.acquire_auth_lock();
        let _ = kill_process(pid, Signal::KILL);
        fs::remove_file(root.join(HELPER_PID_FILE)).expect("remove pid marker");
        acquisition.expect("CLOEXEC prevents exec child from retaining the lock");
    }

    #[test]
    #[ignore]
    fn subprocess_helper() {
        let Ok(root) = env::var(HELPER_ROOT_ENV) else {
            return;
        };
        let mode = env::var(HELPER_MODE_ENV).expect("helper mode");
        let root = std::path::PathBuf::from(root);
        let layout = AuthInstanceLayout::open_or_create(&root).expect("helper layout");
        match mode.as_str() {
            "expect_busy" => {
                assert_eq!(
                    layout.acquire_auth_lock().unwrap_err(),
                    SecretFsError::AlreadyLocked
                );
            }
            "hold" => {
                let _lease = layout.acquire_auth_lock().expect("helper lease");
                fs::write(root.join(HELPER_READY_FILE), b"ready").expect("ready marker");
                loop {
                    thread::sleep(Duration::from_secs(60));
                }
            }
            "spawn_exec_and_exit" => {
                let _lease = layout.acquire_auth_lock().expect("helper lease");
                let child = Command::new("/bin/sleep")
                    .arg("60")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("exec grandchild");
                let child_id = child.id();
                std::mem::forget(child);
                fs::write(root.join(HELPER_PID_FILE), child_id.to_string()).expect("pid marker");
            }
            _ => panic!("unknown helper mode"),
        }
    }

    fn helper_command(root: &Path, mode: &str) -> Command {
        let mut command = Command::new(env::current_exe().expect("current test executable"));
        command
            .arg("--exact")
            .arg("auth::secret_fs::tests::subprocess_helper")
            .arg("--ignored")
            .arg("--nocapture")
            .env(HELPER_ROOT_ENV, root)
            .env(HELPER_MODE_ENV, mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    fn wait_for_file(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            assert!(Instant::now() < deadline, "helper did not become ready");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn lock_descriptor_is_not_exposed_in_debug() {
        let directory = tempdir().expect("temporary parent");
        let root = directory.path().join("instance");
        let layout = AuthInstanceLayout::open_or_create(&root).expect("layout");
        let lease = layout.acquire_auth_lock().expect("lease");
        let raw_fd = lease.lock_fd.as_raw_fd().to_string();
        let rendered = format!("{lease:?}");
        assert!(!rendered.contains(&raw_fd));
    }
}
