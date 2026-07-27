//! Small, audited platform bindings that keep unsafe operating-system FFI out of
//! the application and domain crates.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "this audited module is the sole boundary for macOS ACL FFI"
)]
mod macos {
    use std::{
        error::Error,
        ffi::{c_int, c_void},
        fmt, io,
        os::fd::{AsRawFd, BorrowedFd},
        ptr,
    };

    const ACL_TYPE_EXTENDED: c_int = 0x100;
    const ACL_FIRST_ENTRY: c_int = 0;
    const ENOENT: c_int = 2;

    type Acl = *mut c_void;
    type AclEntry = *mut c_void;

    unsafe extern "C" {
        fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> Acl;
        fn acl_get_entry(acl: Acl, entry_id: c_int, entry: *mut AclEntry) -> c_int;
        fn acl_free(object: *mut c_void) -> c_int;
    }

    /// Result of inspecting a descriptor for macOS extended ACL entries.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum ExtendedAclState {
        Absent,
        Present,
    }

    /// Content-free failure returned when macOS cannot conclusively inspect an
    /// extended ACL.
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub struct ExtendedAclInspectionError {
        kind: io::ErrorKind,
    }

    impl ExtendedAclInspectionError {
        fn last_os_error() -> Self {
            Self {
                kind: io::Error::last_os_error().kind(),
            }
        }

        fn invalid_result() -> Self {
            Self {
                kind: io::ErrorKind::InvalidData,
            }
        }

        pub fn kind(self) -> io::ErrorKind {
            self.kind
        }
    }

    impl fmt::Debug for ExtendedAclInspectionError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("ExtendedAclInspectionError")
        }
    }

    impl fmt::Display for ExtendedAclInspectionError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("extended ACL inspection failed")
        }
    }

    impl Error for ExtendedAclInspectionError {}

    /// Inspects the already-open descriptor without resolving a filesystem path.
    ///
    /// A non-null ACL object is reported as present only after its first entry
    /// can be inspected and the allocation can be released successfully.
    pub fn extended_acl_state(
        fd: BorrowedFd<'_>,
    ) -> Result<ExtendedAclState, ExtendedAclInspectionError> {
        // SAFETY: `fd` is borrowed for this call and therefore remains a valid,
        // open descriptor while macOS reads its extended ACL.
        let acl = unsafe { acl_get_fd_np(fd.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ENOENT) {
                Ok(ExtendedAclState::Absent)
            } else {
                Err(ExtendedAclInspectionError { kind: error.kind() })
            };
        }

        let mut entry: AclEntry = ptr::null_mut();
        // SAFETY: `acl` is the non-null allocation returned above, and `entry`
        // points to valid writable storage for the duration of this call.
        let iteration_status =
            unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, ptr::addr_of_mut!(entry)) };
        let iteration_error = if iteration_status == 0 && !entry.is_null() {
            None
        } else if iteration_status == 0 {
            Some(ExtendedAclInspectionError::invalid_result())
        } else {
            Some(ExtendedAclInspectionError::last_os_error())
        };

        // SAFETY: `acl` is exactly the allocation returned by `acl_get_fd_np`
        // above and has not previously been released.
        let free_status = unsafe { acl_free(acl.cast()) };
        if free_status != 0 {
            return Err(ExtendedAclInspectionError::last_os_error());
        }
        if let Some(error) = iteration_error {
            return Err(error);
        }
        Ok(ExtendedAclState::Present)
    }
}

#[cfg(target_os = "macos")]
pub use macos::{ExtendedAclInspectionError, ExtendedAclState, extended_acl_state};

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::{
        fs,
        os::{
            fd::AsFd,
            unix::fs::{OpenOptionsExt, PermissionsExt},
        },
        process::Command,
    };

    use tempfile::tempdir;

    use super::{ExtendedAclState, extended_acl_state};

    #[test]
    fn descriptor_acl_inspection_distinguishes_absent_and_present() {
        let directory = tempdir().expect("temporary ACL directory");
        let path = directory.path().join("artifact");
        let file = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .expect("owner-only artifact");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("owner-only artifact mode");
        assert_eq!(
            extended_acl_state(file.as_fd()).expect("inspect absent ACL"),
            ExtendedAclState::Absent
        );

        let output = Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&path)
            .output()
            .expect("run macOS chmod ACL command");
        assert!(
            output.status.success(),
            "macOS chmod ACL command failed with status {:?}",
            output.status.code()
        );
        assert_eq!(
            fs::symlink_metadata(&path)
                .expect("artifact metadata after chmod")
                .permissions()
                .mode()
                & 0o7777,
            0o600,
            "extended ACL must not rely on a traditional-mode mismatch"
        );
        assert_eq!(
            extended_acl_state(file.as_fd()).expect("inspect present ACL"),
            ExtendedAclState::Present
        );
    }
}
