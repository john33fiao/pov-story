#![cfg(unix)]

use std::{ffi::OsStr, fs, path::Path, process::Command};

fn rejected(arguments: &[&OsStr], root: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_pov-api"))
        .args(arguments)
        .env_remove("POV_PASSWORD")
        .env_remove("POV_RECOVERY_CODE")
        .output()
        .expect("production subprocess");
    assert!(!output.status.success());
    let mut diagnostic = output.stdout;
    diagnostic.extend(output.stderr);
    assert!(
        !diagnostic
            .windows(root.as_os_str().len())
            .any(|bytes| bytes == root.as_os_str().as_encoded_bytes())
    );
    assert!(
        !root.exists(),
        "rejected dispatch must not create the instance root"
    );
}

#[test]
fn production_dispatch_rejects_noncanonical_and_secret_ingress_without_echo_or_mutation() {
    let parent = tempfile::tempdir().expect("temporary parent");
    let root = parent.path().join("sensitive-instance-name");
    let r = root.as_os_str();
    let cases: &[&[&OsStr]] = &[
        &[
            OsStr::new("auth"),
            OsStr::new("init"),
            OsStr::new("--unknown"),
        ],
        &[
            OsStr::new("auth"),
            OsStr::new("init"),
            OsStr::new("--instance-root"),
            r,
            OsStr::new("--login-id"),
            OsStr::new("sensitive-login"),
            OsStr::new("extra"),
        ],
        &[
            OsStr::new("auth"),
            OsStr::new("init"),
            OsStr::new("--instance-root"),
            r,
            OsStr::new("--instance-root"),
            r,
            OsStr::new("--login-id"),
            OsStr::new("sensitive-login"),
        ],
        &[
            OsStr::new("auth"),
            OsStr::new("init"),
            OsStr::new("--instance-root"),
            r,
            OsStr::new("--login-id"),
            OsStr::new("sensitive-login"),
            OsStr::new("--login-id"),
            OsStr::new("second"),
        ],
        &[
            OsStr::new("auth"),
            OsStr::new("init"),
            OsStr::new("--login-id"),
            OsStr::new("sensitive-login"),
            OsStr::new("--instance-root"),
            r,
        ],
        &[
            OsStr::new("auth"),
            OsStr::new("init"),
            OsStr::new("--instance-root"),
            r,
            OsStr::new("--login-id"),
            OsStr::new("sensitive-login"),
            OsStr::new("--password"),
            OsStr::new("secret-looking-value"),
        ],
        &[
            OsStr::new("auth"),
            OsStr::new("init"),
            OsStr::new("--instance-root"),
            r,
            OsStr::new("--login-id"),
            OsStr::new("sensitive-login"),
            OsStr::new("--recovery-code"),
            OsStr::new("secret-looking-value"),
        ],
        &[
            OsStr::new("auth"),
            OsStr::new("init"),
            OsStr::new("--instance-root"),
            r,
            OsStr::new("--login-id"),
            OsStr::new("sensitive-login"),
            OsStr::new("--secret"),
            OsStr::new("secret-looking-value"),
        ],
    ];
    for case in cases {
        rejected(case, &root);
    }
    assert_eq!(
        fs::read_dir(parent.path()).expect("empty parent").count(),
        0
    );
}

#[test]
fn exact_dispatch_with_redirected_stdio_has_no_secret_fallback_and_does_not_mutate() {
    let parent = tempfile::tempdir().expect("temporary parent");
    let root = parent.path().join("sensitive-instance-name");
    rejected(
        &[
            OsStr::new("auth"),
            OsStr::new("init"),
            OsStr::new("--instance-root"),
            root.as_os_str(),
            OsStr::new("--login-id"),
            OsStr::new("sensitive-login"),
        ],
        &root,
    );
}
