#![cfg(unix)]

use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStringExt,
        fs::{PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use pov_core::{
    process::{
        CleanupStatus, ExecutableId, ExecutableRegistration, ExecutionTerminal, OutputStream,
        ProcessPolicy, ProcessSupervisor, TrustViolation, TrustedExecutableRegistry,
        WorkRootViolation,
    },
    provider::Sha256Digest,
};
use rustix::{
    io::Errno,
    process::{Pid, test_kill_process, test_kill_process_group},
};
use tempfile::TempDir;

const FIXTURE_ID: ExecutableId = ExecutableId::SyntheticFixture;

fn canonical_tempdir() -> (TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("owner-only temporary directory");
    let canonical = fs::canonicalize(directory.path()).expect("canonical temporary directory");
    (directory, canonical)
}

fn current_executable() -> PathBuf {
    fs::canonicalize(env::current_exe().expect("current test executable"))
        .expect("canonical test executable")
}

fn file_sha256(path: &Path) -> Sha256Digest {
    let mut file = fs::File::open(path).expect("open executable for digest");
    Sha256Digest::of_reader(&mut file).expect("digest executable")
}

fn fixture_arguments(fixture: &str, extra: &[&str]) -> Vec<OsString> {
    [
        "--ignored",
        "--exact",
        fixture,
        "--test-threads=1",
        "--no-capture",
        "--",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(OsString::from)
    .collect()
}

fn fixture_registry(fixture: &str, extra: &[&str]) -> TrustedExecutableRegistry {
    let executable = current_executable();
    let trusted_root = executable.parent().expect("test executable parent");
    TrustedExecutableRegistry::try_new(
        trusted_root.to_path_buf(),
        [ExecutableRegistration::new(
            FIXTURE_ID,
            executable.clone(),
            file_sha256(&executable),
            fixture_arguments(fixture, extra),
        )],
    )
    .expect("trusted self-spawn registry")
}

fn supervisor(
    fixture: &str,
    extra: &[&str],
    work_root: &Path,
    wall_time: Duration,
    output_limit: usize,
) -> ProcessSupervisor {
    ProcessSupervisor::try_new(
        fixture_registry(fixture, extra),
        work_root.to_path_buf(),
        ProcessPolicy::try_new(wall_time, Duration::from_secs(2), output_limit)
            .expect("bounded process policy"),
    )
    .expect("process supervisor")
}

fn attempt_contains(work_root: &Path, marker: &str) -> bool {
    fs::read_dir(work_root)
        .expect("read work root")
        .map(|entry| entry.expect("read work-root entry"))
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("pov-process-")
        })
        .any(|entry| entry.path().join(marker).exists())
}

fn attempt_marker(work_root: &Path, marker: &str) -> Option<String> {
    fs::read_dir(work_root)
        .expect("read work root")
        .map(|entry| entry.expect("read work-root entry"))
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("pov-process-")
        })
        .find_map(|entry| fs::read_to_string(entry.path().join(marker)).ok())
}

fn no_attempt_directories(work_root: &Path) -> bool {
    attempt_directory_count(work_root) == 0
}

fn attempt_directory_count(work_root: &Path) -> usize {
    fs::read_dir(work_root)
        .expect("read work root")
        .map(|entry| entry.expect("read work-root entry"))
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("pov-process-")
        })
        .count()
}

async fn wait_until(mut predicate: impl FnMut() -> bool, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

fn parsed_pid(work_root: &Path, marker: &str) -> Pid {
    let raw = attempt_marker(work_root, marker)
        .unwrap_or_else(|| panic!("missing {marker} marker"))
        .parse::<i32>()
        .unwrap_or_else(|_| panic!("invalid {marker} marker"));
    Pid::from_raw(raw).expect("positive fixture PID")
}

fn file_pid(path: &Path) -> Pid {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("missing PID file {}", path.display()))
        .parse::<i32>()
        .unwrap_or_else(|_| panic!("invalid PID file {}", path.display()));
    Pid::from_raw(raw).expect("positive fixture PID")
}

fn assert_process_absent(pid: Pid) {
    assert_eq!(test_kill_process(pid), Err(Errno::SRCH));
}

fn assert_process_group_absent(leader: Pid) {
    assert_eq!(test_kill_process_group(leader), Err(Errno::SRCH));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_contract_runs_without_a_shell_or_inherited_environment() {
    let (_work, work_root) = canonical_tempdir();
    let extra = [
        "space value",
        "line\nbreak",
        "'quote'",
        "$(touch ../shell-sentinel)",
        ";touch ../shell-sentinel",
        "-leading",
    ];
    let supervisor = supervisor(
        "fixture_contract",
        &extra,
        &work_root,
        Duration::from_secs(3),
        256 * 1024,
    );

    let report = supervisor.run(FIXTURE_ID).await.expect("execution report");

    assert_eq!(
        report.terminal(),
        ExecutionTerminal::Success,
        "{report:?}\nstdout={}\nstderr={}",
        String::from_utf8_lossy(report.stdout().as_bytes()),
        String::from_utf8_lossy(report.stderr().as_bytes())
    );
    assert_eq!(report.cleanup(), CleanupStatus::Complete);
    assert!(report.is_success());
    assert!(
        String::from_utf8_lossy(report.stdout().as_bytes()).contains("fixture-stdout"),
        "{report:?}"
    );
    assert!(
        String::from_utf8_lossy(report.stderr().as_bytes()).contains("fixture-stderr"),
        "{report:?}"
    );
    assert!(!work_root.join("shell-sentinel").exists());
    assert!(no_attempt_directories(&work_root));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nonzero_and_signal_terminations_are_typed() {
    let (_work, work_root) = canonical_tempdir();
    let nonzero = supervisor(
        "fixture_exit_23",
        &[],
        &work_root,
        Duration::from_secs(2),
        64 * 1024,
    )
    .run(FIXTURE_ID)
    .await
    .expect("nonzero report");
    let signalled = supervisor(
        "fixture_abort",
        &[],
        &work_root,
        Duration::from_secs(2),
        64 * 1024,
    )
    .run(FIXTURE_ID)
    .await
    .expect("signal report");

    assert_eq!(nonzero.terminal(), ExecutionTerminal::NonZeroExit(23));
    assert_eq!(nonzero.cleanup(), CleanupStatus::Complete);
    assert!(matches!(
        signalled.terminal(),
        ExecutionTerminal::Signalled(_)
    ));
    assert_eq!(signalled.cleanup(), CleanupStatus::Complete);
    assert!(no_attempt_directories(&work_root));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout_and_explicit_cancel_reap_the_attempt() {
    let (_work, work_root) = canonical_tempdir();
    let timeout_supervisor = supervisor(
        "fixture_wait",
        &[],
        &work_root,
        Duration::from_millis(600),
        64 * 1024,
    );
    let timeout_run = timeout_supervisor
        .start(FIXTURE_ID)
        .expect("start timeout run");
    assert!(
        wait_until(
            || attempt_contains(&work_root, "ready"),
            Duration::from_secs(2)
        )
        .await
    );
    let timeout_pid = parsed_pid(&work_root, "pid");
    let timed_out = timeout_run.await.expect("timeout report");
    assert_eq!(timed_out.terminal(), ExecutionTerminal::TimedOut);
    assert_eq!(timed_out.cleanup(), CleanupStatus::Complete);
    assert_process_absent(timeout_pid);
    assert_process_group_absent(timeout_pid);
    assert!(no_attempt_directories(&work_root));

    let supervisor = supervisor(
        "fixture_wait",
        &[],
        &work_root,
        Duration::from_secs(5),
        64 * 1024,
    );
    let run = supervisor.start(FIXTURE_ID).expect("start cancellable run");
    assert!(
        wait_until(
            || attempt_contains(&work_root, "ready"),
            Duration::from_secs(2)
        )
        .await
    );
    let cancelled_pid = parsed_pid(&work_root, "pid");
    run.cancel();
    let cancelled = run.await.expect("cancel report");

    assert_eq!(cancelled.terminal(), ExecutionTerminal::Cancelled);
    assert_eq!(cancelled.cleanup(), CleanupStatus::Complete);
    assert_process_absent(cancelled_pid);
    assert_process_group_absent(cancelled_pid);
    assert!(no_attempt_directories(&work_root));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_waiter_still_cancels_and_cleans_in_the_actor() {
    let (_work, work_root) = canonical_tempdir();
    let supervisor = supervisor(
        "fixture_wait",
        &[],
        &work_root,
        Duration::from_secs(5),
        64 * 1024,
    );
    let run = supervisor.start(FIXTURE_ID).expect("start detached actor");
    let waiter = tokio::spawn(run);
    assert!(
        wait_until(
            || attempt_contains(&work_root, "ready"),
            Duration::from_secs(2)
        )
        .await
    );
    let child_pid = parsed_pid(&work_root, "pid");

    waiter.abort();
    let _ = waiter.await;

    assert!(
        wait_until(
            || no_attempt_directories(&work_root),
            Duration::from_secs(3)
        )
        .await
    );
    assert_process_absent(child_pid);
    assert_process_group_absent(child_pid);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn output_flood_is_bounded_on_both_pipes_without_deadlock() {
    let (_work, work_root) = canonical_tempdir();
    let limit = 32 * 1024;
    let report = supervisor(
        "fixture_flood",
        &[],
        &work_root,
        Duration::from_secs(3),
        limit,
    )
    .run(FIXTURE_ID)
    .await
    .expect("flood report");

    assert!(matches!(
        report.terminal(),
        ExecutionTerminal::OutputLimitExceeded(OutputStream::Stdout | OutputStream::Stderr)
    ));
    assert_eq!(report.cleanup(), CleanupStatus::Complete);
    assert!(report.stdout().len() <= limit);
    assert!(report.stderr().len() <= limit);
    assert!(no_attempt_directories(&work_root));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_pipes_are_drained_concurrently_below_the_limit() {
    let (_work, work_root) = canonical_tempdir();
    let emitted = 128 * 1024;
    let report = supervisor(
        "fixture_dual_within_limit",
        &[],
        &work_root,
        Duration::from_secs(3),
        256 * 1024,
    )
    .run(FIXTURE_ID)
    .await
    .expect("dual-pipe report");

    assert!(report.is_success(), "{report:?}");
    assert_eq!(
        report
            .stdout()
            .as_bytes()
            .iter()
            .filter(|byte| **byte == 0x01)
            .count(),
        emitted
    );
    assert_eq!(
        report
            .stderr()
            .as_bytes()
            .iter()
            .filter(|byte| **byte == 0x02)
            .count(),
        emitted
    );
    assert!(no_attempt_directories(&work_root));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn short_overflow_is_reconciled_even_when_the_child_exits_immediately() {
    let (_work, work_root) = canonical_tempdir();
    let limit = 4 * 1024;
    let report = supervisor(
        "fixture_short_overflow",
        &[],
        &work_root,
        Duration::from_secs(2),
        limit,
    )
    .run(FIXTURE_ID)
    .await
    .expect("short overflow report");

    assert_eq!(
        report.terminal(),
        ExecutionTerminal::OutputLimitExceeded(OutputStream::Stdout),
        "{report:?}"
    );
    assert_eq!(report.cleanup(), CleanupStatus::Complete);
    assert_eq!(report.stdout().len(), limit);
    assert!(no_attempt_directories(&work_root));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout_kills_the_descendant_process_group_before_cleanup() {
    let (_work, work_root) = canonical_tempdir();
    let supervisor = supervisor(
        "fixture_tree_parent",
        &[],
        &work_root,
        Duration::from_millis(700),
        64 * 1024,
    );
    let run = supervisor.start(FIXTURE_ID).expect("tree timeout run");
    assert!(
        wait_until(
            || attempt_contains(&work_root, "descendant-ready"),
            Duration::from_secs(2)
        )
        .await
    );
    let parent_pid = parsed_pid(&work_root, "pid");
    let descendant_pid = parsed_pid(&work_root, "descendant-pid");
    let report = run.await.expect("tree timeout report");

    assert_eq!(report.terminal(), ExecutionTerminal::TimedOut);
    assert_eq!(report.cleanup(), CleanupStatus::Complete);
    assert_process_absent(parent_pid);
    assert_process_absent(descendant_pid);
    assert_process_group_absent(parent_pid);
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    assert!(!work_root.join("tree-sentinel").exists());
    assert!(no_attempt_directories(&work_root));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn natural_parent_exit_still_terminates_its_live_descendant_group() {
    let (_work, work_root) = canonical_tempdir();
    let report = supervisor(
        "fixture_tree_parent_exits",
        &[],
        &work_root,
        Duration::from_secs(3),
        64 * 1024,
    )
    .run(FIXTURE_ID)
    .await
    .expect("natural parent report");

    assert!(report.is_success(), "{report:?}");
    assert!(work_root.join("natural-descendant-ready").exists());
    let parent_pid = file_pid(&work_root.join("natural-parent-pid"));
    let descendant_pid = file_pid(&work_root.join("natural-descendant-pid"));
    assert_process_absent(parent_pid);
    assert_process_absent(descendant_pid);
    assert_process_group_absent(parent_pid);
    tokio::time::sleep(Duration::from_millis(1_700)).await;
    assert!(!work_root.join("tree-sentinel").exists());
    assert!(no_attempt_directories(&work_root));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_supervisors_share_one_process_slot() {
    let (_work, work_root) = canonical_tempdir();
    let first = supervisor(
        "fixture_serial",
        &[],
        &work_root,
        Duration::from_secs(3),
        64 * 1024,
    );
    let second = supervisor(
        "fixture_serial",
        &[],
        &work_root,
        Duration::from_secs(3),
        64 * 1024,
    );

    let first_run = first.start(FIXTURE_ID).expect("first serial run");
    let second_run = second.start(FIXTURE_ID).expect("second serial run");
    let (first_report, second_report) = tokio::join!(first_run, second_run);

    let first_report = first_report.expect("first report");
    let second_report = second_report.expect("second report");
    assert!(first_report.is_success(), "{first_report:?}");
    assert!(second_report.is_success(), "{second_report:?}");
    assert!(!work_root.join("active").exists());
    assert!(no_attempt_directories(&work_root));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_a_queued_run_does_not_create_an_attempt() {
    let (_work, work_root) = canonical_tempdir();
    let blocker = supervisor(
        "fixture_wait",
        &[],
        &work_root,
        Duration::from_secs(5),
        64 * 1024,
    );
    let queued = supervisor(
        "fixture_mark_started",
        &[],
        &work_root,
        Duration::from_secs(2),
        64 * 1024,
    );
    let blocker_run = blocker.start(FIXTURE_ID).expect("blocking run");
    assert!(
        wait_until(
            || attempt_contains(&work_root, "ready"),
            Duration::from_secs(2)
        )
        .await
    );

    let queued_run = queued.start(FIXTURE_ID).expect("queued run");
    queued_run.cancel();
    let queued_report = queued_run.await.expect("queued cancel report");

    assert_eq!(queued_report.terminal(), ExecutionTerminal::Cancelled);
    assert_eq!(queued_report.cleanup(), CleanupStatus::NotRequired);
    assert!(!work_root.join("second-started").exists());

    blocker_run.cancel();
    let blocker_report = blocker_run.await.expect("blocker cancel report");
    assert_eq!(blocker_report.cleanup(), CleanupStatus::Complete);
    assert!(no_attempt_directories(&work_root));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hash_drift_is_rejected_before_an_attempt_is_created() {
    let (_trusted, trusted_root) = canonical_tempdir();
    let executable = trusted_root.join("fixture-bin");
    fs::copy(current_executable(), &executable).expect("copy test executable");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
        .expect("make fixture executable");
    let expected = file_sha256(&executable);
    let registry = TrustedExecutableRegistry::try_new(
        trusted_root,
        [ExecutableRegistration::new(
            FIXTURE_ID,
            executable.clone(),
            expected,
            fixture_arguments("fixture_contract", &[]),
        )],
    )
    .expect("initially trusted registry");
    OpenOptions::new()
        .append(true)
        .open(&executable)
        .expect("open copied executable")
        .write_all(b"drift")
        .expect("mutate copied executable");
    let (_work, work_root) = canonical_tempdir();
    let supervisor = ProcessSupervisor::try_new(registry, &work_root, ProcessPolicy::default())
        .expect("supervisor");

    let report = supervisor.run(FIXTURE_ID).await.expect("rejection report");

    assert!(matches!(
        report.terminal(),
        ExecutionTerminal::ExecutableRejected(error)
            if error.violation() == TrustViolation::ExecutableHashMismatch
    ));
    assert_eq!(report.cleanup(), CleanupStatus::NotRequired);
    assert!(no_attempt_directories(&work_root));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unregistered_typed_identifier_is_rejected_without_an_attempt() {
    let (_work, work_root) = canonical_tempdir();
    let supervisor = supervisor(
        "fixture_contract",
        &[],
        &work_root,
        Duration::from_secs(2),
        64 * 1024,
    );

    let report = supervisor
        .run(ExecutableId::MediaProbe)
        .await
        .expect("unknown identifier report");

    assert!(matches!(
        report.terminal(),
        ExecutionTerminal::ExecutableRejected(error)
            if error.violation() == TrustViolation::UnknownIdentifier
    ));
    assert_eq!(report.cleanup(), CleanupStatus::NotRequired);
    assert!(no_attempt_directories(&work_root));
}

#[test]
fn nonnative_executable_format_is_rejected_before_spawn() {
    let (_trusted, trusted_root) = canonical_tempdir();
    let executable = trusted_root.join("invalid-bin");
    fs::write(&executable, b"not an executable image").expect("write invalid executable");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
        .expect("make invalid file executable");
    let error = TrustedExecutableRegistry::try_new(
        &trusted_root,
        [ExecutableRegistration::new(
            FIXTURE_ID,
            executable.clone(),
            file_sha256(&executable),
            [],
        )],
    )
    .expect_err("nonnative executable format rejected");

    assert_eq!(
        error.violation(),
        TrustViolation::ExecutableFormatUnsupported
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_fixed_argv_is_a_typed_spawn_failure_with_cleanup() {
    let executable = current_executable();
    let registry = TrustedExecutableRegistry::try_new(
        executable
            .parent()
            .expect("test executable parent")
            .to_path_buf(),
        [ExecutableRegistration::new(
            FIXTURE_ID,
            executable.clone(),
            file_sha256(&executable),
            [OsString::from_vec(b"nul\0argument".to_vec())],
        )],
    )
    .expect("trusted executable registry");
    let (_work, work_root) = canonical_tempdir();
    let supervisor = ProcessSupervisor::try_new(registry, &work_root, ProcessPolicy::default())
        .expect("supervisor");

    let report = supervisor
        .run(FIXTURE_ID)
        .await
        .expect("spawn failure report");

    assert_eq!(
        report.terminal(),
        ExecutionTerminal::SpawnFailed(std::io::ErrorKind::InvalidInput)
    );
    assert_eq!(report.cleanup(), CleanupStatus::Complete);
    assert!(no_attempt_directories(&work_root));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attempt_cleanup_unlinks_symlinks_without_deleting_external_targets() {
    let (_work, work_root) = canonical_tempdir();
    fs::write(work_root.join("external-target"), b"keep").expect("external target");
    let report = supervisor(
        "fixture_symlink",
        &[],
        &work_root,
        Duration::from_secs(2),
        64 * 1024,
    )
    .run(FIXTURE_ID)
    .await
    .expect("symlink fixture report");

    assert!(report.is_success());
    assert_eq!(
        fs::read(work_root.join("external-target")).expect("external target remains"),
        b"keep"
    );
    assert!(no_attempt_directories(&work_root));
}

#[test]
fn cleanup_failure_poisoning_blocks_the_next_attempt_in_an_isolated_process() {
    let output = Command::new(current_executable())
        .args([
            "--ignored",
            "--exact",
            "fixture_poison_supervisor_process",
            "--test-threads=1",
            "--no-capture",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("spawn isolated poison test");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn registry_rejects_untrusted_paths_and_registrations() {
    let executable = current_executable();
    let executable_root = executable.parent().expect("executable root").to_path_buf();
    let digest = file_sha256(&executable);

    let relative = TrustedExecutableRegistry::try_new(
        executable_root.clone(),
        [ExecutableRegistration::new(
            FIXTURE_ID,
            "relative-bin",
            digest,
            [],
        )],
    )
    .expect_err("relative executable rejected");
    assert_eq!(relative.violation(), TrustViolation::ExecutableNotAbsolute);

    let duplicate = TrustedExecutableRegistry::try_new(
        executable_root,
        [
            ExecutableRegistration::new(FIXTURE_ID, &executable, digest, []),
            ExecutableRegistration::new(FIXTURE_ID, &executable, digest, []),
        ],
    )
    .expect_err("duplicate identifier rejected");
    assert_eq!(duplicate.violation(), TrustViolation::DuplicateIdentifier);

    let (_trusted, trusted_root) = canonical_tempdir();
    let linked = trusted_root.join("linked-bin");
    symlink(&executable, &linked).expect("fixture symlink");
    let linked_error = TrustedExecutableRegistry::try_new(
        &trusted_root,
        [ExecutableRegistration::new(FIXTURE_ID, linked, digest, [])],
    )
    .expect_err("symlink executable rejected");
    assert_eq!(
        linked_error.violation(),
        TrustViolation::ExecutableIsSymlink
    );

    let outside_error = TrustedExecutableRegistry::try_new(
        &trusted_root,
        [ExecutableRegistration::new(
            FIXTURE_ID,
            &executable,
            digest,
            [],
        )],
    )
    .expect_err("outside executable rejected");
    assert_eq!(
        outside_error.violation(),
        TrustViolation::ExecutableOutsideRoot
    );
}

#[test]
fn registry_rejects_nonfiles_nonexecutables_and_hash_mismatches() {
    let (_trusted, trusted_root) = canonical_tempdir();
    let directory = trusted_root.join("directory-bin");
    fs::create_dir(&directory).expect("directory fixture");
    let directory_error = TrustedExecutableRegistry::try_new(
        &trusted_root,
        [ExecutableRegistration::new(
            FIXTURE_ID,
            directory,
            Sha256Digest::of(b"unused"),
            [],
        )],
    )
    .expect_err("directory rejected");
    assert_eq!(
        directory_error.violation(),
        TrustViolation::ExecutableNotRegularFile
    );

    let copied = trusted_root.join("copied-bin");
    fs::copy(current_executable(), &copied).expect("copy fixture executable");
    fs::set_permissions(&copied, fs::Permissions::from_mode(0o600))
        .expect("remove executable mode");
    let nonexecutable = TrustedExecutableRegistry::try_new(
        &trusted_root,
        [ExecutableRegistration::new(
            FIXTURE_ID,
            &copied,
            file_sha256(&copied),
            [],
        )],
    )
    .expect_err("nonexecutable rejected");
    assert_eq!(
        nonexecutable.violation(),
        TrustViolation::ExecutableNotRunnable
    );

    fs::set_permissions(&copied, fs::Permissions::from_mode(0o700))
        .expect("restore executable mode");
    let wrong_hash = TrustedExecutableRegistry::try_new(
        &trusted_root,
        [ExecutableRegistration::new(
            FIXTURE_ID,
            copied,
            Sha256Digest::of(b"wrong"),
            [],
        )],
    )
    .expect_err("hash mismatch rejected");
    assert_eq!(
        wrong_hash.violation(),
        TrustViolation::ExecutableHashMismatch
    );
}

#[test]
fn registry_rejects_a_writable_intermediate_executable_directory() {
    let (_trusted, trusted_root) = canonical_tempdir();
    let writable_directory = trusted_root.join("writable");
    fs::create_dir(&writable_directory).expect("intermediate directory");
    fs::set_permissions(&writable_directory, fs::Permissions::from_mode(0o777))
        .expect("make intermediate directory unsafe");
    let copied = writable_directory.join("copied-bin");
    fs::copy(current_executable(), &copied).expect("copy fixture executable");
    fs::set_permissions(&copied, fs::Permissions::from_mode(0o700))
        .expect("make copied fixture executable");
    let registration =
        || ExecutableRegistration::new(FIXTURE_ID, &copied, file_sha256(&copied), []);

    let error = TrustedExecutableRegistry::try_new(&trusted_root, [registration()])
        .expect_err("writable executable ancestor rejected");

    assert_eq!(
        error.violation(),
        TrustViolation::ExecutableAncestorWritableByOthers
    );
    fs::set_permissions(&writable_directory, fs::Permissions::from_mode(0o700))
        .expect("harden intermediate directory");
    TrustedExecutableRegistry::try_new(&trusted_root, [registration()])
        .expect("hardened executable hierarchy accepted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executable_ancestor_identity_drift_is_rejected_before_spawn() {
    let (_trusted, trusted_root) = canonical_tempdir();
    let tool_directory = trusted_root.join("tool");
    fs::create_dir(&tool_directory).expect("tool directory");
    fs::set_permissions(&tool_directory, fs::Permissions::from_mode(0o700))
        .expect("harden tool directory");
    let executable = tool_directory.join("fixture-bin");
    fs::copy(current_executable(), &executable).expect("copy fixture executable");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
        .expect("make fixture executable");
    let registry = TrustedExecutableRegistry::try_new(
        &trusted_root,
        [ExecutableRegistration::new(
            FIXTURE_ID,
            &executable,
            file_sha256(&executable),
            fixture_arguments("fixture_contract", &[]),
        )],
    )
    .expect("initial registry");

    let displaced = trusted_root.join("displaced");
    fs::rename(&tool_directory, &displaced).expect("move original ancestor");
    fs::create_dir(&tool_directory).expect("replace tool directory");
    fs::set_permissions(&tool_directory, fs::Permissions::from_mode(0o700))
        .expect("harden replacement directory");
    fs::rename(displaced.join("fixture-bin"), &executable).expect("preserve executable inode");
    fs::remove_dir(displaced).expect("remove displaced directory");

    let (_work, work_root) = canonical_tempdir();
    let supervisor = ProcessSupervisor::try_new(registry, &work_root, ProcessPolicy::default())
        .expect("supervisor");
    let report = supervisor.run(FIXTURE_ID).await.expect("drift report");

    assert!(matches!(
        report.terminal(),
        ExecutionTerminal::ExecutableRejected(error)
            if error.violation() == TrustViolation::ExecutableIdentityChanged
    ));
    assert_eq!(report.cleanup(), CleanupStatus::NotRequired);
    assert!(no_attempt_directories(&work_root));
}

#[test]
fn work_root_must_be_owner_only() {
    let (_work, work_root) = canonical_tempdir();
    fs::set_permissions(&work_root, fs::Permissions::from_mode(0o755))
        .expect("make work root too permissive");

    let error = ProcessSupervisor::try_new(
        fixture_registry("fixture_contract", &[]),
        work_root,
        ProcessPolicy::default(),
    )
    .expect_err("permissive work root rejected");

    assert_eq!(error.violation(), WorkRootViolation::NotOwnerOnly);
}

#[test]
#[ignore]
fn fixture_contract() {
    let expected = fixture_arguments(
        "fixture_contract",
        &[
            "space value",
            "line\nbreak",
            "'quote'",
            "$(touch ../shell-sentinel)",
            ";touch ../shell-sentinel",
            "-leading",
        ],
    );
    assert_eq!(
        env::args_os().skip(1).collect::<Vec<_>>(),
        expected,
        "fixed arguments must arrive byte-for-byte"
    );
    let environment_keys: BTreeSet<_> = env::vars_os().map(|(key, _)| key).collect();
    let expected_environment_keys: BTreeSet<_> = [
        "HOME",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "LANG",
        "LC_ALL",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    assert_eq!(
        environment_keys, expected_environment_keys,
        "child environment must equal the fixed allowlist"
    );
    for forbidden in [
        "PATH",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "DYLD_INSERT_LIBRARIES",
        "LD_PRELOAD",
        "SSH_AUTH_SOCK",
    ] {
        assert!(
            env::var_os(forbidden).is_none(),
            "{forbidden} was inherited"
        );
    }
    let cwd = fs::canonicalize(env::current_dir().expect("attempt cwd")).expect("canonical cwd");
    for scoped in [
        "HOME",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    ] {
        assert_eq!(
            fs::canonicalize(env::var_os(scoped).expect("scoped environment"))
                .expect("canonical scoped environment"),
            cwd
        );
    }
    assert_eq!(env::var_os("LANG"), Some(OsString::from("C")));
    assert_eq!(env::var_os("LC_ALL"), Some(OsString::from("C")));
    assert_eq!(
        fs::metadata(&cwd)
            .expect("attempt metadata")
            .permissions()
            .mode()
            & 0o077,
        0
    );
    let mut stdin = Vec::new();
    std::io::stdin()
        .read_to_end(&mut stdin)
        .expect("read null stdin");
    assert!(stdin.is_empty());
    fs::write("owned-output", b"synthetic").expect("write within attempt");
    println!("fixture-stdout");
    eprintln!("fixture-stderr");
}

#[test]
#[ignore]
fn fixture_exit_23() {
    std::process::exit(23);
}

#[test]
#[ignore]
fn fixture_abort() {
    std::process::abort();
}

#[test]
#[ignore]
fn fixture_wait() {
    fs::write("pid", std::process::id().to_string()).expect("write process PID");
    fs::write("ready", b"ready").expect("write readiness marker");
    thread::sleep(Duration::from_secs(60));
}

#[test]
#[ignore]
fn fixture_flood() {
    let stdout = thread::spawn(|| {
        let mut stream = std::io::stdout().lock();
        for _ in 0..64 {
            stream.write_all(&[b'o'; 8 * 1024]).expect("flood stdout");
            stream.flush().expect("flush stdout");
        }
    });
    let stderr = thread::spawn(|| {
        let mut stream = std::io::stderr().lock();
        for _ in 0..64 {
            stream.write_all(&[b'e'; 8 * 1024]).expect("flood stderr");
            stream.flush().expect("flush stderr");
        }
    });
    stdout.join().expect("stdout writer");
    stderr.join().expect("stderr writer");
}

#[test]
#[ignore]
fn fixture_dual_within_limit() {
    let stdout = thread::spawn(|| {
        std::io::stdout()
            .lock()
            .write_all(&[0x01; 128 * 1024])
            .expect("write bounded stdout");
    });
    let stderr = thread::spawn(|| {
        std::io::stderr()
            .lock()
            .write_all(&[0x02; 128 * 1024])
            .expect("write bounded stderr");
    });
    stdout.join().expect("bounded stdout writer");
    stderr.join().expect("bounded stderr writer");
}

#[test]
#[ignore]
fn fixture_short_overflow() {
    std::io::stdout()
        .lock()
        .write_all(&[b'o'; 8 * 1024])
        .expect("write short overflow");
}

#[test]
#[ignore]
fn fixture_tree_parent() {
    fs::write("pid", std::process::id().to_string()).expect("write parent PID");
    let mut child = Command::new(env::current_exe().expect("tree fixture executable"));
    child
        .args([
            "--ignored",
            "--exact",
            "fixture_tree_child",
            "--test-threads=1",
            "--no-capture",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = child.spawn().expect("spawn descendant fixture");
    thread::sleep(Duration::from_secs(60));
    let _ = child.wait();
}

#[test]
#[ignore]
#[allow(
    clippy::zombie_processes,
    reason = "the fixture intentionally exits before its descendant to verify supervisor cleanup"
)]
fn fixture_tree_parent_exits() {
    let mut child = Command::new(env::current_exe().expect("tree fixture executable"));
    child
        .args([
            "--ignored",
            "--exact",
            "fixture_tree_child",
            "--test-threads=1",
            "--no-capture",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = child.spawn().expect("spawn descendant fixture");
    for _ in 0..200 {
        if Path::new("descendant-ready").exists() {
            fs::write("../natural-descendant-ready", b"ready").expect("copy descendant readiness");
            fs::write("../natural-parent-pid", std::process::id().to_string())
                .expect("copy parent PID");
            fs::copy("descendant-pid", "../natural-descendant-pid").expect("copy descendant PID");
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("descendant did not become ready");
}

#[test]
#[ignore]
fn fixture_tree_child() {
    fs::write("descendant-pid", std::process::id().to_string()).expect("descendant PID");
    fs::write("descendant-ready", b"ready").expect("descendant readiness");
    thread::sleep(Duration::from_millis(1_500));
    fs::write("../tree-sentinel", b"escaped").expect("write tree sentinel");
    thread::sleep(Duration::from_secs(60));
}

#[test]
#[ignore]
fn fixture_serial() {
    let active = Path::new("../active");
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(active)
        .expect("only one fixture may be active");
    marker.write_all(b"active").expect("write active marker");
    thread::sleep(Duration::from_millis(150));
    drop(marker);
    fs::remove_file(active).expect("remove active marker");
}

#[test]
#[ignore]
fn fixture_mark_started() {
    fs::write("../second-started", b"started").expect("mark second attempt");
}

#[test]
#[ignore]
fn fixture_symlink() {
    symlink("../external-target", "external-link").expect("create attempt symlink");
}

#[test]
#[ignore]
fn fixture_break_cleanup() {
    fs::set_permissions("..", fs::Permissions::from_mode(0o500))
        .expect("make work root temporarily non-writable");
}

#[test]
#[ignore]
fn fixture_poison_supervisor_process() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("isolated poison runtime");
    runtime.block_on(async {
        let (_work, work_root) = canonical_tempdir();
        let supervisor = supervisor(
            "fixture_break_cleanup",
            &[],
            &work_root,
            Duration::from_secs(2),
            64 * 1024,
        );

        let failed_cleanup = supervisor
            .run(FIXTURE_ID)
            .await
            .expect("cleanup failure report");
        fs::set_permissions(&work_root, fs::Permissions::from_mode(0o700))
            .expect("restore work-root permissions");

        assert!(matches!(failed_cleanup.cleanup(), CleanupStatus::Failed(_)));
        assert!(supervisor.is_poisoned());
        let attempts_before = attempt_directory_count(&work_root);
        assert_eq!(attempts_before, 1);

        let poisoned = supervisor.run(FIXTURE_ID).await.expect("poisoned report");
        assert_eq!(poisoned.terminal(), ExecutionTerminal::SupervisorPoisoned);
        assert_eq!(poisoned.cleanup(), CleanupStatus::NotRequired);
        assert_eq!(attempt_directory_count(&work_root), attempts_before);

        for entry in fs::read_dir(&work_root).expect("read poisoned work root") {
            let entry = entry.expect("read poisoned work-root entry");
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("pov-process-")
            {
                fs::remove_dir_all(entry.path()).expect("remove synthetic failed attempt");
            }
        }
        assert!(no_attempt_directories(&work_root));
    });
}
