#!/usr/bin/env python3
"""Linux production auth-init and repository smoke evidence.

The harness retains PTY output only in memory and prints no password, recovery
code, key identifier, token, or temporary credential.
"""

import errno
import fcntl
import hashlib
import os
import pty
import select
import signal
import socket
import sqlite3
import subprocess
import tempfile
import termios
import time
import urllib.request
from pathlib import Path


if os.uname().sysname != "Linux":
    raise SystemExit("production auth smoke is implemented for Linux only")

repository_root = Path(__file__).resolve().parent.parent
binary = Path(
    os.environ.get("POV_API_BINARY", repository_root / "target/debug/pov-api")
).resolve()
password_prompt = b"New password: "
recovery_marker = b"Recovery code (shown once): "
saved_prompt = b"Type SAVED to confirm secure storage: "


def read_until(master: int, marker: bytes, timeout: float) -> bytes:
    deadline = time.monotonic() + timeout
    retained = bytearray()
    while marker not in retained:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("expected PTY marker was not observed")
        ready, _, _ = select.select([master], [], [], min(remaining, 0.25))
        if not ready:
            continue
        try:
            chunk = os.read(master, 4096)
        except OSError as error:
            if error.errno == errno.EIO:
                break
            raise
        if not chunk:
            break
        retained.extend(chunk)
        if len(retained) > 16384:
            del retained[:-16384]
    if marker not in retained:
        raise AssertionError("expected PTY marker was not observed")
    return bytes(retained)


def run_init(instance_root: Path, expect_success: bool) -> None:
    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)

    def child_setup() -> None:
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    child = subprocess.Popen(
        [
            os.fspath(binary),
            "auth",
            "init",
            "--instance-root",
            os.fspath(instance_root),
            "--login-id",
            "owner",
        ],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        preexec_fn=child_setup,
        close_fds=True,
    )
    try:
        read_until(master, password_prompt, 10)
        assert not termios.tcgetattr(slave)[3] & termios.ECHO
        password = b"Aa1!" + os.urandom(20).hex().encode()
        retained = b""
        os.write(master, password + b"\n")
        retained = read_until(master, saved_prompt, 20)
        assert password not in retained
        password = b""
        assert retained.count(recovery_marker) == 1
        retained = b""
        os.write(master, b"SAVED\n")
        status = child.wait(timeout=120)
        assert (status == 0) is expect_success
        assert termios.tcgetattr(slave) == original
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        os.close(master)
        os.close(slave)


def normalized(value):
    if isinstance(value, bytes):
        return ("bytes", value.hex())
    return value


def auth_database_digest(database: Path) -> bytes:
    digest = hashlib.sha256()
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        tables = [
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table' AND name LIKE 'auth_%'
                ORDER BY name
                """
            )
        ]
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            columns = tuple(
                row[1] for row in connection.execute(f"PRAGMA table_info({quoted})")
            )
            rows = [
                tuple(normalized(value) for value in row)
                for row in connection.execute(f"SELECT * FROM {quoted}")
            ]
            rows.sort(key=repr)
            digest.update(repr((table, columns, rows)).encode())
    finally:
        connection.close()
    return digest.digest()


def secret_files_digest(secret_root: Path) -> bytes:
    digest = hashlib.sha256()
    for path in sorted(secret_root.rglob("*")):
        relative = path.relative_to(secret_root).as_posix()
        digest.update(relative.encode())
        digest.update(str(path.stat().st_mode & 0o777).encode())
        if path.is_file():
            digest.update(b"F")
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        elif path.is_dir():
            digest.update(b"D")
        else:
            raise AssertionError("unexpected secret artifact type")
    return digest.digest()


def assert_port_free() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(1)
        assert probe.connect_ex(("127.0.0.1", 8080)) != 0


def wait_for_health(server: subprocess.Popen) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        assert server.poll() is None, "server exited before listener readiness"
        try:
            with urllib.request.urlopen(
                "http://127.0.0.1:8080/api/health", timeout=1
            ) as response:
                assert response.status == 200
                assert response.read() == b'{"status":"ok"}'
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError("listener health did not become ready")


with tempfile.TemporaryDirectory(prefix="pov-production-smoke-") as parent:
    instance_root = Path(parent) / "instance"
    run_init(instance_root, expect_success=True)

    before_database = auth_database_digest(
        instance_root / "stores" / "conversation.sqlite3"
    )
    before_secrets = secret_files_digest(instance_root / "secrets")

    assert_port_free()
    server = subprocess.Popen(
        [os.fspath(binary), "--instance-root", os.fspath(instance_root)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_for_health(server)
    finally:
        if server.poll() is None:
            server.send_signal(signal.SIGTERM)
        server.wait(timeout=5)

    environment = os.environ.copy()
    environment["POV_INSTANCE_ROOT"] = os.fspath(instance_root)
    subprocess.run(
        ["sh", "scripts/smoke.sh"],
        cwd=repository_root,
        env=environment,
        check=True,
    )

    run_init(instance_root, expect_success=False)
    after_database = auth_database_digest(
        instance_root / "stores" / "conversation.sqlite3"
    )
    after_secrets = secret_files_digest(instance_root / "secrets")
    assert before_database == after_database
    assert before_secrets == after_secrets

print(
    "production auth-init success, echo suppression, one-time recovery display, "
    "SAVED confirmation, terminal restore, listener health, repository smoke, "
    "and second-init no-replace checks passed"
)
