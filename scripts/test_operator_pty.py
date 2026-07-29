#!/usr/bin/env python3
"""Linux production-binary PTY evidence for operator signal restoration.

The helper deliberately retains only prompt markers and booleans: it never logs a
PTY transcript or any operator secret/recovery material.
"""
import fcntl
import os
import pty
import signal
import subprocess
import tempfile
import termios
import time

if os.uname().sysname != "Linux":
    raise SystemExit("operator PTY signal evidence is implemented for Linux only")

binary = os.path.abspath(os.environ.get("POV_API_BINARY", "target/debug/pov-api"))

# Exercise the production parser and dispatch without a controlling TTY. Values
# are generated per run and only checked for absence; failures never print them.
for suffix in ("unknown", "extra", "duplicate", "reordered", "password", "recovery", "alias"):
    root = os.path.join(tempfile.mkdtemp(prefix="pov-parser-"), "instance")
    opaque = os.urandom(18).hex()
    base = [binary, "auth", "init", "--instance-root", root, "--login-id", "owner"]
    cases = {
        "unknown": base + ["--unknown"],
        "extra": base + [opaque],
        "duplicate": base + ["--login-id", "owner"],
        "reordered": [binary, "auth", "init", "--login-id", "owner", "--instance-root", root],
        "password": base + ["--password", opaque],
        "recovery": base + ["--recovery-code", opaque],
        "alias": base + ["--secret", opaque],
    }
    result = subprocess.run(cases[suffix], stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
    assert result.returncode != 0, "forbidden parser form was accepted"
    assert opaque.encode() not in result.stdout + result.stderr, "usage output repeated an input value"
    assert not os.path.exists(root), "parser failure performed durable mutation"

root = os.path.join(tempfile.mkdtemp(prefix="pov-redirect-"), "instance")
environment = os.environ.copy()
environment["POV_PASSWORD"] = os.urandom(18).hex()
environment["POV_RECOVERY_CODE"] = os.urandom(18).hex()
result = subprocess.run(
    [binary, "auth", "init", "--instance-root", root, "--login-id", "owner"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    env=environment,
    timeout=5,
)
assert result.returncode != 0, "redirected stdin or environment fallback was accepted"
assert not os.path.exists(root), "no-TTY dispatch performed durable mutation"
# A malformed confirmation traverses the real prompt/recovery/confirmation path.
# Captured bytes stay local and are never included in assertion messages.
instance_root = os.path.join(tempfile.mkdtemp(prefix="pov-cancel-"), "instance")
master, slave = pty.openpty()
original = termios.tcgetattr(slave)
def cancel_child_setup():
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
child = subprocess.Popen(
    [binary, "auth", "init", "--instance-root", instance_root, "--login-id", "owner"],
    stdin=slave, stdout=slave, stderr=slave, preexec_fn=cancel_child_setup, close_fds=True,
)
retained = b""
while b"New password: " not in retained:
    retained = (retained + os.read(master, 256))[-256:]
assert not termios.tcgetattr(slave)[3] & termios.ECHO, "PTY echo remained enabled"
password = b"Aa1!" + os.urandom(16).hex().encode()
os.write(master, password + b"\n")
password = b""  # Do not retain secret material beyond ingress.
retained = b""
while b"Type SAVED to confirm secure storage: " not in retained:
    retained += os.read(master, 256)
assert retained.count(b"Recovery code (shown once): ") == 1, "recovery marker count was not one"
retained = b""
os.write(master, b"NOT-SAVED\n")
assert child.wait(timeout=5) != 0, "malformed confirmation was accepted"
assert termios.tcgetattr(slave) == original, "PTY termios was not restored"
assert not os.path.exists(instance_root), "cancel path performed durable bootstrap mutation"
os.close(master)
os.close(slave)

for caught_signal in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
    instance_root = os.path.join(tempfile.mkdtemp(prefix="pov-operator-"), "instance")
    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)

    def child_setup():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    child = subprocess.Popen(
        [binary, "auth", "init", "--instance-root", instance_root, "--login-id", "owner"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        preexec_fn=child_setup,
        close_fds=True,
    )
    prompt_seen = False
    deadline = time.monotonic() + 5
    retained = b""
    while not prompt_seen and time.monotonic() < deadline:
        retained = (retained + os.read(master, 256))[-64:]
        prompt_seen = b"New password: " in retained
    assert prompt_seen, "password prompt marker was not observed"
    assert not termios.tcgetattr(slave)[3] & termios.ECHO, "PTY echo remained enabled"

    os.kill(child.pid, caught_signal)
    status = child.wait(timeout=5)
    assert status == -caught_signal, "child did not preserve signal termination semantics"
    assert termios.tcgetattr(slave) == original, "PTY termios was not restored"
    assert not os.path.exists(instance_root), "signal path performed durable bootstrap mutation"
    os.close(master)
    os.close(slave)

print("production PTY signal/termios checks passed")
