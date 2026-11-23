"""Test helpers: a software stand-in for the card session, and a scripted age client."""
from __future__ import annotations

import importlib.util
import os
import queue
import subprocess
import sys
import threading
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pivcard import plugin
from pivcard.plugin import CardError, PinError, Stanza, read_stanza, write_stanza


class SoftSession:
    """What the card layer promises the plugin, backed by a software P-256 key."""

    def __init__(self, key: ec.EllipticCurvePrivateKey, pin: str = "123456", tries: int = 6):
        self.key, self.pin, self.tries = key, pin, tries
        self.verify_calls = 0
        self.closed = False

    @property
    def pub33(self) -> bytes:
        return self.key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)

    def describe(self) -> str:
        return "software test card"

    def ecdh(self, pin: str, peer65: bytes) -> bytes:
        self.verify_calls += 1
        if pin != self.pin:
            self.tries -= 1
            raise PinError(self.tries)
        self.tries = 6
        return self.key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer65))

    def close(self) -> None:
        self.closed = True


class SoftFactory:
    """A CardFactory over a set of SoftSessions; records every open."""

    def __init__(self, *sessions: SoftSession):
        self.sessions = {s.pub33: s for s in sessions}
        self.opened: list[tuple[int, bytes]] = []

    def __call__(self, slot: int, pub33: bytes) -> SoftSession:
        self.opened.append((slot, pub33))
        if pub33 not in self.sessions:
            raise CardError("no card with this key is present")
        return self.sessions[pub33]


@pytest.fixture(autouse=True)
def _own_settings_only(monkeypatch):
    """The tests must not depend on settings of the person (or AI agent) who runs them. In particular
    PIVCARD_NO_PROMPT=1, which the README recommends for an AI agent's environment, would switch off the
    very prompts that many tests exercise."""
    for name in ("PIVCARD_NO_PROMPT", "PIVCARD_READER", "WITHSECRETS_TTL", "WITHSECRETS_HOME", "AGEDEBUG",
                 "HZ_ENTRY", "HZ_NAME", "HZ_LOCATION", "HZ_TYPE", "HZ_IMAGE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def card() -> SoftSession:
    return SoftSession(ec.generate_private_key(ec.SECP256R1()))


def run_plugin(mode: str, phase1: list[Stanza], respond=None, card_factory=None):
    """Drive one plugin state machine like an age client would.

    Sends `phase1` then `done`, then answers each phase-2 command with `respond(stanza)` (default: ok).
    Returns (exit code, list of the plugin's phase-2 commands).
    """
    respond = respond or (lambda st: Stanza("ok", []))
    c2p_r, c2p_w = os.pipe()
    p2c_r, p2c_w = os.pipe()
    plugin_in, plugin_out = os.fdopen(c2p_r, "rb"), os.fdopen(p2c_w, "wb")
    client_in, client_out = os.fdopen(p2c_r, "rb"), os.fdopen(c2p_w, "wb")
    result: dict = {}

    def target():
        try:
            if mode == "recipient-v1":
                result["rc"] = plugin.run_recipient_v1(plugin_in, plugin_out)
            else:
                result["rc"] = plugin.run_identity_v1(plugin_in, plugin_out, card_factory)
        except Exception as e:  # surfaced to the test below
            result["exc"] = e
        finally:
            plugin_out.close()

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    for st in phase1:
        write_stanza(client_out, st.tag, st.args, st.body)
    write_stanza(client_out, "done")
    seen: list[Stanza] = []
    while True:
        st = read_stanza(client_in)
        if st is None or st.tag == "done":
            break
        seen.append(st)
        reply = respond(st)
        write_stanza(client_out, reply.tag, reply.args, reply.body)
    client_out.close()
    thread.join(timeout=10)
    assert not thread.is_alive(), "plugin did not finish"
    if "exc" in result:
        raise result["exc"]
    return result["rc"], seen


# ------------------------------------------------------------------ child processes on Linux and Windows
POSIX = os.name == "posix"
HAVE_TTY = POSIX or importlib.util.find_spec("winpty") is not None
needs_tty = pytest.mark.skipif(not HAVE_TTY, reason="needs a pseudo-terminal (on Windows: pip install pywinpty)")


# Keyword arguments for subprocess.run: start the child with no terminal it could ask a question on.
# (On Windows that means no console at all. A hidden console would let `age` wait for a PIN for ever.)
NO_TERMINAL = {"start_new_session": True} if POSIX else {"creationflags": getattr(subprocess, "DETACHED_PROCESS", 0)}


def unix_lines(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def child_env(*bin_dirs, **extra) -> dict[str, str]:
    """A small, explicit environment for a child process, with `bin_dirs` first on PATH."""
    if POSIX:
        env = {"PATH": os.pathsep.join([*map(str, bin_dirs), "/usr/bin", "/bin"]), "LANG": "C"}
    else:  # Windows programs need a few variables to start at all (SystemRoot above all)
        keep = {"SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "USERPROFILE",
                "USERNAME", "USERDOMAIN", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "HOMEDRIVE", "HOMEPATH"}
        env = {k: v for k, v in os.environ.items() if k.upper() in keep}
        root = os.environ.get("SYSTEMROOT", r"C:\Windows")           # Windows variable names ignore case
        env["PATH"] = os.pathsep.join([*map(str, bin_dirs), rf"{root}\System32\OpenSSH", rf"{root}\System32", root])
    env.update({k: str(v) for k, v in extra.items()})
    return env


def write_shim(bindir, name: str, source: str) -> None:
    """Put a program called `name` in `bindir` that runs `source` with this Python.
    (age finds a plugin by its name on PATH.)"""
    if POSIX:
        path = bindir / name
        path.write_text(f"#!{sys.executable}\n{source}")
        path.chmod(0o755)
    else:
        (bindir / f"{name}.py").write_text(source)
        (bindir / f"{name}.cmd").write_text(f'@"{sys.executable}" "%~dp0{name}.py" %*\r\n')


def run_on_tty(argv, environ, answers, timeout=30, prompt=b"Enter the PIN"):
    """Run argv on a terminal of its own (a pty; on Windows a pseudo-console) and type `answers` at
    successive prompts. Returns (exit code, everything that appeared on the terminal)."""
    if POSIX:
        import pty
        import select
        pid, fd = pty.fork()
        if pid == 0:
            os.execvpe(argv[0], argv, environ)
        seen, sent, deadline = b"", 0, time.time() + timeout
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if fd in ready:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:      # EIO: the child closed its side
                    break
                if not chunk:
                    break
                seen += chunk
            if sent < len(answers) and seen.count(prompt) > sent:
                os.write(fd, answers[sent] + b"\n")
                sent += 1
        _, status = os.waitpid(pid, 0)
        os.close(fd)
        return os.waitstatus_to_exitcode(status), seen

    from winpty import PtyProcess  # pywinpty
    # a list, not one string: pywinpty splits a string in a way that keeps the quotes inside arguments
    proc = PtyProcess.spawn([str(a) for a in argv], env=environ, dimensions=(40, 200))
    chunks: queue.Queue = queue.Queue()

    def pump():
        try:
            while True:
                chunks.put(proc.read(4096))
        except Exception:            # EOFError when the program has gone
            chunks.put(None)

    threading.Thread(target=pump, daemon=True).start()
    seen, sent, deadline = b"", 0, time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = chunks.get(timeout=0.2)
        except queue.Empty:
            chunk = ""
        if chunk is None:
            break
        seen += chunk.encode("utf-8", "replace") if isinstance(chunk, str) else chunk
        if sent < len(answers) and seen.count(prompt) > sent:
            proc.write(answers[sent].decode() + "\r")
            sent += 1
    if proc.isalive() and time.time() >= deadline:
        proc.terminate(force=True)
    return proc.wait(), seen


def own_command_line() -> str:
    """Python source for a child process: print the command line this process was started with."""
    return ("import os, sys\n"
            "if os.name == 'nt':\n"
            "    import ctypes\n"
            "    ctypes.windll.kernel32.GetCommandLineW.restype = ctypes.c_wchar_p\n"
            "    print(ctypes.windll.kernel32.GetCommandLineW())\n"
            "else:\n"
            "    print(open(f'/proc/{os.getpid()}/cmdline', 'rb').read())\n")
