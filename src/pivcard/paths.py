"""Where things live on Linux and Windows: configuration files and the agent's two endpoints."""
from __future__ import annotations

import contextlib
import getpass
import hashlib
import os
import re
import shutil
import sys
from pathlib import Path

WINDOWS = sys.platform == "win32"


def config_dir(app: str = "pivcard") -> Path:
    """$XDG_CONFIG_HOME/<app> when that variable is set (on Windows too, so a setup can be kept apart),
    else ~/.config/<app> on Linux and %APPDATA%\\<app> on Windows."""
    base = os.environ.get("XDG_CONFIG_HOME")
    if not base:
        base = (os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") if WINDOWS \
            else Path.home() / ".config"
    return Path(base) / app


def runtime_dir() -> Path:
    """A per-user directory for the agent's sockets (POSIX). Created 0700; refused if not ours."""
    override = os.environ.get("PIVCARD_AGENT_DIR")
    if override:
        path = Path(override)
    elif os.environ.get("XDG_RUNTIME_DIR"):
        path = Path(os.environ["XDG_RUNTIME_DIR"]) / "pivcard"
    else:
        path = Path.home() / ".cache" / "pivcard-run"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not WINDOWS:
        st = path.stat()
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise PermissionError(f"{path} must belong to you and be mode 0700")
    return path


def endpoints() -> tuple[str, str]:
    """(SSH agent endpoint, control endpoint): Unix sockets on POSIX, named pipes on Windows.

    They are separate on purpose. Only the first is ever given to `ssh`, so even with agent forwarding
    a remote host can ask for signatures but can never reach the unlocked secrets or the lock controls.
    """
    if WINDOWS:
        suffix = os.environ.get("PIVCARD_AGENT_DIR") or getpass.getuser()
        tag = re.sub(r"[^A-Za-z0-9_.-]", "_", suffix)
        if len(tag) > 40:   # OpenSSH for Windows cannot open a pipe whose full name is longer than about 100 characters
            tag = f"{tag[:16]}-{hashlib.sha256(suffix.encode()).hexdigest()[:20]}"
        return rf"\\.\pipe\pivcard-ssh-{tag}", rf"\\.\pipe\pivcard-control-{tag}"
    base = runtime_dir()
    return str(base / "ssh.sock"), str(base / "control.sock")


def openssh_agent_address() -> str:
    """The SSH endpoint written the way OpenSSH should be given it (IdentityAgent, SSH_AUTH_SOCK).

    On Windows the pipe is named with forward slashes (//./pipe/name). OpenSSH treats a backslash in an
    option value as an escape character, which would eat one of the two leading backslashes.
    """
    address = endpoints()[0]
    return address.replace("\\", "/") if WINDOWS else address


def prompts_off() -> bool:
    """PIVCARD_NO_PROMPT is set (to anything but 0 or nothing): no program here may ask for a PIN.
    Meant for the environment of an AI agent, so that nothing it runs brings up a PIN prompt in its
    terminal. A guard against mistakes: a program can unset a variable."""
    return os.environ.get("PIVCARD_NO_PROMPT", "") not in ("", "0")


def harden_process() -> None:
    """Linux: make this process non-dumpable, so other processes of the user cannot read its memory
    through ptrace or /proc/<pid>/mem (what ssh-agent does). Nothing equivalent is done on Windows."""
    if sys.platform.startswith("linux"):
        import ctypes
        with contextlib.suppress(Exception):
            ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)   # PR_SET_DUMPABLE = 4


def find_program(name: str) -> str | None:
    """Like shutil.which. On Windows it does not look in the current directory first, as cmd.exe would:
    a file dropped into a project directory must not be able to stand in for `age`."""
    if not WINDOWS:
        return shutil.which(name)
    extensions = [e for e in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(os.pathsep) if e]
    names = [name] if Path(name).suffix else [name + e for e in extensions]
    if Path(name).parent != Path("."):                 # given with a folder: that file, nothing is searched
        return next((str(Path(n)) for n in names if Path(n).is_file()), None)
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        if folder and folder != ".":
            for candidate in names:
                if (Path(folder) / candidate).is_file():
                    return str(Path(folder) / candidate)
    return None
