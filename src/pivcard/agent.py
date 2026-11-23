"""The pivcard agent: holds, in memory and for a limited time, what the user has unlocked.

It has two endpoints (Unix sockets on Linux, named pipes on Windows):

  * an **SSH agent** endpoint, the only one ever given to `ssh`. It offers one key, the card's
    authentication key, and only while SSH is unlocked. Each signature is one unit on the card:
    confirm the key, VERIFY, sign, log out. The card is never left in the "PIN verified" state.
  * a **control** endpoint for the user's own tools: unlock/lock SSH, and hold entries decrypted by
    `withsecrets` until they expire.

What this process holds while unlocked: the PIN (only if SSH is unlocked) and the decrypted entries.
Any process of the same user can ask it for a signature or an unlocked entry; that is the same trust
boundary as `ssh-agent`. It never writes any of it to disk, and forgets the PIN at once if the card
ever answers "wrong PIN".
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import math
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from . import paths, piv, tagfmt
from .plugin import CardError, PinError

# SSH agent protocol (draft-miller-ssh-agent)
SSH_AGENT_FAILURE = 5
SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14
KEY_TYPE = b"ecdsa-sha2-nistp256"

MAX_MESSAGE = 256 * 1024
DEFAULT_SSH_TTL = 4 * 3600
DEFAULT_SECRET_TTL = 2 * 3600
MAX_TTL = 24 * 3600
IDLE_EXIT = 30.0                       # seconds with nothing held before the agent exits


def _string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _mpint(n: int) -> bytes:
    return _string(n.to_bytes(n.bit_length() // 8 + 1, "big")) if n else _string(b"")


def ssh_key_blob(pub33: bytes) -> bytes:
    return _string(KEY_TYPE) + _string(b"nistp256") + _string(tagfmt.decompress(pub33))


def ssh_public_key_line(pub33: bytes, comment: str = "piv-card") -> str:
    return f"{KEY_TYPE.decode()} {base64.b64encode(ssh_key_blob(pub33)).decode()} {comment}"


def ssh_signature(der: bytes) -> bytes:
    r, s = decode_dss_signature(der)
    return _string(KEY_TYPE) + _string(_mpint(r) + _mpint(s))


def _take_string(buf: bytes, pos: int) -> tuple[bytes, int]:
    if pos + 4 > len(buf):
        raise ValueError("truncated")
    n = struct.unpack_from(">I", buf, pos)[0]
    if pos + 4 + n > len(buf):
        raise ValueError("truncated")
    return buf[pos + 4:pos + 4 + n], pos + 4 + n


@dataclass
class SshUnlock:
    pin: str
    slot: int
    pub33: bytes
    reader: str
    expires: float


def _clock() -> float:
    """Seconds that keep counting while the computer is suspended, where the system offers such a clock
    (Linux). A time limit is meant as wall-clock time: a night with the lid closed must use it up."""
    boottime = getattr(time, "CLOCK_BOOTTIME", None)
    return time.clock_gettime(boottime) if boottime is not None else time.monotonic()


def _ttl(value, default: float) -> float:
    """A time limit from a request, in seconds: a positive, finite number, capped at MAX_TTL."""
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("ttl must be a number of seconds")
    ttl = float(value)
    if not math.isfinite(ttl) or ttl <= 0:
        raise ValueError("ttl must be a positive number of seconds")
    return min(ttl, MAX_TTL)


class Agent:
    def __init__(self, open_transport: Callable[[], piv.Transport] = piv.open_transport,
                 clock: Callable[[], float] = _clock, idle_exit: float | None = IDLE_EXIT):
        self.open_transport, self.clock, self.idle_exit = open_transport, clock, idle_exit
        self.ssh: SshUnlock | None = None
        self.secrets: dict[str, tuple[bytes, float]] = {}
        self.card_lock = threading.Lock()          # one card operation at a time
        self.stopping = asyncio.Event()
        self._idle_since: float | None = None

    # ------------------------------------------------------------ state
    def purge(self) -> None:
        now = self.clock()
        if self.ssh and self.ssh.expires <= now:
            self.ssh = None
        for name in [n for n, (_, expires) in self.secrets.items() if expires <= now]:
            del self.secrets[name]

    def empty(self) -> bool:
        return self.ssh is None and not self.secrets

    def status(self) -> dict:
        self.purge()
        now = self.clock()
        ssh = None
        if self.ssh:
            ssh = {"reader": self.ssh.reader, "slot": piv.slot_name(self.ssh.slot),
                   "seconds_left": int(self.ssh.expires - now),
                   "public_key": ssh_public_key_line(self.ssh.pub33)}
        return {"ok": True, "pid": os.getpid(), "ssh": ssh, "ssh_endpoint": paths.endpoints()[0],
                "secrets": [{"name": n, "seconds_left": int(e - now)} for n, (_, e) in sorted(self.secrets.items())]}

    # ------------------------------------------------------------ card operations (run in a thread)
    def _session(self, slot: int, pub33: bytes) -> piv.PivSession:
        return piv.PivSession(self.open_transport(), slot, pub33)

    def _ssh_unlock(self, pin: str, slot: int, ttl: float, expect: bytes | None = None) -> dict:
        with self.card_lock:
            t = self.open_transport()
            session = None
            try:
                with piv.exclusive(t):
                    pub = piv.slot_public_key(t, slot)
                if pub is None:
                    raise CardError(f"slot {piv.slot_name(slot)} has no certificate; see `pivcard mkcert`")
                try:
                    pub33 = tagfmt.public_key_to_compressed(pub)
                except tagfmt.FormatError as e:
                    raise CardError(f"slot {piv.slot_name(slot)}: {e} (this agent signs with ECC P-256)") from None
                if expect is not None and pub33 != expect:
                    raise CardError(f"slot {piv.slot_name(slot)} of the card in {t.name} does not hold the "
                                    "expected key: this is another card. No PIN was sent to it.")
                session = piv.PivSession(t, slot, pub33)
                session.check_pin(pin)             # the PIN is only kept if the card accepts it now
            finally:
                with contextlib.suppress(Exception):
                    session.close() if session is not None else t.close()
        self.ssh = SshUnlock(pin, slot, pub33, t.name, self.clock() + ttl)
        return self.status()

    def _sign(self, digest: bytes) -> bytes:
        with self.card_lock:
            # Read the state only now. A request that waited for the card must see a lock, an expiry or a
            # rejected PIN that happened meanwhile, or it would send that PIN to the card again.
            unlock = self.ssh
            if unlock is None or unlock.expires <= self.clock():
                raise CardError("SSH is locked")
            session = None
            try:
                session = self._session(unlock.slot, unlock.pub33)
                return session.sign(unlock.pin, digest)
            except PinError:
                self.ssh = None                    # never offer a rejected PIN to the card again
                raise
            finally:
                if session is not None:
                    with contextlib.suppress(Exception):
                        session.close()

    # ------------------------------------------------------------ SSH agent endpoint
    async def ssh_message(self, msg: bytes) -> bytes:
        self.purge()
        failure = bytes([SSH_AGENT_FAILURE])
        if not msg:
            return failure
        if msg[0] == SSH_AGENTC_REQUEST_IDENTITIES:
            if self.ssh is None:
                return bytes([SSH_AGENT_IDENTITIES_ANSWER]) + struct.pack(">I", 0)
            comment = f"PIV card slot {piv.slot_name(self.ssh.slot)}".encode()
            return (bytes([SSH_AGENT_IDENTITIES_ANSWER]) + struct.pack(">I", 1)
                    + _string(ssh_key_blob(self.ssh.pub33)) + _string(comment))
        if msg[0] == SSH_AGENTC_SIGN_REQUEST and self.ssh is not None:
            try:
                blob, pos = _take_string(msg, 1)
                data, pos = _take_string(msg, pos)
            except ValueError:
                return failure
            if blob != ssh_key_blob(self.ssh.pub33):
                return failure
            try:
                der = await asyncio.to_thread(self._sign, hashlib.sha256(data).digest())
            except CardError as e:
                print(f"pivcard agent: signature refused: {e}", file=sys.stderr, flush=True)
                return failure
            return bytes([SSH_AGENT_SIGN_RESPONSE]) + _string(ssh_signature(der))
        return failure                              # everything else, including extensions

    async def handle_ssh(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            if not _same_user(writer):
                return
            while True:
                size = struct.unpack(">I", await reader.readexactly(4))[0]
                if not 0 < size <= MAX_MESSAGE:
                    return
                reply = await self.ssh_message(await reader.readexactly(size))
                writer.write(struct.pack(">I", len(reply)) + reply)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    # ------------------------------------------------------------ control endpoint
    async def control_request(self, req: dict) -> dict:
        self.purge()
        op = req.get("op")
        try:
            if op == "status":
                return self.status()
            if op == "ssh-unlock":
                ttl = _ttl(req.get("ttl"), DEFAULT_SSH_TTL)
                slot = piv.parse_slot(req.get("slot", "9A"))
                expect = bytes.fromhex(req["expect"]) if req.get("expect") else None
                return await asyncio.to_thread(self._ssh_unlock, str(req["pin"]), slot, ttl, expect)
            if op == "ssh-lock":
                self.ssh = None
                return self.status()
            if op == "put":
                ttl = _ttl(req.get("ttl"), DEFAULT_SECRET_TTL)
                self.secrets[str(req["name"])] = (base64.b64decode(req["data"], validate=True), self.clock() + ttl)
                return {"ok": True}
            if op == "get":
                entry = self.secrets.get(str(req["name"]))
                if entry is None:
                    return {"ok": False, "error": "locked"}
                return {"ok": True, "data": base64.b64encode(entry[0]).decode(),
                        "seconds_left": int(entry[1] - self.clock())}
            if op == "clear":
                if req.get("name") is None:
                    self.secrets.clear()
                else:
                    self.secrets.pop(str(req["name"]), None)
                return {"ok": True}
            if op == "stop":
                self.ssh = None
                self.secrets.clear()
                self.stopping.set()
                return {"ok": True}
        except CardError as e:
            return {"ok": False, "error": str(e)}
        except (KeyError, ValueError, TypeError, OverflowError) as e:
            return {"ok": False, "error": f"bad request: {e}"}
        return {"ok": False, "error": f"unknown operation {op!r}"}

    async def handle_control(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            if not _same_user(writer):
                return
            while True:
                size = struct.unpack(">I", await reader.readexactly(4))[0]
                if not 0 < size <= MAX_MESSAGE:
                    return
                try:
                    req = json.loads(await reader.readexactly(size))
                    reply = await self.control_request(req if isinstance(req, dict) else {})
                except ValueError:
                    reply = {"ok": False, "error": "not JSON"}
                raw = json.dumps(reply).encode()
                writer.write(struct.pack(">I", len(raw)) + raw)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    # ------------------------------------------------------------ lifetime
    async def run(self, ssh_address: str, control_address: str) -> None:
        servers = [await _serve(ssh_address, self.handle_ssh), await _serve(control_address, self.handle_control)]
        try:
            while not self.stopping.is_set():
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self.stopping.wait(), timeout=1.0)
                self.purge()
                if self.idle_exit is not None:
                    if not self.empty():
                        self._idle_since = None
                    elif self._idle_since is None:
                        self._idle_since = self.clock()
                    elif self.clock() - self._idle_since >= self.idle_exit:
                        break
        finally:
            for server in servers:
                for s in server if isinstance(server, list) else [server]:
                    s.close()
            if not paths.WINDOWS:
                for address in (ssh_address, control_address):
                    with contextlib.suppress(OSError):
                        os.unlink(address)


def _same_user(writer: asyncio.StreamWriter) -> bool:
    """On Linux, check the peer's uid (the socket directory is 0700 as well). No-op elsewhere."""
    sock = writer.get_extra_info("socket")
    if sock is None or not hasattr(socket, "SO_PEERCRED"):
        return True
    try:
        _, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    except OSError:
        return False
    return uid == os.getuid()


def _local_pipes_only() -> None:
    """Windows: make the agent's pipes refuse clients on other machines (a named pipe is reachable over
    the network by default). asyncio creates the pipes itself and has no option for this, so the flag is
    added on the way in, for pipes with this project's names only."""
    import _winapi
    if getattr(_winapi.CreateNamedPipe, "pivcard_local_only", False):
        return
    create = _winapi.CreateNamedPipe

    def create_local(name, open_mode, pipe_mode, *rest):
        if str(name).lower().startswith("\\\\.\\pipe\\pivcard-"):
            pipe_mode |= 0x00000008                # PIPE_REJECT_REMOTE_CLIENTS
        return create(name, open_mode, pipe_mode, *rest)

    create_local.pivcard_local_only = True
    _winapi.CreateNamedPipe = create_local


async def _serve(address: str, handler):
    if paths.WINDOWS:
        _local_pipes_only()
        loop = asyncio.get_running_loop()

        def factory():
            return asyncio.StreamReaderProtocol(asyncio.StreamReader(), handler)

        return await loop.start_serving_pipe(factory, address)
    with contextlib.suppress(OSError):
        os.unlink(address)
    old = os.umask(0o077)
    try:
        return await asyncio.start_unix_server(handler, path=address)
    finally:
        os.umask(old)


# ---------------------------------------------------------------------- client side
class AgentUnavailable(Exception):
    pass


class AgentNotOurs(Exception):
    """Windows: the agent's pipe is served by a process that does not run as this user. Nothing is sent to it."""


def _served_by_me(pipe) -> bool:
    """Windows: does the process that serves this named pipe run as the same user as this process?

    A pipe name can be taken by any program that asks first. Without this check, a program of another user
    could wait under the agent's name and be handed the PIN or a secret by `pivcard ssh unlock` or
    `withsecrets unlock`. Anything that cannot be checked counts as "no".
    """
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.GetNamedPipeServerProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
    advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    token_query, token_user, query_limited_information = 0x0008, 1, 0x1000

    def user_of(process):
        """The TOKEN_USER buffer of a process (it starts with a pointer to the user's SID), or None."""
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(process, token_query, ctypes.byref(token)):
            return None
        try:
            size = wintypes.DWORD()
            advapi32.GetTokenInformation(token, token_user, None, 0, ctypes.byref(size))
            buffer = ctypes.create_string_buffer(size.value)
            if not size.value or not advapi32.GetTokenInformation(token, token_user, buffer, size, ctypes.byref(size)):
                return None
            return buffer
        finally:
            kernel32.CloseHandle(token)

    pid = wintypes.ULONG()
    if not kernel32.GetNamedPipeServerProcessId(msvcrt.get_osfhandle(pipe.fileno()), ctypes.byref(pid)):
        return False
    server = kernel32.OpenProcess(query_limited_information, False, pid.value)
    if not server:
        return False
    try:
        theirs, mine = user_of(server), user_of(kernel32.GetCurrentProcess())
    finally:
        kernel32.CloseHandle(server)
    if theirs is None or mine is None:
        return False
    sid = [ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0] for buffer in (theirs, mine)]
    return bool(advapi32.EqualSid(sid[0], sid[1]))


def _open_pipe(address: str):
    """Windows: connect to a named pipe at the "identification" level, so that the program serving it can
    see who we are but cannot act with our rights. (Plain open() would allow impersonation.)"""
    import _winapi
    import msvcrt
    sqos_present, identification, pipe_busy = 0x00100000, 0x00010000, 231
    for _ in range(40):
        try:
            handle = _winapi.CreateFile(address, _winapi.GENERIC_READ | _winapi.GENERIC_WRITE, 0, _winapi.NULL,
                                        _winapi.OPEN_EXISTING, sqos_present | identification, _winapi.NULL)
        except OSError as e:
            if getattr(e, "winerror", None) != pipe_busy:
                raise
            time.sleep(0.05)                       # every instance is taken for a moment: try again
            continue
        return os.fdopen(msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY), "r+b", buffering=0)
    raise OSError("the agent's pipe stayed busy")


class _Connection:
    def __init__(self, address: str, timeout: float = 30.0):
        self._sock = self._pipe = None
        try:
            if paths.WINDOWS:
                self._pipe = _open_pipe(address)
                if not _served_by_me(self._pipe):
                    self.close()
                    raise AgentNotOurs(f"the pipe {address} is not served by a program running as you. Nothing was "
                                       "sent to it. Another program has taken the pivcard agent's name: find and "
                                       "stop it before you unlock anything.")
            else:
                self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._sock.settimeout(timeout)
                self._sock.connect(address)
        except OSError as e:
            self.close()
            raise AgentUnavailable(str(e)) from None

    def send(self, data: bytes) -> None:
        if self._sock:
            self._sock.sendall(data)
        else:
            self._pipe.write(data)

    def recv(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            chunk = self._sock.recv(n - len(out)) if self._sock else self._pipe.read(n - len(out))
            if not chunk:
                raise AgentUnavailable("the agent closed the connection")
            out += chunk
        return out

    def close(self) -> None:
        for obj in (self._sock, self._pipe):
            if obj is not None:
                with contextlib.suppress(OSError):
                    obj.close()


def control(request: dict, *, autostart: bool = False, timeout: float = 60.0) -> dict:
    """Send one request to the agent's control endpoint. Raises AgentUnavailable if it is not running."""
    address = paths.endpoints()[1]
    try:
        conn = _Connection(address, timeout)
    except AgentUnavailable:
        if not autostart:
            raise
        start_detached()
        conn = _Connection(address, timeout)
    try:
        raw = json.dumps(request).encode()
        conn.send(struct.pack(">I", len(raw)) + raw)
        size = struct.unpack(">I", conn.recv(4))[0]
        return json.loads(conn.recv(size))
    except OSError as e:
        raise AgentUnavailable(str(e)) from None
    finally:
        conn.close()


def running() -> bool:
    try:
        return bool(control({"op": "status"}).get("ok"))
    except AgentUnavailable:
        return False


# How the agent process is started. It will hold the PIN and the secrets, so it must not import anything
# from the directory the user happens to be in, which may be a project that the AI agent can write to.
# `python -m` and `python -c` both put that directory first on the import path. -P (Python 3.11 and later)
# stops that; for older versions the first thing the process does is to take the entry out again, before
# it imports anything that is not already loaded. -E makes it ignore PYTHONPATH as well: an empty or
# relative entry there (PYTHONPATH=. for example) also means "the current directory".
SAFE_PATH = ["-E", "-P"] if sys.version_info >= (3, 11) else ["-E"]
BOOT = "import sys; sys.path[:] = [p for p in sys.path if p]; from pivcard.agent import main; sys.exit(main())"


def start_detached(wait: float = 10.0) -> None:
    """Start the agent in the background and wait until it answers."""
    kwargs: dict = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if paths.WINDOWS:
        kwargs["creationflags"] = (subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
                                   | subprocess.CREATE_NO_WINDOW)
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen([sys.executable, *SAFE_PATH, "-c", BOOT], **kwargs)
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if running():
            return
        time.sleep(0.1)
    raise AgentUnavailable("the agent did not start")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if running():
        print("pivcard agent: already running", file=sys.stderr)
        return 0
    paths.harden_process()
    ssh_address, control_address = paths.endpoints()
    agent = Agent(idle_exit=None if "--keep" in argv else IDLE_EXIT)

    async def serve() -> None:
        # A stop signal ends the loop instead of killing the process, so a card operation in progress
        # still finishes with its logout.
        loop = asyncio.get_running_loop()
        for name in ("SIGTERM", "SIGHUP", "SIGINT", "SIGBREAK"):
            sig = getattr(signal, name, None)
            if sig is not None:
                with contextlib.suppress(ValueError, OSError):
                    signal.signal(sig, lambda *_: loop.call_soon_threadsafe(agent.stopping.set))
        await agent.run(ssh_address, control_address)

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(serve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
