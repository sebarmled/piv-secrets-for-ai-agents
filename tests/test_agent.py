"""The agent, in-process, with the software card and the real OpenSSH tools as clients."""
import asyncio
import os
import shutil
import struct
import subprocess
import threading
import time

import pytest

from conftest import POSIX, child_env
from pivcard import agent as ag
from pivcard import paths, piv
from pivcard.fake import SoftCard

needs_openssh = pytest.mark.skipif(not shutil.which("ssh-keygen") or not shutil.which("ssh-add"),
                                   reason="needs the OpenSSH client tools")


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Running:
    def __init__(self, agent, card, clock, thread, ssh_address):
        self.agent, self.card, self.clock, self.thread, self.ssh_address = agent, card, clock, thread, ssh_address


@pytest.fixture
def running(tmp_path, monkeypatch):
    monkeypatch.setenv("PIVCARD_AGENT_DIR", str(tmp_path / "run"))
    card = SoftCard()
    card.ssh_pub = card.add_key(0x9A)
    clock = Clock()
    agent = ag.Agent(open_transport=lambda: card, clock=clock, idle_exit=None)
    ssh_address, control_address = paths.endpoints()
    thread = threading.Thread(target=lambda: asyncio.run(agent.run(ssh_address, control_address)), daemon=True)
    thread.start()
    deadline = time.time() + 5
    while not ag.running():
        assert time.time() < deadline, "agent did not start"
        time.sleep(0.02)
    yield Running(agent, card, clock, thread, ssh_address)
    with pytest.raises(Exception) if not thread.is_alive() else _noop():
        ag.control({"op": "stop"})
    thread.join(timeout=5)


class _noop:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def unlock(pin="123456", **extra):
    return ag.control({"op": "ssh-unlock", "pin": pin, **extra})


# ---------------------------------------------------------------- control: secrets
def test_starts_empty(running):
    st = ag.control({"op": "status"})
    assert st["ok"] and st["ssh"] is None and st["secrets"] == [] and st["ssh_endpoint"] == running.ssh_address


def test_entries_are_held_until_they_expire(running):
    data = b"API_TOKEN=abc\n"
    assert ag.control({"op": "put", "name": "cloud/demo", "data": ag.base64.b64encode(data).decode(), "ttl": 600})["ok"]
    got = ag.control({"op": "get", "name": "cloud/demo"})
    assert ag.base64.b64decode(got["data"]) == data and got["seconds_left"] == 600
    assert ag.control({"op": "status"})["secrets"] == [{"name": "cloud/demo", "seconds_left": 600}]
    running.clock.now += 599
    assert ag.control({"op": "get", "name": "cloud/demo"})["ok"]
    running.clock.now += 2
    assert ag.control({"op": "get", "name": "cloud/demo"}) == {"ok": False, "error": "locked"}
    assert running.agent.secrets == {}


def test_clear_one_or_all_and_ttl_is_capped(running):
    for name in ("a", "b", "c"):
        ag.control({"op": "put", "name": name, "data": "eA==", "ttl": 10 ** 9})
    assert ag.control({"op": "status"})["secrets"][0]["seconds_left"] == ag.MAX_TTL
    ag.control({"op": "clear", "name": "b"})
    assert [s["name"] for s in ag.control({"op": "status"})["secrets"]] == ["a", "c"]
    ag.control({"op": "clear"})
    assert ag.control({"op": "status"})["secrets"] == []


def test_bad_requests_get_an_error_not_a_crash(running):
    assert not ag.control({"op": "nope"})["ok"]
    assert not ag.control({"op": "get"})["ok"]
    assert not ag.control({"op": "put", "name": "x", "data": "!!!"})["ok"]
    assert ag.control({"op": "status"})["ok"]


# ---------------------------------------------------------------- control: SSH unlock
def test_wrong_pin_is_not_kept(running):
    reply = unlock("000000")
    assert not reply["ok"] and "wrong PIN" in reply["error"] and "5 tries left" in reply["error"]
    assert running.agent.ssh is None and not running.card.verified


def test_unlock_checks_the_pin_on_the_card_and_leaves_it_locked(running):
    reply = unlock(ttl=3600)
    assert reply["ok"] and reply["ssh"]["slot"] == "9A" and reply["ssh"]["seconds_left"] == 3600
    assert reply["ssh"]["public_key"] == ag.ssh_public_key_line(running.card.ssh_pub)
    assert not running.card.verified and running.card.verify_attempts == 1
    running.clock.now += 3601
    assert ag.control({"op": "status"})["ssh"] is None


def test_unlock_refuses_a_slot_without_a_usable_key(running):
    assert "no certificate" in unlock(slot="9C")["error"]
    assert "unknown PIV slot" in unlock(slot="zz")["error"]
    assert running.card.verify_attempts == 0


def test_unlock_with_an_expected_key_refuses_another_card_before_any_pin(running):
    other = SoftCard().add_key(0x9A)
    reply = unlock(expect=other.hex())
    assert not reply["ok"] and "another card" in reply["error"] and "No PIN was sent" in reply["error"]
    assert running.card.verify_attempts == 0 and running.agent.ssh is None
    assert unlock(expect=running.card.ssh_pub.hex())["ok"]


# ---------------------------------------------------------------- `pivcard ssh unlock` (the command)
@pytest.fixture
def ssh_unlock(running, tmp_path, monkeypatch):
    """Run `pivcard ssh unlock` in-process against the software card, as if typed on a terminal."""
    from pivcard import tool
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "config"))
    monkeypatch.setattr(tool.piv, "open_transport", lambda reader=None: running.card)
    monkeypatch.setattr(tool.sys, "stdin", type("Tty", (), {"isatty": staticmethod(lambda: True)})())
    asked = []
    monkeypatch.setattr(tool.getpass, "getpass", lambda prompt="": asked.append(prompt) or "123456")

    def run(*extra):
        return tool.main(["ssh", "unlock", *extra])

    run.asked, run.key_file = asked, tool.ssh_key_file
    return run


def test_ssh_unlock_remembers_the_cards_key(running, ssh_unlock, capsys):
    assert ssh_unlock() == 0
    saved = ssh_unlock.key_file().read_text()
    assert saved.strip() == ag.ssh_public_key_line(running.card.ssh_pub)
    assert "IdentitiesOnly=yes" in capsys.readouterr().out and running.agent.ssh is not None
    assert ssh_unlock() == 0 and ssh_unlock.key_file().read_text() == saved


def test_pin_prompts_switched_off_also_stop_ssh_unlock(running, ssh_unlock, monkeypatch, capsys):
    monkeypatch.setenv("PIVCARD_NO_PROMPT", "1")
    assert ssh_unlock() == 1 and "PIVCARD_NO_PROMPT" in capsys.readouterr().err
    assert ssh_unlock.asked == [] and running.card.log == [] and running.agent.ssh is None
    for bad in ("0", "-1", "nan", "inf", "1e308", "24.5"):
        with pytest.raises(SystemExit):                         # argparse refuses the time limit
            ssh_unlock("--hours", bad)
    assert ssh_unlock.asked == []


def test_ssh_unlock_refuses_another_card_before_asking_for_the_pin(running, ssh_unlock, capsys):
    assert ssh_unlock() == 0
    ag.control({"op": "ssh-lock"})
    attempts, prompts = running.card.verify_attempts, len(ssh_unlock.asked)
    new_key = running.card.add_key(0x9A)                        # another card is now in the reader
    assert ssh_unlock() == 1
    assert "not the card SSH was set up with" in capsys.readouterr().err
    assert len(ssh_unlock.asked) == prompts and running.card.verify_attempts == attempts
    assert running.agent.ssh is None
    assert ssh_unlock("--new-card") == 0                        # changing cards on purpose
    assert ssh_unlock.key_file().read_text().strip() == ag.ssh_public_key_line(new_key)


def test_ssh_unlock_without_a_terminal_sends_nothing(running, ssh_unlock, monkeypatch, capsys):
    from pivcard import tool
    monkeypatch.setattr(tool.sys, "stdin", type("Pipe", (), {"isatty": staticmethod(lambda: False)})())
    sent = len(running.card.log)
    assert ssh_unlock() == 1 and "needs your terminal" in capsys.readouterr().err
    assert len(running.card.log) == sent and not ssh_unlock.asked


# ---------------------------------------------------------------- SSH endpoint with real OpenSSH
def ssh_env(running):
    return child_env(SSH_AUTH_SOCK=running.ssh_address, SSH_ASKPASS_REQUIRE="never")


def sign_and_check(running, tmp_path) -> bool:
    pub = tmp_path / "key.pub"
    pub.write_text(ag.ssh_public_key_line(running.card.ssh_pub) + "\n")
    msg = tmp_path / "msg"
    msg.write_bytes(b"payload " + str(time.time()).encode())
    sig = tmp_path / "msg.sig"
    sig.unlink(missing_ok=True)
    made = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(pub), "-n", "test", str(msg)], env=ssh_env(running),
                          capture_output=True, stdin=subprocess.DEVNULL, check=False)
    if made.returncode != 0 or not sig.exists():
        return False
    with msg.open("rb") as f:
        checked = subprocess.run(["ssh-keygen", "-Y", "check-novalidate", "-n", "test", "-s", str(sig)], stdin=f,
                                 capture_output=True, check=False)
    return checked.returncode == 0


@needs_openssh
def test_openssh_sees_no_key_while_locked_and_one_key_when_unlocked(running):
    listed = subprocess.run(["ssh-add", "-L"], env=ssh_env(running), capture_output=True, text=True, check=False)
    assert "no identities" in (listed.stdout + listed.stderr)
    unlock()
    listed = subprocess.run(["ssh-add", "-L"], env=ssh_env(running), capture_output=True, text=True, check=True)
    assert listed.stdout.split()[:2] == ag.ssh_public_key_line(running.card.ssh_pub).split()[:2]


@needs_openssh
def test_openssh_signature_through_the_agent_verifies_and_card_is_locked_after_each(running, tmp_path):
    unlock()
    before = running.card.verify_attempts
    for i in range(3):
        assert sign_and_check(running, tmp_path)
        assert not running.card.verified                       # logged out after every signature
        assert running.card.verify_attempts == before + i + 1


@needs_openssh
def test_locked_agent_does_not_sign_or_touch_the_card(running, tmp_path):
    assert not sign_and_check(running, tmp_path)
    unlock()
    ag.control({"op": "ssh-lock"})
    sent = len(running.card.log)
    assert not sign_and_check(running, tmp_path) and len(running.card.log) == sent


@needs_openssh
def test_a_rejected_pin_is_forgotten_at_once(running, tmp_path):
    unlock()
    running.card.pin = "999999"                                 # the PIN was changed behind the agent's back
    assert not sign_and_check(running, tmp_path)
    assert running.agent.ssh is None and running.card.tries == 5
    assert not sign_and_check(running, tmp_path) and running.card.tries == 5   # no second attempt


@needs_openssh
def test_a_different_card_gets_no_pin(running, tmp_path):
    unlock()
    attempts = running.card.verify_attempts
    running.card.add_key(0x9A)                                  # another card is now in the reader
    assert not sign_and_check(running, tmp_path)
    assert running.card.verify_attempts == attempts


def raw_ssh_request(address: str, payload: bytes) -> bytes:
    connection = ag._Connection(address)        # a Unix socket on Linux, a named pipe on Windows
    try:
        connection.send(struct.pack(">I", len(payload)) + payload)
        return connection.recv(struct.unpack(">I", connection.recv(4))[0])
    finally:
        connection.close()


def test_ssh_endpoint_offers_nothing_but_identities_and_signing(running):
    ag.control({"op": "put", "name": "x", "data": "eA==", "ttl": 60})
    unlock()
    for payload in (b'{"op": "get", "name": "x"}', bytes([27]) + ag._string(b"secret-get@pivcard"),
                    bytes([17]), bytes([19]), bytes([13]) + b"\x00"):
        assert raw_ssh_request(running.ssh_address, payload) == bytes([ag.SSH_AGENT_FAILURE])


def test_signature_encoding_matches_the_ssh_format():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    blob = ag.ssh_signature(key.sign(b"x", ec.ECDSA(hashes.SHA256())))
    kind, pos = ag._take_string(blob, 0)
    inner, end = ag._take_string(blob, pos)
    r, p2 = ag._take_string(inner, 0)
    s, p3 = ag._take_string(inner, p2)
    assert kind == b"ecdsa-sha2-nistp256" and end == len(blob) and p3 == len(inner)
    assert all(v[0] < 0x80 and (len(v) == 1 or v[0] != 0 or v[1] >= 0x80) for v in (r, s))   # minimal positive mpints


# ---------------------------------------------------------------- lifetime
def test_agent_exits_by_itself_when_it_holds_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("PIVCARD_AGENT_DIR", str(tmp_path / "run"))
    agent = ag.Agent(open_transport=SoftCard, idle_exit=0.3)
    ssh_address, control_address = paths.endpoints()
    thread = threading.Thread(target=lambda: asyncio.run(agent.run(ssh_address, control_address)), daemon=True)
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive() and not ag.running()
    assert not os.path.exists(ssh_address)                      # the socket file (or the pipe) is gone


@pytest.mark.skipif(not POSIX, reason="file modes; on Windows the endpoints are named pipes, not files")
def test_runtime_dir_is_private(tmp_path, monkeypatch):
    monkeypatch.setenv("PIVCARD_AGENT_DIR", str(tmp_path / "run"))
    assert (paths.runtime_dir().stat().st_mode & 0o777) == 0o700
    (tmp_path / "run").chmod(0o755)
    with pytest.raises(PermissionError):
        paths.runtime_dir()
    assert piv.MIN_TRIES == 1


def test_the_windows_pipe_is_named_with_forward_slashes_for_openssh(monkeypatch):
    monkeypatch.setattr(paths, "WINDOWS", True)
    monkeypatch.setenv("PIVCARD_AGENT_DIR", "t e/st")
    ssh, control = paths.endpoints()
    assert ssh == r"\\.\pipe\pivcard-ssh-t_e_st" and control == r"\\.\pipe\pivcard-control-t_e_st"
    assert paths.openssh_agent_address() == "//./pipe/pivcard-ssh-t_e_st"
    monkeypatch.setenv("PIVCARD_AGENT_DIR", "C:\\Users\\someone\\AppData\\Local\\Temp\\" + "x" * 90)
    ssh, control = paths.endpoints()                            # OpenSSH for Windows fails on long pipe names
    assert len(ssh) < 70 and ssh.startswith(r"\\.\pipe\pivcard-ssh-C__Users_someone") and ssh != control
    monkeypatch.setenv("PIVCARD_AGENT_DIR", "C:\\Users\\someone\\AppData\\Local\\Temp\\" + "x" * 89 + "y")
    assert paths.endpoints()[0] != ssh


# ---------------------------------------------------------------- Windows: who serves the pipe
@pytest.mark.skipif(POSIX, reason="named pipes; on Linux the socket directory and the peer's uid are checked")
def test_a_pipe_served_by_someone_else_gets_nothing(running, monkeypatch):
    assert ag.control({"op": "status"})["ok"]                   # the real check accepts our own agent
    before = running.card.verify_attempts
    with monkeypatch.context() as patch:
        patch.setattr(ag, "_served_by_me", lambda pipe: False)
        for request in ({"op": "status"}, {"op": "ssh-unlock", "pin": "123456"},
                        {"op": "put", "name": "x", "data": "eA==", "ttl": 60}):
            with pytest.raises(ag.AgentNotOurs, match="Nothing was sent"):
                ag.control(request, autostart=True)
    assert running.agent.ssh is None and running.card.verify_attempts == before
    assert ag.control({"op": "status"})["secrets"] == []


def test_the_commands_say_so_and_stop(monkeypatch, capsys):
    from pivcard import tool
    from pivcard import withsecrets as ws

    def refuse(request, **kw):
        raise ag.AgentNotOurs("the pipe is not served by a program running as you. Nothing was sent to it.")

    monkeypatch.setattr(ag, "control", refuse)
    assert tool.main(["ssh", "status"]) == 1 and "Nothing was sent" in capsys.readouterr().err
    assert ws.main(["status"]) == 1 and "Nothing was sent" in capsys.readouterr().err


# ---------------------------------------------------------------- time limits and requests that overlap
@pytest.mark.parametrize("ttl", [float("nan"), float("inf"), 0, -1, "60", True, 10 ** 400])
def test_a_time_limit_must_be_a_positive_finite_number(running, ttl):
    for request in ({"op": "put", "name": "x", "data": "eA==", "ttl": ttl},
                    {"op": "ssh-unlock", "pin": "123456", "ttl": ttl}):
        reply = ag.control(request)
        assert not reply["ok"] and reply["error"].startswith("bad request"), reply
    status = ag.control({"op": "status"})                       # and the agent still answers, holding nothing
    assert status["ok"] and status["ssh"] is None and status["secrets"] == []
    assert running.card.verify_attempts == 0


def sign_request(running) -> bytes:
    payload = (bytes([ag.SSH_AGENTC_SIGN_REQUEST]) + ag._string(ag.ssh_key_blob(running.card.ssh_pub))
               + ag._string(b"data to sign") + struct.pack(">I", 0))
    return raw_ssh_request(running.ssh_address, payload)


def slow_pin_check(running, monkeypatch, seconds=0.3):
    """Make the card take its time over a VERIFY, so that several requests are in the agent at once."""
    transmit = running.card.transmit

    def slow(apdu):
        if apdu[1] == 0x20 and apdu[2] == 0x00 and len(apdu) > 5:
            time.sleep(seconds)
        return transmit(apdu)

    monkeypatch.setattr(running.card, "transmit", slow)


def test_requests_that_waited_for_the_card_do_not_send_a_rejected_pin_again(running, monkeypatch):
    unlock()
    running.card.pin = "654321"                                 # the PIN was changed elsewhere meanwhile
    slow_pin_check(running, monkeypatch)
    before, replies = running.card.verify_attempts, []
    threads = [threading.Thread(target=lambda: replies.append(sign_request(running))) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert replies == [bytes([ag.SSH_AGENT_FAILURE])] * 5
    assert running.card.verify_attempts - before == 1 and running.card.tries == 5
    assert running.agent.ssh is None


def test_a_lock_also_stops_a_signature_that_was_waiting_for_the_card(running, monkeypatch):
    unlock()
    slow_pin_check(running, monkeypatch, seconds=0.6)
    before, replies = running.card.verify_attempts, []
    first = threading.Thread(target=lambda: replies.append(sign_request(running)))
    first.start()
    deadline = time.time() + 5
    while not running.card.in_transaction:                      # the first request has the card
        assert time.time() < deadline
        time.sleep(0.01)
    second = threading.Thread(target=lambda: replies.append(sign_request(running)))
    second.start()
    time.sleep(0.1)                                             # the second one now waits for the card
    ag.control({"op": "ssh-lock"})
    first.join(timeout=20)
    second.join(timeout=20)
    assert running.card.verify_attempts - before == 1           # no PIN went to the card after the lock
    assert sorted(r[0] for r in replies) == [ag.SSH_AGENT_FAILURE, ag.SSH_AGENT_SIGN_RESPONSE]


@pytest.mark.parametrize("with_safe_path_option", [True, False])
def test_the_agent_does_not_import_from_the_directory_it_is_started_in(tmp_path, monkeypatch, with_safe_path_option):
    """Python puts the working directory first on the import path of a process started with -m or -c. A file
    dropped into a project directory must not get to run inside the process that holds the PIN. Checked
    both with Python's -P option and without it, which is how it runs on Python 3.10."""
    if with_safe_path_option and not ag.SAFE_PATH:
        pytest.skip("this Python has no -P option")
    project = tmp_path / "project"
    project.mkdir()
    marker = tmp_path / "hijacked"
    for name in ("json.py", "struct.py", "pivcard.py", "asyncio.py", "runpy.py", "contextlib.py"):
        (project / name).write_text(f"open({str(marker)!r}, 'w').write('x')\nraise ImportError('planted')\n")
    monkeypatch.chdir(project)
    monkeypatch.setenv("PIVCARD_AGENT_DIR", "run" if POSIX else str(tmp_path / "run"))   # relative: still works
    # an empty entry in PYTHONPATH also means "the current directory" (export PYTHONPATH=$PYTHONPATH:/x)
    monkeypatch.setenv("PYTHONPATH", os.pathsep + os.environ.get("PYTHONPATH", ""))
    if not with_safe_path_option:
        monkeypatch.setattr(ag, "SAFE_PATH", ["-E"])
    ag.start_detached()
    try:
        assert ag.control({"op": "status"})["ok"] and not marker.exists()
    finally:
        ag.control({"op": "stop"})


def test_how_the_agent_is_started(monkeypatch):
    started = {}
    monkeypatch.setattr(ag.subprocess, "Popen", lambda argv, **kw: started.update(argv=argv, **kw))
    monkeypatch.setattr(ag, "running", lambda: True)
    ag.start_detached()
    assert started["argv"][-2:] == ["-c", ag.BOOT] and "-m" not in started["argv"] and "cwd" not in started
    assert "-E" in started["argv"] and ("-P" in started["argv"]) == (ag.sys.version_info >= (3, 11))
    assert ag.BOOT.startswith("import sys; sys.path[:] = [p for p in sys.path if p];")


@pytest.mark.skipif(POSIX, reason="named pipes")
def test_the_pipes_are_created_for_local_clients_only(running):
    import _winapi
    assert getattr(_winapi.CreateNamedPipe, "pivcard_local_only", False)
