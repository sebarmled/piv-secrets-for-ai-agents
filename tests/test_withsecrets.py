"""withsecrets end to end: the real CLI, the real `age`, a real background agent, a software card."""
import os
import shutil
import subprocess
import sys

import pytest

from conftest import HAVE_TTY, NO_TERMINAL, child_env, own_command_line, run_on_tty, unix_lines, write_shim
from pivcard import tagfmt as t
from pivcard import withsecrets as ws
from test_interop import AGE, SHIM

pytestmark = pytest.mark.skipif(not AGE, reason="needs age on PATH")


@pytest.fixture
def box(tmp_path):
    """An isolated withsecrets home, agent directory and PATH with the software-card plugin shim."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    pem = tmp_path / "soft.pem"
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    write_shim(bindir, "age-plugin-pivcard", SHIM.format(pem=str(pem), log=str(tmp_path / "verify.log")))
    pub33 = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    home = tmp_path / "ws"
    home.mkdir()
    (home / "identity.txt").write_text(t.encode_identity(0x9D, pub33) + "\n")
    env = child_env(bindir, os.path.dirname(AGE), os.path.dirname(sys.executable), HOME=tmp_path,
                    XDG_CONFIG_HOME=tmp_path / ".config", WITHSECRETS_HOME=home, PIVCARD_AGENT_DIR=tmp_path / "run")

    class Box:
        path, environ = tmp_path, env

        @staticmethod
        def run(*args, stdin=b"", **kw):
            done = subprocess.run([sys.executable, "-m", "pivcard.withsecrets", *args], input=stdin, env=env,
                                  capture_output=True, timeout=60, check=False, **NO_TERMINAL, **kw)
            done.stdout, done.stderr = unix_lines(done.stdout), unix_lines(done.stderr)
            return done

        @staticmethod
        def tty(*args, pin=b"123456"):
            if not HAVE_TTY:
                pytest.skip("needs a pseudo-terminal (on Windows: pip install pywinpty)")
            return run_on_tty([sys.executable, "-m", "pivcard.withsecrets", *args], env, [pin])

        @staticmethod
        def verifies() -> int:
            log = tmp_path / "verify.log"
            return len(log.read_text().splitlines()) if log.exists() else 0

    yield Box
    subprocess.run([sys.executable, "-m", "pivcard.tool", "agent", "stop"], env=env, capture_output=True, check=False)


SECRET = b"# demo entry\nexport API_TOKEN=tok-123\nREGION=eu-central\n\nnot a pair\n"


def test_set_needs_no_card_and_writes_only_ciphertext(box):
    done = box.run("set", "cloud/demo", stdin=SECRET)
    assert done.returncode == 0 and b"API_TOKEN, REGION" in done.stderr and b"tok-123" not in done.stderr
    blob = (box.path / "ws" / "store" / "cloud" / "demo.age").read_bytes()
    assert blob.startswith(b"age-encryption.org/v1") and b"tok-123" not in blob and box.verifies() == 0
    assert box.run("set", "empty", stdin=b"just text\n").returncode == ws.EXIT_USAGE


def test_locked_entry_from_a_shell_without_terminal_exits_3_and_never_reaches_the_card(box):
    box.run("set", "cloud/demo", stdin=SECRET)
    for args in (["cloud/demo", "--", "env"], ["--cached-only", "cloud/demo", "--", "env"],
                 ["unlock", "cloud/demo"], ["list", "cloud/demo"]):
        got = box.run(*args)
        assert got.returncode == ws.EXIT_LOCKED, (args, got.stderr)
        assert b"tok-123" not in got.stdout + got.stderr
    assert box.verifies() == 0
    assert box.run("status").stdout == b"nothing unlocked\n"


def test_unlock_on_a_terminal_then_the_agent_shell_can_run_commands(box):
    box.run("set", "cloud/demo", stdin=SECRET)
    rc, screen = box.tty("unlock", "cloud/demo", "--ttl", "600")
    assert rc == 0 and b"stays unlocked for 10 min" in screen, screen
    assert box.verifies() == 1
    assert box.run("status").stdout.startswith(b"cloud/demo: unlocked, ")
    # from here on: no terminal, no PIN, no card
    got = box.run("--cached-only", "cloud/demo", "--", sys.executable, "-c",
                  "import os; print(os.environ['API_TOKEN'], os.environ['REGION'])")
    assert got.returncode == 0 and got.stdout == b"tok-123 eu-central\n"
    assert box.run("list", "cloud/demo").stdout == b"API_TOKEN\nREGION\n"
    assert box.verifies() == 1
    # the child's exit status is passed through
    assert box.run("cloud/demo", "--", sys.executable, "-c", "raise SystemExit(7)").returncode == 7
    # lock: gone again
    box.run("lock", "cloud/demo")
    assert box.run("--cached-only", "cloud/demo", "--", "env").returncode == ws.EXIT_LOCKED


def test_values_are_never_on_a_command_line(box):
    box.run("set", "cloud/demo", stdin=SECRET)
    box.tty("unlock", "cloud/demo")
    got = box.run("cloud/demo", "--", sys.executable, "-c", own_command_line())
    assert got.returncode == 0 and b"tok-123" not in got.stdout


def test_one_locked_entry_stops_the_whole_run(box):
    box.run("set", "a", stdin=b"A=1\n")
    box.run("set", "b", stdin=b"B=2\n")
    box.tty("unlock", "a")
    got = box.run("a", "b", "--", sys.executable, "-c", "print('ran')")
    assert got.returncode == ws.EXIT_LOCKED and got.stdout == b""


def test_running_a_command_never_asks_for_the_pin_even_on_a_terminal(box):
    box.run("set", "cloud/demo", stdin=SECRET)
    show = [sys.executable, "-c", "import os; print('T=' + os.environ['API_TOKEN'])"]
    for flags in ([], ["--cached-only"]):                        # the old flag is accepted and changes nothing
        rc, screen = box.tty(*flags, "cloud/demo", "--", *show)
        assert rc == ws.EXIT_LOCKED and b"withsecrets unlock cloud/demo" in screen
        assert b"Enter the PIN" not in screen and box.verifies() == 0
    assert box.tty("unlock", "cloud/demo")[0] == 0 and box.verifies() == 1
    rc, screen = box.tty("cloud/demo", "--", *show)
    assert rc == 0 and b"T=tok-123" in screen and box.verifies() == 1


def test_pin_prompts_can_be_switched_off_for_an_environment(box):
    box.run("set", "cloud/demo", stdin=SECRET)
    box.environ["PIVCARD_NO_PROMPT"] = "1"
    try:
        rc, screen = box.tty("unlock", "cloud/demo")
        assert rc == ws.EXIT_LOCKED and b"PIVCARD_NO_PROMPT" in screen and b"Enter the PIN" not in screen
        assert box.verifies() == 0
    finally:
        del box.environ["PIVCARD_NO_PROMPT"]
    assert box.tty("unlock", "cloud/demo")[0] == 0


def test_an_entry_cannot_change_what_programs_load(box):
    done = box.run("set", "bad", stdin=b"TOKEN=x\nLD_PRELOAD=/tmp/evil.so\n")
    assert done.returncode == ws.EXIT_USAGE and b"LD_PRELOAD" in done.stderr
    assert not (box.path / "ws" / "store" / "bad.age").exists()
    # the same entry planted directly in the agent (no card is needed for that) is refused when used
    from pivcard import agent as ag
    env = dict(os.environ)
    os.environ.update(box.environ)
    try:
        for planted in (b"PATH=/tmp/evil\n", b"A=1\nPYTHONSTARTUP=/tmp/evil.py\n", b"DYLD_INSERT_LIBRARIES=x\n",
                        b"SHELLOPTS=xtrace\nPS4=$(id)\n", b"GIT_CONFIG_COUNT=1\n", b"pythonpath=x\n", b"Path=x\n",
                        b"NODE_PATH=x\n", b"HOME=/tmp\n", b"EDITOR=sh\n", b"PIVCARD_NO_PROMPT=0\n", b"HZ_INNER=1\n"):
            import base64
            ag.control({"op": "put", "name": "planted", "data": base64.b64encode(planted).decode(), "ttl": 60},
                       autostart=True)
            got = box.run("planted", "--", sys.executable, "-c", "print('ran')")
            assert got.returncode == 1 and got.stdout == b"" and b"would change what programs load" in got.stderr
    finally:
        os.environ.clear()
        os.environ.update(env)


def test_time_limits_must_be_positive_numbers(box):
    box.run("set", "a", stdin=b"A=1\n")
    for bad in (["--ttl", "0"], ["--ttl", "-5"], ["--ttl", "soon"], ["--ttl"]):
        got = box.run("unlock", "a", *bad)
        assert got.returncode == ws.EXIT_USAGE, (bad, got.stderr)
    rc, screen = box.tty("unlock", "a", "--ttl", "999999")
    assert rc == 0 and b"stays unlocked for 1440 min" in screen  # what is announced is what is kept: one day


def test_find_program_takes_a_given_path_as_it_is(tmp_path):
    from pivcard import paths
    assert paths.find_program(sys.executable) == sys.executable
    assert paths.find_program(str(tmp_path / "no-such-program")) is None
    assert paths.find_program("no-such-program-anywhere") is None


def test_wrong_pin_is_a_decrypt_failure_and_nothing_is_cached(box):
    box.run("set", "cloud/demo", stdin=SECRET)
    rc, screen = box.tty("unlock", "cloud/demo", pin=b"000000")
    assert rc == ws.EXIT_DECRYPT and b"wrong PIN" in screen
    assert box.run("status").stdout == b"nothing unlocked\n"


def test_setting_an_entry_drops_its_unlocked_copy(box):
    box.run("set", "cloud/demo", stdin=SECRET)
    box.tty("unlock", "cloud/demo")
    box.run("set", "cloud/demo", stdin=b"API_TOKEN=new\n")
    assert box.run("--cached-only", "cloud/demo", "--", "env").returncode == ws.EXIT_LOCKED


@pytest.mark.parametrize("name", ["../x", "/abs", "a//b", ".hidden", "a b", "", "-x", "nul", "CON", "com1/x", "a.",
                                  "x/aux.old", "C:x", "a\\b"])
def test_entry_names_cannot_escape_the_store(box, name):
    assert box.run("set", name, stdin=b"A=1\n").returncode == ws.EXIT_USAGE
    assert not list((box.path / "ws").rglob("*.age"))


def test_usage_and_missing_command(box):
    assert box.run().returncode == ws.EXIT_USAGE
    assert box.run("a", "b").returncode == ws.EXIT_USAGE
    box.run("set", "a", stdin=b"A=1\n")
    box.tty("unlock", "a")
    assert box.run("a", "--", "definitely-not-a-command").returncode == 127


def test_parse_pairs():
    pairs, ignored = ws.parse_pairs("A=1\n  # c\n\nexport B=x=y \nbad line\n9X=1\n_C=\nc2VjcmV0=\n")
    assert pairs == [("A", "1"), ("B", "x=y ")] and ignored == 4      # a name with no value is not a pair
    assert ws.parse_pairs("A=1\x0cB=2\u2028C=3\r\nD=4\n")[0] == [("A", "1\x0cB=2\u2028C=3"), ("D", "4")]


def test_set_with_names_reads_values_at_a_hidden_prompt(box, monkeypatch, capsys):
    for key, value in box.environ.items():
        monkeypatch.setenv(key, value)
    typed = iter(["tok-typed", "eu"])
    prompts = []
    monkeypatch.setattr(ws.getpass, "getpass", lambda prompt="": prompts.append(prompt) or next(typed))
    monkeypatch.setattr(ws, "on_terminal", lambda: True)
    assert ws.main(["set", "cloud/typed", "API_TOKEN", "REGION"]) == 0
    assert len(prompts) == 2 and "API_TOKEN" in prompts[0] and "tok-typed" not in capsys.readouterr().err
    assert box.tty("unlock", "cloud/typed")[0] == 0
    shown = box.run("--cached-only", "cloud/typed", "--", sys.executable, "-c",
                    "import os; print(os.environ['API_TOKEN'] + '-' + os.environ['REGION'])").stdout
    assert shown.strip() == b"tok-typed-eu"
    # bad names, an empty value and "no terminal" all write nothing
    assert ws.main(["set", "cloud/bad", "1BAD"]) == ws.EXIT_USAGE
    monkeypatch.setattr(ws.getpass, "getpass", lambda prompt="": "")
    assert ws.main(["set", "cloud/bad", "EMPTY"]) == ws.EXIT_USAGE
    monkeypatch.setattr(ws, "on_terminal", lambda: False)
    assert ws.main(["set", "cloud/bad", "API_TOKEN"]) == ws.EXIT_USAGE
    assert not (box.path / "ws" / "store" / "cloud" / "bad.age").exists()


def test_extra_recipients_can_open_an_entry_without_the_card(box):
    keygen = shutil.which("age-keygen", path=os.path.dirname(AGE))
    if not keygen:
        pytest.skip("needs age-keygen")
    backup = box.path / "backup.key"
    subprocess.run([keygen, "-o", str(backup)], check=True, capture_output=True)
    recipient = subprocess.run([keygen, "-y", str(backup)], check=True, capture_output=True, text=True).stdout
    (box.path / "ws" / "recipients.txt").write_text("# offline backup key\n" + recipient)
    done = box.run("set", "cloud/demo", stdin=SECRET)
    assert done.returncode == 0 and b"recipients.txt" in done.stderr
    entry = box.path / "ws" / "store" / "cloud" / "demo.age"
    plain = subprocess.run([AGE, "-d", "-i", str(backup), str(entry)], capture_output=True, env=box.environ,
                           check=True).stdout
    assert plain == SECRET and box.verifies() == 0               # opened with the backup key, card untouched
    assert box.tty("unlock", "cloud/demo")[0] == 0 and box.verifies() == 1   # and still with the card
