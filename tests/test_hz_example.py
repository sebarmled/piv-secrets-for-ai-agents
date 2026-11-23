"""The Hetzner example, against an in-memory stand-in for the Hetzner API (no network, no card)."""
import base64
import http.server
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import threading

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pivcard import agent as ag
from pivcard import tool

HZ = pathlib.Path(__file__).resolve().parent.parent / "examples" / "hetzner" / "hz.py"
spec = importlib.util.spec_from_file_location("hz_example", HZ)
hz = importlib.util.module_from_spec(spec)
_own = {name: os.environ.pop(name) for name in list(os.environ) if name.startswith("HZ_")}
try:                                     # the script reads its settings when it is loaded: use its defaults,
    spec.loader.exec_module(hz)          # not the settings of whoever runs the tests
finally:
    os.environ.update(_own)

TYPES = [
    {"name": "big", "cpu_type": "shared", "architecture": "x86", "deprecated": False,
     "prices": [{"location": "nbg1", "price_hourly": {"gross": "0.0500"}}]},
    {"name": "small", "cpu_type": "shared", "architecture": "x86", "deprecated": False,
     "prices": [{"location": "nbg1", "price_hourly": {"gross": "0.0080"}},
                {"location": "hel1", "price_hourly": {"gross": "0.0010"}}]},
    {"name": "old", "cpu_type": "shared", "architecture": "x86", "deprecated": True,
     "prices": [{"location": "nbg1", "price_hourly": {"gross": "0.0010"}}]},
    {"name": "arm", "cpu_type": "shared", "architecture": "arm", "deprecated": False,
     "prices": [{"location": "nbg1", "price_hourly": {"gross": "0.0020"}}]},
    {"name": "dedicated", "cpu_type": "dedicated", "architecture": "x86", "deprecated": False,
     "prices": [{"location": "nbg1", "price_hourly": {"gross": "0.0030"}}]},
    # As the real API answers: a price is listed for every location, also where the type is sold out or
    # retired. Only the per-location entry says whether it can be created there.
    {"name": "soldout", "cpu_type": "shared", "architecture": "x86", "deprecation": None,
     "prices": [{"location": "nbg1", "price_hourly": {"gross": "0.0040"}}],
     "locations": [{"name": "nbg1", "available": False, "deprecation": None}]},
    {"name": "retired-here", "cpu_type": "shared", "architecture": "x86", "deprecation": None,
     "prices": [{"location": "nbg1", "price_hourly": {"gross": "0.0050"}}],
     "locations": [{"name": "nbg1", "available": True, "deprecation": {"unavailable_after": "2025-12-31"}},
                   {"name": "ash", "available": True, "deprecation": None}]},
    {"name": "elsewhere", "cpu_type": "shared", "architecture": "x86", "deprecation": None,
     "prices": [{"location": "nbg1", "price_hourly": {"gross": "0.0060"}}],
     "locations": [{"name": "hel1", "available": True, "deprecation": None}]},
    {"name": "listed", "cpu_type": "shared", "architecture": "x86", "deprecation": None,
     "prices": [{"location": "nbg1", "price_hourly": {"gross": "0.0700"}}],
     "locations": [{"name": "nbg1", "available": True, "deprecation": None}]},
]


class FakeHetzner:
    """Just enough of the API: servers, ssh_keys, server_types, with labels and fingerprints."""

    def __init__(self):
        self.servers, self.keys, self.calls, self.next_id = [], [], [], 100
        self.on_create = lambda body: None

    @staticmethod
    def _labelled(items, selector):
        key, _, value = selector.partition("=")
        return [i for i in items if i["labels"].get(key) == value]

    def call(self, method, path, body=None, **query):
        self.calls.append((method, path))
        if (method, path) == ("GET", "/server_types"):
            return {"server_types": TYPES}
        if (method, path) == ("GET", "/servers"):
            return {"servers": self._labelled(self.servers, query["label_selector"])}
        if (method, path) == ("GET", "/ssh_keys"):
            if "fingerprint" in query:
                return {"ssh_keys": [k for k in self.keys if k["fingerprint"] == query["fingerprint"]]}
            return {"ssh_keys": self._labelled(self.keys, query["label_selector"])}
        if (method, path) == ("POST", "/ssh_keys"):
            if any(k["name"] == body["name"] for k in self.keys):
                raise hz.ApiError(409, "uniqueness_error", "SSH key not unique")
            self.next_id += 1
            key = {"id": self.next_id, "name": body["name"], "labels": body.get("labels", {}),
                   "public_key": body["public_key"], "fingerprint": hz.fingerprint(body["public_key"])}
            self.keys.append(key)
            return {"ssh_key": key}
        if (method, path) == ("POST", "/servers"):
            self.on_create(body)
            self.next_id += 1
            server = {"id": self.next_id, "name": body["name"], "labels": body["labels"], "status": "running",
                      "server_type": {"name": body["server_type"]}, "created": "2026-01-01T00:00:00+00:00",
                      "public_net": {"ipv4": {"ip": "192.0.2.10"}}, "request": body}
            self.servers.append(server)
            return {"server": server, "action": {"id": 1, "status": "success"}, "root_password": None}
        if method == "DELETE" and path.startswith("/servers/"):
            self.servers = [s for s in self.servers if s["id"] != int(path.rsplit("/", 1)[1])]
            return {"action": {"id": 2, "status": "success"}}
        if method == "DELETE" and path.startswith("/ssh_keys/"):
            self.keys = [k for k in self.keys if k["id"] != int(path.rsplit("/", 1)[1])]
            return {}
        raise AssertionError(f"unexpected API call {method} {path}")

    def wait(self, action, what, timeout=0):
        assert action is None or action["status"] == "success"


@pytest.fixture
def box(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "config"))
    monkeypatch.setenv("PIVCARD_AGENT_DIR", str(tmp_path / "run"))
    monkeypatch.setenv("WITHSECRETS_HOME", str(tmp_path / "ws"))
    monkeypatch.delenv("HZ_TYPE", raising=False)
    monkeypatch.delenv("HCLOUD_TOKEN", raising=False)
    monkeypatch.delenv(hz.INNER, raising=False)
    monkeypatch.setattr(hz, "wait_for_port", lambda ip, port, timeout=0: True)
    card_key = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    tool.ssh_key_file().parent.mkdir(parents=True)
    tool.ssh_key_file().write_text(card_key + " piv-card\n")
    api = FakeHetzner()
    api.card_key = card_key
    yield api
    subprocess.run([sys.executable, "-m", "pivcard.tool", "agent", "stop"], capture_output=True, check=False)


def test_create_pins_the_host_key_before_the_vm_exists_and_uploads_only_the_public_key(box, capsys):
    yaml = pytest.importorskip("yaml")
    seen = {}
    box.on_create = lambda body: seen.update(known_hosts=hz.known_hosts().read_text())
    assert hz.cmd_create(box, []) == 0
    request = box.servers[0]["request"]
    assert request["server_type"] == "small" and request["labels"] == {"pivcard-hz": "pivcard-demo"}
    assert request["ssh_keys"] == [box.keys[0]["id"]] and box.keys[0]["public_key"].startswith(box.card_key)
    # the host key in known_hosts (written before the POST) is the one the VM is told to use
    assert request["user_data"].startswith("#cloud-config\n")
    config = yaml.safe_load(request["user_data"])
    assert config["ssh_deletekeys"] is True and config["ssh_pwauth"] is False
    private = serialization.load_ssh_private_key(config["ssh_keys"]["ed25519_private"].encode(), None)
    public = private.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                               serialization.PublicFormat.OpenSSH).decode()
    assert seen["known_hosts"] == f"pivcard-demo {public}\n" == hz.known_hosts().read_text()
    assert json.loads(hz.server_file().read_text())["ip"] == "192.0.2.10"
    out = capsys.readouterr().out
    assert "EUR 0.0080 per hour" in out and "PRIVATE KEY" not in out


def test_create_refuses_a_second_vm_and_reuses_the_registered_key(box):
    assert hz.cmd_create(box, []) == 0
    with pytest.raises(hz.Fail, match="already exists"):
        hz.cmd_create(box, [])
    assert len(box.servers) == 1 and len(box.keys) == 1
    assert hz.cmd_key_upload(box, []) == 0 and len(box.keys) == 1


def test_a_chosen_type_is_used_and_an_unknown_one_is_refused(box, monkeypatch):
    monkeypatch.setenv("HZ_TYPE", "big")
    assert hz.choose_type(box) == ("big", 0.05)
    monkeypatch.setenv("HZ_TYPE", "nope")
    with pytest.raises(hz.Fail, match="HZ_TYPE"):
        hz.choose_type(box)


def test_a_type_that_cannot_be_created_here_is_not_chosen(box, monkeypatch):
    # "soldout", "retired-here" and "elsewhere" are all cheaper than "small" and all have an nbg1 price
    assert hz.choose_type(box) == ("small", 0.008)
    monkeypatch.setattr(sys.modules[__name__], "TYPES", [t for t in TYPES if "locations" in t])
    assert hz.choose_type(box) == ("listed", 0.07)
    for name in ("soldout", "retired-here", "elsewhere"):
        monkeypatch.setenv("HZ_TYPE", name)
        with pytest.raises(hz.Fail, match="cannot be created in nbg1 now"):
            hz.choose_type(box)
    monkeypatch.setenv("HZ_TYPE", "listed")
    assert hz.choose_type(box) == ("listed", 0.07)


def test_destroy_removes_only_what_carries_the_label(box, capsys):
    box.servers.append({"id": 1, "name": "someone-elses", "labels": {}, "status": "running",
                        "public_net": {"ipv4": {"ip": "192.0.2.99"}}})
    box.keys.append({"id": 2, "name": "other", "labels": {}, "public_key": "x", "fingerprint": "00"})
    hz.cmd_create(box, [])
    assert hz.cmd_destroy(box, ["--yes"]) == 0
    assert [s["name"] for s in box.servers] == ["someone-elses"] and [k["name"] for k in box.keys] == ["other"]
    assert not hz.server_file().exists() and not hz.known_hosts().exists()
    assert "nothing labelled" in capsys.readouterr().out
    assert hz.cmd_destroy(box, ["--yes"]) == 0 and len(box.servers) == 1


def test_destroy_needs_yes_and_never_asks_for_the_token_without_it(box, capsys):
    assert hz.main(["destroy"]) == hz.EXIT_USAGE and "--yes" in capsys.readouterr().err
    assert box.calls == []


def test_ssh_uses_only_the_card_agent_and_only_the_pinned_host_key(box):
    hz.cmd_create(box, [])
    argv = hz.ssh_command("192.0.2.10", ["uname", "-a"])
    text = " ".join(argv)
    assert pathlib.Path(argv[0]).stem == "ssh" and argv[-4:] == ["--", "root@192.0.2.10", "uname", "-a"]
    for option in ("IdentitiesOnly=yes", "StrictHostKeyChecking=yes", "HostKeyAlias=pivcard-demo",
                   "ForwardAgent=no", "BatchMode=yes", f"UserKnownHostsFile={hz.known_hosts()}",
                   f"IdentityAgent={hz.paths.openssh_agent_address()}", f"-i {tool.ssh_key_file()}"):
        assert option in text, option
    assert hz._option("UserKnownHostsFile", "C:/Users/A B/x") == ["-o", 'UserKnownHostsFile="C:/Users/A B/x"']


@pytest.mark.skipif(not shutil.which("ssh"), reason="needs the OpenSSH client")
def test_what_follows_the_host_is_a_remote_command_never_an_option_of_ssh(box):
    """`hz.py ssh -oProxyCommand=...` must not run a local command, switch forwarding on or change host."""
    hz.cmd_create(box, [])
    hostile = ["-oProxyCommand=touch /tmp/should-not-exist", "-A", "-oHostName=198.51.100.7"]
    argv = hz.ssh_command("192.0.2.10", hostile)
    shown = subprocess.run([argv[0], "-G", *argv[1:]], capture_output=True, text=True, check=False).stdout.lower()
    settings = dict(line.split(" ", 1) for line in shown.splitlines() if " " in line)
    assert settings["hostname"] == "192.0.2.10" and settings["forwardagent"] == "no"
    assert "proxycommand" not in settings and settings["identitiesonly"] == "yes"


def test_an_address_that_is_not_an_ip_address_is_never_put_on_the_ssh_command_line(box):
    for bad in ("-oProxyCommand=x", "host.example", "192.0.2.10 -A", "", None, "::1%x -oProxyCommand=id",
                "2001:db8::1", "192.0.2.10\n"):
        with pytest.raises(hz.Fail, match="not an IP address"):
            hz.ssh_command(bad, ["true"])
    assert hz.ssh_command("192.0.2.10", [])[-1] == "root@192.0.2.10"


def test_a_token_in_the_callers_environment_is_never_used_in_place_of_the_entry(box, monkeypatch, capsys):
    ag.control({"op": "put", "name": "hetzner", "data": base64.b64encode(b"SOMETHING_ELSE=1\n").decode(),
                "ttl": 60}, autostart=True)
    monkeypatch.setenv("HCLOUD_TOKEN", "ambient-token")
    got = subprocess.run([sys.executable, str(HZ), "key-upload"], capture_output=True, text=True, timeout=60,
                         stdin=subprocess.DEVNULL, check=False)
    assert got.returncode == 1 and "has no HCLOUD_TOKEN" in got.stderr


def test_destroy_does_not_rely_on_the_api_to_filter_by_label(box, capsys):
    box.servers.append({"id": 1, "name": "someone-elses", "labels": {}, "status": "running",
                        "public_net": {"ipv4": {"ip": "192.0.2.99"}}})
    box.keys.append({"id": 2, "name": "other", "labels": {}, "public_key": "x", "fingerprint": "00"})
    hz.cmd_create(box, [])
    box._labelled = lambda items, selector: list(items)          # an API that ignores label_selector
    assert hz.cmd_destroy(box, ["--yes"]) == 0
    assert [s["name"] for s in box.servers] == ["someone-elses"] and [k["name"] for k in box.keys] == ["other"]


def test_ssh_is_refused_with_a_hint_while_locked_or_without_a_vm(box, capsys):
    assert hz.main(["ssh", "true"]) == 1 and "create" in capsys.readouterr().err
    hz.cmd_create(box, [])
    assert hz.main(["ssh", "true"]) == hz.EXIT_LOCKED and "unlock" in capsys.readouterr().err


def test_the_script_never_asks_for_a_pin_and_says_which_commands_do(box, capsys):
    assert hz.main(["unlock"]) == hz.EXIT_USAGE
    said = capsys.readouterr().err
    assert "withsecrets unlock hetzner" in said and "pivcard ssh unlock" in said


def test_the_token_is_taken_out_of_the_environment_before_anything_runs(box, monkeypatch):
    seen = {}

    def spy(api, rest):
        seen.update(env="HCLOUD_TOKEN" in os.environ, token=api._token)
        return 0

    monkeypatch.setitem(hz.TOKEN_COMMANDS, "status", spy)
    monkeypatch.setenv(hz.INNER, "1")
    monkeypatch.setenv("HCLOUD_TOKEN", "tok-xyz")
    assert hz.main(["status"]) == 0 and seen == {"env": False, "token": "tok-xyz"}


def run_script(*args):
    return subprocess.run([sys.executable, str(HZ), *args], capture_output=True, text=True, timeout=60,
                          stdin=subprocess.DEVNULL, start_new_session=True, check=False)


def test_locked_token_means_exit_3_and_a_hint_from_the_real_script(box):
    for command in (["status"], ["create"], ["key-upload"], ["destroy", "--yes"]):
        got = run_script(*command)
        assert got.returncode == hz.EXIT_LOCKED, (command, got.stderr)
        assert "withsecrets unlock hetzner" in got.stderr
    assert "API token (hetzner): locked" in run_script("status").stdout


def test_an_unlocked_entry_reaches_the_script_only_through_withsecrets(box):
    ag.control({"op": "put", "name": "hetzner", "data": base64.b64encode(b"SOMETHING_ELSE=1\n").decode(),
                "ttl": 60}, autostart=True)
    got = run_script("create")                                   # unlocked, but the entry has no token line
    assert got.returncode == 1 and "has no HCLOUD_TOKEN" in got.stderr
    assert "API token (hetzner): unlocked" in run_script("status").stdout


# ---------------------------------------------------------------- the HTTP client itself
class Handler(http.server.BaseHTTPRequestHandler):
    seen: list = []

    def do_GET(self):
        Handler.seen.append((self.path, self.headers.get("Authorization")))
        if self.path.startswith("/v1/redirect"):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/v1/elsewhere")
            self.end_headers()
            return
        if self.path.startswith("/v1/denied"):
            body, status = json.dumps({"error": {"code": "unauthorized", "message": "bad token"}}).encode(), 401
        else:
            body, status = json.dumps({"ok": True, "path": self.path}).encode(), 200
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    Handler.seen = []
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}/v1"
    httpd.shutdown()


def test_http_client_sends_the_token_reports_errors_and_never_follows_redirects(server):
    api = hz.Api("tok-123", base=server)
    assert api.call("GET", "/servers", label_selector="a=b") == {"ok": True, "path": "/v1/servers?label_selector=a%3Db"}
    assert Handler.seen[-1][1] == "Bearer tok-123"
    with pytest.raises(hz.ApiError, match="bad token") as denied:
        api.call("GET", "/denied")
    assert denied.value.code == "unauthorized" and "tok-123" not in str(denied.value)
    with pytest.raises(hz.ApiError) as moved:
        api.call("GET", "/redirect")
    assert moved.value.status == 302
    assert not any(path.startswith("/v1/elsewhere") for path, _ in Handler.seen)


@pytest.mark.skipif(not shutil.which("ssh-keygen"), reason="needs ssh-keygen")
def test_fingerprint_matches_openssh(box, tmp_path):
    pub = tmp_path / "k.pub"
    pub.write_text(box.card_key + "\n")
    shown = subprocess.run(["ssh-keygen", "-l", "-E", "md5", "-f", str(pub)], capture_output=True, text=True,
                           check=True).stdout
    assert "MD5:" + hz.fingerprint(box.card_key) in shown
