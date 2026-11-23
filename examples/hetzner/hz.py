#!/usr/bin/env python3
"""hz: one small Hetzner Cloud VM, created, used and destroyed with two credentials kept behind a PIV card.

First, in YOUR terminal (these two commands ask for the card PIN; this script never does):

    withsecrets unlock hetzner      the API token, through slot 9D of the card
    pivcard ssh unlock              the SSH key, slot 9A of the card

Then, from any shell of yours, the AI agent's included:

    python hz.py status             what is unlocked here, and what exists at Hetzner
    python hz.py key-upload         register the card's SSH public key in the Hetzner project
    python hz.py create             create the VM (it costs money until it is destroyed)
    python hz.py ssh [command...]   log in as root, or run one command
    python hz.py destroy --yes      delete the VM and the uploaded key

How the two credentials are handled:

  * The API token is the line HCLOUD_TOKEN=... in a withsecrets entry (default name: hetzner), an age
    file sealed to the card's key-management key (slot 9D). This script never opens that file. It runs
    itself again through `withsecrets`, which hands the token over only if the owner has unlocked the
    entry, and never asks for a PIN. Locked means exit status 3 and a hint.
  * The SSH key was generated on the card (slot 9A) and cannot leave it. `ssh` is pointed at the
    pivcard agent, which has the card sign each login while the owner keeps SSH unlocked.

The VM's SSH host key is generated here and given to the VM at creation, so the first connection is
already checked against a known key (no "trust on first use").

Everything created here carries the label pivcard-hz=<name>; only things with that label are deleted.

Settings (environment): HZ_ENTRY (hetzner), HZ_NAME (pivcard-demo), HZ_LOCATION (nbg1),
HZ_TYPE (the cheapest shared x86 type on offer in that location), HZ_IMAGE (ubuntu-24.04).
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pivcard import agent, paths, tool, withsecrets

API = "https://api.hetzner.cloud/v1"
ENTRY = os.environ.get("HZ_ENTRY", "hetzner")
NAME = os.environ.get("HZ_NAME", "pivcard-demo")
LOCATION = os.environ.get("HZ_LOCATION", "nbg1")
IMAGE = os.environ.get("HZ_IMAGE", "ubuntu-24.04")
LABEL = "pivcard-hz"
INNER = "HZ_INNER"                       # set on the copy of this script that withsecrets starts
EXIT_USAGE, EXIT_LOCKED = 2, 3
UNLOCK_TOKEN = f"withsecrets unlock {ENTRY}"
UNLOCK_SSH = "pivcard ssh unlock"


def _me() -> str:
    """This script as the user would type it from where they are: used in the hints."""
    try:
        shown = os.path.relpath(__file__)
    except ValueError:                               # Windows: the script is on another drive
        shown = str(Path(__file__).resolve())
    return f"python {shown}"


ME = _me()


class Fail(Exception):
    def __init__(self, message: str, status: int = 1):
        super().__init__(message)
        self.status = status


# ------------------------------------------------------------------ Hetzner Cloud API
class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"Hetzner API: {message} ({code or status})")
        self.status, self.code = status, code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):     # the token must never follow a redirect elsewhere
        return None


class Api:
    def __init__(self, token: str, base: str = API):
        self._token, self._base = token, base
        self._opener = urllib.request.build_opener(_NoRedirect)

    def call(self, method: str, path: str, body: dict | None = None, **query) -> dict:
        url = self._base + path + ("?" + urllib.parse.urlencode(query) if query else "")
        request = urllib.request.Request(
            url, method=method, data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": "Bearer " + self._token, "Content-Type": "application/json",
                     "User-Agent": "pivcard-hz-example"})
        try:
            with self._opener.open(request, timeout=30) as response:
                raw = response.read()
        except urllib.error.HTTPError as e:
            try:
                error = json.loads(e.read()).get("error") or {}
            except ValueError:
                error = {}
            raise ApiError(e.code, str(error.get("code", "")), str(error.get("message", e.reason))) from None
        except urllib.error.URLError as e:
            raise Fail(f"cannot reach the Hetzner API: {e.reason}") from None
        return json.loads(raw) if raw else {}

    def wait(self, action: dict | None, what: str, timeout: float = 180) -> None:
        deadline = time.monotonic() + timeout
        while action and action.get("status") == "running":
            if time.monotonic() > deadline:
                raise Fail(f"{what}: still running after {timeout:.0f} s")
            time.sleep(2)
            action = self.call("GET", f"/actions/{action['id']}")["action"]
        if action and action.get("status") == "error":
            raise Fail(f"{what} failed: {(action.get('error') or {}).get('message', 'unknown error')}")


# ------------------------------------------------------------------ local pieces
def state_dir() -> Path:
    return paths.config_dir("pivcard-hz")


def known_hosts() -> Path:
    return state_dir() / f"{NAME}.known_hosts"


def server_file() -> Path:
    return state_dir() / f"{NAME}.json"


def card_public_key() -> str:
    """The card's SSH public key, from the file `pivcard ssh unlock` keeps. Public; no card needed."""
    path = tool.ssh_key_file()
    if not path.is_file():
        raise Fail(f"the card's SSH key is not known here yet. In your own terminal run: {UNLOCK_SSH}")
    return " ".join(path.read_text().split()[:2])


def fingerprint(public_key: str) -> str:
    """MD5 fingerprint, the form the Hetzner API looks SSH keys up by (not used for security)."""
    digest = hashlib.md5(base64.b64decode(public_key.split()[1]), usedforsecurity=False).hexdigest()
    return ":".join(digest[i:i + 2] for i in range(0, 32, 2))


def new_host_key() -> tuple[str, str]:
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                serialization.NoEncryption()).decode()
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                           serialization.PublicFormat.OpenSSH).decode()
    return private, public


def cloud_config(host_private: str, host_public: str) -> str:
    """cloud-init user data: replace the image's SSH host keys with ours. (JSON is valid YAML.)"""
    return "#cloud-config\n" + json.dumps({
        "ssh_deletekeys": True,
        "ssh_keys": {"ed25519_private": host_private, "ed25519_public": f"{host_public} {NAME}"},
        "ssh_pwauth": False,
    }, indent=1) + "\n"


def ssh_unlocked() -> dict | None:
    try:
        return agent.control({"op": "status"}).get("ssh")
    except agent.AgentUnavailable:
        return None


def wait_for_port(ip: str, port: int, timeout: float = 180) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((ip, port), timeout=5):
                return True
        except OSError:
            time.sleep(3)
    return False


# ------------------------------------------------------------------ commands that need the API token
def _ours(items: list[dict]) -> list[dict]:
    """Only what carries our label. The API is asked to filter; this does not rely on it having done so."""
    return [item for item in items if (item.get("labels") or {}).get(LABEL) == NAME]


def servers(api: Api) -> list[dict]:
    return _ours(api.call("GET", "/servers", label_selector=f"{LABEL}={NAME}")["servers"])


def labelled_keys(api: Api) -> list[dict]:
    return _ours(api.call("GET", "/ssh_keys", label_selector=f"{LABEL}={NAME}")["ssh_keys"])


def checked_ip(value) -> str:
    """An address from the API or from the state file, before it is put on an ssh command line."""
    try:
        return str(ipaddress.IPv4Address(str(value)))     # this script only ever stores the IPv4 address
    except ValueError:
        raise Fail(f"{value!r} is not an IP address; refusing to use it") from None


def ensure_key(api: Api) -> int:
    """Register the card's public key in the project (once). Returns its id at Hetzner."""
    public_key = card_public_key()
    found = api.call("GET", "/ssh_keys", fingerprint=fingerprint(public_key))["ssh_keys"]
    if found:
        print(f"SSH key: already registered at Hetzner as {found[0]['name']!r}")
        return found[0]["id"]
    try:
        made = api.call("POST", "/ssh_keys", {"name": f"{NAME}-card", "public_key": f"{public_key} {NAME}-card",
                                              "labels": {LABEL: NAME}})["ssh_key"]
    except ApiError as e:
        if e.code == "uniqueness_error":
            raise Fail(f"the project already has another key named {NAME}-card. Remove it with "
                       f"`{ME} destroy --yes` or in the Hetzner Console, then try again.") from None
        raise
    print(f"SSH key: registered the card's public key as {made['name']!r}")
    return made["id"]


def _on_offer(kind: dict) -> bool:
    """Can this server type be created in LOCATION now? The API lists a price for every location, also
    where a type is retired or sold out. Its per-location entry says what is really on offer."""
    places = kind.get("locations")
    if places is None:                                   # older answers have no per-location list
        return True
    here = next((place for place in places if place.get("name") == LOCATION), None)
    return here is not None and here.get("available", True) and not here.get("deprecation")


def choose_type(api: Api) -> tuple[str, float]:
    """(server type, gross price per hour in this location): HZ_TYPE, else the cheapest shared x86 type
    that can be created in this location now."""
    wanted = os.environ.get("HZ_TYPE")
    best: tuple[str, float] | None = None
    for kind in api.call("GET", "/server_types", per_page=50)["server_types"]:
        if wanted:
            if kind["name"] != wanted:
                continue
            if not _on_offer(kind):
                raise Fail(f"server type {wanted} cannot be created in {LOCATION} now; set HZ_TYPE or HZ_LOCATION")
        elif (kind.get("cpu_type") != "shared" or kind.get("architecture") != "x86"
              or kind.get("deprecated") or kind.get("deprecation") or not _on_offer(kind)):
            continue
        for price in kind.get("prices") or []:
            if price.get("location") == LOCATION:
                hourly = float(price["price_hourly"]["gross"])
                if best is None or hourly < best[1]:
                    best = (kind["name"], hourly)
    if best is None:
        raise Fail(f"no server type {wanted or '(shared x86)'} can be created in {LOCATION} now; "
                   "set HZ_TYPE or HZ_LOCATION")
    return best


def cmd_key_upload(api: Api, _args: list[str]) -> int:
    ensure_key(api)
    return 0


def cmd_create(api: Api, _args: list[str]) -> int:
    existing = servers(api)
    if existing:
        raise Fail(f"{NAME} already exists (id {existing[0]['id']}). To start over: {ME} destroy --yes")
    key_id = ensure_key(api)
    server_type, hourly = choose_type(api)
    host_private, host_public = new_host_key()
    # The host key is written down BEFORE the VM exists: no connection is ever made to an unknown key.
    state_dir().mkdir(parents=True, exist_ok=True)
    known_hosts().write_text(f"{NAME} {host_public}\n")
    print(f"creating {NAME}: {server_type} in {LOCATION}, {IMAGE}, about EUR {hourly:.4f} per hour until destroyed")
    made = api.call("POST", "/servers", {
        "name": NAME, "server_type": server_type, "image": IMAGE, "location": LOCATION,
        "ssh_keys": [key_id], "user_data": cloud_config(host_private, host_public),
        "labels": {LABEL: NAME}, "start_after_create": True})
    del host_private
    server = made["server"]
    ip = checked_ip(server["public_net"]["ipv4"]["ip"])
    server_file().write_text(json.dumps({"id": server["id"], "name": NAME, "ip": ip}) + "\n")
    api.wait(made.get("action"), "creating the server")
    print(f"created: id {server['id']}, {ip}. Waiting for SSH to answer...")
    if not wait_for_port(ip, 22):
        print(f"SSH does not answer yet. Try in a minute: {ME} ssh uname -a")
        return 0
    print(f"{NAME} is up. Next: {ME} ssh uname -a")
    return 0


def cmd_status(api: Api, _args: list[str]) -> int:
    found = servers(api)
    for s in found:
        print(f"server {s['name']}: {s['status']}, id {s['id']}, {s['server_type']['name']}, "
              f"{s['public_net']['ipv4']['ip']}, created {s['created']}")
    if not found:
        print(f"server {NAME}: none at Hetzner")
    for key in labelled_keys(api):
        print(f"ssh key {key['name']}: id {key['id']}, {key['fingerprint']}")
    return 0


def cmd_destroy(api: Api, _args: list[str]) -> int:
    found = servers(api)
    for s in found:
        print(f"deleting server {s['name']} (id {s['id']}, {s['public_net']['ipv4']['ip']})")
        api.wait(api.call("DELETE", f"/servers/{s['id']}").get("action"), "deleting the server")
    for key in labelled_keys(api):
        print(f"deleting ssh key {key['name']} (id {key['id']})")
        api.call("DELETE", f"/ssh_keys/{key['id']}")
    for path in (server_file(), known_hosts()):
        path.unlink(missing_ok=True)
    left = servers(api)
    if left:
        raise Fail(f"{len(left)} server(s) with the label are still there; check the Hetzner Console")
    print(f"done: nothing labelled {LABEL}={NAME} is left" if found else f"nothing to delete for {NAME}")
    return 0


# ------------------------------------------------------------------ commands that need no token
def _option(name: str, value) -> list[str]:
    value = str(value)
    return ["-o", f'{name}="{value}"' if " " in value else f"{name}={value}"]


def ssh_command(ip: str, command: list[str]) -> list[str]:
    ssh = paths.find_program("ssh")                  # on Windows: never an ssh.exe from the current directory
    if ssh is None:
        raise Fail("the OpenSSH client `ssh` was not found on PATH")
    return [ssh,
            *_option("IdentityAgent", paths.openssh_agent_address()),  # the pivcard agent, nothing else
            *_option("IdentitiesOnly", "yes"), "-i", str(tool.ssh_key_file()),
            *_option("UserKnownHostsFile", known_hosts()),           # only the key we generated
            *_option("StrictHostKeyChecking", "yes"), *_option("HostKeyAlias", NAME),
            *_option("ForwardAgent", "no"), *_option("BatchMode", "yes"), *_option("ConnectTimeout", 15),
            "--",                                    # nothing after this is read as an option of ssh itself
            f"root@{checked_ip(ip)}", *command]


def cmd_ssh(args: list[str]) -> int:
    command = args[1:] if args[:1] == ["--"] else args
    if not server_file().is_file() or not known_hosts().is_file():
        raise Fail(f"no VM is known here. Create one with: {ME} create")
    if ssh_unlocked() is None:
        raise Fail(f"SSH is locked. In your own terminal run: {UNLOCK_SSH}", EXIT_LOCKED)
    argv = ssh_command(json.loads(server_file().read_text())["ip"], command)
    if paths.WINDOWS:
        return subprocess.call(argv)
    os.execvp(argv[0], argv)
    return 0  # pragma: no cover


def print_local_state() -> None:
    try:
        held = [s["name"] for s in agent.control({"op": "status"}).get("secrets", [])]
    except agent.AgentUnavailable:
        held = []
    print(f"API token ({ENTRY}): {'unlocked' if ENTRY in held else 'locked'}")
    ssh = ssh_unlocked()
    left = f"unlocked, {ssh['seconds_left'] // 60} min left" if ssh else "locked"
    print(f"SSH key on the card: {left}")
    if server_file().is_file():
        print(f"VM known here: {json.loads(server_file().read_text())['ip']}")


# ------------------------------------------------------------------ entry point
TOKEN_COMMANDS = {"status": cmd_status, "key-upload": cmd_key_upload, "create": cmd_create, "destroy": cmd_destroy}


def rerun_with_token(argv: list[str]) -> int:
    """Start this script again under withsecrets, so the token exists only in that process's environment.
    withsecrets never asks for a PIN: with the entry locked it returns status 3 and nothing has run."""
    os.environ.pop("HCLOUD_TOKEN", None)             # only the entry may supply the token, never the caller
    os.environ[INNER] = "1"
    try:
        status = withsecrets.main([ENTRY, "--", sys.executable, str(Path(__file__).resolve()), *argv])
    finally:
        os.environ.pop(INNER, None)
    if status == EXIT_LOCKED:
        print(f"hz: the API token is locked. In your own terminal run: {UNLOCK_TOKEN}", file=sys.stderr)
    return status


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else EXIT_USAGE
    command, rest = argv[0], argv[1:]
    try:
        if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?", NAME):
            raise Fail("HZ_NAME must be lower-case letters, digits and dashes", EXIT_USAGE)
        if command == "unlock":
            raise Fail(f"this script never asks for the PIN. In your own terminal run: {UNLOCK_TOKEN}"
                       f"   and then: {UNLOCK_SSH}", EXIT_USAGE)
        if command == "ssh":
            return cmd_ssh(rest)
        if command not in TOKEN_COMMANDS:
            raise Fail(f"unknown command {command!r}; see {ME} --help", EXIT_USAGE)
        if command == "destroy" and rest != ["--yes"]:
            raise Fail(f"destroy deletes the VM {NAME} and the uploaded key. To go ahead: {ME} destroy --yes",
                       EXIT_USAGE)
        if not os.environ.get(INNER):
            if command == "status":
                print_local_state()
            return rerun_with_token(argv)
        token = os.environ.pop("HCLOUD_TOKEN", "")       # nothing started from here inherits it
        if not token:
            raise Fail(f"the withsecrets entry {ENTRY!r} has no HCLOUD_TOKEN=... line")
        return TOKEN_COMMANDS[command](Api(token), rest)
    except (Fail, ApiError, agent.AgentNotOurs) as e:
        print(f"hz: {e}", file=sys.stderr)
        return getattr(e, "status", 1) if isinstance(e, Fail) else 1


if __name__ == "__main__":
    sys.exit(main())
