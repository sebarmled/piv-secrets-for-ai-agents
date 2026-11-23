"""Interoperability with the real `age` client (>= 1.3, which implements p256tag natively).

A PATH shim named `age-plugin-pivcard` runs this package's plugin with a software key standing in for
the card, so these tests exercise the real client on both sides of the protocol:

  * age encrypts natively to `age1tag1…`; our plugin decrypts          (proves our unwrap is the format)
  * age asks our plugin to encrypt to `age1pivcard1…`; our plugin decrypts
  * the PIN travels through age's own terminal prompt (run under a pty)
  * with no terminal at all, decryption fails and the "card" never sees a VERIFY
"""
import os
import pathlib
import re
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from conftest import NO_TERMINAL, child_env, needs_tty, run_on_tty, write_shim
from pivcard import tagfmt as t

AGE = shutil.which("age")


def _age_version() -> tuple[int, ...]:
    if not AGE:
        return (0,)
    out = subprocess.run([AGE, "--version"], capture_output=True, text=True, check=False).stdout
    m = re.search(r"(\d+)\.(\d+)", out)
    return (int(m.group(1)), int(m.group(2))) if m else (0,)


pytestmark = pytest.mark.skipif(_age_version() < (1, 3), reason="needs age >= 1.3 on PATH")

SHIM = '''import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pivcard import plugin
from pivcard.plugin import PinError

KEY = serialization.load_pem_private_key(open({pem!r}, "rb").read(), None)

class Soft:
    def describe(self): return "software test card"
    def close(self): pass
    def ecdh(self, pin, peer65):
        open({log!r}, "a").write("VERIFY\\n")
        if pin != "123456":
            raise PinError(5)
        return KEY.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer65))

sys.exit(plugin.main(card_factory=lambda slot, pub33: Soft()))
'''


@pytest.fixture
def env(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    pem = tmp_path / "soft.pem"
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    log = tmp_path / "verify.log"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    write_shim(bindir, "age-plugin-pivcard", SHIM.format(pem=str(pem), log=str(log)))
    pub33 = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    ident = tmp_path / "identity.txt"
    ident.write_text(t.encode_identity(0x9D, pub33) + "\n")

    class Env:
        path = tmp_path
        identity = str(ident)
        tag_recipient = t.encode_recipient(pub33, t.TAG_RECIPIENT_HRP)
        plugin_recipient = t.encode_recipient(pub33, t.RECIPIENT_HRP)
        environ = child_env(bindir, os.path.dirname(AGE), HOME=tmp_path, XDG_CONFIG_HOME=tmp_path / ".config")

        @staticmethod
        def verifies() -> int:
            return len(log.read_text().splitlines()) if log.exists() else 0

    return Env


def encrypt(env, recipient: str, plaintext: bytes) -> str:
    out = env.path / "secret.age"
    subprocess.run([AGE, "-r", recipient, "-o", str(out)], input=plaintext, env=env.environ, check=True,
                   capture_output=True)
    return str(out)


def decrypt_on_tty(env, path, pin=b"123456"):
    out = env.path / "plain.out"
    rc, screen = run_on_tty([AGE, "-d", "-i", env.identity, "-o", str(out), path], env.environ, [pin])
    return rc, screen, (out.read_bytes() if out.exists() else None)


@needs_tty
def test_age_native_tag_recipient_decrypts_with_our_plugin(env):
    path = encrypt(env, env.tag_recipient, b"HCLOUD_TOKEN=not-a-real-token\n")
    assert b"-> p256tag " in pathlib.Path(path).read_bytes()
    rc, screen, plain = decrypt_on_tty(env, path)
    assert rc == 0, screen
    assert plain == b"HCLOUD_TOKEN=not-a-real-token\n" and env.verifies() == 1
    assert b"123456" not in screen                               # the PIN is not echoed


@needs_tty
def test_plugin_recipient_round_trips_through_age(env):
    path = encrypt(env, env.plugin_recipient, b"second secret\n")
    assert b"-> p256tag " in pathlib.Path(path).read_bytes()
    rc, screen, plain = decrypt_on_tty(env, path)
    assert rc == 0, screen
    assert plain == b"second secret\n"


def test_no_terminal_fails_before_any_verify(env):
    path = encrypt(env, env.tag_recipient, b"x\n")
    proc = subprocess.run([AGE, "-d", "-i", env.identity, path], env=env.environ, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=30, check=False, **NO_TERMINAL)
    assert proc.returncode != 0 and proc.stdout == b""
    assert env.verifies() == 0, proc.stderr


@needs_tty
def test_wrong_pin_fails_after_exactly_one_verify(env):
    path = encrypt(env, env.tag_recipient, b"x\n")
    rc, screen, plain = decrypt_on_tty(env, path, pin=b"000000")
    assert rc != 0 and not plain and env.verifies() == 1
    assert b"wrong PIN" in screen
