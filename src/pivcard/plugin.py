"""The age plugin protocol (C2SP age-plugin.md): `recipient-v1` and `identity-v1`.

Encrypting (`recipient-v1`) is pure software: it needs only the recipient's public key.

Decrypting (`identity-v1`) is where the card comes in, and the order of operations is the point:

  1. find the stanzas addressed to one of our identities (a public tag check, no card);
  2. open the card that holds that key and confirm it does (certificate read, no PIN);
  3. only then ask the age client for the PIN (`request-secret`). The client prompts on the user's
     terminal. With no terminal it answers `fail`, and we stop here: no VERIFY has reached the card;
  4. VERIFY + ECDH + logout, as one unit, inside the card layer.

The PIN lives in this process for the length of one age invocation and is never written anywhere.
"""
from __future__ import annotations

import contextlib
import signal
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO, Protocol

from cryptography.exceptions import InvalidTag

from . import paths, tagfmt
from .tagfmt import FormatError


class ProtocolError(Exception):
    """The age client sent something that is not a valid stanza."""


class CardError(Exception):
    """The card cannot be used. The message is shown to the user by the age client."""


class PinError(CardError):
    def __init__(self, tries_left: int | None):
        self.tries_left = tries_left
        left = "" if tries_left is None else f" {tries_left} tries left."
        super().__init__(f"wrong PIN.{left} Not retrying.")


class CardSession(Protocol):
    def describe(self) -> str:
        """Where the card is, for the PIN prompt (a reader name)."""

    def ecdh(self, pin: str, peer65: bytes) -> bytes:
        """VERIFY, ECDH on the slot, log out. Raises PinError / CardError."""

    def close(self) -> None: ...


# (PIV key reference, compressed public key) -> session on the card that holds that key.
# Contract: sends no PIN, and raises CardError unless the card's certificate carries exactly this key.
CardFactory = Callable[[int, bytes], CardSession]


@dataclass
class Stanza:
    tag: str
    args: list[str]
    body: bytes = b""


def read_stanza(f: BinaryIO) -> Stanza | None:
    """Read one stanza in the age header text format. None at end of input."""
    line = f.readline()
    if not line:
        return None
    try:
        text = line.decode("ascii").rstrip("\n")
        if not text.startswith("-> "):
            raise ProtocolError("expected a stanza")
        parts = text[3:].split(" ")
        chunks = []
        while True:
            raw = f.readline()
            if not raw:
                raise ProtocolError("truncated stanza body")
            chunk = raw.decode("ascii").rstrip("\n")
            chunks.append(chunk)
            if len(chunk) < 64:
                break
        return Stanza(parts[0], parts[1:], tagfmt.b64d("".join(chunks)))
    except (UnicodeDecodeError, FormatError) as e:
        raise ProtocolError(f"malformed stanza: {e}") from None


def write_stanza(f: BinaryIO, tag: str, args=(), body: bytes = b"") -> None:
    encoded = tagfmt.b64e(body)
    lines = [encoded[i:i + 64] for i in range(0, len(encoded), 64)]
    if not lines or len(lines[-1]) == 64:
        lines.append("")  # the body always ends with a line shorter than 64 columns
    f.write(("-> " + " ".join([tag, *args]) + "\n" + "\n".join(lines) + "\n").encode("ascii"))
    f.flush()


class Channel:
    def __init__(self, inp: BinaryIO, out: BinaryIO):
        self.inp, self.out = inp, out

    def read(self) -> Stanza | None:
        return read_stanza(self.inp)

    def send(self, tag: str, args=(), body: bytes = b"") -> None:
        write_stanza(self.out, tag, args, body)

    def ask(self, tag: str, args=(), body: bytes = b"") -> Stanza:
        """Phase 2 is bi-directional: every command gets exactly one response."""
        self.send(tag, args, body)
        reply = self.read()
        if reply is None:
            raise ProtocolError("the age client closed the connection")
        return reply


# ------------------------------------------------------------------ recipient-v1 (encrypt)
def run_recipient_v1(inp: BinaryIO, out: BinaryIO) -> int:
    ch = Channel(inp, out)
    recipients: list[str] = []
    identities: list[str] = []
    file_keys: list[bytes] = []
    while True:
        st = ch.read()
        if st is None:
            return 1
        if st.tag == "done":
            break
        if st.tag == "add-recipient" and st.args:
            recipients.append(st.args[0])
        elif st.tag == "add-identity" and st.args:
            identities.append(st.args[0])
        elif st.tag == "wrap-file-key":
            file_keys.append(st.body)
        # anything else (grease, extension-labels) is ignored; an empty label set is implied

    targets: list[bytes] = []
    failed = False
    for kind, items, decode in (("recipient", recipients, tagfmt.decode_recipient),
                                ("identity", identities, lambda s: tagfmt.decode_identity(s)[1])):
        for i, text in enumerate(items):
            try:
                targets.append(decode(text))
            except FormatError as e:
                ch.ask("error", [kind, str(i)], str(e).encode())
                failed = True
    if not failed:
        try:
            stanzas = [(i, *tagfmt.wrap(fk, pub)) for i, fk in enumerate(file_keys) for pub in targets]
        except FormatError as e:
            ch.ask("error", ["internal"], str(e).encode())
        else:
            for i, args, body in stanzas:
                ch.ask("recipient-stanza", [str(i), tagfmt.STANZA, *args], body)
    ch.send("done")
    return 0


# ------------------------------------------------------------------ identity-v1 (decrypt)
def run_identity_v1(inp: BinaryIO, out: BinaryIO, card_factory: CardFactory) -> int:
    ch = Channel(inp, out)
    identities: list[str] = []
    files: dict[int, list[Stanza]] = {}
    while True:
        st = ch.read()
        if st is None:
            return 1
        if st.tag == "done":
            break
        if st.tag == "add-identity" and st.args:
            identities.append(st.args[0])
        elif st.tag == "recipient-stanza" and len(st.args) >= 2 and st.args[0].isdigit():
            files.setdefault(int(st.args[0]), []).append(Stanza(st.args[1], st.args[2:], st.body))

    keys: list[tuple[int, bytes]] = []
    for i, text in enumerate(identities):
        try:
            keys.append(tagfmt.decode_identity(text))
        except FormatError as e:
            ch.ask("error", ["identity", str(i)], str(e).encode())
    if len(keys) != len(identities):
        ch.send("done")  # an invalid identity: do not unwrap anything with the others either
        return 0

    # Which stanzas are for us? Decided from public data alone, before any card is opened.
    todo: list[tuple[int, int, int, bytes, bytes]] = []  # file, stanza index, identity index, enc, body
    for idx in sorted(files):
        match = None
        for j, st in enumerate(files[idx]):
            if st.tag != tagfmt.STANZA:
                continue
            try:
                tag, enc = tagfmt.parse(st.args, st.body)
            except FormatError as e:
                ch.ask("error", ["stanza", str(idx), str(j)], str(e).encode())
                match = None
                break
            if match is None:
                for i, (_, pub) in enumerate(keys):
                    if tagfmt.is_for(tag, enc, pub):
                        match = (idx, j, i, enc, st.body)
                        break
        if match:
            todo.append(match)

    sessions: dict[int, CardSession] = {}
    pins: dict[int, str] = {}
    unusable: set[int] = set()
    try:
        for idx, j, i, enc, body in todo:
            if i in unusable:
                continue
            slot, pub = keys[i]
            try:
                if i not in sessions:
                    sessions[i] = card_factory(slot, pub)
                session = sessions[i]
                if i not in pins:
                    if paths.prompts_off():
                        raise CardError("PIN prompts are switched off here (PIVCARD_NO_PROMPT is set). "
                                        "Nothing was sent to the card.")
                    reply = ch.ask("request-secret", [],
                                   f"Enter the PIN for the PIV card in {session.describe()}".encode())
                    if reply.tag != "ok":
                        raise CardError("cannot ask for the PIN here (no terminal). "
                                        "Nothing was sent to the card.")
                    pins[i] = reply.body.decode("utf-8", "replace").strip()
                file_key = tagfmt.unwrap(enc, body, pub, lambda peer, s=session, p=pins[i]: s.ecdh(p, peer))
            except CardError as e:
                unusable.add(i)
                pins.pop(i, None)
                ch.ask("error", ["identity", str(i)], str(e).encode())
                continue
            except (InvalidTag, FormatError):
                ch.ask("error", ["stanza", str(idx), str(j)],
                       b"this stanza is addressed to the card's key but did not decrypt")
                continue
            ch.ask("file-key", [str(idx)], file_key)
    finally:
        pins.clear()
        for session in sessions.values():
            with contextlib.suppress(Exception):  # best effort: the results have already been sent
                session.close()
    ch.send("done")
    return 0


# ------------------------------------------------------------------ entry point
USAGE = """age-plugin-pivcard: age plugin for standard PIV smart cards (NIST SP 800-73).

This binary is started by age itself. To set up a card, use the companion tool:

    pivcard identity    print the identity and recipients for the card in the reader
    pivcard status      show the card and its PIN state
    pivcard --help      everything else
"""


def _exit_cleanly_on_signals() -> None:
    """Turn "please stop" signals into a normal exit, so the `finally` blocks that log the card out run.
    (age forwards Ctrl-C as SIGINT, which Python already raises as KeyboardInterrupt.)"""
    def stop(signum, _frame):
        raise SystemExit(128 + signum)

    for name in ("SIGTERM", "SIGHUP", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            with contextlib.suppress(ValueError, OSError):     # not the main thread, or not supported here
                signal.signal(sig, stop)


def main(argv: list[str] | None = None, card_factory: CardFactory | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    mode = next((a.split("=", 1)[1] for a in argv if a.startswith("--age-plugin=")), None)
    if mode is None:
        sys.stderr.write(USAGE)
        return 0 if any(a in ("-h", "--help") for a in argv) else 2
    inp, out = sys.stdin.buffer, sys.stdout.buffer
    paths.harden_process()                              # this process is handed the PIN
    _exit_cleanly_on_signals()
    try:
        if mode == "recipient-v1":
            return run_recipient_v1(inp, out)
        if mode == "identity-v1":
            if card_factory is None:
                from .piv import open_card as card_factory
            return run_identity_v1(inp, out, card_factory)
    except (ProtocolError, BrokenPipeError) as e:
        sys.stderr.write(f"age-plugin-pivcard: {e}\n")
        return 1
    sys.stderr.write(f"age-plugin-pivcard: unknown state machine {mode!r}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
