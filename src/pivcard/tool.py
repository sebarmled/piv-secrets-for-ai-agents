"""`pivcard`: set up and inspect the card, and control the agent.

    pivcard readers                 list readers (without connecting to any card)
    pivcard use <reader>            remember which reader this tool may talk to
    pivcard status                  PIN state and the keys the card shows
    pivcard identity [-o FILE]      age identity + recipients for the key-management key (slot 9D)
    pivcard ssh-pubkey              OpenSSH public key of the authentication key (slot 9A)
    pivcard lock                    put the card back in the "PIN not verified" state
    pivcard check                   try the card (asks for the PIN): one decryption, one signature,
                                    and whether the card is locked again after each
                                    (--new-card: a card other than the one set up here)
    pivcard mkcert PUB OUT          placeholder certificate carrying a slot's public key

    pivcard ssh unlock [--hours N]  type the PIN (terminal only); the agent may then sign SSH logins
                                    (--new-card: accept a card other than the one used before)
    pivcard ssh lock                make the agent forget the PIN
    pivcard ssh status              is SSH unlocked, for how long, and where the agent listens
    pivcard ssh socket              print the agent endpoint, for: ssh -o IdentityAgent=...
    pivcard agent stop              stop the agent (forgets everything it holds)

Only `ssh unlock` and `check` ask for a PIN, and only on a terminal. With PIVCARD_NO_PROMPT=1 in the
environment they refuse.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import getpass
import hashlib
import math
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from . import __version__, agent, apdu, paths, piv, tagfmt
from .placeholder import placeholder_certificate
from .plugin import CardError


def _key_kind(pub) -> str:
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"ECC {pub.curve.name}"
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA {pub.key_size}"
    return type(pub).__name__


def _p256(t, slot: int) -> bytes:
    pub = piv.slot_public_key(t, slot)
    if pub is None:
        raise CardError(f"slot {piv.slot_name(slot)} has no certificate. Generate the key, then store a "
                        "certificate carrying its public key (see `pivcard mkcert`).")
    try:
        return tagfmt.public_key_to_compressed(pub)
    except tagfmt.FormatError as e:
        raise CardError(f"slot {piv.slot_name(slot)}: {e}") from None


def ssh_key_file() -> Path:
    """The SSH public key of the card SSH was last unlocked with (public; written by `ssh unlock`)."""
    return paths.config_dir() / "ssh-key.pub"


def cmd_readers(args) -> int:
    wanted = args.reader or apdu.configured_reader()
    readers = apdu.list_readers()
    if not readers:
        print("no PC/SC readers found")
        return 1
    for r in readers:
        mark = "*" if wanted and wanted in r.name else " "
        print(f"{mark} {r.name}    {'card present, ATR ' + r.atr.hex(' ').upper() if r.present else 'empty'}")
    print(f"\n* = the reader pivcard uses ({wanted!r})" if wanted else
          "\nNo reader is selected. With several cards present, run: pivcard use <part of the reader name>")
    return 0


def cmd_use(args) -> int:
    info = apdu.pick_reader(apdu.list_readers(), args.name)
    path = paths.config_dir() / "reader"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(args.name + "\n")
    print(f"pivcard will only talk to readers matching {args.name!r} (now: {info.name!r})")
    return 0


def cmd_status(args) -> int:
    t = piv.open_transport(args.reader)
    try:
        with piv.exclusive(t):
            tries = piv.pin_tries(t)
            certs = {slot: piv.read_certificate(t, slot) for slot in (0x9A, 0x9C, 0x9D, 0x9E)}
        print(f"reader: {t.name}")
        print("PIN:    VERIFIED: the card is unlocked for every process (run `pivcard lock`)" if tries is None
              else f"PIN:    not verified, {tries} tries left")
        for slot, role in ((0x9A, "authentication (SSH)"), (0x9C, "signature"),
                           (0x9D, "key management (age)"), (0x9E, "card authentication")):
            der = certs[slot]
            if der is None:
                print(f"  {piv.slot_name(slot)}  {role:<22} no certificate")
                continue
            cert = x509.load_der_x509_certificate(der)
            subject = cert.subject.rfc4514_string()
            print(f"  {piv.slot_name(slot)}  {role:<22} {_key_kind(cert.public_key())}, {subject}")
    finally:
        t.close()
    return 0


def cmd_identity(args) -> int:
    slot = piv.parse_slot(args.slot)
    if slot not in piv.KEY_AGREEMENT_SLOTS:
        raise CardError(f"slot {piv.slot_name(slot)} is not a key-management slot (use 9D or 82..95)")
    t = piv.open_transport(args.reader)
    try:
        with piv.exclusive(t):
            pub33 = _p256(t, slot)
        reader = t.name
    finally:
        t.close()
    text = (
        f"# created: {datetime.datetime.now().astimezone().isoformat(timespec='seconds')}\n"
        f"# PIV card in {reader}, slot {piv.slot_name(slot)}. This file holds no secret.\n"
        f"# recipient: {tagfmt.encode_recipient(pub33, tagfmt.TAG_RECIPIENT_HRP)}\n"
        f"# recipient for age older than 1.3: {tagfmt.encode_recipient(pub33)}\n"
        f"{tagfmt.encode_identity(slot, pub33)}\n"
    )
    if args.output:
        Path(args.output).write_text(text)
        print(f"wrote {args.output}", file=sys.stderr)
        print(f"recipient: {tagfmt.encode_recipient(pub33, tagfmt.TAG_RECIPIENT_HRP)}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def cmd_ssh_pubkey(args) -> int:
    slot = piv.parse_slot(args.slot)
    t = piv.open_transport(args.reader)
    try:
        with piv.exclusive(t):
            pub = piv.slot_public_key(t, slot)
    finally:
        t.close()
    if pub is None:
        raise CardError(f"slot {piv.slot_name(slot)} has no certificate")
    line = pub.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    print(f"{line} {args.comment}")
    return 0


def cmd_lock(args) -> int:
    t = piv.open_transport(args.reader)
    reset = False
    try:
        with piv.exclusive(t):
            was = piv.pin_tries(t)
            reset = not piv.logout(t)
            if reset:
                t.end(reset=True)                  # reset as the transaction ends, not a moment later
        print(f"{t.name}: {'was unlocked, now locked' if was is None else 'already locked'}"
              f"{' (by card reset)' if reset else ''}")
    finally:
        t.close(reset=reset)
    return 0


def _may_ask_for_pin(command: str) -> None:
    if paths.prompts_off():
        raise CardError(f"PIN prompts are switched off here (PIVCARD_NO_PROMPT is set), so `{command}` does "
                        "nothing. Run it in your own terminal. Nothing was sent to the card.")
    if not (sys.stdin and sys.stdin.isatty()):
        raise CardError(f"`{command}` needs your terminal for the PIN. Nothing was sent to the card.")


def _known_keys() -> dict[int, tuple[bytes, Path]]:
    """The public keys the tools have recorded for the user's card: {slot: (compressed key, file)}.
    A record that exists but cannot be read is an error, never "nothing recorded"."""
    from . import withsecrets
    known: dict[int, tuple[bytes, Path]] = {}
    identity = withsecrets.identity_file()
    if identity.is_file():
        found = False
        for line in identity.read_text(errors="replace").splitlines():
            if line.strip().upper().startswith(tagfmt.IDENTITY_HRP):
                try:
                    slot, pub33 = tagfmt.decode_identity(line.strip())
                except tagfmt.FormatError as e:
                    raise CardError(f"{identity} holds an identity that cannot be read ({e}). No PIN was asked "
                                    "for or sent. Write it again with: withsecrets init --force") from None
                known[slot], found = (pub33, identity), True
        if not found:
            raise CardError(f"{identity} holds no identity. No PIN was asked for or sent. Write it again "
                            "with: withsecrets init --force")
    saved = ssh_key_file()
    if saved.is_file():
        try:
            kind, encoded = saved.read_text(errors="replace").split()[:2]
            blob = base64.b64decode(encoded, validate=True)
            if kind != "ecdsa-sha2-nistp256" or blob != agent.ssh_key_blob(tagfmt.compress(blob[-65:])):
                raise ValueError("not an ecdsa-sha2-nistp256 key")
            known[0x9A] = (tagfmt.compress(blob[-65:]), saved)
        except (ValueError, tagfmt.FormatError) as e:
            raise CardError(f"{saved} does not hold the card's SSH public key ({e}). No PIN was asked for or "
                            "sent. Remove the file, then run: pivcard ssh unlock") from None
    return known


def cmd_check(args) -> int:
    """Does this card work with these tools, and does it lock again after each use?"""
    _may_ask_for_pin("pivcard check")
    slots = ((0x9D, "decrypts an age file key"), (0x9A, "signs for SSH"))
    known = {} if args.new_card else _known_keys()
    keys: dict[int, bytes | None] = {}
    t = piv.open_transport(args.reader)
    try:
        with piv.exclusive(t):
            was_open = piv.pin_tries(t) is None
            for slot in dict.fromkeys([*(slot for slot, _ in slots), *known]):   # also slots recorded for the card
                try:
                    pub = piv.slot_public_key(t, slot)
                    keys[slot] = tagfmt.public_key_to_compressed(pub) if pub is not None else None
                except tagfmt.FormatError:
                    keys[slot] = None
        print(f"reader: {t.name}")
    finally:
        t.close()
    if was_open:
        print("note: another program had left the card unlocked; this check locks it")
    if not any(keys[slot] for slot, _ in slots):
        raise CardError("neither slot 9D nor slot 9A holds an ECC P-256 key with a certificate")
    # Once the tools know a card, the PIN goes to that card only. A card that was never set up here has
    # nothing to be compared with: that is what this command is for.
    for slot, (recorded, where) in known.items():
        if keys.get(slot) != recorded:
            raise CardError(f"this is not the card these tools were set up with (slot {piv.slot_name(slot)} "
                            f"does not hold the key recorded in {where}). No PIN was asked for or sent. "
                            "To test another card on purpose, run: pivcard check --new-card")
    pin = getpass.getpass("PIN for the PIV card: ").strip()
    if not pin:
        raise CardError("no PIN entered. Nothing was sent to the card.")
    failed = 0
    for slot, what in slots:
        name = piv.slot_name(slot)
        if keys[slot] is None:
            print(f"  skip  slot {name}: no ECC P-256 key with a certificate")
            continue
        session = piv.PivSession(piv.open_transport(args.reader), slot, keys[slot])
        try:
            if slot == 0x9D:                           # the same steps as decrypting a real age file
                file_key = os.urandom(16)
                stanza_args, body = tagfmt.wrap(file_key, keys[slot])
                _, enc = tagfmt.parse(stanza_args, body)
                try:
                    good = tagfmt.unwrap(enc, body, keys[slot], lambda peer, s=session: s.ecdh(pin, peer)) == file_key
                except InvalidTag:
                    good = False
            else:
                digest = hashlib.sha256(os.urandom(32)).digest()
                signature = session.sign(pin, digest)
                public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), tagfmt.decompress(keys[slot]))
                try:
                    public.verify(signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
                    good = True
                except InvalidSignature:
                    good = False
            by_reset = session._must_reset
        finally:
            session.close()
        after = piv.open_transport(args.reader)
        try:
            with piv.exclusive(after):
                locked = piv.pin_tries(after) is not None
        finally:
            after.close()
        print(f"  {'ok  ' if good else 'FAIL'}  slot {name} {what}")
        print(f"  {'ok  ' if locked else 'FAIL'}  the card is locked again afterwards"
              f"{' (it needed a card reset: the logout command is not supported)' if by_reset and locked else ''}")
        failed += (not good) + (not locked)
    print("this card works with these tools" if not failed else f"{failed} check(s) failed")
    return 1 if failed else 0


def cmd_mkcert(args) -> int:
    pub = serialization.load_pem_public_key(Path(args.pubkey).read_bytes())
    cert = placeholder_certificate(pub, args.cn, args.usage)
    encoding = serialization.Encoding.DER if args.der else serialization.Encoding.PEM
    Path(args.out).write_bytes(cert.public_bytes(encoding))
    print(f"wrote {args.out} (placeholder: it asserts nothing, it only carries the public key)", file=sys.stderr)
    return 0


def _agent_request(request: dict, *, autostart: bool = False) -> dict:
    try:
        return agent.control(request, autostart=autostart)
    except agent.AgentUnavailable:
        return {"ok": False, "error": "the agent is not running", "down": True}


def _print_ssh_status(status: dict) -> None:
    ssh = status.get("ssh")
    if not ssh:
        print("SSH: locked")
        return
    print(f"SSH: unlocked for {ssh['seconds_left'] // 60} more min (card in {ssh['reader']}, slot {ssh['slot']})")
    print(f"     {ssh['public_key']}")
    print(f"     use it with: ssh -o IdentityAgent={paths.openssh_agent_address()} -o IdentitiesOnly=yes "
          f"-i {ssh_key_file()} ...")


def cmd_ssh(args) -> int:
    if args.action == "socket":
        print(paths.openssh_agent_address())
        return 0
    if args.action == "status":
        status = _agent_request({"op": "status"})
        if status.get("down"):
            print("SSH: locked (the agent is not running)")
            return 0
        _print_ssh_status(status)
        return 0
    if args.action == "lock":
        status = _agent_request({"op": "ssh-lock"})
        print("SSH: locked")
        return 0 if status.get("ok") or status.get("down") else 1
    # unlock: the one place a PIN is typed for the agent. Terminal only.
    _may_ask_for_pin("pivcard ssh unlock")
    # Which key does this card hold? Read without a PIN, and compared with the key remembered from the
    # first unlock, so that a different card left in the reader is refused before a PIN is even typed.
    slot = piv.parse_slot(args.slot)
    t = piv.open_transport(args.reader)
    try:
        with piv.exclusive(t):
            pub33 = _p256(t, slot)
    finally:
        t.close()
    line = agent.ssh_public_key_line(pub33)
    saved = ssh_key_file()
    known = saved.read_text().split() if saved.is_file() else []
    if known and known[:2] != line.split()[:2] and not args.new_card:
        raise CardError(f"this is not the card SSH was set up with (slot {piv.slot_name(slot)} holds a different "
                        f"key than {saved}). No PIN was asked for or sent. If you changed cards on purpose, "
                        "run: pivcard ssh unlock --new-card")
    pin = getpass.getpass("PIN for the PIV card: ").strip()
    if not pin:
        raise CardError("no PIN entered. Nothing was sent to the card.")
    status = _agent_request({"op": "ssh-unlock", "pin": pin, "slot": args.slot, "ttl": args.hours * 3600,
                             "expect": pub33.hex()}, autostart=True)
    if not status.get("ok"):
        raise CardError(status.get("error", "unlock failed"))
    if known[:2] != line.split()[:2]:
        saved.parent.mkdir(parents=True, exist_ok=True)
        saved.write_text(line + "\n")
        print(f"remembered this card's SSH public key in {saved}")
    _print_ssh_status(status)
    return 0


def cmd_agent(args) -> int:
    if args.action == "stop":
        reply = _agent_request({"op": "stop"})
        print("agent stopped" if reply.get("ok") else "the agent was not running")
        return 0
    if args.action == "status":
        status = _agent_request({"op": "status"})
        if status.get("down"):
            print("agent: not running")
            return 0
        print(f"agent: running (pid {status['pid']})")
        _print_ssh_status(status)
        for item in status["secrets"]:
            print(f"entry {item['name']}: unlocked, {item['seconds_left'] // 60} min left")
        return 0
    return agent.main(["--keep"])                       # start: run in the foreground


def _hours(text: str) -> float:
    value = float(text)
    if not math.isfinite(value) or not 0 < value <= agent.MAX_TTL / 3600:
        raise argparse.ArgumentTypeError("a number of hours above 0, at most 24")
    return value


def main(argv: list[str] | None = None) -> int:
    paths.harden_process()                              # `ssh unlock` and `check` handle the PIN
    p = argparse.ArgumentParser(prog="pivcard", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"pivcard {__version__}")
    p.add_argument("--reader", help="part of the reader name (default: $PIVCARD_READER, then `pivcard use`)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("readers").set_defaults(fn=cmd_readers)
    s = sub.add_parser("use")
    s.add_argument("name")
    s.set_defaults(fn=cmd_use)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    s = sub.add_parser("identity")
    s.add_argument("--slot", default="9D")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_identity)
    s = sub.add_parser("ssh-pubkey")
    s.add_argument("--slot", default="9A")
    s.add_argument("--comment", default="piv-card")
    s.set_defaults(fn=cmd_ssh_pubkey)
    sub.add_parser("lock").set_defaults(fn=cmd_lock)
    s = sub.add_parser("check")
    s.add_argument("--new-card", action="store_true", help="test a card other than the one set up here")
    s.set_defaults(fn=cmd_check)
    s = sub.add_parser("mkcert")
    s.add_argument("pubkey")
    s.add_argument("out")
    s.add_argument("--cn", default="PIV key holder")
    s.add_argument("--usage", choices=("agree", "sign"), default="agree")
    s.add_argument("--der", action="store_true")
    s.set_defaults(fn=cmd_mkcert)
    s = sub.add_parser("ssh")
    s.add_argument("action", choices=("unlock", "lock", "status", "socket"))
    s.add_argument("--hours", type=_hours, default=4.0, help="time limit, at most 24 (default: 4)")
    s.add_argument("--slot", default="9A")
    s.add_argument("--new-card", action="store_true", help="accept a card with a different SSH key")
    s.set_defaults(fn=cmd_ssh)
    s = sub.add_parser("agent")
    s.add_argument("action", choices=("start", "stop", "status"))
    s.set_defaults(fn=cmd_agent)
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except (CardError, agent.AgentNotOurs) as e:
        print(f"pivcard: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
