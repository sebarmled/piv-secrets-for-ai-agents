"""The handful of NIST SP 800-73 commands this project needs, and the rules for using the PIN.

A PIV card has ONE PIN state, shared by every slot and every process that can reach the reader. Once
VERIFY succeeds, the key-management key (and the others) stay usable by anyone on the host until the
card is logged out, reset or removed. So here a PIN is only ever used like this, as one unit inside a
PC/SC transaction (which keeps other processes out for its duration):

    VERIFY  ->  one key operation  ->  log out  ->  confirm the card reports "not verified"

and the PIN is sent only after the card has shown, from its certificate, that it holds the expected key.
"""
from __future__ import annotations

import contextlib
import gzip
import signal
import threading

from cryptography import x509

from . import tagfmt
from .apdu import PcscTransport, Transport, configured_reader, list_readers, pick_reader
from .plugin import CardError, PinError

PIV_AID = bytes.fromhex("A00000030800001000")        # right-truncated AID, per SP 800-73-4 part 2, 3.1.1
ALG_ECC_P256 = 0x11
PIN_REF = 0x80
MIN_TRIES = 1                                        # never use the last try: refuse to VERIFY at this count

# key reference -> data object holding that key's certificate
CERT_OBJECT = {0x9A: 0x5FC105, 0x9C: 0x5FC10A, 0x9D: 0x5FC10B, 0x9E: 0x5FC101}
CERT_OBJECT.update({0x82 + i: 0x5FC10D + i for i in range(20)})          # retired key management 82..95
KEY_AGREEMENT_SLOTS = (0x9D, *range(0x82, 0x96))


def slot_name(slot: int) -> str:
    return f"{slot:02X}"


def parse_slot(text: str) -> int:
    try:
        slot = int(text, 16)
    except ValueError:
        slot = -1
    if slot not in CERT_OBJECT:
        raise CardError(f"unknown PIV slot {text!r} (expected 9A, 9C, 9D, 9E or 82..95)")
    return slot


def _tlv(buf: bytes):
    """Iterate (tag, value) over single-byte-tag BER-TLV."""
    pos = 0
    while pos + 2 <= len(buf):
        tag, length = buf[pos], buf[pos + 1]
        pos += 2
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(buf[pos:pos + n], "big")
            pos += n
        yield tag, buf[pos:pos + length]
        pos += length


def _find(buf: bytes, tag: int) -> bytes | None:
    return next((value for t, value in _tlv(buf) if t == tag), None)


# ------------------------------------------------------------------ commands (none of these send a PIN
# except verify_pin)
def select(t: Transport) -> None:
    head = bytes([0x00, 0xA4, 0x04, 0x00, len(PIV_AID)]) + PIV_AID
    _, sw = t.transmit(head + b"\x00")
    if sw == 0x6700:                                  # some applets reject Le on SELECT
        _, sw = t.transmit(head)
    if sw != 0x9000:
        raise CardError(f"the card in {t.name!r} has no PIV application (SELECT returned {sw:04X})")


def read_certificate(t: Transport, slot: int) -> bytes | None:
    """The DER certificate stored for a slot, or None if the container is empty. Needs no PIN."""
    tag = CERT_OBJECT[slot].to_bytes(3, "big")
    data, sw = t.transmit(bytes([0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03]) + tag + b"\x00")
    if sw != 0x9000:
        return None
    obj = _find(data, 0x53)
    der = _find(obj, 0x70) if obj else None
    if not der:
        return None
    info = _find(obj, 0x71)
    if info and info[0] & 0x01:                       # CertInfo bit 0: gzip-compressed
        try:
            der = gzip.decompress(der)
        except (OSError, EOFError):
            raise CardError(f"slot {slot_name(slot)} holds a compressed certificate that does not decompress") from None
    return der


def slot_public_key(t: Transport, slot: int):
    """The public key in the slot's certificate (a cryptography key object), or None."""
    der = read_certificate(t, slot)
    if der is None:
        return None
    try:
        return x509.load_der_x509_certificate(der).public_key()
    except ValueError as e:
        raise CardError(f"slot {slot_name(slot)} certificate is unreadable: {e}") from None


def pin_tries(t: Transport) -> int | None:
    """Tries left, read without spending one. None means the card is currently in the verified state."""
    _, sw = t.transmit(bytes([0x00, 0x20, 0x00, PIN_REF]))
    if sw == 0x9000:
        return None
    if sw >> 4 == 0x63C:
        return sw & 0x0F
    if sw == 0x6983:
        return 0
    raise CardError(f"the card did not answer the PIN status query (returned {sw:04X})")


def verify_pin(t: Transport, pin: str) -> None:
    """Send the PIN. Raises PinError (wrong PIN) or CardError; the format is checked before sending."""
    if not (pin.isascii() and pin.isdigit() and 6 <= len(pin) <= 8):
        raise CardError("a PIV PIN is 6 to 8 digits. It was not sent to the card.")
    _, sw = t.transmit(bytes([0x00, 0x20, 0x00, PIN_REF, 0x08]) + pin.encode().ljust(8, b"\xff"))
    if sw == 0x9000:
        return
    if sw >> 4 == 0x63C:
        raise PinError(sw & 0x0F)
    if sw == 0x6983:
        raise CardError("the PIN is blocked. Unblock it with the PUK using your card's management tool.")
    raise CardError(f"VERIFY failed with status {sw:04X}")


def logout(t: Transport) -> bool:
    """Put the card back in the "not verified" state. Returns False if the card would not do it."""
    with contextlib.suppress(CardError):
        t.transmit(bytes([0x00, 0x20, 0xFF, PIN_REF]))                # reset the security status
        if pin_tries(t) is not None:
            return True
    with contextlib.suppress(CardError):                              # fallback: leave the PIV applet and return
        t.transmit(bytes([0x00, 0xA4, 0x04, 0x00, 0x00]))
        select(t)
        if pin_tries(t) is not None:
            return True
    return False


def ecdh(t: Transport, slot: int, peer65: bytes) -> bytes:
    """GENERAL AUTHENTICATE, ECDH with the slot's P-256 key. Needs the verified state."""
    if len(peer65) != 65 or peer65[0] != 0x04:
        raise CardError("ECDH peer key must be an uncompressed P-256 point")
    body = bytes([0x7C, 0x45, 0x82, 0x00, 0x85, 0x41]) + peer65
    data, sw = t.transmit(bytes([0x00, 0x87, ALG_ECC_P256, slot, len(body)]) + body + b"\x00")
    if sw == 0x6982:
        raise CardError("the card refused the key operation (security status not satisfied)")
    if sw != 0x9000:
        raise CardError(f"ECDH on slot {slot_name(slot)} failed with status {sw:04X}")
    template = _find(data, 0x7C)
    shared = _find(template, 0x82) if template else None
    if not shared or len(shared) != 32:
        raise CardError("the card returned a malformed ECDH response")
    return shared


def sign(t: Transport, slot: int, digest: bytes) -> bytes:
    """GENERAL AUTHENTICATE, ECDSA over a SHA-256 digest with the slot's P-256 key. Returns the DER signature."""
    if len(digest) != 32:
        raise CardError("the card signs a 32-byte SHA-256 digest")
    body = bytes([0x7C, 0x24, 0x82, 0x00, 0x81, 0x20]) + digest
    data, sw = t.transmit(bytes([0x00, 0x87, ALG_ECC_P256, slot, len(body)]) + body + b"\x00")
    if sw == 0x6982:
        raise CardError("the card refused the key operation (security status not satisfied)")
    if sw != 0x9000:
        raise CardError(f"signing with slot {slot_name(slot)} failed with status {sw:04X}")
    template = _find(data, 0x7C)
    signature = _find(template, 0x82) if template else None
    if not signature:
        raise CardError("the card returned a malformed signature response")
    return signature


@contextlib.contextmanager
def uninterrupted():
    """Hold back stop signals (Ctrl-C, Ctrl-\\, SIGTERM, SIGHUP, Ctrl-Break) until the block is over, then deliver
    the first one. Without this, a signal that arrives while the PIN is on its way to the card would end
    the program before the logout. Python runs signal handlers in the main thread only; in any other
    thread this does nothing, and nothing is needed."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    held: list[int] = []
    saved = {}
    for name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGBREAK"):
        number = getattr(signal, name, None)
        if number is not None:
            with contextlib.suppress(ValueError, OSError):
                saved[number] = signal.signal(number, lambda received, _frame: held.append(received))
    try:
        yield
    finally:
        for number, handler in saved.items():
            signal.signal(number, signal.SIG_DFL if handler is None else handler)
        if held:
            signal.raise_signal(held[0])


@contextlib.contextmanager
def exclusive(t: Transport):
    """Hold the card for one sequence of commands, with the PIV application selected.

    The connection is shared with every other program on the host. Without a PC/SC transaction their
    commands can interleave with ours (a chained read then returns someone else's bytes), and they may
    have selected another application since our last command. Re-selecting PIV keeps its PIN state.
    """
    t.begin()
    try:
        select(t)
        yield t
    finally:
        t.end()


# ------------------------------------------------------------------ PIN-gated use of one key
class PivSession:
    """One key on one card. Every use of the PIN is a unit, inside a single transaction:

        confirm the slot still holds the expected key  ->  VERIFY  ->  one operation  ->  log out

    The key is re-checked each time because a card can be swapped between two commands; the PIN must
    never reach a card other than the one the user meant.
    """

    def __init__(self, transport: Transport, slot: int, pub33: bytes):
        self.t, self.slot, self.pub33 = transport, slot, pub33
        self._must_reset = False

    def describe(self) -> str:
        return f"{self.t.name} (slot {slot_name(self.slot)})"

    def _check_key(self, t: Transport) -> None:
        pub = slot_public_key(t, self.slot)
        if pub is None:
            raise CardError(f"the card in {t.name!r} has no certificate in slot {slot_name(self.slot)}, so its "
                            "key cannot be checked before the PIN is sent")
        try:
            on_card = tagfmt.public_key_to_compressed(pub)
        except tagfmt.FormatError as e:
            raise CardError(f"slot {slot_name(self.slot)}: {e}") from None
        if on_card != self.pub33:
            raise CardError(f"the card in {t.name!r} holds a different key than expected. No PIN was sent to it.")

    def check_key(self) -> None:
        """Confirm the card holds the expected key. Sends no PIN."""
        with exclusive(self.t) as t:
            self._check_key(t)

    def _use(self, pin: str, operation):
        # Stop signals wait until the card is logged out again; other processes wait until the block ends.
        with uninterrupted(), exclusive(self.t) as t:
            self._check_key(t)
            tries = pin_tries(t)                      # None: another program left the card verified
            if tries == 0:
                raise CardError("the PIN is blocked. Unblock it with the PUK using your card's management tool.")
            if tries is not None and tries <= MIN_TRIES:
                raise CardError(f"only {tries} PIN try left, and these tools never use the last one. Verify "
                                "the PIN once with your card's management tool, which resets the counter.")
            try:
                verify_pin(t, pin)                    # from here on the card may be in the verified state,
                return operation(t)                   # also if this is cut short: so always log out below
            finally:
                if not logout(t):
                    self._must_reset = True           # close() resets the card as well
                    t.end(reset=True)                 # reset it now, before any other program can reach it

    def ecdh(self, pin: str, peer65: bytes) -> bytes:
        return self._use(pin, lambda t: ecdh(t, self.slot, peer65))

    def sign(self, pin: str, digest: bytes) -> bytes:
        return self._use(pin, lambda t: sign(t, self.slot, digest))

    def check_pin(self, pin: str) -> None:
        """VERIFY and log out, with no key operation. Raises PinError if the PIN is wrong."""
        self._use(pin, lambda t: None)

    def close(self) -> None:
        self.t.close(reset=self._must_reset)


def open_transport(reader: str | None = None) -> Transport:
    """Connect to the chosen reader and check it has a PIV application. Sends no PIN."""
    info = pick_reader(list_readers(), reader or configured_reader())
    t = PcscTransport(info.name)
    try:
        with exclusive(t):
            pass
    except CardError:
        t.close()
        raise
    return t


def open_key(slot: int, pub33: bytes, transport: Transport | None = None) -> PivSession:
    """A session on the card whose certificate for `slot` carries exactly `pub33`. Sends no PIN."""
    session = PivSession(transport or open_transport(), slot, pub33)
    try:
        session.check_key()
    except CardError:
        session.t.close()
        raise
    return session


def open_card(slot: int, pub33: bytes, transport: Transport | None = None) -> PivSession:
    """The age plugin's CardFactory: like open_key, restricted to key-management slots."""
    if slot not in KEY_AGREEMENT_SLOTS:
        raise CardError(f"slot {slot_name(slot)} is not a key-management slot")
    return open_key(slot, pub33, transport)
