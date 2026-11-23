"""An in-memory PIV card for tests: enough of SP 800-73 to exercise the real command sequences.

It models what matters for this project's guarantees: the single shared PIN state, the retry counter,
the status query that costs no try, logout, and ECDH that only works while verified. It records every
APDU so tests can assert that no VERIFY was ever sent.
"""
from __future__ import annotations

import gzip

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .piv import CERT_OBJECT, PIV_AID
from .placeholder import placeholder_certificate


def _ber(tag: int, value: bytes) -> bytes:
    n = len(value)
    length = bytes([n]) if n < 0x80 else bytes([0x81, n]) if n < 0x100 else bytes([0x82]) + n.to_bytes(2, "big")
    return bytes([tag]) + length + value


class SoftCard:
    """Implements the Transport protocol against software keys."""

    def __init__(self, pin: str = "123456", max_tries: int = 6, name: str = "soft reader",
                 supports_reset: bool = True, supports_deselect: bool = True, has_piv: bool = True):
        self.name = name
        self.pin, self.max_tries, self.tries = pin, max_tries, max_tries
        self.supports_reset, self.supports_deselect, self.has_piv = supports_reset, supports_deselect, has_piv
        self.keys: dict[int, ec.EllipticCurvePrivateKey] = {}
        self.objects: dict[int, bytes] = {}
        self.selected = self.verified = False
        self.log: list[bytes] = []
        self.transactions = 0
        self.in_transaction = False
        self.closed: str | None = None
        self.ended: str | None = None                 # "reset" if a transaction was ended with a card reset

    # ---- test setup
    def add_key(self, slot: int, key: ec.EllipticCurvePrivateKey | None = None, *, cert: bool = True,
                compress: bool = False) -> bytes:
        """Put a key in a slot (and its certificate, unless cert=False). Returns the compressed public key."""
        key = key or ec.generate_private_key(ec.SECP256R1())
        self.keys[slot] = key
        if cert:
            der = placeholder_certificate(key.public_key()).public_bytes(serialization.Encoding.DER)
            info = b"\x01" if compress else b"\x00"
            body = _ber(0x70, gzip.compress(der) if compress else der) + _ber(0x71, info) + _ber(0xFE, b"")
            self.objects[CERT_OBJECT[slot]] = _ber(0x53, body)
        return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)

    @property
    def verify_attempts(self) -> int:
        """How many VERIFY commands carrying a PIN this card has received."""
        return sum(1 for a in self.log if a[1] == 0x20 and a[2] == 0x00 and len(a) > 4)

    # ---- Transport
    def begin(self) -> None:
        self.in_transaction = True
        self.transactions += 1

    def end(self, reset: bool = False) -> None:
        self.in_transaction = False
        if reset:
            self.ended = "reset"
            self.selected = self.verified = False

    def close(self, reset: bool = False) -> None:
        self.closed = "reset" if reset else "leave"
        if reset:
            self.selected = self.verified = False

    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        self.log.append(bytes(apdu))
        ins, p1, p2 = apdu[1], apdu[2], apdu[3]
        data = apdu[5:5 + apdu[4]] if len(apdu) > 5 else b""
        if ins == 0xA4:
            if data and PIV_AID.startswith(data[:len(PIV_AID)]) and data[:len(PIV_AID)] == PIV_AID:
                if not self.has_piv:
                    return b"", 0x6A82
                self.selected = True                  # re-selecting PIV keeps the security status
                return b"\x61\x00", 0x9000
            if not data and self.supports_deselect:
                self.selected = self.verified = False  # another application: PIV status is cleared
                return b"", 0x9000
            return b"", 0x6A82
        if not self.selected:
            return b"", 0x6D00
        if ins == 0xCB:
            tag = int.from_bytes(data[2:5], "big")
            return self.objects.get(tag, _ber(0x53, b"")), 0x9000
        if ins == 0x20 and p2 == 0x80:
            return b"", self._verify(p1, apdu, data)
        if ins == 0x87:
            if p1 != 0x11 or p2 not in self.keys:
                return b"", 0x6A86
            if not self.verified:
                return b"", 0x6982
            if data[4] == 0x81:                        # challenge present: sign the digest
                signature = self.keys[p2].sign(data[6:6 + data[5]], ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                return _ber(0x7C, _ber(0x82, signature)), 0x9000
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data[6:71])
            shared = self.keys[p2].exchange(ec.ECDH(), peer)
            return _ber(0x7C, _ber(0x82, shared)), 0x9000
        return b"", 0x6D00

    def _verify(self, p1: int, apdu: bytes, data: bytes) -> int:
        if p1 == 0xFF:
            if not self.supports_reset:
                return 0x6A86
            self.verified = False
            return 0x9000
        if len(apdu) == 4:                             # status query: costs no try
            if self.verified:
                return 0x9000
            return 0x63C0 | self.tries if self.tries else 0x6983
        if not self.tries:
            return 0x6983
        if len(data) != 8:
            return 0x6A80
        if data.rstrip(b"\xff").decode("ascii", "replace") == self.pin:
            self.verified, self.tries = True, self.max_tries
            return 0x9000
        self.verified = False
        self.tries -= 1
        return 0x63C0 | self.tries if self.tries else 0x6983
