"""The age `p256tag` recipient stanza and the Bech32 encodings around it. Pure software.

Format: C2SP age.md, "The tagged recipient types". The file key is sealed with HPKE (RFC 9180) base
mode, suite DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305. Decryption needs exactly one
private-key operation, a raw P-256 ECDH, which is the one thing a PIV card's key-management slot does.
Everything else here runs on the host and needs no secret.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PLUGIN_NAME = "pivcard"
RECIPIENT_HRP = "age1pivcard"          # handled by this plugin on any plugin-capable age client
TAG_RECIPIENT_HRP = "age1tag"          # the same key as a native recipient (age >= 1.3, no plugin)
IDENTITY_HRP = "AGE-PLUGIN-PIVCARD-"
STANZA = "p256tag"
INFO = b"age-encryption.org/p256tag"
FILE_KEY_LEN = 16
BODY_LEN = FILE_KEY_LEN + 16           # ChaCha20-Poly1305 tag

Ecdh = Callable[[bytes], bytes]        # peer public key (65 bytes, uncompressed) -> shared x (32 bytes)


class FormatError(ValueError):
    """A recipient, identity or stanza that is structurally invalid."""


# ------------------------------------------------------------------ base64 as age uses it
def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    """Decode unpadded standard base64, rejecting non-canonical encodings."""
    try:
        raw = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except (ValueError, TypeError) as e:
        raise FormatError(f"invalid base64: {e}") from None
    if b64e(raw) != text:
        raise FormatError("non-canonical base64")
    return raw


# ------------------------------------------------------------------ Bech32 (BIP-173, no length limit)
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values: list[int]) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _GEN[i]
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits: int, tobits: int, pad: bool) -> list[int]:
    acc = bits = 0
    out: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise FormatError("invalid Bech32 padding")
    return out


def bech32_encode(hrp: str, data: bytes) -> str:
    """Encode `data` under `hrp`. An upper-case HRP gives an upper-case string (age identities)."""
    low = hrp.lower()
    values = _convertbits(data, 8, 5, True)
    polymod = _polymod(_hrp_expand(low) + values + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    text = low + "1" + "".join(_CHARSET[v] for v in values + checksum)
    return text.upper() if hrp != low else text


def bech32_decode(text: str) -> tuple[str, bytes]:
    """Return (lower-case HRP, data). Rejects mixed case and bad checksums."""
    if text != text.lower() and text != text.upper():
        raise FormatError("mixed-case Bech32")
    low = text.lower()
    pos = low.rfind("1")
    if pos < 1 or pos + 7 > len(low):
        raise FormatError("not a Bech32 string")
    hrp, tail = low[:pos], low[pos + 1:]
    try:
        values = [_CHARSET.index(c) for c in tail]
    except ValueError:
        raise FormatError("invalid Bech32 character") from None
    if any(ord(c) < 33 or ord(c) > 126 for c in hrp) or _polymod(_hrp_expand(hrp) + values) != 1:
        raise FormatError("invalid Bech32 checksum")
    return hrp, bytes(_convertbits(values[:-6], 5, 8, False))


# ------------------------------------------------------------------ P-256 points
def _point(encoded: bytes) -> ec.EllipticCurvePublicKey:
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), encoded)
    except ValueError:
        raise FormatError("not a valid P-256 point") from None


def compress(point: bytes) -> bytes:
    return _point(point).public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def decompress(point: bytes) -> bytes:
    return _point(point).public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def public_key_to_compressed(pub: ec.EllipticCurvePublicKey) -> bytes:
    if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
        raise FormatError("the slot's key is not ECC P-256")
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


# ------------------------------------------------------------------ recipients and identities
def encode_recipient(pub33: bytes, hrp: str = RECIPIENT_HRP) -> str:
    return bech32_encode(hrp, compress(pub33))


def decode_recipient(text: str) -> bytes:
    hrp, data = bech32_decode(text)
    if hrp not in (RECIPIENT_HRP, TAG_RECIPIENT_HRP):
        raise FormatError(f"not a {RECIPIENT_HRP} or {TAG_RECIPIENT_HRP} recipient")
    if len(data) != 33:
        raise FormatError("recipient is not a 33-byte compressed P-256 point")
    return compress(data)


_IDENTITY_VERSION = 1


def encode_identity(slot: int, pub33: bytes) -> str:
    """An identity holds no secret: a version byte, the PIV key reference, and the public key."""
    return bech32_encode(IDENTITY_HRP, bytes([_IDENTITY_VERSION, slot]) + compress(pub33))


def decode_identity(text: str) -> tuple[int, bytes]:
    hrp, data = bech32_decode(text)
    if hrp != IDENTITY_HRP.lower():
        raise FormatError(f"not an {IDENTITY_HRP} identity")
    if len(data) != 35 or data[0] != _IDENTITY_VERSION:
        raise FormatError("unsupported identity version or length")
    return data[1], compress(data[2:])


# ------------------------------------------------------------------ HPKE base mode, one suite
_KEM_SUITE = b"KEM" + (0x0010).to_bytes(2, "big")
_HPKE_SUITE = b"HPKE" + (0x0010).to_bytes(2, "big") + (0x0001).to_bytes(2, "big") + (0x0003).to_bytes(2, "big")


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _labeled_extract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _extract(salt, b"HPKE-v1" + suite + label + ikm)


def _labeled_expand(suite: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    return _expand(prk, length.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info, length)


def _kem_secret(dh: bytes, enc65: bytes, pkr65: bytes) -> bytes:
    prk = _labeled_extract(_KEM_SUITE, b"", b"eae_prk", dh)
    return _labeled_expand(_KEM_SUITE, prk, b"shared_secret", enc65 + pkr65, 32)


def _key_schedule(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    context = (b"\x00" + _labeled_extract(_HPKE_SUITE, b"", b"psk_id_hash", b"")
               + _labeled_extract(_HPKE_SUITE, b"", b"info_hash", info))
    secret = _labeled_extract(_HPKE_SUITE, shared_secret, b"secret", b"")
    return (_labeled_expand(_HPKE_SUITE, secret, b"key", context, 32),
            _labeled_expand(_HPKE_SUITE, secret, b"base_nonce", context, 12))


def hpke_seal(pkr65: bytes, info: bytes, aad: bytes, plaintext: bytes,
              ephemeral: ec.EllipticCurvePrivateKey | None = None) -> tuple[bytes, bytes]:
    """SealBase for the first message of a context. Returns (enc, ciphertext)."""
    eph = ephemeral or ec.generate_private_key(ec.SECP256R1())
    enc = eph.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    dh = eph.exchange(ec.ECDH(), _point(pkr65))
    key, nonce = _key_schedule(_kem_secret(dh, enc, pkr65), info)
    return enc, ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def hpke_open(enc65: bytes, pkr65: bytes, ecdh: Ecdh, info: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """OpenBase where the recipient's private key is only reachable through `ecdh`."""
    _point(enc65)  # reject anything that is not a curve point before it goes to the card
    dh = ecdh(enc65)
    if len(dh) != 32:
        raise FormatError("ECDH result is not 32 bytes")
    key, nonce = _key_schedule(_kem_secret(dh, enc65, pkr65), info)
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)


# ------------------------------------------------------------------ the p256tag stanza
def stanza_tag(enc65: bytes, pub33: bytes) -> bytes:
    """HKDF-Extract(salt = info string, ikm = enc || SHA-256(recipient)[:4])[:4]."""
    return hmac.new(INFO, enc65 + hashlib.sha256(pub33).digest()[:4], hashlib.sha256).digest()[:4]


def wrap(file_key: bytes, pub33: bytes) -> tuple[list[str], bytes]:
    """Seal a file key to a recipient. Returns (stanza arguments after the type, body)."""
    if len(file_key) != FILE_KEY_LEN:
        raise FormatError("file key is not 16 bytes")
    enc, body = hpke_seal(decompress(pub33), INFO, b"", file_key)
    return [b64e(stanza_tag(enc, pub33)), b64e(enc)], body


def parse(args: list[str], body: bytes) -> tuple[bytes, bytes]:
    """Validate a p256tag stanza's shape. Returns (tag, enc). Raises FormatError when malformed."""
    if len(args) != 2:
        raise FormatError("p256tag stanza must have exactly three arguments")
    tag, enc = b64d(args[0]), b64d(args[1])
    if len(tag) != 4 or len(enc) != 65:
        raise FormatError("p256tag tag must be 4 bytes and enc 65 bytes")
    if len(body) != BODY_LEN:
        raise FormatError("p256tag body must be 32 bytes")
    _point(enc)                                       # an off-curve point must never be sent to the card
    return tag, enc


def is_for(tag: bytes, enc65: bytes, pub33: bytes) -> bool:
    return hmac.compare_digest(tag, stanza_tag(enc65, pub33))


def unwrap(enc65: bytes, body: bytes, pub33: bytes, ecdh: Ecdh) -> bytes:
    """Open a stanza addressed to `pub33`. Raises cryptography's InvalidTag if it does not decrypt."""
    return hpke_open(enc65, decompress(pub33), ecdh, INFO, b"", body)
