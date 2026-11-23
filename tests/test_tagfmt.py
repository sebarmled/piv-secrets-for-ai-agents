"""Format tests that need no hardware: Bech32, HPKE (RFC 9180 A.5.1 vector), the p256tag stanza."""
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from pivcard import tagfmt as t

H = bytes.fromhex


def soft_key():
    key = ec.generate_private_key(ec.SECP256R1())
    pub33 = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    return key, pub33


def soft_ecdh(key):
    return lambda peer65: key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer65))


# ---------------------------------------------------------------- Bech32
def test_bech32_matches_the_age_spec_examples():
    # C2SP age.md, "The X25519 recipient type": identity and its recipient.
    hrp, raw = t.bech32_decode("AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX")
    assert hrp == "age-secret-key-" and len(raw) == 32
    pub = x25519.X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert t.bech32_encode("age", pub) == "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"
    assert t.bech32_encode("AGE-SECRET-KEY-", raw) == (
        "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX")


def test_spec_tag_recipient_decodes_to_a_p256_point():
    pub33 = t.decode_recipient("age1tag1qt8lw0ual6avlwmwatk888yqnmdamm7xfd0wak53ut6elz5c4swx2yqdj4e")
    assert len(pub33) == 33 and pub33[0] in (2, 3)
    assert t.encode_recipient(pub33, t.TAG_RECIPIENT_HRP) == (
        "age1tag1qt8lw0ual6avlwmwatk888yqnmdamm7xfd0wak53ut6elz5c4swx2yqdj4e")


@pytest.mark.parametrize("bad", [
    "age1tag1qt8lw0ual6avlwmwatk888yqnmdamm7xfd0wak53ut6elz5c4swx2yqdj4f",   # checksum
    "Age1tag1qt8lw0ual6avlwmwatk888yqnmdamm7xfd0wak53ut6elz5c4swx2yqdj4e",   # mixed case
    "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj",        # another recipient type
    "nonsense",
])
def test_bad_recipients_are_rejected(bad):
    with pytest.raises(t.FormatError):
        t.decode_recipient(bad)


def test_recipient_and_identity_round_trip():
    _, pub33 = soft_key()
    for hrp in (t.RECIPIENT_HRP, t.TAG_RECIPIENT_HRP):
        text = t.encode_recipient(pub33, hrp)
        assert text.startswith(hrp + "1") and t.decode_recipient(text) == pub33
    ident = t.encode_identity(0x9D, pub33)
    assert ident.startswith("AGE-PLUGIN-PIVCARD-1") and ident == ident.upper()
    assert t.decode_identity(ident) == (0x9D, pub33)
    with pytest.raises(t.FormatError):
        t.decode_identity(t.encode_recipient(pub33))


# ---------------------------------------------------------------- HPKE, RFC 9180 Appendix A.5.1
INFO = H("4f6465206f6e2061204772656369616e2055726e")
SK_E = H("7550253e1147aae48839c1f8af80d2770fb7a4c763afe7d0afa7e0f42a5b3689")
SK_R = H("a4d1c55836aa30f9b3fbb6ac98d338c877c2867dd3a77396d13f68d3ab150d3b")
PK_R = H("04a697bffde9405c992883c5c439d6cc358170b51af72812333b015621dc0f"
         "40bad9bb726f68a5c013806a790ec716ab8669f84f6b694596c2987cf35baba2a006")
ENC = H("04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824"
        "fc1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291")
SHARED = H("806520f82ef0b03c823b7fc524b6b55a088f566b9751b89551c170f4113bd850")
KEY = H("a8f45490a92a3b04d1dbf6cf2c3939ad8bfc9bfcb97c04bffe116730c9dfe3fc")
NONCE = H("726b4390ed2209809f58c693")
PT = H("4265617574792069732074727574682c20747275746820626561757479")
AAD = H("436f756e742d30")
CT = H("6469c41c5c81d3aa85432531ecf6460ec945bde1eb428cb2fedf7a29f5a685b4ccb0d057f03ea2952a27bb458b")


def _priv(raw):
    return ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())


def test_hpke_matches_rfc9180_vector():
    enc, ct = t.hpke_seal(PK_R, INFO, AAD, PT, ephemeral=_priv(SK_E))
    assert enc == ENC and ct == CT
    dh = _priv(SK_E).exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), PK_R))
    assert t._kem_secret(dh, ENC, PK_R) == SHARED
    assert t._key_schedule(SHARED, INFO) == (KEY, NONCE)
    assert t.hpke_open(ENC, PK_R, soft_ecdh(_priv(SK_R)), INFO, AAD, CT) == PT


def test_hpke_open_rejects_a_point_off_the_curve_before_calling_ecdh():
    calls = []
    with pytest.raises(t.FormatError):
        t.hpke_open(b"\x04" + bytes(64), PK_R, lambda p: calls.append(p) or bytes(32), INFO, b"", CT)
    assert calls == []


# ---------------------------------------------------------------- p256tag stanza
def test_wrap_unwrap_round_trip():
    key, pub33 = soft_key()
    file_key = bytes(range(16))
    args, body = t.wrap(file_key, pub33)
    tag, enc = t.parse(args, body)
    assert len(body) == 32 and t.is_for(tag, enc, pub33)
    assert t.unwrap(enc, body, pub33, soft_ecdh(key)) == file_key


def test_tag_does_not_match_another_recipient_and_wrong_key_fails():
    _, pub33 = soft_key()
    other, other33 = soft_key()
    args, body = t.wrap(bytes(16), pub33)
    tag, enc = t.parse(args, body)
    assert not t.is_for(tag, enc, other33)
    with pytest.raises(InvalidTag):
        t.unwrap(enc, body, pub33, soft_ecdh(other))


def test_spec_example_stanza_has_the_expected_shape():
    args = ["CXBuUw", "BOqTylUtZFwkMTxd6UENg8kopiMhRJBOUXMv5w2xVOmJu7eezoALGXiNtq5Vka+UQvaYbQvAdwjIJEDaoBaq7So"]
    tag, enc = t.parse(args, t.b64d("bZQpLsV8uGqGPs70J6dVodiHejsZ5BODjaRsB0RcBqI"))
    assert len(tag) == 4 and t.decompress(enc) == enc


@pytest.mark.parametrize("args, body_len", [
    (["CXBuUw"], 32),                                   # too few arguments
    (["CXBuUw", "AAAA", "AAAA"], 32),                   # too many
    (["CXBuUw=", "AAAA"], 32),                          # padded base64
    (["CXBuUx", "AAAA"], 32),                           # non-canonical trailing bits
    (["CXBu", "AAAA"], 32),                             # tag not 4 bytes
    (["CXBuUw", "AAAA"], 32),                           # enc not 65 bytes
])
def test_malformed_stanzas_are_rejected(args, body_len):
    with pytest.raises(t.FormatError):
        t.parse(args, bytes(body_len))


def test_body_length_is_checked():
    _, pub33 = soft_key()
    args, body = t.wrap(bytes(16), pub33)
    with pytest.raises(t.FormatError):
        t.parse(args, body + b"\x00")
    with pytest.raises(t.FormatError):
        t.wrap(bytes(15), pub33)


def test_chacha_nonce_is_the_hpke_base_nonce_not_zero():
    # Guards against confusing this with the X25519 stanza's fixed zero nonce.
    key, pub33 = soft_key()
    args, body = t.wrap(bytes(16), pub33)
    _, enc = t.parse(args, body)
    dh = soft_ecdh(key)(enc)
    k, nonce = t._key_schedule(t._kem_secret(dh, enc, t.decompress(pub33)), t.INFO)
    assert nonce != bytes(12) and ChaCha20Poly1305(k).decrypt(nonce, body, b"") == bytes(16)
