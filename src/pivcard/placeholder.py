"""Placeholder certificates: the only way a PIV card can show a slot's public key."""
from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def placeholder_certificate(public_key, cn: str = "PIV key holder", usage: str = "agree") -> x509.Certificate:
    """A certificate that only carries a slot's public key, signed by a throwaway key.

    A PIV card has no "read public key" command: the key is returned once at generation and is then
    only reachable through the certificate in the slot's container. The key-management slot cannot
    sign, so it cannot self-sign. This certificate asserts nothing and is not a trust anchor.
    """
    throwaway = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    key_usage = x509.KeyUsage(
        digital_signature=usage == "sign", key_agreement=usage == "agree", content_commitment=False,
        key_encipherment=False, data_encipherment=False, key_cert_sign=False, crl_sign=False,
        encipher_only=False, decipher_only=False)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "placeholder (not a trust anchor)")]))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(key_usage, critical=True)
        .sign(throwaway, hashes.SHA256())
    )
