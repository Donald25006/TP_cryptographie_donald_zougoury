#!/usr/bin/env python3
"""Verifie la sortie critique avec un certificat de laboratoire valable cinq jours."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


def main() -> int:
    surveiller = Path(__file__).with_name("surveiller.py")
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.tp.local")])
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((now - timedelta(minutes=1)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(days=5)).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    with tempfile.TemporaryDirectory(prefix="certificat-5-jours-") as temp:
        folder = Path(temp)
        (folder / "test-5-jours.crt").write_bytes(
            certificate.public_bytes(Encoding.PEM)
        )
        result = subprocess.run(
            [sys.executable, str(surveiller), str(folder)],
            text=True,
            capture_output=True,
            check=False,
        )
    if result.returncode != 2 or "CRITIQUE" not in result.stdout:
        print("ECHEC du test de certificat a cinq jours.", file=sys.stderr)
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return 1
    print("Test reussi: certificat a cinq jours classe CRITIQUE, code 2.")
    print(result.stdout.strip())

    certificat_valide = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((now - timedelta(minutes=1)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(days=90)).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(subject)
        .last_update((now - timedelta(minutes=1)).replace(tzinfo=None))
        .next_update((now + timedelta(days=7)).replace(tzinfo=None))
        .sign(key, hashes.SHA256())
    )
    with tempfile.TemporaryDirectory(prefix="surveillance-crl-") as temp:
        folder = Path(temp)
        (folder / "serveur.crt").write_bytes(
            certificat_valide.public_bytes(Encoding.PEM)
        )
        (folder / "crls.pem").write_bytes(crl.public_bytes(Encoding.PEM))
        result = subprocess.run(
            [sys.executable, str(surveiller), str(folder)],
            text=True,
            capture_output=True,
            check=False,
        )
    if (
        result.returncode != 0
        or "OK:" not in result.stdout
        or "CRITIQUE" in result.stdout
    ):
        print("ECHEC du test avec certificat et CRL PEM.", file=sys.stderr)
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return 1
    print("Test reussi: la CRL PEM est ignoree et le certificat valide reste OK.")
    print(result.stdout.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
