#!/usr/bin/env python3
"""Inventorie les certificats PEM/DER et retourne 0, 1 ou 2 selon le risque."""

from __future__ import annotations

import argparse
import math
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509


EXTENSIONS = {".pem", ".crt", ".cer", ".der"}
ALERTE = timedelta(days=30)
CRITIQUE = timedelta(days=7)


def _charger_certificats(path: Path) -> list[x509.Certificate]:
    data = path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in data:
        return list(x509.load_pem_x509_certificates(data))
    if (
        b"-----BEGIN X509 CRL-----" in data
        or b"-----BEGIN CRL-----" in data
    ):
        return []
    return [x509.load_der_x509_certificate(data)]


def _etat(expiration: datetime, maintenant: datetime) -> tuple[str, int, int]:
    restant = expiration - maintenant
    if restant.total_seconds() <= 0:
        return "CRITIQUE", 0, 2
    jours = math.ceil(restant.total_seconds() / 86400)
    if restant < CRITIQUE:
        return "CRITIQUE", jours, 2
    if restant < ALERTE:
        return "ALERTE", jours, 1
    return "OK", jours, 0


def surveiller(dossier: Path) -> int:
    if not dossier.is_dir():
        print(f"CRITIQUE: dossier introuvable: {dossier}", file=sys.stderr)
        return 2

    fichiers = sorted(
        path for path in dossier.rglob("*")
        if path.is_file() and path.suffix.lower() in EXTENSIONS
    )
    if not fichiers:
        print(f"CRITIQUE: aucun certificat trouve dans {dossier}", file=sys.stderr)
        return 2

    maintenant = datetime.now(timezone.utc)
    code_global = 0
    nombre = 0
    for path in fichiers:
        try:
            certificats = _charger_certificats(path)
            if not certificats:
                continue
        except Exception as exc:
            print(f"CRITIQUE: {path}: certificat illisible ({type(exc).__name__})")
            code_global = 2
            continue

        for index, certificat in enumerate(certificats, start=1):
            nombre += 1
            etat, jours, code = _etat(certificat.not_valid_after_utc, maintenant)
            code_global = max(code_global, code)
            numero = f" #{index}" if len(certificats) > 1 else ""
            print(
                f"{etat}: {path}{numero} - {jours} jour(s) restant(s), "
                f"expiration {certificat.not_valid_after_utc:%Y-%m-%d %H:%M UTC}"
            )

    return code_global if nombre else 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Surveille les dates de validite de certificats PEM et DER."
    )
    parser.add_argument("dossier", type=Path, help="dossier parcouru recursivement")
    args = parser.parse_args()
    return surveiller(args.dossier)


if __name__ == "__main__":
    raise SystemExit(main())
