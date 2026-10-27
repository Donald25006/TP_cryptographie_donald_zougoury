"""Mini-coffre CFR1 : Argon2id, HKDF-SHA256 et AES-256-GCM."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


FORMAT_ID = b"CFR1"
HEADER = struct.Struct(">4sIII16s12s")
HEADER_SIZE = HEADER.size  # 44 octets
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16
MAX_TIME_COST = 10
MAX_MEMORY_KIB = 256 * 1024
MAX_PARALLELISM = 8


@dataclass(frozen=True)
class Argon2Params:
    """Parametres Argon2id : temps, memoire en Kio et parallelisme."""

    t: int
    m: int
    p: int


PARAMETRES_DEFAUT = Argon2Params(t=8, m=128 * 1024, p=4)


def _valider_parametres(params: Argon2Params) -> None:
    if not isinstance(params, Argon2Params):
        raise TypeError("parametres Argon2id invalides")
    if any(type(value) is not int for value in (params.t, params.m, params.p)):
        raise ValueError("parametres Argon2id invalides")
    if not (1 <= params.t <= MAX_TIME_COST):
        raise ValueError("parametres Argon2id hors limites")
    if not (1 <= params.p <= MAX_PARALLELISM):
        raise ValueError("parametres Argon2id hors limites")
    if not (8 * params.p <= params.m <= MAX_MEMORY_KIB):
        raise ValueError("parametres Argon2id hors limites")


def cle_maitresse(
    mot_de_passe: str,
    sel: bytes,
    params: Argon2Params = PARAMETRES_DEFAUT,
) -> bytes:
    """Derive une cle maitresse de 32 octets avec Argon2id."""
    if not isinstance(mot_de_passe, str) or not mot_de_passe:
        raise ValueError("mot de passe invalide")
    if not isinstance(sel, bytes) or len(sel) != SALT_SIZE:
        raise ValueError("le sel doit contenir 16 octets")
    _valider_parametres(params)
    return hash_secret_raw(
        secret=mot_de_passe.encode("utf-8"),
        salt=sel,
        time_cost=params.t,
        memory_cost=params.m,
        parallelism=params.p,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """Derive une sous-cle distincte par usage avec HKDF-SHA256."""
    if not isinstance(maitresse, bytes) or len(maitresse) != KEY_SIZE:
        raise ValueError("cle maitresse invalide")
    if not isinstance(usage, bytes) or not usage:
        raise ValueError("etiquette d'usage invalide")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=b"coffre-v1|" + usage,
    ).derive(maitresse)


def _nom_encode(nom: str) -> bytes:
    if not isinstance(nom, str) or not nom:
        raise ValueError("nom de fichier invalide")
    encoded = nom.encode("utf-8")
    if len(encoded) > 4096:
        raise ValueError("nom de fichier trop long")
    return encoded


def chiffrer(
    mot_de_passe: str,
    nom: str,
    donnees: bytes,
    *,
    params: Argon2Params = PARAMETRES_DEFAUT,
) -> bytes:
    """Chiffre les donnees et retourne en-tete || chiffre || etiquette."""
    if not isinstance(donnees, bytes):
        raise TypeError("les donnees doivent etre des octets")
    _valider_parametres(params)
    nom_bytes = _nom_encode(nom)
    sel = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    en_tete = HEADER.pack(FORMAT_ID, params.t, params.m, params.p, sel, nonce)
    cle = sous_cle(cle_maitresse(mot_de_passe, sel, params), b"fichier")
    chiffre_et_tag = AESGCM(cle).encrypt(nonce, donnees, en_tete + nom_bytes)
    return en_tete + chiffre_et_tag


def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    """Dechiffre CFR1. InvalidTag est propage si l'authentification echoue."""
    if not isinstance(blob, bytes) or len(blob) < HEADER_SIZE + TAG_SIZE:
        raise ValueError("fichier chiffre invalide")
    nom_bytes = _nom_encode(nom)
    format_id, t, m, p, sel, nonce = HEADER.unpack_from(blob)
    if format_id != FORMAT_ID:
        raise ValueError("format de fichier inconnu")
    params = Argon2Params(t=t, m=m, p=p)
    _valider_parametres(params)
    en_tete = blob[:HEADER_SIZE]
    cle = sous_cle(cle_maitresse(mot_de_passe, sel, params), b"fichier")
    return AESGCM(cle).decrypt(
        nonce,
        blob[HEADER_SIZE:],
        en_tete + nom_bytes,
    )


def rechiffrer(
    ancien_mdp: str,
    nouveau_mdp: str,
    nom: str,
    blob: bytes,
    nouveaux_parametres: Argon2Params = PARAMETRES_DEFAUT,
) -> bytes:
    """Dechiffre avec l'ancien secret et re-chiffre avec un nouveau sel/nonce."""
    clair = dechiffrer(ancien_mdp, nom, blob)
    return chiffrer(
        nouveau_mdp,
        nom,
        clair,
        params=nouveaux_parametres,
    )
