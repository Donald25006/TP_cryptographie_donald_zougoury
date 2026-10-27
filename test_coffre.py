import pytest
from cryptography.exceptions import InvalidTag

from coffre import (
    Argon2Params,
    PARAMETRES_DEFAUT,
    chiffrer,
    dechiffrer,
    rechiffrer,
)


MOT_DE_PASSE = "Une phrase secrete assez longue pour le test"
NOM = "notes.txt"
DONNEES = b"Contenu confidentiel du coffre."


def test_aller_retour():
    blob = chiffrer(MOT_DE_PASSE, NOM, DONNEES)
    assert dechiffrer(MOT_DE_PASSE, NOM, blob) == DONNEES


def test_deux_chiffrements_sont_differents():
    premier = chiffrer(MOT_DE_PASSE, NOM, DONNEES)
    second = chiffrer(MOT_DE_PASSE, NOM, DONNEES)
    assert premier != second


def test_mauvais_mot_de_passe_est_rejete():
    blob = chiffrer(MOT_DE_PASSE, NOM, DONNEES)
    with pytest.raises(InvalidTag):
        dechiffrer("mauvais mot de passe", NOM, blob)


def test_modification_du_chiffre_est_rejetee():
    blob = bytearray(chiffrer(MOT_DE_PASSE, NOM, DONNEES))
    blob[44] ^= 1
    with pytest.raises(InvalidTag):
        dechiffrer(MOT_DE_PASSE, NOM, bytes(blob))


def test_renommage_est_rejete_par_les_donnees_associees():
    blob = chiffrer(MOT_DE_PASSE, NOM, DONNEES)
    with pytest.raises(InvalidTag):
        dechiffrer(MOT_DE_PASSE, "autre_nom.txt", blob)


def test_rechiffrement_change_le_secret_et_les_parametres():
    blob = chiffrer(MOT_DE_PASSE, NOM, DONNEES)
    params_plus_forts = Argon2Params(
        t=PARAMETRES_DEFAUT.t + 1,
        m=PARAMETRES_DEFAUT.m,
        p=PARAMETRES_DEFAUT.p,
    )
    migre = rechiffrer(
        MOT_DE_PASSE,
        "nouvelle phrase secrete encore plus longue",
        NOM,
        blob,
        nouveaux_parametres=params_plus_forts,
    )
    assert dechiffrer(
        "nouvelle phrase secrete encore plus longue",
        NOM,
        migre,
    ) == DONNEES
    with pytest.raises(InvalidTag):
        dechiffrer(MOT_DE_PASSE, NOM, migre)

\n