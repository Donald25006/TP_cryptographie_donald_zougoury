# TP EC1 - resolution

Ce depot rassemble une resolution des trois seances du TP EC1 : coffre de fichiers AEAD, infrastructure de gestion de cles, puis TLS avec authentification mutuelle et renouvellement.

## Fichiers

- coffre.py : format CFR1, derivation Argon2id et HKDF-SHA256, chiffrement AES-GCM, rechiffrement.
- test_coffre.py : tests de non-regression demandes pour le TP 1.
- pki/racine.cnf, pki/inter.cnf, pki/pki.sh : configurations et generation d'une IGC de laboratoire OpenSSL.
- tls/nginx.conf : exemple Nginx pour TLS 1.2/1.3 et mTLS.
- tls/surveiller.py, tls/test_surveiller.py : surveillance des expirations et verification avec un certificat de cinq jours.
- tls/renouveler.sh : renouvellement avec verification prealable, sauvegarde et retour arriere.
- Rapport_de_Résolution_TP_EC1.pdf : compte rendu detaille.

## Partie Python

Avec Python 3.10 ou plus recent :

    python -m pip install -r requirements.txt
    python -m pytest -q
    python tls/test_surveiller.py

Le format CFR1 contient un en-tete de 44 octets : identifiant, parametres Argon2id en entiers non signes big-endian, sel de 16 octets et nonce de 12 octets. Le nom logique du fichier est ajoute a l'en-tete dans les donnees associees.

## IGC et TLS

La partie OpenSSL et Nginx cible une machine Linux avec OpenSSL 3 et Nginx. Depuis le depot :

    bash pki/pki.sh

Le script demande les phrases secretes des deux autorites sans les afficher. Il produit des cles locales ignorees par Git et des certificats/CRL publics de laboratoire. Les cles privees, CSR, bases CA et numeros de serie sont exclus du depot.

La configuration Nginx suppose que les certificats et CRL ont ete installes sous /etc/nginx/tls. Il faut adapter les chemins et verifier nginx -t avant le rechargement.

Pour tls/renouveler.sh, fournir le repertoire TLS, le repertoire PKI et une source OpenSSL protegee pour la phrase secrete de l'intermediaire, par exemple file:/run/credentials/renew/inter-passphrase. Le script conserve une sauvegarde datee avant de remplacer les fichiers.

Les sorties dependantes de la machine (suite negociee, groupe ECDHE, details de Nginx et certificats emis) doivent etre relevees sur la machine Linux de laboratoire. 

# TP_cryptographie_donald_zougoury
