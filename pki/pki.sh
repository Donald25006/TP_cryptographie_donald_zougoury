#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

command -v openssl >/dev/null
openssl version | grep -Eq '^OpenSSL 3\.'
if [[ -e racine/racine.key || -e inter/inter.key || -e racine/index.txt || -e inter/index.txt ]]; then
    echo "Etat PKI existant detecte; refuse d'ecraser les cles ou la base CA." >&2
    exit 1
fi

umask 077
mkdir -p racine/certs racine/crl racine/newcerts inter/certs inter/crl inter/newcerts
: > racine/index.txt
: > inter/index.txt
printf '1000\n' > racine/serial
printf '1000\n' > racine/crlnumber
printf '2000\n' > inter/serial
printf '2000\n' > inter/crlnumber

read -r -s -p "Phrase secrete de l'AC racine : " ROOT_CA_PASSPHRASE
printf '\n'
read -r -s -p "Phrase secrete de l'AC intermediaire : " INTER_CA_PASSPHRASE
printf '\n'
if [[ -z "$ROOT_CA_PASSPHRASE" || -z "$INTER_CA_PASSPHRASE" ]]; then
    echo "Les deux phrases secretes sont obligatoires." >&2
    exit 1
fi
export ROOT_CA_PASSPHRASE INTER_CA_PASSPHRASE

# Racine P-384, auto-signee, dix ans. Sa cle doit ensuite rester hors ligne.
# Le profil ext_root n'est pas dans l'annexe B : ses extensions sont donnees ici.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
    -aes-256-cbc -pass env:ROOT_CA_PASSPHRASE -out racine/racine.key
openssl req -new -x509 -key racine/racine.key \
    -passin env:ROOT_CA_PASSPHRASE -sha384 -days 3650 \
    -subj "/C=BF/O=Universite TP/CN=Racine TP" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -addext "authorityKeyIdentifier=keyid:always" \
    -out racine/racine.crt

# Intermediaire P-256, signee par la racine, avec pathlen:0 et nameConstraints.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -aes-256-cbc -pass env:INTER_CA_PASSPHRASE -out inter/inter.key
openssl req -new -key inter/inter.key -passin env:INTER_CA_PASSPHRASE \
    -subj "/C=BF/O=Universite TP/CN=Intermediaire TP" \
    -out inter/inter.csr
openssl ca -batch -config racine.cnf -passin env:ROOT_CA_PASSPHRASE \
    -extensions ext_inter -days 1825 -in inter/inter.csr -out inter/inter.crt

# Certificat de serveur www.tp.local.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/serveur.key
openssl req -new -key inter/serveur.key -subj "/CN=www.tp.local" \
    -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out inter/serveur.csr
openssl ca -batch -config inter.cnf -passin env:INTER_CA_PASSPHRASE \
    -extensions ext_serveur -days 90 -in inter/serveur.csr -out inter/serveur.crt
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
    -verify_hostname www.tp.local -purpose sslserver inter/serveur.crt
if openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
    -verify_hostname autre.example inter/serveur.crt; then
    echo "ERREUR: le mauvais nom d'hote a ete accepte." >&2
    exit 1
fi

# Certificat d'Alice, qui sera revoque apres la demonstration.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/alice.key
openssl req -new -key inter/alice.key -subj "/CN=alice@tp.local" \
    -addext "subjectAltName=email:alice@tp.local" -out inter/alice.csr
openssl ca -batch -config inter.cnf -passin env:INTER_CA_PASSPHRASE \
    -extensions ext_client -days 90 -in inter/alice.csr -out inter/alice.crt
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
    -purpose sslclient inter/alice.crt

# L'AC peut signer hors de son perimetre; le validateur doit rejeter la chaine.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/hors_scope.key
openssl req -new -key inter/hors_scope.key -subj "/CN=www.example.com" \
    -addext "subjectAltName=DNS:www.example.com" -out inter/hors_scope.csr
openssl ca -batch -config inter.cnf -passin env:INTER_CA_PASSPHRASE \
    -extensions ext_serveur_hors_scope -days 90 \
    -extfile profils_supplementaires.cnf \
    -in inter/hors_scope.csr -out inter/hors_scope.crt
if output=$(openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
    -verify_hostname www.example.com inter/hors_scope.crt 2>&1); then
    echo "ERREUR: un certificat hors perimetre a ete accepte." >&2
    exit 1
fi
if ! grep -qi "permitted subtree" <<< "$output"; then
    printf '%s\n' "$output" >&2
    echo "Echec inattendu pendant le test des contraintes de nom." >&2
    exit 1
fi
printf 'Rejet attendu par les contraintes de nom : %s\n' "$output"

# Alice est revoquee pour compromission; Bob obtient un certificat de remplacement.
openssl ca -config inter.cnf -passin env:INTER_CA_PASSPHRASE \
    -revoke inter/alice.crt -crl_reason keyCompromise
openssl ca -config inter.cnf -passin env:INTER_CA_PASSPHRASE \
    -gencrl -out inter/crl/inter.crl
openssl ca -config racine.cnf -passin env:ROOT_CA_PASSPHRASE \
    -gencrl -out racine/crl/racine.crl
cat inter/crl/inter.crl racine/crl/racine.crl > crls.pem

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/bob.key
openssl req -new -key inter/bob.key -subj "/CN=bob@tp.local" \
    -addext "subjectAltName=email:bob@tp.local" -out inter/bob.csr
openssl ca -batch -config inter.cnf -passin env:INTER_CA_PASSPHRASE \
    -extfile profils_supplementaires.cnf -extensions ext_client_bob \
    -days 90 -in inter/bob.csr -out inter/bob.crt
openssl verify -crl_check_all -CRLfile crls.pem \
    -CAfile racine/racine.crt -untrusted inter/inter.crt \
    -purpose sslclient inter/bob.crt
if openssl verify -crl_check_all -CRLfile crls.pem \
    -CAfile racine/racine.crt -untrusted inter/inter.crt \
    -purpose sslclient inter/alice.crt; then
    echo "ERREUR: le certificat revoque d'Alice a ete accepte." >&2
    exit 1
fi

cat inter/serveur.crt inter/inter.crt > inter/serveur_chaine.crt
echo "IGC generee. Les fichiers .key et .csr sont locaux et ignores par Git."
