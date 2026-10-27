#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 3 ]]; then
    echo "Usage: $0 <dossier-tls> <dossier-pki> <source-openssl-passin>" >&2
    echo "Exemple du troisieme argument: file:/run/credentials/renew/inter-passphrase" >&2
    exit 2
fi

TLS_DIR=$1
PKI_DIR=$2
INTER_CA_PASSIN=$3
THRESHOLD=$((30 * 24 * 60 * 60))
CURRENT_KEY="$TLS_DIR/serveur.key"
CURRENT_CHAIN="$TLS_DIR/serveur_chaine.crt"

if [[ -z "$INTER_CA_PASSIN" ]]; then
    echo "Une source protegee pour la phrase de l'AC intermediaire est requise." >&2
    exit 2
fi
if [[ ! -r "$CURRENT_KEY" || ! -r "$CURRENT_CHAIN" ]]; then
    echo "Certificat/cle courants introuvables sous $TLS_DIR." >&2
    exit 1
fi
openssl x509 -in "$CURRENT_CHAIN" -noout >/dev/null
if openssl x509 -in "$CURRENT_CHAIN" -noout -checkend "$THRESHOLD" >/dev/null 2>&1; then
    echo "Renouvellement ignore: plus de 30 jours de validite."
    exit 0
fi

umask 077
STAGE=$(mktemp -d "$TLS_DIR/.renouvellement.XXXXXX")
mkdir -p "$TLS_DIR/backup"
chmod 700 "$TLS_DIR/backup"
BACKUP_DIR=$(mktemp -d "$TLS_DIR/backup/$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
cp -p "$CURRENT_KEY" "$BACKUP_DIR/serveur.key"
cp -p "$CURRENT_CHAIN" "$BACKUP_DIR/serveur_chaine.crt"

NEW_KEY="$STAGE/serveur.key"
NEW_CSR="$STAGE/serveur.csr"
NEW_CERT="$STAGE/serveur.crt"
NEW_CHAIN="$STAGE/serveur_chaine.crt"
DEPLOY_STARTED=0

rollback() {
    local status=$?
    trap - ERR
    if [[ "$DEPLOY_STARTED" == "1" ]]; then
        set +e
        install -m 600 "$BACKUP_DIR/serveur.key" "$CURRENT_KEY"
        install -m 644 "$BACKUP_DIR/serveur_chaine.crt" "$CURRENT_CHAIN"
        if nginx -t; then
            systemctl reload nginx
        fi
        set -e
    fi
    rm -rf "$STAGE"
    exit "$status"
}
trap rollback ERR

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$NEW_KEY"
openssl req -new -key "$NEW_KEY" -subj "/CN=www.tp.local" \
    -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out "$NEW_CSR"

# Les chemins de la configuration CA sont relatifs au repertoire PKI.
pushd "$PKI_DIR" >/dev/null
openssl ca -batch -config inter.cnf -passin "$INTER_CA_PASSIN" \
    -extensions ext_serveur -days 90 -in "$NEW_CSR" -out "$NEW_CERT"
popd >/dev/null

cat "$NEW_CERT" "$PKI_DIR/inter/inter.crt" > "$NEW_CHAIN"
openssl verify -CAfile "$PKI_DIR/racine/racine.crt" \
    -untrusted "$PKI_DIR/inter/inter.crt" \
    -verify_hostname www.tp.local -purpose sslserver "$NEW_CERT"

CERT_PUBLIC_KEY=$(openssl x509 -in "$NEW_CERT" -pubkey -noout |
    openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)
KEY_PUBLIC_KEY=$(openssl pkey -in "$NEW_KEY" -pubout -outform DER |
    sha256sum | cut -d' ' -f1)
[[ "$CERT_PUBLIC_KEY" == "$KEY_PUBLIC_KEY" ]]

install -m 600 "$NEW_KEY" "$TLS_DIR/serveur.key.next"
install -m 644 "$NEW_CHAIN" "$TLS_DIR/serveur_chaine.crt.next"
DEPLOY_STARTED=1
mv -f "$TLS_DIR/serveur.key.next" "$CURRENT_KEY"
mv -f "$TLS_DIR/serveur_chaine.crt.next" "$CURRENT_CHAIN"
nginx -t
systemctl reload nginx

trap - ERR
rm -rf "$STAGE"
echo "Renouvellement deploye. Ancienne chaine et ancienne cle sauvegardees dans $BACKUP_DIR."

\n