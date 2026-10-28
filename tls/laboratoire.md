# Vérifications du TP 3 sur Linux

Les résultats de négociation et la capture réseau dépendent du serveur de laboratoire. Cette fiche donne les commandes à exécuter et les observations à reporter; elle ne remplace pas une capture réelle.

## Installer et démarrer Nginx

Après génération de l'IGC avec `bash pki/pki.sh`, installer les fichiers de laboratoire :

```sh
sudo install -d -m 700 /etc/nginx/tls
sudo install -m 600 pki/inter/serveur.key /etc/nginx/tls/serveur.key
sudo install -m 644 pki/inter/serveur_chaine.crt pki/racine/racine.crt pki/crls.pem /etc/nginx/tls/
sudo install -m 644 tls/nginx.conf /etc/nginx/conf.d/tp-ec1.conf
echo '127.0.0.1 www.tp.local' | sudo tee -a /etc/hosts
sudo nginx -t
sudo systemctl reload nginx
```

Adapter le chemin du fichier de configuration au paquet Nginx de la distribution. Le certificat serveur doit être suivi de l'intermédiaire dans `serveur_chaine.crt`; la racine reste dans le magasin client et n'est pas envoyée par le serveur.

## Authentification mutuelle et révocation

Depuis la racine du dépôt, tester Bob, l'absence de certificat client, puis Alice révoquée :

```sh
openssl s_client -connect www.tp.local:443 -servername www.tp.local \
  -verify_hostname www.tp.local -CAfile pki/racine/racine.crt \
  -cert pki/inter/bob.crt -key pki/inter/bob.key \
  -cert_chain pki/inter/inter.crt -brief

openssl s_client -connect www.tp.local:443 -servername www.tp.local \
  -CAfile pki/racine/racine.crt -brief

openssl s_client -connect www.tp.local:443 -servername www.tp.local \
  -verify_hostname www.tp.local -CAfile pki/racine/racine.crt \
  -cert pki/inter/alice.crt -key pki/inter/alice.key \
  -cert_chain pki/inter/inter.crt -brief

curl --cacert pki/racine/racine.crt --cert pki/inter/bob.crt \
  --key pki/inter/bob.key https://www.tp.local/
```

Bob doit être accepté, le client sans certificat doit être refusé et Alice doit échouer en raison de la révocation. Relever la version TLS, la suite, le groupe d'échange et la ligne de vérification dans la sortie réelle.

## Version et suites TLS

```sh
openssl s_client -connect www.tp.local:443 -servername www.tp.local -tls1_1 -brief
nmap --script ssl-enum-ciphers -p 443 www.tp.local
```

TLS 1.1 doit échouer. Vérifier que les suites TLS 1.2 proposées utilisent ECDHE et un chiffrement AEAD. Les suites TLS 1.3 sont négociées séparément par OpenSSL.

## Capture Wireshark

Sur le serveur de laboratoire, démarrer une capture de la boucle locale, lancer une connexion TLS depuis un autre terminal, puis arrêter la capture :

```sh
sudo tcpdump -i lo -s 0 -w tls-ec1.pcap 'tcp port 443'
```

Ouvrir `tls-ec1.pcap` dans Wireshark et filtrer avec `tcp.port == 443`. Repérer `ClientHello` et `ServerHello`. En TLS 1.3, le certificat du serveur est transmis après `ServerHello`, dans la partie chiffrée de la poignée de main; il n'est donc pas lisible dans une capture sans secrets de session.

À conserver avec le compte rendu : la capture issue du serveur utilisé, les sorties de commandes ci-dessus et les versions TLS/suite/groupe observées. Ne pas remplacer ces observations par des exemples inventés.

## Minuteur quotidien de renouvellement

Les unités `tls/renouveler.service` et `tls/renouveler.timer` déclenchent le script chaque jour. Avant installation, adapter dans le service les chemins TLS et PKI à la machine. Le fichier de phrase secrète de l'intermédiaire doit être lisible uniquement par root et reste hors du dépôt; `LoadCredential` le fournit au script sans inscrire son contenu dans l'unité.

```sh
sudo install -m 755 tls/renouveler.sh /usr/local/sbin/tls-renouveler.sh
sudo install -m 644 tls/renouveler.service tls/renouveler.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now renouveler.timer
systemctl list-timers renouveler.timer
```

Le minuteur lance le contrôle quotidien; le script ne renouvelle que lorsqu'il reste moins de 30 jours, puis vérifie la chaîne, teste Nginx, recharge le service et conserve une sauvegarde pour retour arrière.
