# TP EC1 - Solution détaillée et réponses

Ce README rassemble la démarche, les choix d'implémentation et les réponses aux questions de réflexion des trois séances. Les fichiers Python, PKI et TLS cités ci-dessous contiennent les implémentations correspondantes.

## Contenu du dépôt

- `coffre.py`, `test_coffre.py` : coffre CFR1, dérivation Argon2id/HKDF, chiffrement AES-GCM et tests de propriétés.
- `pki/racine.cnf`, `pki/inter.cnf` : configurations reproduites depuis l'annexe B du sujet.
- `pki/profils_supplementaires.cnf` : profils de démonstration pour Bob et pour le certificat hors périmètre.
- `pki/pki.sh` : création de l'IGC, des certificats, des CRL, validation et révocation.
- `pki/annexe_b.md` : explication ligne par ligne des extensions demandées.
- `tls/nginx.conf` : serveur TLS avec authentification mutuelle.
- `tls/surveiller.py`, `tls/test_surveiller.py` : surveillance d'expiration et test d'un certificat valable cinq jours.
- `tls/renouveler.sh`, `tls/renouveler.service`, `tls/renouveler.timer` : renouvellement vérifié et planification quotidienne systemd.
- `tls/laboratoire.md` : commandes d'installation, de connexion et de capture à exécuter sur Linux.

## Préparer l'environnement

Les étapes Python demandent Python 3.10 ou plus récent. Les étapes PKI et TLS demandent Linux, OpenSSL 3, Nginx et, pour l'inventaire des suites, Nmap.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
python tls/test_surveiller.py
openssl version
```

Les phrases secrètes d'AC sont saisies sans affichage par `pki/pki.sh`. Les clés privées, les CSR et les bases locales de l'AC ne doivent pas être ajoutées au dépôt.

# TP 1 - Chiffrement authentifié et dérivation de clés

## Conception et format CFR1

`coffre.py` stocke les informations nécessaires pour redériver la clé, puis authentifie l'en-tête et le nom du fichier avec AES-GCM.

| Champ | Taille | Rôle |
| --- | ---: | --- |
| Identifiant `CFR1` | 4 octets | Reconnaître le format. |
| `t`, `m`, `p` Argon2id | 12 octets | Relire les coûts temps, mémoire et parallélisme utilisés. |
| Sel | 16 octets | Dériver une clé propre à chaque fichier. |
| Nonce | 12 octets | Initialiser AES-GCM pour ce chiffrement. |
| Chiffré et tag | Variable | Contenu protégé et étiquette d'authentification de 16 octets. |

Les entiers de l'en-tête sont encodés en big-endian. Les 44 premiers octets suivis du nom UTF-8 constituent les données associées : ils ne sont pas chiffrés, mais toute modification est détectée au déchiffrement.

`cle_maitresse` utilise Argon2id et produit 32 octets. `sous_cle` applique HKDF-SHA256 avec `info = b"coffre-v1|" + usage`; cette étiquette sépare les clés selon leur usage. Le chiffrement tire un nouveau sel et un nouveau nonce avec `os.urandom`. Avant d'appeler Argon2id, le lecteur valide l'identifiant et borne `t`, `m` et `p`, afin qu'un en-tête hostile ne puisse pas imposer un coût arbitraire.

Sur la machine Windows 11 de préparation, des mesures avec `time.perf_counter` ont donné une médiane de 0,071 s pour `t=3, m=65536 Kio, p=4` (trois mesures), puis 0,497 s pour `t=10, m=131072 Kio, p=4` (deux mesures). Cette dernière combinaison est la valeur par défaut de `coffre.py`; il faut remesurer sur la machine Linux cible.

`rechiffrer` déchiffre avec l'ancien mot de passe et les paramètres stockés dans le blob, puis chiffre avec le nouveau mot de passe, un nouveau sel et un nouveau nonce. Les anciens fichiers restent lisibles grâce aux paramètres de leur en-tête. Un changement incompatible de structure ou d'algorithme demanderait un nouvel identifiant de format.

## Tests de sécurité

`test_coffre.py` couvre les cinq propriétés demandées et le rechiffrement :

| Cas | Résultat attendu | Propriété démontrée |
| --- | --- | --- |
| Aller-retour | Les octets récupérés sont identiques au clair. | Correction du chiffrement/déchiffrement. |
| Deux chiffrements identiques en entrée | Les blobs diffèrent. | Sel et nonce neufs. |
| Mauvais mot de passe | `InvalidTag`. | Authentification de la clé. |
| Chiffré modifié | `InvalidTag`. | Intégrité. |
| Blob renommé | `InvalidTag`. | Liaison au nom par les données associées. |
| Rechiffrement | Le nouveau mot de passe fonctionne et l'ancien échoue. | Migration du secret et des paramètres. |

## Questions de réflexion

1. **Pourquoi le sel est-il stocké en clair?** Le sel n'est pas un secret. Il rend la dérivation propre à chaque fichier et empêche l'emploi direct de tables précalculées. La sécurité dépend du mot de passe et du coût d'Argon2id, pas du secret du sel.
2. **Pourquoi le nonce de 96 bits ne risque-t-il pas de se répéter sous la même clé?** Chaque fichier reçoit un sel aléatoire, donc une clé dérivée différente, sauf collision de sel. GCM exige l'unicité du nonce par clé, pas entre toutes les clés. Pour un million de sels aléatoires de 128 bits, la probabilité de collision est d'environ `1,5 × 10^-27`.
3. **Que se passerait-il si le nom n'était pas authentifié?** Un attaquant pourrait déplacer ou renommer le blob et faire traiter son contenu dans un autre contexte, par exemple charger une configuration sous un nom réservé à des autorisations.
4. **Pourquoi authentifier l'en-tête?** Sans lui dans les données associées, l'attaquant pourrait modifier version ou paramètres sans invalider le tag. Cela pourrait rendre le fichier illisible, exploiter une configuration faible ou provoquer un coût de calcul excessif. Les bornes de paramètres restent nécessaires, car elles sont appliquées avant la vérification du tag.
5. **Pourquoi l'application doit-elle afficher une erreur générique?** Distinguer mauvais mot de passe, tag invalide, format corrompu ou paramètres refusés peut fournir un oracle à l'attaquant. L'interface doit donner un seul message de rejet; les détails peuvent rester dans des journaux internes protégés.

# TP 2 - Infrastructure de gestion de clés

## Hiérarchie et profils

| Élément | Clé et durée | Rôle et extensions |
| --- | --- | --- |
| AC racine | EC P-384, 10 ans | Auto-signée, conservée hors ligne; `CA:TRUE,pathlen:1`, signature de certificats et de CRL. |
| AC intermédiaire | EC P-256, 5 ans | Signataire des certificats terminaux; `CA:TRUE,pathlen:0`, contraintes DNS et courriel vers `tp.local`. |
| Serveur | EC P-256, 90 jours | `CA:FALSE`, `serverAuth`, SAN `www.tp.local` et `tp.local`. |
| Client | EC P-256, 90 jours | `CA:FALSE`, `clientAuth`, SAN `alice@tp.local` ou `bob@tp.local`. |

Les fichiers `racine.cnf` et `inter.cnf` reprennent l'annexe B. La racine a `copy_extensions = none`. L'intermédiaire a `copy_extensions = copy`, conformément au sujet : comme `ext_serveur` ne définit pas de SAN, le SAN demandé dans la CSR est repris. Cela ne vérifie pas l'identité du demandeur; l'AC doit contrôler chaque nom avant de signer. Les profils additionnels de démonstration sont conservés dans un troisième fichier pour ne pas modifier les deux configurations fournies.

### Rôle de chaque ligne d'extension de l'annexe B

**`ext_inter` - certificat de l'autorité intermédiaire :**

- `basicConstraints = critical,CA:TRUE,pathlen:0` : marque le certificat comme AC; `critical` oblige les validateurs à comprendre la contrainte, et `pathlen:0` interdit de créer une AC subordonnée.
- `keyUsage = critical,keyCertSign,cRLSign` : autorise la signature des certificats et des CRL, et restreint les autres usages de la clé.
- `nameConstraints = critical,permitted;DNS:.tp.local,permitted;DNS:tp.local,permitted;email:tp.local` : n'autorise que les sous-domaines DNS `.tp.local`, le nom DNS exact `tp.local`, et les adresses du domaine courriel `tp.local` dans les certificats de la chaîne.
- `subjectKeyIdentifier = hash` : calcule un identifiant de clé à partir de la clé publique de l'intermédiaire.
- `authorityKeyIdentifier = keyid` : identifie la clé de l'AC émettrice, ici la racine.

**`ext_serveur` - certificat serveur :**

- `basicConstraints = critical,CA:FALSE` : indique que le certificat est terminal et ne peut pas signer d'autres certificats.
- `keyUsage = critical,digitalSignature` : limite la clé à la signature numérique TLS appropriée à la clé EC du TP.
- `extendedKeyUsage = serverAuth` : autorise l'authentification comme serveur TLS.
- `subjectKeyIdentifier = hash` : calcule l'identifiant de la clé publique du serveur.
- `authorityKeyIdentifier = keyid` : relie le certificat à la clé de l'intermédiaire qui l'a signé.

Le profil serveur n'a pas de directive `subjectAltName`. Le SAN DNS demandé dans sa CSR est copié par `copy_extensions = copy`; l'AC doit vérifier que le demandeur contrôle ces noms avant émission.

**`ext_client` - certificat client :**

- `basicConstraints = critical,CA:FALSE` : indique que le certificat est terminal.
- `keyUsage = critical,digitalSignature` : autorise la signature numérique utilisée pour l'authentification du client.
- `extendedKeyUsage = clientAuth` : réserve le certificat à l'authentification d'un client TLS.
- `subjectAltName = email:alice@tp.local` : porte l'identité courriel d'Alice que le service peut vérifier.
- `subjectKeyIdentifier = hash` : calcule l'identifiant de la clé publique du client.
- `authorityKeyIdentifier = keyid` : relie le certificat à la clé de l'intermédiaire émettrice.

Le script initialise les bases et les dossiers `certs`, `crl` et `newcerts`, avec le numéro 1000 pour la racine et 2000 pour l'intermédiaire. Il génère la racine P-384, l'intermédiaire P-256, les certificats feuille, les CRL, puis vérifie les cas valides et invalides. Les extensions de la racine sont passées à `openssl req -addext`, car l'annexe ne fournit pas de profil `ext_root`.

```sh
bash pki/pki.sh
```

Le script doit être lancé sur Linux avec OpenSSL 3. Il refuse d'écraser une base d'AC ou des clés déjà présentes. Dans une vraie exploitation, la clé racine est créée et utilisée lors d'une cérémonie hors ligne.

## Émission, validation et révocation

Le certificat serveur contient le SAN DNS de sa CSR et est émis par l'intermédiaire. Le certificat Alice est émis avec `clientAuth`; l'intermédiaire révoque ensuite Alice pour `keyCompromise`, puis génère sa CRL et celle de la racine. Un certificat Bob de remplacement est émis et vérifié avec les deux CRL.

Les validations attendues sont :

- `www.tp.local` et `alice@tp.local` sont acceptés pour leurs usages respectifs;
- le certificat serveur vérifié sous le nom `autre.example` est refusé;
- un certificat pour `www.example.com` peut être signé, car l'AC signe une demande selon le profil choisi, mais la chaîne est refusée par le vérificateur à cause de `nameConstraints`;
- Bob est accepté après publication des CRL et Alice est marquée révoquée par `-crl_check_all`.

Les certificats publics sont produits localement par le script. Les clés privées, CSR et bases d'émission restent locales et ignorées par Git.

## Questions de réflexion

1. **Pourquoi la racine reste-t-elle hors ligne? Que faire en cas de compromission?** La racine peut créer ou remplacer toute autorité de la hiérarchie; la garder hors ligne réduit fortement son exposition. Si l'intermédiaire est compromis, l'arrêter, le révoquer avec la racine, publier la CRL, créer un nouvel intermédiaire et réémettre les certificats terminaux. Si la racine est compromise, la confiance est perdue : créer une nouvelle racine, la distribuer par un canal de confiance, retirer l'ancienne et réémettre toute la chaîne.
2. **À quoi sert `pathlen:0`?** Il autorise l'intermédiaire à signer des certificats terminaux, mais pas une autre AC. Sans cette limite, une AC compromise pourrait déléguer l'émission et étendre la hiérarchie.
3. **Pourquoi le serveur génère-t-il sa clé privée?** La clé reste sur le serveur; seule la CSR est envoyée à l'AC. La clé ne circule pas et l'AC n'en possède pas de copie.
4. **Le CN ou le SAN est-il vérifié par les clients modernes?** Le SAN est l'identité utilisée pour vérifier le nom d'hôte. Le CN peut rester informatif, mais ne remplace pas un SAN correct.
5. **Quelles sont les limites d'une CRL?** Une CRL peut devenir volumineuse et son état est périmé entre deux publications. OCSP fournit un état ciblé et souvent plus récent, mais ajoute un service et une latence, révèle des informations de consultation au répondeur et dépend de sa disponibilité. Des certificats très courts réduisent la fenêtre d'exposition, mais imposent un renouvellement automatique et surveillé.
6. **Quelle politique minimale adopter?** (1) Réserver l'émission aux services inscrits à l'inventaire. (2) Faire approuver la demande par le propriétaire du service. (3) Vérifier les noms par contrôle DNS ou validation humaine. (4) Faire générer la clé par le demandeur. (5) Vérifier la signature et les champs de la CSR. (6) N'émettre que des profils serveur ou client approuvés. (7) Limiter les certificats terminaux à 90 jours. (8) Conserver la racine chiffrée hors ligne et protéger la clé intermédiaire. (9) Révoquer rapidement une clé compromise et publier les CRL. (10) Journaliser émissions, renouvellements et révocations et vérifier l'inventaire régulièrement.

Dans un certificat racine auto-signé, l'émetteur et le sujet sont identiques parce que la racine signe son propre certificat. La signature vérifie l'intégrité du certificat, mais la confiance provient de l'installation explicite de cette racine chez le client.

# TP 3 - Canal TLS et cycle de vie des certificats

## Configuration Nginx

`tls/nginx.conf` configure TLS 1.2/1.3 et mTLS. Les directives principales ont les rôles suivants :

| Directive | Justification |
| --- | --- |
| `ssl_certificate` | Présente le certificat serveur suivi de l'intermédiaire; la racine n'est pas envoyée. |
| `ssl_certificate_key` | Utilise la clé privée locale du serveur. |
| `ssl_protocols TLSv1.2 TLSv1.3` | Refuse les versions antérieures à TLS 1.2. |
| `ssl_prefer_server_ciphers off` | Laisse le choix des suites au client dans la négociation TLS 1.2. |
| `ssl_ciphers ...` | Pour TLS 1.2, limite aux suites ECDHE-ECDSA avec AES-GCM ou ChaCha20-Poly1305 : échange éphémère et chiffrement authentifié. |
| `ssl_session_tickets off` | Évite les tickets dont les clés ne sont pas gérées et renouvelées. |
| `ssl_client_certificate` | Indique la racine qui sert à vérifier les certificats clients. |
| `ssl_verify_client on` | Rend obligatoire le certificat client. |
| `ssl_verify_depth 2` | Limite la profondeur de la chaîne client à racine, intermédiaire et feuille. |
| `ssl_crl` | Refuse les certificats révoqués présents dans les CRL. |
| `Strict-Transport-Security` | Demande au navigateur de privilégier HTTPS pendant un an après réception. |
| `$ssl_client_s_dn` | Affiche le sujet du client authentifié dans la réponse de démonstration. |

`ssl_ciphers` règle les suites TLS 1.2 dans cette configuration; les suites TLS 1.3 sont gérées séparément par OpenSSL. La directive HSTS ne contient pas `includeSubDomains`; elle ne couvre donc pas les sous-domaines.

## Poignée de main et vérifications à effectuer

Le client envoie `ClientHello` avec ses versions, suites, aléa et clé éphémère. Le serveur répond `ServerHello` avec la suite choisie et sa clé éphémère. Les deux côtés dérivent les secrets de session. En TLS 1.3, les messages suivants, dont le certificat serveur et `CertificateVerify`, sont chiffrés; une capture passive sans secrets de session ne montre pas le certificat en clair. En TLS 1.2, le certificat est normalement visible.

Les commandes pour installer le certificat, vérifier Bob, essayer une connexion sans certificat, retester Alice révoquée, refuser TLS 1.1, énumérer les suites et capturer le trafic sont dans [`tls/laboratoire.md`](tls/laboratoire.md). Les versions, suites, groupes ECDHE et paquets Wireshark dépendent de l'exécution sur le serveur Linux et doivent être consignés à partir des sorties réelles.

## Surveillance et renouvellement

`tls/surveiller.py` parcourt les fichiers PEM et DER du dossier fourni. Il affiche chaque certificat et son nombre de jours restants : `OK` à partir de 30 jours, `ALERTE` sous 30 jours, `CRITIQUE` sous 7 jours ou après expiration. Les codes de sortie sont 0, 1 et 2 selon le risque maximal. Un certificat illisible ou un dossier sans certificat est critique.

`tls/test_surveiller.py` construit temporairement un certificat valable cinq jours et vérifie qu'il est classé `CRITIQUE` avec le code 2. Il vérifie également qu'une CRL PEM n'est pas prise pour un certificat.

`tls/renouveler.sh` quitte sans changement s'il reste plus de 30 jours. Sinon, il génère une nouvelle clé et une CSR, demande la signature à l'intermédiaire, vérifie chaîne, nom d'hôte, usage et correspondance entre clé/certificat, sauvegarde les fichiers courants, installe les nouveaux fichiers, exécute `nginx -t` et recharge Nginx. En cas d'erreur au déploiement, il restaure la sauvegarde.

`tls/renouveler.timer` lance ce contrôle chaque jour. Le service fournit la phrase de l'intermédiaire avec les credentials systemd (`LoadCredential`), sans mettre le secret dans l'unité ni dans le dépôt. Adapter les chemins `/etc/nginx/tls` et `/opt/tp-ec1/pki` du service à la machine, puis suivre les commandes d'installation dans `tls/laboratoire.md`.

## Questions de réflexion

1. **Pourquoi le serveur n'envoie-t-il pas la racine?** Le client doit déjà posséder la racine dans son magasin de confiance. La transmettre ne crée pas cette confiance; le serveur envoie son certificat et les intermédiaires nécessaires pour construire le chemin.
2. **Pourquoi désactiver les tickets de session?** Les tickets sont protégés avec une clé côté serveur. Si cette clé n'est pas renouvelée, sa fuite peut prolonger le risque de reprise de session. On les désactive tant que leurs clés ne sont pas correctement gérées et tournées.
3. **Que garantit HSTS?** Après réception, le navigateur utilise HTTPS pendant la durée demandée et évite les retours vers HTTP qui faciliteraient une attaque de rétrogradation ou un SSL stripping. Le premier contact n'est pas protégé par HSTS sauf si le domaine est préchargé.
4. **Qu'impliquent les durées publiques de 100 jours en 2027 puis 47 jours en 2029 indiquées dans le sujet?** Un renouvellement manuel augmente le risque d'oubli et d'indisponibilité. Il faut un inventaire fiable, des alertes, une automatisation et une procédure de retour arrière.
5. **Pourquoi certains clients acceptent-ils une chaîne incomplète?** Certains ont déjà l'intermédiaire en cache ou savent le récupérer; d'autres ne l'ont pas et échouent. Le serveur doit fournir la feuille et les intermédiaires nécessaires.
6. **Que faire si la clé du serveur fuit?** Isoler la machine et prévenir l'AC, révoquer le certificat, générer une nouvelle paire sur un système sain, faire signer et vérifier un nouveau certificat, déployer la chaîne, publier les CRL, invalider les sessions/tickets concernés et enquêter sur l'incident avant d'informer les parties touchées.

## Contrôles et limites

Les commandes de reproduction sont listées dans les sections ci-dessus. Les opérations qui exigent un vrai serveur — résultat de `nginx -t`, négociation TLS, refus du certificat révoqué, scan Nmap et capture Wireshark — doivent être exécutées sur la machine Linux de laboratoire; les valeurs observées ne sont pas remplacées par des exemples fictifs.
