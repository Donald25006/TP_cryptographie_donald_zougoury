# Annexe B du sujet : profils de certificats

`racine.cnf` et `inter.cnf` reproduisent les fichiers de configuration fournis dans le sujet. Les profils de demonstration propres a la solution sont conserves dans `profils_supplementaires.cnf`.

## Profil `ext_inter` (AC intermediaire)

| Directive | Rôle |
| --- | --- |
| `basicConstraints = critical,CA:TRUE,pathlen:0` | Déclare une autorité de certification. L'extension est critique et `pathlen:0` interdit à l'intermédiaire de signer une autre AC. |
| `keyUsage = critical,keyCertSign,cRLSign` | Autorise la signature de certificats et de listes de révocation (CRL). |
| `nameConstraints = critical,permitted;DNS:.tp.local,permitted;DNS:tp.local,permitted;email:tp.local` | Limite la chaîne aux sous-domaines DNS de `tp.local`, au nom DNS exact `tp.local` et aux adresses du domaine de courriel `tp.local`. |
| `subjectKeyIdentifier = hash` | Calcule l'identifiant de la clé publique de ce certificat, utilisé pour reconnaître cette AC. |
| `authorityKeyIdentifier = keyid` | Identifie la clé de l'AC émettrice à l'aide de son identifiant de clé. |

## Profil `ext_serveur` (certificat serveur)

| Directive | Rôle |
| --- | --- |
| `basicConstraints = critical,CA:FALSE` | Marque le certificat comme certificat terminal, et non comme AC. |
| `keyUsage = critical,digitalSignature` | Limite l'usage de la clé à la signature numérique requise pour TLS avec la clé EC du TP. |
| `extendedKeyUsage = serverAuth` | Réserve ce certificat à l'authentification d'un serveur TLS. |
| `subjectKeyIdentifier = hash` | Fournit l'identifiant calculé de la clé publique du serveur. |
| `authorityKeyIdentifier = keyid` | Relie le certificat à l'identifiant de la clé de l'intermédiaire émettrice. |

Le profil ne contient pas de directive `subjectAltName`. Conformément à l'annexe, `inter.cnf` utilise `copy_extensions = copy` : le SAN DNS demandé dans la CSR est alors repris dans le certificat. L'AC doit vérifier ce nom avant de signer.

## Profil `ext_client` (certificat client)

| Directive | Rôle |
| --- | --- |
| `basicConstraints = critical,CA:FALSE` | Marque le certificat comme certificat terminal. |
| `keyUsage = critical,digitalSignature` | Autorise la signature numérique utilisée pour l'authentification TLS du client. |
| `extendedKeyUsage = clientAuth` | Réserve le certificat à l'authentification d'un client TLS. |
| `subjectAltName = email:alice@tp.local` | Porte l'identité courriel d'Alice que l'application peut vérifier. |
| `subjectKeyIdentifier = hash` | Fournit l'identifiant calculé de la clé publique du client. |
| `authorityKeyIdentifier = keyid` | Relie le certificat à l'identifiant de la clé de l'intermédiaire émettrice. |

## Correction apportée au rapport

La phrase de la première version du rapport qui attribuait `copy_extensions = none` à l'AC intermédiaire est remplacée par la configuration de l'annexe B : `copy_extensions = copy`. La configuration de l'AC racine conserve `none`, comme dans l'annexe. Les profils Bob et hors périmètre sont séparés pour ne pas modifier les fichiers fournis.
