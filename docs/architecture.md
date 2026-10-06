# Architecture de Khimy

## Vue d'ensemble

Khimy est un chat chiffré de bout en bout composé de deux programmes :

- **`khimy relay`** : un serveur TCP qui route les messages entre clients.
- **`khimy chat`** : un client qui chiffre, envoie, reçoit et déchiffre.

Le relay est **aveugle** : il ne possède aucune clé, ne peut pas déchiffrer les messages, et ne voit 
que des octets opaques (le ciphertext Signal).

## Flux d'un message

Alice Relay Bob
│ │ │
│── PreKeyBundle ───────▶│◀──── PreKeyBundle ────│
│ │ │
│── demande bundle Bob ─▶│ │
│◀── bundle de Bob ──────│ │
│ │ │
│ (établit session X3DH) │ │
│ │ │
│── ciphertext ─────────▶│─── ciphertext ───────▶│
│ │ │
│ │ (déchiffre
│ │ avec X3DH
│ │ + Double Ratchet)
text


## Modules

| Module | Rôle |
|---|---|
| `main.rs` | Point d'entrée, parse les arguments, dispatch vers `relay` ou `chat` |
| `keys.rs` | Génération des clés Signal (identity, signed pre-key, kyber, 100 one-time) + persistance 
sur disque |
| `session.rs` | Enveloppe les fonctions libsignal : `process_prekey_bundle`, `message_encrypt`, 
`message_decrypt_*` |
| `network.rs` | Framing TCP (u32 BE + payload), sérialisation custom du PreKeyBundle |
| `relay.rs` | Serveur multi-thread, annuaire de bundles, waiting list, routage |
| `client.rs` | Client TCP : publish, request, send, recv |
| `stores.rs` | Conteneur `InMemoryStores` (5 HashMaps sous Mutex) |
| `stores_wrappers.rs` | Implémentation des 5 traits libsignal |
| `persist.rs` | Sérialise sessions et identités sur disque |

## Protocole réseau

### Framing

Chaque message TCP est préfixé par sa longueur en **u32 big-endian** :

[4 octets : longueur N] [N octets : payload]
text


Taille max : 1 MiB.

### Enveloppe

Le payload est une enveloppe :

[1 octet : type]
[4 octets : longueur dest][dest UTF-8]
[4 octets : longueur payload][payload]
text


**Types :**
- `0x01` : `BUNDLE_REQUEST` — demande le bundle d'un utilisateur
- `0x02` : `BUNDLE` — publication ou envoi d'un PreKeyBundle
- `0x03` : `CIPHERTEXT` — message chiffré

### Sérialisation du PreKeyBundle

libsignal n'expose pas de `serialize()` public pour `PreKeyBundle`. Khimy utilise un format wire 
custom (registration_id, device_id, pre_key, signed_pre_key, kyber_pre_key, identity_key).

## Persistance

Chaque utilisateur a un dossier `~/.khimy/<nom>/` :

| Fichier | Contenu |
|---|---|
| `keys.bin` | Identity key, registration ID, signed pre-key, kyber pre-key, 100 one-time pre-keys |
| `sessions.bin` | Sessions Signal actives (`SessionRecord` sérialisés) |
| `identities.bin` | Identités distantes (nom.device_id → IdentityKey) |

Ces fichiers permettent de **reprendre une session après redémarrage** sans refaire le handshake X3DH.

## Crypto

- **X3DH** : établissement de session
- **Double Ratchet** : forward secrecy
- **ML-KEM-1024** : post-quantique, hybride avec X25519
- **Ed25519** : signatures des pre-keys

Le ciphertext résultant fait ~1792 octets minimum.

## Limites connues

- Pas de rotation automatique des pre-keys
- Pas de messages hors-ligne (si Bob est déconnecté, le message est perdu)
- Le relay ne fait aucune authentification
- Pas de chiffrement des fichiers de session sur disque
- Un seul device par utilisateur (device_id = 1)
- Pas d'interopérabilité avec Signal (format wire custom)
