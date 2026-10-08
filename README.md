# Khimy

Chat chiffré de bout en bout (E2EE) en Rust, basé sur le protocole Signal.

## Ce que c'est

Khimy implémente les mêmes primitives cryptographiques que Signal utilise en production :

- **X3DH** pour l'établissement de session
- **Double Ratchet** pour le forward secrecy
- **ML-KEM-1024** (post-quantique) via `libsignal-protocol`
- Un **relay TCP aveugle** qui ne voit que des octets opaques
- **Persistance des sessions** sur disque
- **Messages hors-ligne** (stockage temporaire côté relay)
- **Notifications** (bip terminal + notification native macOS/Linux)

Le ciphertext fait ~1792 octets pour un message de 40 caractères.

## Installation

Automatique (recommandé) :

    bash <(curl -s https://raw.githubusercontent.com/iam-skb/Khimy/main/install.sh)

Le script installe Rust + protoc si nécessaire, clone le repo, compile et installe le binaire `khimy` dans `~/.cargo/bin/`.

## Utilisation

| Commande | Rôle |
|---|---|
| `khimy relay <addr>` | Lance un serveur relay (VPS) |
| `khimy connect` | Initie une conversation |
| `khimy listen` | Attend les messages |
| `khimy chat <addr> <nom> <dest>` | Variante non interactive |
| `khimy config` | Affiche la config |

## Exemple

Ton contact lance :

    khimy listen
    # Pseudo : marc

Toi tu lances :

    khimy connect
    # Ton pseudo   : skb
    # Destinataire : marc

Tape un message, il arrive chiffre chez `marc`. S'il repond, tu recois sa reponse.

## Messages hors-ligne

Si ton contact est absent, le relay stocke les ciphertexts (100 max, TTL 7 jours). A sa reconnexion, il recoit tout automatiquement.

## Securite

- Les cles privees ne quittent jamais la machine locale.
- Le relay ne peut pas dechiffrer les messages.
- Forward secrecy par Double Ratchet.
- Rotation pre-keys infinie.

Projet personnel, non audite. Pas une alternative a Signal.

## Licence

MIT
