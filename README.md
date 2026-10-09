# Khimy

Chat chiffre de bout en bout (E2EE) en Rust, base sur le protocole Signal.

## Ce que c'est

Khimy implemente les memes primitives cryptographiques que Signal utilise en production :

- **X3DH** pour l'etablissement de session
- **Double Ratchet** pour le forward secrecy
- **ML-KEM-1024** (post-quantique) via `libsignal-protocol`
- Un **relay TCP aveugle** qui ne voit que des octets opaques
- **Persistance des sessions** sur disque
- **Messages hors-ligne** (stockage temporaire cote relay)
- **Notifications** (bip terminal + notification native macOS/Linux)

Le ciphertext fait ~1792 octets pour un message de 40 caracteres.

## Installation

### Binaire precompile (recommande)

Telecharge la version pour ton systeme depuis la page Releases :

    https://github.com/iam-skb/Khimy/releases/latest

    macOS Intel    : khimy-macos-x86_64.tar.gz
    macOS ARM      : khimy-macos-aarch64.tar.gz
    Linux x86_64   : khimy-linux-x86_64.tar.gz

Puis :

    tar xzf khimy-macos-x86_64.tar.gz
    ./khimy connect

### Depuis les sources

Prerequis : Rust >= 1.80, `protoc` >= 28.

    git clone https://github.com/iam-skb/Khimy.git
    cd Khimy
    cargo build --release
    cp target/release/khimy ~/.cargo/bin/

### Script automatique

    bash <(curl -s https://raw.githubusercontent.com/iam-skb/Khimy/main/install.sh)

## Utilisation

| Commande | Role |
|---|---|
| `khimy relay <addr>` | Lance un serveur relay (VPS) |
| `khimy connect` | Initie une conversation |
| `khimy listen` | Attend les messages |
| `khimy chat <addr> <nom> <dest>` | Variante non interactive |
| `khimy config` | Affiche la config |
| `khimy tui` | Interface menu (squelette) |

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
