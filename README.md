# Khimy

[![tests](https://github.com/iam-skb/Khimy/actions/workflows/test.yml/badge.svg)](https://github.com/iam-skb/Khimy/actions/workflows/test.yml)

Chat chiffre de bout en bout (E2EE) en Rust — X3DH + Double Ratchet + ML-KEM-1024.

## Installation

### Binaire precompile (recommande)

Telecharge depuis la page Releases :

    https://github.com/iam-skb/Khimy/releases/latest

    macOS ARM    : khimy-macos-aarch64.tar.gz
    macOS Intel  : khimy-macos-x86_64.tar.gz
    Linux x86_64 : khimy-linux-x86_64.tar.gz

Puis :

    tar xzf khimy-macos-aarch64.tar.gz
    ./khimy

### Depuis les sources

Prerequis : Rust >= 1.80, `protoc` >= 28.

    git clone https://github.com/iam-skb/Khimy.git
    cd Khimy
    cargo build --release
    ./target/release/khimy

Pour l'installer dans ton PATH :

    cargo install --path .

### Script automatique

    bash <(curl -s https://raw.githubusercontent.com/iam-skb/Khimy/main/install.sh)

## Demarrage en 3 etapes

**1. Lance un relay** (le serveur qui fait passer les messages, aveugle) :

    khimy relay 0.0.0.0:9000

**2. Toi, lance Khimy** :

    khimy

Puis reponds :

- `Relay` : l'adresse de ton relay (ex: `127.0.0.1:9000` ou `78.232.48.151:9000`)
- `Ton pseudo` : ton nom (ex: `alice`)
- `Destinataire` : le pseudo de ton contact (ex: `bob`)

**3. Ton contact fait pareil** (meme relay, pseudo different) :

    khimy
    # Relay        : 78.232.48.151:9000
    # Ton pseudo   : bob
    # Destinataire : alice

Vous etes dans le TUI. Tapez vos messages. C'est chiffre.

> Attention : le destinataire doit etre connecte au meme relay, sinon tu auras un message « X n'est pas connecte ». Demande-lui de lancer `khimy` de son cote.

## Toutes les commandes

| Commande | Role |
|---|---|
| `khimy` | Lance l'interface (TUI). Recommande. |
| `khimy relay <addr>` | Lance un serveur relay (a faire sur un VPS ou en local). |
| `khimy tui` | Identique a `khimy`. |
| `khimy connect` | Mode texte : initie une conversation. |
| `khimy listen` | Mode texte : attend les messages. |
| `khimy chat <relay> <moi> <dest>` | Mode non-interactif (scripts). |
| `khimy config` | Affiche la config actuelle. |

## Commandes dans le TUI

Une fois dans l'interface, tape ces commandes dans la zone de saisie :

| Commande | Role |
|---|---|
| `/to <nom>` | Change de destinataire sans quitter l'app. |
| `/help` | Affiche la liste des commandes. |
| `/status` | Affiche ton pseudo, ton relay, ton destinataire. |
| `/clear` | Efface l'historique affiche. |
| `/banner` | Re-affiche le banner KHIMY. |
| `/quit` | Quitte. |
| `Ctrl+C` | Quitte aussi. |

## Statuts des messages

A droite de tes messages envoyes :

| Symbole | Signification |
|---|---|
| `check` | Envoye au relay. |
| `check check` gris | Recu par ton contact. |
| `check check` bleu | Lu par ton contact (TUI ouvert). |

## Messages hors-ligne

Si ton contact est absent, le relay stocke jusqu'a 100 messages pendant 7 jours. A sa reconnexion, il les recoit automatiquement.

## Historique local

Tes messages sont sauvegardes dans `~/.khimy/<pseudo>/messages.json`. Tu les retrouves au redemarrage.

## Securite

- Les cles privees ne quittent jamais ta machine.
- Le relay ne peut pas lire tes messages.
- Forward secrecy (Double Ratchet).
- Post-quantique (ML-KEM-1024).

Projet personnel, non audite. Pas une alternative a Signal.

## Auteur

Projet cree et developpe par **iam-skb**.

    GitHub : https://github.com/iam-skb

## Licence

MIT
