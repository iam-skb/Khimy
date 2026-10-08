cat > ~/Projets/khimy/README.md << 'KHIMY_EOF'
# Khimy

Chat chiffré de bout en bout (E2EE) en Rust, basé sur le protocole Signal.

![Khimy en action](docs/screenshot.png)

## Ce que c'est

Khimy est un chat E2EE qui implémente les mêmes primitives cryptographiques que Signal utilise en production :

- **X3DH** pour l'établissement de session
- **Double Ratchet** pour le forward secrecy
- **ML-KEM-1024** (post-quantique) via `libsignal-protocol`
- Un **relay TCP aveugle** qui ne voit que des octets opaques
- **Persistance des sessions** sur disque
- **Messages hors-ligne** (stockage temporaire côté relay)
- **Notifications** (bip terminal + notification native macOS/Linux)
- **Multi-utilisateurs simultanés** (plusieurs pairs peuvent contacter le même destinataire)

Le ciphertext fait ~1792 octets pour un message de 40 caractères : header ratchet + signatures + padding + encapsulation ML-KEM.

## Installation

**Prérequis :** Rust ≥ 1.80, `protoc` ≥ 28.

### Automatique (recommandé)

```bash
bash <(curl -s https://raw.githubusercontent.com/iam-skb/Khimy/main/install.sh)


Le script installe Rust + protoc si nécessaire, clone le repo, compile et installe khimy dans ~/.cargo/bin/khimy.
Manuelle
bash
# macOS
brew install protobuf

# Ubuntu / Debian
sudo apt install protobuf-compiler

# Clone + build
git clone https://github.com/iam-skb/Khimy.git
cd Khimy
cargo build --release
cp target/release/khimy ~/.cargo/bin/
Utilisation
Khimy a 5 commandes :


Commande	Rôle
khimy relay <addr>	Lance un serveur relay (sur un VPS)
khimy connect	Initie une conversation avec un destinataire connu
khimy listen	Attend les messages de n'importe qui
khimy chat <addr> <nom> <dest>	Variante non interactive
khimy config	Affiche la config actuelle
Configuration
Au premier connect ou listen, Khimy te demande :
* Relay : adresse du serveur (mémorisée)
* Pseudo : ton identifiant (mémorisé)
Ces valeurs sont stockées dans ~/.khimy/config.toml et réutilisées par défaut.
Exemple : discuter avec un ami
Ton pote lance :
bash
khimy listen
# Relay   : 78.232.48.151:9000
# Pseudo  : marc
Toi tu lances :
bash
khimy connect
# Relay        : 78.232.48.151:9000
# Ton pseudo   : skb
# Destinataire : marc
Tape un message, il arrive chiffré chez marc. S'il répond, tu reçois sa réponse.
Messages hors-ligne
Si tu écris à quelqu'un qui n'est pas connecté, le relay stocke le ciphertext (jusqu'à 100 messages par utilisateur, TTL 7 jours). À sa reconnexion, ton contact reçoit automatiquement tous les messages en attente.
Commandes en mode listen


Commande	Effet
/to <nom>	Définit le destinataire courant
/quit	Quitter
<texte>	Envoyer au dernier expéditeur (ou destinataire courant)
Architecture
text
┌─────────┐         ┌──────────────┐         ┌─────────┐
│  Alice  │ ──────▶ │    Relay     │ ──────▶ │   Bob   │
│  chat   │  TCP    │  (aveugle)   │  TCP    │  chat   │
└─────────┘         └──────────────┘         └─────────┘
     │                                              │
     │◀──── X3DH + Double Ratchet (E2EE) ──────────▶│
     │                                              │
     └─ Le relay route les octets mais ne peut ─────┘
        jamais les déchiffrer
Détails complets dans docs/architecture.md.
Stack
* Rust (edition 2024)
* libsignal-protocol (cœur crypto Signal officiel)
* tokio (async runtime)
* prost (protobuf interne)
* rand (aléa cryptographique)
* X25519 (échange de clés)
* Ed25519 (signatures)
* ML-KEM-1024 (post-quantique)
Structure du projet


Fichier	Rôle
main.rs	CLI relay / chat / connect / listen / config
keys.rs	Génération et persistance des clés Signal
config.rs	Fichier ~/.khimy/config.toml
session.rs	X3DH + Double Ratchet (via libsignal)
network.rs	Framing TCP + sérialisation PreKeyBundle
relay.rs	Serveur relay + annuaire + stockage hors-ligne
client.rs	Client TCP
stores.rs + stores_wrappers.rs	5 vues libsignal
persist.rs	Persistance sessions + identités
notify.rs	Notifications (terminal + OS)
Sécurité
* Les clés privées ne quittent jamais la machine locale.
* Seuls les PreKeyBundle publics et les CiphertextMessage transitent sur le réseau.
* Le relay ne peut pas déchiffrer les messages (il ne possède aucune clé).
* Les sessions sont persistées dans ~/.khimy/<nom>/ et survivent aux redémarrages.
* Forward secrecy assuré par le Double Ratchet.
* Rotation des pre-keys infinie (le bundle n'embarque pas de one-time pre-key).
⚠️ Cette version est un projet personnel, pas une alternative à Signal. Elle n'a pas été auditée. Ne l'utilisez pas pour des communications sensibles.
Déploiement d'un relay
Sur un VPS (Ubuntu 24.04) :
bash
# Installation
apt update && apt install -y protobuf-compiler build-essential git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Clone + build
git clone https://github.com/iam-skb/Khimy.git
cd Khimy
cargo build --release

# Test
./target/release/khimy relay 0.0.0.0:9000
Service systemd (/etc/systemd/system/khimy-relay.service) :
ini
[Unit]
Description=Khimy E2EE Relay
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/Khimy
ExecStart=/root/Khimy/target/release/khimy relay 0.0.0.0:9000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
bash
systemctl daemon-reload
systemctl enable khimy-relay
systemctl start khimy-relay
systemctl status khimy-relay
N'oublie pas d'ouvrir le port 9000 dans le firewall de ton VPS.
État du projet
* ☑ Génération des clés Signal (X25519, Ed25519, ML-KEM-1024)
* ☑ X3DH + Double Ratchet
* ☑ Relay TCP aveugle + annuaire + pseudos uniques
* ☑ Persistance sessions + identités
* ☑ Chat E2EE bidirectionnel
* ☑ Fichier de configuration
* ☑ Mode listen (attente de messages)
* ☑ Messages d'erreur propres
* ☑ Notifications
* ☑ Rotation pre-keys infinie
* ☑ Messages hors-ligne
* ☑ Script d'installation
* □ Interface graphique
* □ Multi-device
* □ Chiffrement des fichiers de session sur disque
* □ Tests unitaires
* □ TLS pour la couche TCP
* □ Interopérabilité Signal
Licence
MIT KHIMY_EOF
