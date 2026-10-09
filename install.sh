#!/usr/bin/env bash
# Script d'installation de Khimy.
# Usage : bash install.sh
set -e

REPO_URL="https://github.com/iam-skb/Khimy.git"
REPO_DIR="${HOME}/Projets/khimy"
BIN_DIR="${HOME}/.cargo/bin"

echo ""
echo "=== Installation de Khimy ==="
echo ""

# 1. Detecter l'OS
OS="$(uname -s)"
echo "[1/5] OS detecte : $OS"

# 2. Verifier / installer Rust
echo "[2/5] Verification de Rust..."
if ! command -v cargo >/dev/null 2>&1; then
    echo "    Rust absent. Installation..."
    if [ "$OS" = "Darwin" ] || [ "$OS" = "Linux" ]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s 
-- -y
        # shellcheck disable=SC1091
        source "${HOME}/.cargo/env"
    else
        echo "    OS non supporte pour l'installation automatique de 
Rust."
        echo "    Installe Rust manuellement : https://rustup.rs/"
        exit 1
    fi
else
    echo "    Rust present : $(cargo --version)"
fi

# 3. Verifier / installer protoc
echo "[3/5] Verification de protoc..."
if ! command -v protoc >/dev/null 2>&1; then
    echo "    protoc absent. Installation..."
    if [ "$OS" = "Darwin" ]; then
        if command -v brew >/dev/null 2>&1; then
            brew install protobuf
        else
            echo "    Homebrew absent. Installe brew d'abord : 
https://brew.sh/"
            exit 1
        fi
    elif [ "$OS" = "Linux" ]; then
        if command -v apt >/dev/null 2>&1; then
            sudo apt update
            sudo apt install -y protobuf-compiler build-essential
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y protobuf-compiler gcc
        elif command -v pacman >/dev/null 2>&1; then
            sudo pacman -S --noconfirm protobuf base-devel
        else
            echo "    Gestionnaire de paquets inconnu."
            echo "    Installe protoc manuellement : 
https://grpc.io/docs/protoc-installation/"
            exit 1
        fi
    fi
else
    echo "    protoc present : $(protoc --version)"
fi

# 4. Cloner ou mettre a jour le repo
echo "[4/5] Recuperation du code..."
if [ -d "${REPO_DIR}/.git" ]; then
    echo "    Repo deja present, mise a jour..."
    cd "${REPO_DIR}"
    git pull --ff-only || true
else
    if [ -d "${REPO_DIR}" ]; then
        echo "    Dossier ${REPO_DIR} existe mais n'est pas un repo git."
        echo "    Supprime-le ou deplace-le, puis relance."
        exit 1
    fi
    mkdir -p "$(dirname "${REPO_DIR}")"
    git clone "${REPO_URL}" "${REPO_DIR}"
    cd "${REPO_DIR}"
fi

# 5. Compiler et installer
echo "[5/5] Compilation (5-10 min)..."
cargo build --release

echo "    Installation du binaire dans ${BIN_DIR}..."
mkdir -p "${BIN_DIR}"
cp target/release/khimy "${BIN_DIR}/khimy"
chmod +x "${BIN_DIR}/khimy"

# Verifier que BIN_DIR est dans le PATH
if ! echo "${PATH}" | grep -q "${BIN_DIR}"; then
    echo ""
    echo "ATTENTION : ${BIN_DIR} n'est pas dans ton PATH."
    echo "Ajoute cette ligne a ton ~/.zshrc ou ~/.bashrc :"
    echo ""
    echo "    export PATH=\"\$HOME/.cargo/bin:\$PATH\""
    echo ""
    echo "Puis relance ton terminal."
    echo ""
fi

echo ""
echo "=== Installation terminee ! ==="
echo ""
echo "Commandes disponibles :"
echo ""
echo "    khimy                             # interface TUI (recommande)"
echo "    khimy relay <addr>                # serveur (sur VPS)"
echo "    khimy connect                     # mode texte : initier"
echo "    khimy listen                      # mode texte : attendre"
echo "    khimy config                      # voir la config"
echo ""
echo "Pour discuter avec un ami :"
echo ""
echo "    khimy"
echo "    Relay        : 78.232.48.151:9000"
echo "    Ton pseudo   : ton_nom"
echo "    Destinataire : son_nom"
echo ""
