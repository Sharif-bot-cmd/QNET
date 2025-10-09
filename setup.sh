#!/usr/bin/env bash
# 🌐 QNET Setup Script (Hybrid Node 1.2+)
# Installs dependencies for any architecture or OS (Linux, Termux, macOS, WSL)

echo "==============================================="
echo "     QNET Environment Setup (Universal Node)"
echo "==============================================="

# Detect OS & ARCH
OS=$(uname | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
echo "[i] Detected OS: $OS"
echo "[i] Detected Arch: $ARCH"

# Normalize arch names
case "$ARCH" in
  arm64|aarch64) ARCH="arm64" ;;
  x86_64|amd64)  ARCH="amd64" ;;
  i*86)           ARCH="386" ;;
  *) echo "[!] Unknown architecture ($ARCH), defaulting to amd64."; ARCH="amd64";;
esac

# -----------------------
# 1. Python & Pip
# -----------------------
if ! command -v python3 &>/dev/null; then
    echo "[!] Python3 not found. Please install Python 3.10+ manually."
    exit 1
fi

if ! command -v pip3 &>/dev/null; then
    echo "[i] Installing pip..."
    if [[ "$OS" == *"android"* ]]; then
        pkg install -y python-pip
    elif [[ "$OS" == *"linux"* ]]; then
        sudo apt update && sudo apt install -y python3-pip
    elif [[ "$OS" == *"darwin"* ]]; then
        brew install python
    else
        echo "[!] Please install pip manually for Windows/WSL."
    fi
fi

# -----------------------
# 2. Helper packages
# -----------------------
install_pkg() {
    pkg_name=$1
    if ! command -v "$pkg_name" &>/dev/null; then
        echo "[i] Installing $pkg_name..."
        if [[ "$OS" == *"android"* ]]; then
            pkg install -y "$pkg_name"
        elif [[ "$OS" == *"linux"* ]]; then
            sudo apt update && sudo apt install -y "$pkg_name"
        elif [[ "$OS" == *"darwin"* ]]; then
            brew install "$pkg_name"
        else
            echo "[!] Please install $pkg_name manually."
        fi
    else
        echo "[✓] $pkg_name already installed."
    fi
}

for tool in curl wget unzip tar; do
    install_pkg "$tool"
done

# -----------------------
# 3. Install IPFS (Kubo)
# -----------------------
if ! command -v ipfs &>/dev/null; then
    echo "[i] Installing IPFS (Kubo)..."
    IPFS_VERSION="v0.31.0"
    FILE="kubo_${IPFS_VERSION}_linux-${ARCH}.tar.gz"

    # macOS fix
    if [[ "$OS" == *"darwin"* ]]; then
        FILE="kubo_${IPFS_VERSION}_darwin-${ARCH}.tar.gz"
    fi

    URL="https://dist.ipfs.tech/kubo/${IPFS_VERSION}/${FILE}"
    echo "[i] Downloading from: $URL"
    wget -q "$URL" -O kubo.tar.gz || { echo "[!] Download failed"; exit 1; }

    tar -xzf kubo.tar.gz && cd kubo && sudo bash install.sh && cd ..
    ipfs init || true
    echo "[✓] IPFS installed successfully."
else
    echo "[✓] IPFS already installed."
fi

# -----------------------
# 4. Install Cloudflared
# -----------------------
if ! command -v cloudflared &>/dev/null; then
    echo "[i] Installing Cloudflared..."
    FILE="cloudflared-linux-${ARCH}"

    if [[ "$OS" == *"darwin"* ]]; then
        FILE="cloudflared-darwin-${ARCH}"
    fi

    curl -L "https://github.com/cloudflare/cloudflared/releases/latest/download/${FILE}" -o cloudflared
    chmod +x cloudflared && sudo mv cloudflared /usr/local/bin/
    echo "[✓] Cloudflared installed successfully."
else
    echo "[✓] Cloudflared already installed."
fi

# -----------------------
# 5. Install Ngrok
# -----------------------
if ! command -v ngrok &>/dev/null; then
    echo "[i] Installing Ngrok..."
    if [[ "$OS" == *"linux"* ]] || [[ "$OS" == *"android"* ]]; then
        curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
        echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list
        sudo apt update && sudo apt install -y ngrok
    elif [[ "$OS" == *"darwin"* ]]; then
        brew install ngrok/ngrok/ngrok
    fi
    echo "[✓] Ngrok installed successfully."
    echo "[!] Run: ngrok config add-authtoken <YOUR_TOKEN> after setup."
else
    echo "[✓] Ngrok already installed."
fi

# -----------------------
# 6. Python Dependencies
# -----------------------
echo "[i] Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip3 install --upgrade -r requirements.txt
else
    echo "[!] requirements.txt not found. Skipping Python dependencies."
fi

# -----------------------
# 7. Final summary
# -----------------------
echo ""
echo "==============================================="
echo "✅ QNET setup complete!"
echo "Run your node using:  python3 qnet.py"
echo "-----------------------------------------------"
echo "📦 Installed tools:"
echo "  - Python3 + pip"
echo "  - IPFS (Kubo ${IPFS_VERSION})"
echo "  - Cloudflared"
echo "  - Ngrok"
echo "  - curl, wget, unzip, tar"
echo "==============================================="
