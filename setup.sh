#!/usr/bin/env bash
# 🌐 QNET Setup Script (Hybrid Node 1.1+)
# Prepares environment by installing Python dependencies, IPFS, Cloudflared, and Ngrok.

echo "==============================================="
echo "     QNET Environment Setup (Hybrid Node)"
echo "==============================================="

# Detect platform
OS=$(uname | tr '[:upper:]' '[:lower:]')
echo "[i] Detected platform: $OS"

# -----------------------
# 1. Check Python
# -----------------------
if ! command -v python3 &>/dev/null; then
    echo "[!] Python3 not found. Please install Python 3.10+ manually."
    exit 1
fi

# -----------------------
# 2. Check pip
# -----------------------
if ! command -v pip3 &>/dev/null; then
    echo "[i] Installing pip..."
    if [[ "$OS" == *"linux"* ]] || [[ "$OS" == *"android"* ]]; then
        apt update && apt install -y python3-pip
    elif [[ "$OS" == *"darwin"* ]]; then
        brew install python3
    else
        echo "[!] Please install pip manually for Windows."
    fi
fi

# -----------------------
# 3. Install helper packages (curl, wget, unzip)
# -----------------------
install_pkg() {
    pkg_name=$1
    if ! command -v "$pkg_name" &>/dev/null; then
        echo "[i] Installing $pkg_name..."
        if [[ "$OS" == *"android"* ]]; then
            apt install -y "$pkg_name"
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

for tool in curl wget unzip; do
    install_pkg "$tool"
done

# -----------------------
# 4. Install IPFS (Kubo)
# -----------------------
if ! command -v ipfs &>/dev/null; then
    echo "[i] Installing IPFS (Kubo)..."
    IPFS_VERSION="v0.31.0"
    wget -q "https://dist.ipfs.tech/kubo/${IPFS_VERSION}/kubo_${IPFS_VERSION}_linux-amd64.tar.gz" -O kubo.tar.gz
    tar -xzf kubo.tar.gz && cd kubo && sudo bash install.sh && cd ..
    ipfs init || true
    echo "[✓] IPFS installed successfully."
else
    echo "[✓] IPFS already installed."
fi

# -----------------------
# 5. Install Cloudflared
# -----------------------
if ! command -v cloudflared &>/dev/null; then
    echo "[i] Installing Cloudflared..."
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared
    chmod +x cloudflared && sudo mv cloudflared /usr/local/bin/
    echo "[✓] Cloudflared installed successfully."
else
    echo "[✓] Cloudflared already installed."
fi

# -----------------------
# 6. Install Ngrok
# -----------------------
if ! command -v ngrok &>/dev/null; then
    echo "[i] Installing Ngrok..."
    curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
    echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list
    sudo apt update && sudo apt install -y ngrok
    echo "[✓] Ngrok installed successfully."
    echo "[!] Run: ngrok config add-authtoken <YOUR_TOKEN> after setup."
else
    echo "[✓] Ngrok already installed."
fi

# -----------------------
# 7. Python dependencies
# -----------------------
echo "[i] Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip3 install --upgrade -r requirements.txt
else
    echo "[!] requirements.txt not found. Skipping Python dependency install."
fi

# -----------------------
# 8. Final check
# -----------------------
echo ""
echo "==============================================="
echo "✅ QNET setup complete!"
echo "Run your node using:  python3 qnet.py"
echo "-----------------------------------------------"
echo "📦 Installed tools:"
echo "  - Python3 + pip"
echo "  - IPFS (Kubo)"
echo "  - Cloudflared"
echo "  - Ngrok"
echo "  - curl, wget, unzip"
echo "==============================================="
