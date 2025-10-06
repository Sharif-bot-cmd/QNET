#!/usr/bin/env bash
# 🌐 QNET Setup Script (cross-platform)
# Prepares environment by installing dependencies & tools.

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
# 3. Install IPFS, curl, wget
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
            echo "[!] Please install $pkg_name manually (Windows users: use WSL or Git Bash)."
        fi
    else
        echo "[✓] $pkg_name already installed."
    fi
}

for tool in ipfs curl wget; do
    install_pkg "$tool"
done

# -----------------------
# 4. Python dependencies
# -----------------------
echo "[i] Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip install --upgrade -r requirements.txt
else
    echo "[!] requirements.txt not found. Skipping Python dependency install."
fi

# -----------------------
# 5. Final check
# -----------------------
echo ""
echo "==============================================="
echo "✅ QNET setup complete!"
echo "Run your node using:  python3 qnet.py"
echo "-----------------------------------------------"
echo "📦 Installed tools: python3, pip, ipfs, curl, wget"
echo "==============================================="
