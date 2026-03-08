#!/bin/bash
# AutoRecon v2.0 — Tool Installation Script
# Supports: Kali, Parrot, Ubuntu, macOS
set -e

echo "╔═══════════════════════════════════════════╗"
echo "║   AutoRecon v2.0 — Tool Installer         ║"
echo "╚═══════════════════════════════════════════╝"
echo ""

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    PKG="brew"
    echo "[*] Detected macOS — using Homebrew"
elif command -v apt-get &>/dev/null; then
    PKG="apt"
    echo "[*] Detected Debian/Ubuntu/Kali/Parrot — using apt"
else
    echo "[!] Unsupported OS. Install tools manually."
    exit 1
fi

echo ""
echo "[1/6] Installing system packages..."
if [ "$PKG" = "apt" ]; then
    sudo apt-get update -qq
    sudo apt-get install -y nmap gobuster whatweb amass whois dnsutils curl git golang-go python3-pip 2>/dev/null || true
elif [ "$PKG" = "brew" ]; then
    brew install nmap gobuster whatweb amass whois go python3 2>/dev/null || true
fi

echo ""
echo "[2/6] Installing Python tools..."
pip3 install theHarvester wafw00f 2>/dev/null || pip install theHarvester wafw00f --break-system-packages 2>/dev/null || true

export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$GOPATH/bin:$PATH"

echo ""
echo "[3/6] Installing Go-based tools..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || echo "  [!] subfinder failed"
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || echo "  [!] nuclei failed"
go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || echo "  [!] httpx failed"
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || echo "  [!] dnsx failed"
go install github.com/sensepost/gowitness@latest 2>/dev/null || echo "  [!] gowitness failed"

echo ""
echo "[4/6] Installing testssl.sh..."
if ! command -v testssl.sh &>/dev/null; then
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh 2>/dev/null || true
    sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh 2>/dev/null || true
fi

echo ""
echo "[5/6] Updating nuclei templates..."
nuclei -update-templates 2>/dev/null || echo "  [!] Could not update templates"

echo ""
echo "[6/6] Setting up data directory..."
mkdir -p ~/.autorecon/output

echo ""
echo "═══════════════════════════════════════════"
echo " Tool Status Check"
echo "═══════════════════════════════════════════"
for tool in nmap subfinder amass httpx nuclei gobuster whatweb gowitness wafw00f dnsx testssl.sh whois; do
    if command -v "$tool" &>/dev/null; then
        echo "  ✓ $tool — $(which $tool)"
    else
        echo "  ✗ $tool — NOT FOUND"
    fi
done

echo ""
echo "[+] Setup complete! Run ./start.sh to launch AutoRecon."
