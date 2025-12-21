#!/bin/bash
# SecretHunter Installation Script for Linux/WSL/macOS
# This script installs all dependencies required for SecretHunter

set -e

echo "============================================================"
echo "SecretHunter - Installation Script"
echo "============================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}Note: Some installations may require sudo privileges${NC}"
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    echo -e "${GREEN}✓ Detected: Linux${NC}"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    echo -e "${GREEN}✓ Detected: macOS${NC}"
else
    echo -e "${RED}✗ Unsupported OS: $OSTYPE${NC}"
    exit 1
fi

echo ""
echo "[1/5] Updating package manager..."
if [ "$OS" == "linux" ]; then
    sudo apt update
elif [ "$OS" == "macos" ]; then
    brew update
fi

echo ""
echo "[2/5] Installing system dependencies..."
if [ "$OS" == "linux" ]; then
    sudo apt install -y python3 python3-pip python3-venv yara libyara-dev git wget
elif [ "$OS" == "macos" ]; then
    brew install python yara git wget
fi

echo ""
echo "[3/5] Installing APK analysis tools..."
if [ "$OS" == "linux" ]; then
    # apktool
    if ! command -v apktool &> /dev/null; then
        echo "Installing apktool..."
        sudo apt install -y apktool || {
            echo -e "${YELLOW}apktool not available via apt, downloading manually...${NC}"
            wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /tmp/apktool
            wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.0.jar -O /tmp/apktool.jar
            sudo mv /tmp/apktool /usr/local/bin/apktool
            sudo mv /tmp/apktool.jar /usr/local/bin/apktool.jar
            sudo chmod +x /usr/local/bin/apktool
        }
    else
        echo -e "${GREEN}✓ apktool already installed${NC}"
    fi
    
    # jadx
    if ! command -v jadx &> /dev/null; then
        echo "Installing jadx..."
        sudo apt install -y jadx || {
            echo -e "${YELLOW}jadx not available via apt, downloading from GitHub...${NC}"
            JADX_VERSION="1.4.7"
            wget https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip -O /tmp/jadx.zip
            sudo unzip /tmp/jadx.zip -d /usr/local/jadx
            sudo ln -sf /usr/local/jadx/bin/jadx /usr/local/bin/jadx
            rm /tmp/jadx.zip
        }
    else
        echo -e "${GREEN}✓ jadx already installed${NC}"
    fi
    
elif [ "$OS" == "macos" ]; then
    brew install apktool jadx || echo -e "${YELLOW}Warning: apktool/jadx installation may have failed${NC}"
fi

echo ""
echo "[4/5] Installing GitLeaks..."
if ! command -v gitleaks &> /dev/null; then
    if [ "$OS" == "linux" ]; then
        GITLEAKS_VERSION="8.18.0"
        wget https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz -O /tmp/gitleaks.tar.gz
        tar -xzf /tmp/gitleaks.tar.gz -C /tmp/
        sudo mv /tmp/gitleaks /usr/local/bin/gitleaks
        sudo chmod +x /usr/local/bin/gitleaks
        rm /tmp/gitleaks.tar.gz
    elif [ "$OS" == "macos" ]; then
        brew install gitleaks
    fi
    echo -e "${GREEN}✓ GitLeaks installed${NC}"
else
    echo -e "${GREEN}✓ GitLeaks already installed${NC}"
fi

echo ""
echo "[5/5] Installing Python dependencies..."
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing Python packages..."
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

echo ""
echo "============================================================"
echo -e "${GREEN}Installation Complete!${NC}"
echo "============================================================"
echo ""
echo "To use SecretHunter:"
echo "  1. Activate the virtual environment:"
echo "     source venv/bin/activate"
echo ""
echo "  2. Run a scan:"
echo "     python cli.py /path/to/project"
echo "     python cli.py /path/to/app.apk"
echo ""
echo "  3. View help:"
echo "     python cli.py --help"
echo ""
echo "============================================================"

# Verify installations
echo ""
echo "Verifying installations..."
echo -n "Python: "
python3 --version
echo -n "GitLeaks: "
gitleaks version 2>/dev/null || echo -e "${YELLOW}Not installed${NC}"
echo -n "apktool: "
apktool --version 2>/dev/null | head -n1 || echo -e "${YELLOW}Not installed${NC}"
echo -n "jadx: "
jadx --version 2>/dev/null || echo -e "${YELLOW}Not installed${NC}"
echo -n "YARA: "
python3 -c "import yara; print(f'yara-python {yara.__version__}')" 2>/dev/null || echo -e "${YELLOW}Not installed${NC}"

echo ""
echo -e "${GREEN}Setup complete! Happy hunting! 🔍🔐${NC}"
