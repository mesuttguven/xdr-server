#!/bin/bash
# XDR Malware Detection Platform - Linux/Ubuntu Installer
# Usage: chmod +x install.sh && ./install.sh

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  XDR Malware Detection Platform - Installer   ${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""

# Check OS
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${RED}This script is for Linux/Ubuntu only.${NC}"
    exit 1
fi

# Check Python 3.8+
echo -e "${YELLOW}[1/6] Checking Python version...${NC}"
if ! command -v python3 &> /dev/null; then
    echo "Python3 not found. Installing..."
    sudo apt-get update && sudo apt-get install -y python3 python3-pip
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Python $PYTHON_VERSION found."

# Install system dependencies
echo -e "${YELLOW}[2/6] Installing system dependencies...${NC}"
sudo apt-get update
sudo apt-get install -y \
    libpcap-dev \
    tcpdump \
    libhdf5-dev \
    build-essential \
    libssl-dev \
    libffi-dev

# Create virtual environment
echo -e "${YELLOW}[3/6] Creating virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install Python dependencies
echo -e "${YELLOW}[4/6] Installing Python packages...${NC}"
pip install -r requirements.txt

# Create required directories
echo -e "${YELLOW}[5/6] Creating directories...${NC}"
mkdir -p models/pre-trained
mkdir -p Dynamic_Analysis
mkdir -p uploads
mkdir -p logs

# Check for models
echo -e "${YELLOW}[6/6] Checking ML models...${NC}"
MODELS_MISSING=0

check_model() {
    if [ ! -f "$1" ]; then
        echo -e "${RED}  MISSING: $1${NC}"
        MODELS_MISSING=1
    else
        echo -e "${GREEN}  FOUND: $1${NC}"
    fi
}

check_model "models/vgg16.h5"
check_model "models/resnet50.h5"
check_model "models/autoencoder.h5"
check_model "models/basic_cnn.h5"
check_model "models/pre-trained/model_inceptionv3.h5"
check_model "models/pre-trained/model_mobilenet.h5"
check_model "Dynamic_Analysis/random_forest_model.joblib"

echo ""
echo -e "${GREEN}================================================${NC}"

if [ $MODELS_MISSING -eq 1 ]; then
    echo -e "${YELLOW}⚠️  Some models are missing!${NC}"
    echo ""
    echo "Download models from Google Drive:"
    echo "https://drive.google.com/your-folder-link-here"
    echo ""
    echo "Place them in the correct directories as shown above."
    echo ""
fi

echo -e "${GREEN}✅ Installation complete!${NC}"
echo ""
echo "To start the XDR server:"
echo "  source venv/bin/activate"
echo "  uvicorn main:app --host 0.0.0.0 --port 8000"
echo ""
echo "Dashboard: http://localhost:8000"
echo -e "${GREEN}================================================${NC}"
