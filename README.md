# XDR Malware Detection Platform

> **POC (Proof of Concept)** — Academic research project implementing a 3-layer Extended Detection & Response pipeline for malware analysis.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-green)](https://fastapi.tiangolo.com)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-orange)](https://tensorflow.org)
[![License](https://img.shields.io/badge/License-Academic-lightgrey)](#license)

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    XDR Detection Pipeline                        │
│                                                                   │
│  File Input                                                       │
│      │                                                            │
│      ▼                                                            │
│  ┌─────────────────────────────────────────────┐                 │
│  │  Layer 1: Hash Reputation Check             │                 │
│  │  • SHA-256 hash lookup                      │                 │
│  │  • VirusTotal / local DB comparison         │                 │
│  │  → KNOWN MALICIOUS: block immediately       │                 │
│  └──────────────────────┬──────────────────────┘                 │
│                         │ UNKNOWN                                 │
│                         ▼                                         │
│  ┌─────────────────────────────────────────────┐                 │
│  │  Layer 2: Static CNN Analysis               │                 │
│  │  • PE → RGB Image conversion                │                 │
│  │  • 5-model CNN Ensemble:                    │                 │
│  │    - VGG16                                  │                 │
│  │    - ResNet50                               │                 │
│  │    - InceptionV3                            │                 │
│  │    - Autoencoder (anomaly detection)        │                 │
│  │    - BasicCNN (custom architecture)         │                 │
│  │  → Majority vote classification             │                 │
│  └──────────────────────┬──────────────────────┘                 │
│                         │ SUSPICIOUS                              │
│                         ▼                                         │
│  ┌─────────────────────────────────────────────┐                 │
│  │  Layer 3: Dynamic PCAP Analysis             │                 │
│  │  • Execute in isolated Windows sandbox      │                 │
│  │  • Capture network traffic (PCAP)           │                 │
│  │  • Extract 39 network features              │                 │
│  │  • Random Forest classifier                 │                 │
│  │  → Final verdict: CLEAN / MALICIOUS         │                 │
│  └─────────────────────────────────────────────┘                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📚 Research Foundation

This platform is based on three peer-reviewed academic papers:

| Paper | Method | Our Implementation |
|-------|--------|-------------------|
| Nataraj et al. (2011) — Malware images: visualization and automatic classification | PE binary → grayscale image | Extended to RGB, 5-CNN ensemble |
| Anderson et al. — Ember: An Open Dataset for Training Static ML Models | Static feature extraction | CNN-based image classification |
| Bartos et al. — Network traffic fingerprinting | PCAP feature engineering | 39-feature Random Forest |

---

## 🔧 Components

### `main.py` — FastAPI Server
- Serves all 7 ML models on port **8000**
- Endpoints: `/api/analyze`, `/api/status`, `/api/history`
- Web dashboard at `/`

### `agent.py` — Endpoint Monitoring Agent
- Watches `Downloads/`, `Desktop/`, `Temp/` folders
- Auto-quarantines SUSPICIOUS/MALICIOUS files
- Sends results to the XDR server API

### `dynamic_features.py` — PCAP Feature Extractor
- Scapy-based packet analysis
- Extracts 39 network behavioral features
- Used by the Dynamic Analysis layer

---

## 📦 ML Models

Models are stored on **Google Drive** (too large for GitHub):

| Model | Size | İndir |
|-------|------|-------|
| `models/vgg16.h5` | ~57 MB | [📥 Google Drive](https://drive.google.com/file/d/1voExBDPQLtSh0NTMZW7PNnETykPnumKZ/view?usp=sharing) |
| `models/resnet50.h5` | ~94 MB | [📥 Google Drive](https://drive.google.com/file/d/1m0OOSUcf9pxdC7Jd2r7CGMhOO_hMkic7/view?usp=sharing) |
| `models/autoencoder.h5` | ~55 MB | [📥 Google Drive](https://drive.google.com/file/d/1n6avpHJRVT8LVn_EzvRCf5jdYPa0Uwr_/view?usp=sharing) |
| `models/basic_cnn.h5` | ~22 MB | GitHub'da mevcut (`models/` klasörü) |
| `models/pre-trained/model_inceptionv3.h5` | ~14 MB | GitHub'da mevcut (`models/` klasörü) |
| `Dynamic_Analysis/random_forest_model.joblib` | ~1 MB | GitHub'da mevcut (`models/` klasörü) |

> **Büyük modeller** (vgg16, resnet50, autoencoder) Google Drive'dan indirilmeli.  
> **Küçük modeller** bu repo'nun `models/` klasöründe mevcuttur.

After downloading, place models in the `models/` directory.

---

## 🚀 Installation

### Linux / Ubuntu (Recommended)

```bash
# Clone repository
git clone https://github.com/mesuttguven/xdr-server.git
cd xdr-server

# One-click install
chmod +x install.sh
./install.sh

# Download models to models/ directory (see Google Drive link above)

# Start server
uvicorn main:app --host 0.0.0.0 --port 8000
```

### Windows (Agent Only)

```powershell
# Install Python dependencies
pip install -r requirements.txt

# Edit config.json with your server URL
# Start the endpoint agent
python agent.py
```

---

## ⚙️ Configuration

Edit `config.json`:

```json
{
  "server_url": "http://YOUR-SERVER-IP:8000",
  "watch_folders": [
    "C:\\Users\\%USERNAME%\\Downloads",
    "C:\\Users\\%USERNAME%\\Desktop",
    "C:\\Temp"
  ],
  "quarantine_folder": "C:\\Quarantine",
  "auto_quarantine": true,
  "log_level": "INFO"
}
```

---

## 🏖️ Sandbox Setup (Dynamic Analysis)

Dynamic analysis requires a VirtualBox sandbox environment:
- **REMnux VM** — network simulation (InetSim + FakeDNS)
- **Windows VM** — malware execution environment
- **WinRM** — remote Windows management

See [Sandbox Setup Guide](docs/sandbox_setup.md) for complete instructions.

---

## 📡 API Reference

### Analyze a File

```bash
curl -X POST http://localhost:8000/api/analyze \
  -F "file=@suspicious.exe"
```

**Response:**
```json
{
  "hash": "sha256...",
  "verdict": "MALICIOUS",
  "confidence": 0.94,
  "layers": {
    "hash_check": "UNKNOWN",
    "static_cnn": "MALICIOUS",
    "dynamic_pcap": "MALICIOUS"
  },
  "models": {
    "vgg16": "MALICIOUS",
    "resnet50": "MALICIOUS",
    "inception": "CLEAN",
    "autoencoder": "MALICIOUS",
    "basic_cnn": "MALICIOUS"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Check Server Status

```bash
curl http://localhost:8000/api/status
```

---

## 📁 Project Structure

```
xdr-server/
├── main.py                    # FastAPI server + all ML models
├── agent.py                   # Windows endpoint monitoring agent
├── dynamic_features.py        # PCAP feature extraction (39 features)
├── config.json                # Agent configuration
├── requirements.txt           # Python dependencies
├── install.sh                 # Linux one-click installer
├── static/                    # Web dashboard (HTML/CSS/JS)
├── models/                    # ML model files (download from Drive)
│   ├── vgg16.h5
│   ├── resnet50.h5
│   ├── autoencoder.h5
│   ├── basic_cnn.h5
│   └── pre-trained/
│       ├── model_inceptionv3.h5
│       └── model_mobilenet.h5
├── Dynamic_Analysis/
│   └── random_forest_model.joblib
├── uploads/                   # Temporary upload directory (gitignored)
└── docs/
    ├── architecture.md        # Detailed architecture documentation
    └── sandbox_setup.md       # VirtualBox sandbox setup guide
```

---

## 👤 Author

**Mesut Güven**
- GitHub: [@mesuttguven](https://github.com/mesuttguven)
- Email: mesuttguven@gmail.com

---

## 📄 License

This project is for **academic research purposes only**. Not for production use.

---

## 📖 Citation

```bibtex
@misc{guven2024xdr,
  title={XDR Malware Detection Platform: A Three-Layer Detection Pipeline},
  author={Güven, Mesut},
  year={2024},
  note={Academic POC based on peer-reviewed research}
}
```
