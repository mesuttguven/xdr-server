XDR Platform — System Architecture
Overview
The XDR (Extended Detection & Response) platform implements a 3-layer detection pipeline that progressively escalates analysis based on threat confidence.

Detection Layers
Layer 1: Hash Reputation Check
Speed: Milliseconds
Purpose: Instantly block known malware

Input File
    │
    ▼
SHA-256 Hash
    │
    ▼
Local DB / VirusTotal API
    │
    ├── KNOWN MALICIOUS → Block + Alert
    ├── KNOWN CLEAN → Allow
    └── UNKNOWN → Layer 2
Layer 2: Static CNN Ensemble Analysis
Speed: 2–5 seconds
Purpose: Detect malware without execution

The PE (Portable Executable) binary is converted to an RGB image and classified by 5 CNN models:

PE Binary
    │
    ▼
PE → RGB Image (Nataraj et al. method)
    │
    ▼
┌──────────┬──────────┬──────────┬──────────┬──────────┐
│  VGG16   │ ResNet50 │Inception │  AutoEnc │BasicCNN  │
│(fine-tune│(fine-tune│  V3      │(anomaly) │(custom)  │
└─────┬────┴─────┬────┴────┬─────┴────┬─────┴────┬─────┘
      │          │         │          │          │
      └──────────┴─────────┴──────────┴──────────┘
                           │
                    Majority Vote
                           │
              ├── CLEAN → Allow
              ├── MALICIOUS → Block + Alert
              └── SUSPICIOUS → Layer 3
PE to Image Conversion:

Read raw bytes of PE file
Map bytes to pixel values (0–255)
Arrange into square RGB image
Resize to 224×224 for CNN input
Layer 3: Dynamic PCAP Analysis
Speed: 60–120 seconds
Purpose: Behavioral analysis through controlled execution

Suspicious File
      │
      ▼
Windows Sandbox VM (VirtualBox)
      │
      ├── InetSim (fake internet services)
      ├── FakeDNS (DNS simulation)
      └── Execute malware sample
              │
              ▼
      PCAP Capture (tcpdump)
              │
              ▼
      39 Network Features Extracted:
      ├── Connection counts
      ├── Protocol distribution (TCP/UDP/ICMP)
      ├── Port usage patterns
      ├── Packet size statistics
      ├── Flow duration metrics
      ├── DNS query patterns
      ├── HTTP/HTTPS ratio
      └── Beacon detection features
              │
              ▼
      Random Forest Classifier
              │
      ├── CLEAN → Allow
      └── MALICIOUS → Block + Quarantine
Component Architecture
┌─────────────────────────────────────────────────────────┐
│                   XDR Server (Linux)                     │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │                FastAPI (port 8000)                │   │
│  │                                                   │   │
│  │  POST /api/analyze  →  Detection Pipeline         │   │
│  │  GET  /api/status   →  Server Health              │   │
│  │  GET  /api/history  →  Analysis History           │   │
│  │  GET  /             →  Web Dashboard              │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │              ML Model Layer                       │   │
│  │  • VGG16, ResNet50, InceptionV3 (TensorFlow)     │   │
│  │  • Autoencoder (Keras)                            │   │
│  │  • BasicCNN (Keras)                               │   │
│  │  • Random Forest (scikit-learn)                   │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │           VirtualBox Sandbox Manager              │   │
│  │  • VM lifecycle (start/stop/restore snapshot)     │   │
│  │  • WinRM command execution                        │   │
│  │  • PCAP file retrieval (WinSCP/SCP)              │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
              ▲                          ▲
              │ HTTP API                 │ HTTP API
              │                          │
┌─────────────────────┐    ┌─────────────────────────┐
│  Windows Endpoint   │    │   Windows Endpoint       │
│  Agent (agent.py)   │    │   Agent (agent.py)       │
│                     │    │                          │
│  Watches folders:   │    │  Watches folders:        │
│  • Downloads/       │    │  • Downloads/            │
│  • Desktop/         │    │  • Desktop/              │
│  • Temp/            │    │  • Temp/                 │
│                     │    │                          │
│  Auto-quarantine    │    │  Auto-quarantine         │
└─────────────────────┘    └─────────────────────────┘
Network Topology (Sandbox)
┌─────────────────────────────────────────────────────────┐
│                VirtualBox Host (XDR Server)              │
│                                                          │
│  ┌──────────────────┐    ┌──────────────────────────┐   │
│  │  REMnux VM       │    │  Windows VM              │   │
│  │  (192.168.56.10) │    │  (192.168.56.20)         │   │
│  │                  │◄───│                          │   │
│  │  • InetSim       │    │  • Malware execution     │   │
│  │  • FakeDNS       │    │  • WinRM enabled         │   │
│  │  • PCAP capture  │    │  • Snapshot: Clean_NAT   │   │
│  └──────────────────┘    └──────────────────────────┘   │
│                                                          │
│       Host-only Network: 192.168.56.0/24                 │
└─────────────────────────────────────────────────────────┘
Data Flow
1. Agent detects new file in watched folder
2. Agent sends file to XDR Server via HTTP POST
3. Server computes SHA-256 hash → checks reputation
4. If unknown: Server converts PE to image → runs CNN ensemble
5. If suspicious: Server sends file to Windows sandbox
6. Windows VM executes file → network traffic captured
7. PCAP features extracted → Random Forest predicts verdict
8. Final verdict returned to Agent
9. Agent quarantines file if MALICIOUS
10. Event logged to history database
Technology Stack
Component	Technology
API Server	FastAPI + Uvicorn
Deep Learning	TensorFlow 2.x + Keras
ML	scikit-learn
Image Processing	Pillow + NumPy
PCAP Analysis	Scapy
File Monitoring	Watchdog
Sandbox Control	VBoxManage CLI
Remote Execution	WinRM (pywinrm)
File Transfer	WinSCP / SCP
