<div align="center">

  # 🛡️ ThreatLens

  **Enterprise Binary Forensics Engine & Cyber Threat Intelligence Consensus Platform**

  [![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
  [![Flask](https://img.shields.io/badge/Flask-3.0.3-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
  [![OWASP Hardened](https://img.shields.io/badge/OWASP-Hardened%20Pipeline-005EA6?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

  *Sub-second local static entropy calculations, PE forensic architecture inspections, YARA heuristic rule evaluations, and hybrid AI Security Advisor SOP generation.*

</div>

---

## 📋 Executive Overview

**ThreatLens** is an advanced, high-performance static binary analysis and cyber threat intelligence platform engineered for modern Security Operations Centers (SOC) and Incident Response teams. Built with zero-trust infrastructure principles and an OWASP-hardened processing pipeline, ThreatLens converts complex binary artifacts and cryptographic signatures into structured, actionable security intelligence in sub-second execution speeds (`< 1.0s`).

By synthesizing multi-vendor intelligence feeds with block-level Shannon Information Entropy metrics and PE structure heuristic matchers, ThreatLens eliminates false positives and generates executive risk briefings alongside step-by-step SOC remediation Standard Operating Procedures (SOPs).

---

## 🔥 Core Operational Capabilities

### 🔍 1. Multi-Engine File Analyzer
- **Streaming Inspection**: Supports Windows Executables (`.exe`, `.dll`), Scripts (`.py`, `.js`, `.bat`), Documents (`.pdf`, `.docx`), and Archives (`.zip`, `.apk`) up to **200 MB** via streaming chunk processing.
- **Static Shannon Entropy**: Measures byte randomness on a scale of `0.0` to `8.0` to detect packed, compressed, or encrypted malware payloads evading static inspection.
- **Portable Executable (PE) Architecture**: Maps PE section headers, import tables, and suspicious Windows API execution strings (`VirtualAllocEx`, `CreateRemoteThread`, `WriteProcessMemory`).

### 🔎 2. Hash Inspector & Global Reconnaissance
- **Instant Cryptographic Queries**: Performs instant threat reconnaissance across MD5, SHA-1, and SHA-256 digests against global threat databases.
- **Multi-Vendor Consensus Scoring**: Computes a weighted threat consensus verdict (`Safe`, `Suspicious`, `Malicious`) based on antivirus detection ratios and threat family classifications.

### 🛡️ 3. YARA & Heuristic Pattern Inspection
- **Rule Engine Scanning**: Scans compiled YARA pattern heuristics to uncover anti-debugging routines, ransomware encryption hooks, and process injection indicators.

### 🤖 4. AI Security Advisor SOP Generation
- **Hybrid Intelligence Engine**: Synthesizes binary indicators into executive threat briefings, potential business impact assessments, and tactical SOC containment protocols aligned with **NIST Cybersecurity Framework** standards.

---

## 🛠️ Technological Stack & Standards

- **Core Engine**: Python 3.10+, Flask 3.0.3, Werkzeug
- **Security & Hardening**: OWASP Top 10 Security Headers (`nosniff`, `SAMEORIGIN`, `strict-origin-when-cross-origin`)
- **Cybersecurity Framework Alignment**: [MITRE ATT&CK Framework](https://attack.mitre.org/), [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- **Threat Feeds**: VirusTotal v3 API, abuse.ch MalwareBazaar Intelligence API
- **Deployment Architecture**: WSGI / Gunicorn Enterprise Web Server

---

## ⚡ Quick Start & Installation

### Prerequisites
- Python 3.10 or higher
- Git

### 1. Clone Repository
```bash
git clone https://github.com/dhruvkaklotar-tech/ThreatLens.git
cd ThreatLens
```

### 2. Configure Virtual Environment
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables (`.env`)
Create a `.env` file in the root directory:
```env
APP_NAME=ThreatLens
APP_ENV=development
DEBUG=true
PORT=5000
ALLOWED_EXTENSIONS=exe,dll,pdf,zip,docx,apk,js,bat,py
MAX_UPLOAD_SIZE=209715200
REQUEST_TIMEOUT_SECONDS=60
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
FLASK_SECRET_KEY=your_secure_random_flask_secret_key
```

### 5. Launch Local Development Server
```bash
python app.py
```
Navigate to `http://127.0.0.1:5000` in your browser.

---

## 🌐 Production Web Hosting & Deployment

ThreatLens is pre-configured for one-click WSGI deployment on platforms such as **Render**, **Railway**, **Heroku**, or custom VPS instances.

### Production Execution via Gunicorn WSGI
```bash
gunicorn wsgi:app
```

---

## 🧪 Automated Testing Suite

ThreatLens includes comprehensive unit and contract tests verifying backend validation, hash generation, entropy calculations, and security headers.

Run test suite via `pytest`:
```bash
pytest -v
```

---

## 👨‍💻 Author & Lead Architect

**Dhruv Kaklotar**
*Student of Computer Engineering & Cybersecurity Researcher*
- 📍 **Location**: Surat, Gujarat, India
- 🌐 **GitHub**: [@dhruvkaklotar-tech](https://github.com/dhruvkaklotar-tech)
- 💼 **LinkedIn**: [Dhruv Kaklotar](https://www.linkedin.com/in/dhruv-kaklotar-8b4295362)
- ✉️ **Secure Mail**: `dhruvkaklotar@proton.me`

---

## 📜 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for detailed terms and permissions.
