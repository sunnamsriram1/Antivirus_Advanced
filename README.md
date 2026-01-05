# 🛡️ Advanced Mini Antivirus + 🤖 AI Malware Detection

An **educational Python-based Mini Antivirus** project designed to demonstrate
how modern antivirus software works using:

- Signature-based detection
- Heuristic analysis
- Behavioral monitoring
- Sandbox analysis
- 🤖 AI-style malware detection (scoring based)
- 🔐 AES encrypted quarantine
- 🌐 Web URL phishing scanner
- 📂 Real-time file monitoring (polling based – Termux safe)
- 📊 Logs & scan reports

> ⚠️ **Note:**  
> This project is for **learning & cyber security education only**.  
> It is **NOT a replacement** for commercial antivirus software.

---
## 🧰 Requirements

### ✅ Python Version
- **Python 3.8 or higher**
- Works on:
  - Termux (Android)
  - Linux
  - Windows

### 📦 Required Python Modules

Only the following modules are required:

```bash
pip install cryptography requests
```
## 🚀 Features

### 🔍 File Protection
- Automatic scanning when new files are added to `scan_files/`
- Signature-based malware detection (MD5 hash)
- Heuristic keyword analysis
- Behavioral detection (script / executable files)
- Sandbox-style filename analysis

### 🤖 AI Malware Detection
- ML-style scoring system based on:
  - File size
  - File type
  - Suspicious keywords
- If AI score ≥ threshold → file treated as malware

### 🔐 Secure Quarantine
- AES (Fernet) encryption
- Encrypted files stored safely in `quarantine/`
- Original malicious file is deleted

### 🌐 Web Protection
- URL scanner for phishing indicators
- Detects suspicious login/password pages

### 📊 Logging & Reports
- Detailed activity logs (`antivirus_log.txt`)
- Summary report on exit (`scan_report.txt`)

---

## 📁 Project Structure

```text
.
├── Antivirus_Advanced_1v.py
├── README.md
├── aes.key
├── antivirus_log.txt
├── scan_report.txt
├── scan_files/
│   └── (drop files here to scan)
└── quarantine/
    └── *.locked
