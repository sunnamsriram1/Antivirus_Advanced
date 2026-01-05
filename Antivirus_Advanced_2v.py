#!/usr/bin/env python3
# 🔐 Advanced Mini Antivirus + AI Malware Detection
# Cyber Security Learning Tool
# 🔐 Encrypted & coded by Sriram

import os, time, hashlib, requests, threading
from cryptography.fernet import Fernet
from datetime import datetime

# ================= CONFIG =================

SCAN_DIR = "scan_files"
QUARANTINE_DIR = "quarantine"
LOG_FILE = "antivirus_log.txt"
REPORT_FILE = "scan_report.txt"
KEY_FILE = "aes.key"

KNOWN_VIRUS_SIGNATURES = {
    "eicar": "275a021bbfb6489e54d471899f7db9d1"
}

SUSPICIOUS_KEYWORDS = [
    "encrypt", "rm -rf", "keylogger",
    "password", "ransom", "delete all",
    "wallet", "bitcoin", "backdoor"
]

# ================= AES SETUP =================

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        open(KEY_FILE, "wb").write(key)
    return open(KEY_FILE, "rb").read()

FERNET = Fernet(load_key())

# ================= UTILS =================

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} | {msg}\n")

def banner():
    print("="*65)
    print("🛡️ ADVANCED MINI ANTIVIRUS + 🤖 AI MALWARE DETECTION")
    print("🔍 Real-Time | Web | AES | AI | Logs")
    print("="*65)

def file_hash(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

# ================= CLASSIC SCANNERS =================

def signature_scan(path):
    md5 = file_hash(path)
    for name, sig in KNOWN_VIRUS_SIGNATURES.items():
        if md5 == sig:
            return True, name
    return False, None

def heuristic_scan(path):
    try:
        with open(path, "r", errors="ignore") as f:
            data = f.read().lower()
            for k in SUSPICIOUS_KEYWORDS:
                if k in data:
                    return True, k
    except:
        pass
    return False, None

def behavioral_scan(path):
    return path.endswith((".py", ".sh", ".exe", ".apk"))

def sandbox_scan(path):
    return "mal" not in path.lower()

# ================= 🤖 AI MALWARE DETECTION =================
# ML-style feature scoring (educational)

def ai_malware_detection(path):
    score = 0
    reasons = []

    try:
        size = os.path.getsize(path)
        if size > 5_000_000:
            score += 1
            reasons.append("Large file size")

        if behavioral_scan(path):
            score += 1
            reasons.append("Executable/script type")

        with open(path, "r", errors="ignore") as f:
            content = f.read().lower()
            for k in SUSPICIOUS_KEYWORDS:
                if k in content:
                    score += 2
                    reasons.append(f"Keyword: {k}")
    except:
        pass

    # AI decision
    if score >= 3:
        return True, score, reasons
    return False, score, reasons

# ================= AES QUARANTINE =================

def encrypt_and_quarantine(path):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    data = open(path, "rb").read()
    encrypted = FERNET.encrypt(data)

    qfile = os.path.join(
        QUARANTINE_DIR,
        os.path.basename(path) + ".locked"
    )

    open(qfile, "wb").write(encrypted)
    os.remove(path)

    log(f"QUARANTINED: {path}")
    print(f"🔒 Encrypted & Quarantined → {qfile}")

# ================= FILE SCAN =================

def scan_file(path):
    if not os.path.isfile(path):
        return

    print(f"\n🔍 Scanning: {path}")
    log(f"Scanning {path}")

    infected, name = signature_scan(path)
    if infected:
        print("☠️ Signature Virus:", name)
        encrypt_and_quarantine(path)
        return

    h, key = heuristic_scan(path)
    if h:
        print("⚠️ Heuristic detected:", key)

    if behavioral_scan(path):
        print("🧠 Behavioral: Suspicious file type")

    if not sandbox_scan(path):
        print("❌ Sandbox verdict: MALICIOUS")
        encrypt_and_quarantine(path)
        return

    # 🤖 AI Scan
    ai_bad, score, reasons = ai_malware_detection(path)
    if ai_bad:
        print(f"🤖 AI DETECTION: MALWARE (score={score})")
        for r in reasons:
            print("   •", r)
        log(f"AI MALWARE: {path} | score={score}")
        encrypt_and_quarantine(path)
        return

    print("✅ File SAFE")
    log(f"SAFE: {path}")

# ================= REAL-TIME MONITOR =================

def polling_monitor():
    print("📂 Polling-based real-time scan started")
    scanned = set()
    while True:
        for f in os.listdir(SCAN_DIR):
            path = os.path.join(SCAN_DIR, f)
            if path not in scanned and os.path.isfile(path):
                scan_file(path)
                scanned.add(path)
        time.sleep(2)

# ================= WEB URL SCANNER =================

def scan_url(url):
    print("\n🌐 URL Scan:", url)
    try:
        r = requests.get(url, timeout=5)
        text = r.text.lower()
        if "login" in text or "password" in text:
            print("⚠️ Possible Phishing Page")
            log(f"PHISHING WARNING: {url}")
        else:
            print("✅ URL seems SAFE")
            log(f"URL SAFE: {url}")
    except:
        print("❌ URL Unreachable / Suspicious")
        log(f"URL ERROR: {url}")

# ================= REPORT =================

def generate_report():
    with open(REPORT_FILE, "w") as f:
        f.write("🛡️ Antivirus Scan Report\n")
        f.write(f"Date: {datetime.now()}\n")
        f.write("See antivirus_log.txt for full details\n")
    print("📊 Report Generated")

# ================= USER INPUT =================

def user_input():
    while True:
        print("\n[1] Scan URL")
        print("[2] Exit Antivirus")
        ch = input("Select: ").strip()

        if ch == "1":
            url = input("Enter URL: ").strip()
            if url:
                scan_url(url)
        elif ch == "2":
            print("🛑 Exiting Antivirus")
            generate_report()
            os._exit(0)
        else:
            print("❌ Invalid option")

# ================= MAIN =================

if __name__ == "__main__":
    banner()
    os.makedirs(SCAN_DIR, exist_ok=True)

    threading.Thread(target=polling_monitor, daemon=True).start()
    threading.Thread(target=user_input, daemon=True).start()

    print("📌 Drop files into 'scan_files' folder")
    while True:
        time.sleep(1)
