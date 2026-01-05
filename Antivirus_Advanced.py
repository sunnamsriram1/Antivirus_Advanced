#!/usr/bin/env python3
# 🔐 Advanced Mini Antivirus
# Cyber Security Learning Tool
# 🔐 Encrypted & coded by Sriram

import os, time, hashlib, shutil, requests, json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
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
    "password", "ransom", "delete all"
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
    print("="*60)
    print("🛡️ PYTHON ADVANCED MINI ANTIVIRUS")
    print("🔍 Real-Time | Web | AES | Logs")
    print("="*60)

def file_hash(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

# ================= SCANNERS =================

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
    if path.endswith((".py", ".sh", ".exe")):
        return True
    return False

def sandbox_scan(path):
    if "mal" in path.lower():
        return False
    return True

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
        print("⚠️ Heuristic:", key)

    if behavioral_scan(path):
        print("🧠 Behavioral Suspicious")

    if not sandbox_scan(path):
        print("❌ Sandbox MALICIOUS")
        encrypt_and_quarantine(path)
    else:
        print("✅ File SAFE")

# ================= REAL-TIME MONITOR =================

class Monitor(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            scan_file(event.src_path)

# ================= WEB URL SCANNER =================

def scan_url(url):
    print("\n🌐 URL Scan:", url)
    try:
        r = requests.get(url, timeout=5)
        if "login" in r.text.lower() or "password" in r.text.lower():
            print("⚠️ Possible Phishing Page")
        else:
            print("✅ URL seems SAFE")
    except:
        print("❌ URL Unreachable / Suspicious")

# ================= REPORT =================

def generate_report():
    with open(REPORT_FILE, "w") as f:
        f.write("🛡️ Antivirus Scan Report\n")
        f.write(f"Date: {datetime.now()}\n")
        f.write("Check antivirus_log.txt for details\n")
    print("📊 Report Generated")

# ================= MAIN =================

if __name__ == "__main__":
    banner()

    os.makedirs(SCAN_DIR, exist_ok=True)

    observer = Observer()
    observer.schedule(Monitor(), SCAN_DIR, recursive=True)
    observer.start()

    print("📂 Real-time monitoring started...")
    print("🌐 Example URL Scan: scan_url('https://example.com')")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        generate_report()

    observer.join()
