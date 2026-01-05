#!/usr/bin/env python3
# 🔐 Mini Antivirus Simulator
# Coded for Cyber Security Learning
# 🔐 Encrypted & coded by Sriram

import os
import hashlib
import shutil
import time
import subprocess

# ================= CONFIG =================

SCAN_DIR = "scan_files"
QUARANTINE_DIR = "quarantine"

# Known virus signatures (hashes)
KNOWN_VIRUS_SIGNATURES = {
    "eicar_test": "275a021bbfb6489e54d471899f7db9d1"
}

SUSPICIOUS_KEYWORDS = [
    "encrypt", "delete all", "rm -rf", "format",
    "keylogger", "password steal", "ransom"
]

# ================= UTILS =================

def banner():
    print("="*60)
    print("🛡️  PYTHON MINI ANTIVIRUS SIMULATOR")
    print("🔍 Signature | Heuristic | Behavior | Sandbox")
    print("="*60)

def file_hash(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

# ================= SIGNATURE SCAN =================

def signature_scan(file_path):
    file_md5 = file_hash(file_path)
    for name, sig in KNOWN_VIRUS_SIGNATURES.items():
        if file_md5 == sig:
            return True, name
    return False, None

# ================= HEURISTIC ANALYSIS =================

def heuristic_scan(file_path):
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read().lower()
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in content:
                    return True, keyword
    except:
        pass
    return False, None

# ================= BEHAVIOR MONITOR =================

def behavioral_monitor(file_path):
    # Simulation only
    suspicious_actions = [
        "access_system_files",
        "mass_file_changes",
        "unauthorized_network"
    ]
    # Fake detection logic
    if file_path.endswith(".sh") or file_path.endswith(".py"):
        return True, suspicious_actions
    return False, None

# ================= SANDBOX =================

def sandbox_analysis(file_path):
    print(f"🧪 Sandbox testing: {file_path}")
    time.sleep(1)
    # Simulated sandbox result
    if "mal" in file_path.lower():
        return False
    return True

# ================= QUARANTINE =================

def quarantine(file_path):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    dest = os.path.join(QUARANTINE_DIR, os.path.basename(file_path))
    shutil.move(file_path, dest)
    print(f"🚫 QUARANTINED: {dest}")

# ================= MAIN SCANNER =================

def scan():
    if not os.path.exists(SCAN_DIR):
        print("❌ scan_files folder not found!")
        return

    for file in os.listdir(SCAN_DIR):
        path = os.path.join(SCAN_DIR, file)
        if not os.path.isfile(path):
            continue

        print(f"\n🔍 Scanning: {file}")

        # 1️⃣ Signature Detection
        infected, name = signature_scan(path)
        if infected:
            print(f"☠️ Virus detected (Signature): {name}")
            quarantine(path)
            continue

        # 2️⃣ Heuristic Analysis
        suspicious, keyword = heuristic_scan(path)
        if suspicious:
            print(f"⚠️ Heuristic warning: '{keyword}' found")
        
        # 3️⃣ Behavioral Monitoring
        behavior, actions = behavioral_monitor(path)
        if behavior:
            print(f"🧠 Behavioral alert: {actions}")

        # 4️⃣ Sandbox
        safe = sandbox_analysis(path)
        if not safe:
            print("❌ Sandbox verdict: MALICIOUS")
            quarantine(path)
        else:
            print("✅ File is SAFE")

# ================= RUN =================

if __name__ == "__main__":
    banner()
    scan()
