import psutil
import os

# Suspicious keywords commonly used by keyloggers
SUSPICIOUS_NAMES = ['keylog', 'logger', 'hook', 'spy', 'stealth', 'record']
SUSPICIOUS_LOCATIONS = ['\\AppData\\', '\\Temp\\', '\\Roaming\\', '\\ProgramData\\']
SUSPICIOUS_PARENTS = ['cmd.exe', 'powershell.exe', 'wscript.exe']

def calculate_threat_score(proc):
    score = 0
    reasons = []

    try:
        name = proc.name().lower()
        exe_path = proc.exe()

        # Check for suspicious name
        if any(word in name for word in SUSPICIOUS_NAMES):
            score += 40
            reasons.append("Suspicious name")

        # Check for shady location
        if any(loc in exe_path for loc in SUSPICIOUS_LOCATIONS):
            score += 20
            reasons.append("Located in suspicious folder")

        # Check for no visible window (no GUI)
        if not proc.status() in ['running', 'sleeping']:
            score += 10
            reasons.append("Hidden or background process")

        # Check for suspicious parent process
        parent = proc.parent()
        if parent and parent.name().lower() in SUSPICIOUS_PARENTS:
            score += 30
            reasons.append(f"Suspicious parent: {parent.name()}")

        # Cap score to 100
        score = min(score, 100)

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    return score, reasons

def scan_processes_with_scores():
    results = []

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            score, reasons = calculate_threat_score(proc)
            if score > 0:
                results.append({
                    "pid": proc.pid,
                    "name": proc.name(),
                    "path": proc.exe(),
                    "score": score,
                    "reasons": reasons
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return sorted(results, key=lambda x: x['score'], reverse=True)
