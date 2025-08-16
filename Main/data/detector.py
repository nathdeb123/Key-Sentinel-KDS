import psutil
import ctypes
import win32api
import win32con
import win32process
import win32gui
import win32ui
from keylogger_db import KeyloggerThreatDB

db = KeyloggerThreatDB()
db.log_threat("suspicious.exe", 1234, "High", "Terminated")
db.close()


# Windows Hook Identifiers
WH_KEYBOARD_LL = 13

def is_hooking_keystrokes(pid):
    """
    Check if a process is attempting to hook keyboard input (possible keylogger).
    """
    try:
        handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid)
        modules = win32process.EnumProcessModules(handle)

        for module in modules:
            module_name = win32process.GetModuleFileNameEx(handle, module).lower()
            if any(kw in module_name for kw in ['keylog', 'hook', 'capture', 'monitor']):
                return True
    except Exception:
        pass
    return False

def get_suspicious_processes():
    """
    Scans running processes for suspicious keylogging patterns.
    """
    suspicious_list = []

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            path = proc.info['exe']

            if not path:
                continue

            if is_hooking_keystrokes(pid):
                suspicious_list.append({
                    "pid": pid,
                    "name": name,
                    "path": path,
                    "reason": "Hooking keywords found in modules"
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return suspicious_list
