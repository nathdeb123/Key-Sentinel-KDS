# -*- mode: python ; coding: utf-8 -*-
import os
import sys

# Resolve icon path robustly: spec files can be exec'd where __file__ is not defined.
# Try several candidate locations (spec dir, current working dir, sys.argv[0] dir)
icon_path = None
try:
    if '__file__' in globals():
        candidate = os.path.join(os.path.dirname(__file__), 'KeySentinel_logo.ico')
        if os.path.exists(candidate):
            icon_path = os.path.abspath(candidate)
except Exception:
    pass

if not icon_path:
    candidates = [
        os.path.join(os.getcwd(), 'KeySentinel_logo.ico'),
        os.path.join(os.path.dirname(sys.argv[0]) if sys.argv and sys.argv[0] else os.getcwd(), 'KeySentinel_logo.ico'),
        os.path.abspath('KeySentinel_logo.ico'),
    ]
    for c in candidates:
        try:
            if os.path.exists(c):
                icon_path = os.path.abspath(c)
                break
        except Exception:
            continue

if not icon_path:
    # Final fallback: use relative name; PyInstaller may still pick it up from datas
    icon_path = 'KeySentinel_logo.ico'


a = Analysis(
    ['advanced_main.py'],
    pathex=[],
    binaries=[],
    datas=[('KeySentinel_logo.ico', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='advanced_main',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)
