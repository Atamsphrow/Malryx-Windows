# -*- mode: python ; coding: utf-8 -*-
# Spécification PyInstaller de Malryx (utilisée par build.ps1).
#   MALRYX_ONEDIR=1  → dossier dist\Malryx\ (pour l'installateur, démarrage plus rapide)
#   sinon            → fichier unique dist\Malryx.exe (portable)
import os
from pathlib import Path

ROOT = Path(SPECPATH)
onedir = os.environ.get("MALRYX_ONEDIR") == "1"
version_file = os.environ.get("MALRYX_VERSION_FILE")

datas = [(str(ROOT / "assets"), "assets"), (str(ROOT / "rules"), "rules"),
         (str(ROOT / "hashes.txt"), "."), (str(ROOT / "VERSION"), ".")]
for folder in ("vendor", "signatures"):
    if (ROOT / folder).exists():
        datas.append((str(ROOT / folder), folder))

a = Analysis(
    [str(ROOT / "main.py")],
    pathex=[str(ROOT)],
    datas=datas,
    hiddenimports=["yara", "cryptography.hazmat.primitives.ciphers.aead"],
    excludes=["tkinter", "unittest", "pydoc", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtQml",
              "PySide6.QtQuick", "PySide6.Qt3DCore", "PySide6.QtMultimedia", "PySide6.QtPdf", "PySide6.QtCharts",
              "PySide6.QtDataVisualization", "PySide6.QtOpenGL", "PySide6.QtDesigner"],
    noarchive=False,
)
from PyInstaller.utils.hooks import collect_submodules  # noqa: E402
a.hiddenimports += collect_submodules("watchdog") + collect_submodules("malryx")

# Allègement : fichiers Qt inutiles pour une application Widgets (≈ 30 Mo de moins)
DROP = ("opengl32sw.dll", "qt6quick", "qt6qml", "qt6pdf", "qt6virtualkeyboard", "qt6webengine", "qt6designer",
        "qt6multimedia", "qt6charts", "qt63d", "qt6opengl", "qt6labs")
a.binaries = [b for b in a.binaries if not any(x in b[0].lower() for x in DROP)]
a.datas = [d for d in a.datas if "translations" not in d[0].replace("\\", "/").lower() or "qtbase_fr" in d[0].lower()]

pyz = PYZ(a.pure)
common = dict(name="Malryx", debug=False, strip=False, upx=False, console=False,
              icon=str(ROOT / "assets" / "malryx.ico"), version=version_file)

if onedir:
    exe = EXE(pyz, a.scripts, [], exclude_binaries=True, **common)
    coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="Malryx")
else:
    exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], runtime_tmpdir=None, **common)
