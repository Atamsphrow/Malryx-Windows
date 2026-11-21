"""Chemins : ressources embarquées dans l'exe (PyInstaller) et dossier de données utilisateur."""
import os
import shutil
import sys
from pathlib import Path

APP_NAME = "Malryx"
def _read_version():
    """Source unique : le fichier VERSION à la racine (embarqué dans l'exe)."""
    import sys as _s
    base = Path(getattr(_s, "_MEIPASS", Path(__file__).resolve().parent.parent))
    try:
        return (base / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return "0.0.0"


VERSION = _read_version()
IS_WIN = sys.platform == "win32"
FROZEN = getattr(sys, "frozen", False)


def resource(*parts):
    """Fichier embarqué (dans l'exe) ou dans le dossier source en développement."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base.joinpath(*parts)


def data_dir(*parts):
    root = Path(os.environ.get("LOCALAPPDATA", Path.home())) if IS_WIN else Path.home() / ".local" / "share"
    d = root / APP_NAME
    d.mkdir(parents=True, exist_ok=True)
    p = d.joinpath(*parts)
    if not parts or not p.suffix:
        p.mkdir(parents=True, exist_ok=True)
    return p


def _copy_tree_if_new(src, dst, stamp):
    """Copie un dossier embarqué vers AppData une seule fois par version."""
    src, dst = Path(src), Path(dst)
    if not src.exists():
        return False
    marker = dst / ".version"
    if marker.exists() and marker.read_text() == stamp:
        return True
    dst.mkdir(parents=True, exist_ok=True)
    for f in src.rglob("*"):
        if f.is_file():
            target = dst / f.relative_to(src)
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(f, target)
            except PermissionError:  # binaire en cours d'utilisation
                pass
    marker.write_text(stamp)
    return True


def install_vendor():
    """Les binaires (adb, clamd) sont exécutés depuis AppData et non depuis le dossier
    temporaire de l'exe : sinon le dossier temporaire ne pourrait pas être nettoyé à la fermeture."""
    _copy_tree_if_new(resource("vendor", "adb"), data_dir("bin", "adb"), VERSION)
    _copy_tree_if_new(resource("vendor", "clamav"), data_dir("bin", "clamav"), VERSION)
    db = data_dir("clamav-db")
    if not any(db.glob("*.c[vl]d")):  # première installation : signatures ClamAV embarquées
        for f in resource("vendor", "clamav-db").glob("*.c[vl]d") if resource("vendor", "clamav-db").exists() else []:
            shutil.copy2(f, db / f.name)


def find_tool(name, sub):
    """Cherche d'abord la version embarquée, puis le PATH."""
    exe = name + (".exe" if IS_WIN else "")
    for cand in (data_dir("bin", sub) / exe, resource("vendor", sub) / exe):
        if cand.exists():
            return str(cand)
    return shutil.which(name)
