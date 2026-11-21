"""Nettoyage des fichiers inutiles : standard (temporaires, caches, corbeille) et approfondi
(Windows.old, journaux, cache de distribution, vidages mémoire, composants obsolètes)."""
import os
import shutil
import subprocess
import time
from pathlib import Path

from .paths import IS_WIN

NO_WINDOW = 0x08000000 if IS_WIN else 0


def _env(k, d=""):
    return Path(os.environ.get(k, d))


def categories(deep=False):
    la, win = _env("LOCALAPPDATA"), _env("SystemRoot", r"C:\Windows")
    sysdrive = Path(os.environ.get("SystemDrive", "C:") + "\\")
    cats = {
        "Fichiers temporaires de l'utilisateur": [_env("TEMP")],
        "Fichiers temporaires de Windows": [win / "Temp"],
        "Cache de Google Chrome": [la / r"Google\Chrome\User Data\Default\Cache", la / r"Google\Chrome\User Data\Default\Code Cache"],
        "Cache de Microsoft Edge": [la / r"Microsoft\Edge\User Data\Default\Cache", la / r"Microsoft\Edge\User Data\Default\Code Cache"],
        "Cache de Firefox": list((la / r"Mozilla\Firefox\Profiles").glob("*/cache2")) if (la / r"Mozilla\Firefox\Profiles").exists() else [],
        "Cache des miniatures": [la / r"Microsoft\Windows\Explorer"],
        "Rapports d'erreurs et vidages": [la / "CrashDumps", _env("PROGRAMDATA", r"C:\ProgramData") / r"Microsoft\Windows\WER\ReportArchive"],
        "Cache de Windows Update": [win / r"SoftwareDistribution\Download"],
    }
    deep_cats = {
        "Ancienne installation de Windows (Windows.old)": [sysdrive / "Windows.old"],
        "Journaux de Windows": [win / "Logs" / "CBS", win / "Logs" / "DISM", win / "Panther"],
        "Cache d'optimisation de distribution": [win / r"ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache",
                                                 win / r"SoftwareDistribution\DeliveryOptimization"],
        "Vidages mémoire du système": [win / "Minidump", win / "MEMORY.DMP", win / "LiveKernelReports"],
        "Fichiers d'installation de pilotes obsolètes": [win / r"System32\DriverStore\Temp"],
    }
    if not IS_WIN:
        cats = {"Cache utilisateur": [Path.home() / ".cache"]}  # hors Windows : uniquement pour le développement
        deep_cats = {"Journaux système": [Path("/var/log/journal")]}
    if deep:
        cats.update(deep_cats)
    return {k: [p for p in v if str(p) not in ("", ".") and p.exists()] for k, v in cats.items()}


DEEP_NAMES = {"Ancienne installation de Windows (Windows.old)", "Journaux de Windows", "Cache d'optimisation de distribution",
              "Vidages mémoire du système", "Fichiers d'installation de pilotes obsolètes", "Journaux système"}


def _files(root, pattern=None):
    if root.is_file():
        yield str(root)
        return
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if pattern and not fn.lower().startswith(pattern):
                continue
            yield os.path.join(dirpath, fn)


def _keep_recent(category, st):
    """Ne jamais supprimer un fichier temporaire de moins de 24 h : il peut être en cours d'utilisation
    (installation, téléchargement, application ouverte)."""
    return "temporaires" in category.lower() and time.time() - max(st.st_mtime, st.st_ctime) < 86400


def analyse(deep=False):
    res = []
    for name, roots in categories(deep).items():
        size = count = 0
        for r in roots:
            pat = "thumbcache" if r.name == "Explorer" else None
            for f in _files(r, pat):
                try:
                    st = os.stat(f)
                    if _keep_recent(name, st):
                        continue  # fichiers temporaires en cours d'utilisation
                    size += st.st_size; count += 1
                except OSError:
                    continue
        res.append({"name": name, "size": size, "count": count, "deep": name in DEEP_NAMES})
    res.append({"name": "Corbeille", "size": recycle_bin_size(), "count": None, "deep": False})
    if deep and IS_WIN:
        res.append({"name": "Composants Windows obsolètes (DISM)", "size": 0, "count": None, "deep": True,
                    "note": "taille connue après nettoyage"})
    return res


def _force_remove_tree(path):
    """Windows.old appartient à TrustedInstaller : on reprend la propriété avant suppression (admin requis)."""
    p = str(path)
    subprocess.run(["takeown", "/F", p, "/R", "/A", "/D", "O"], capture_output=True, creationflags=NO_WINDOW)
    subprocess.run(["takeown", "/F", p, "/R", "/A", "/D", "Y"], capture_output=True, creationflags=NO_WINDOW)
    subprocess.run(["icacls", p, "/grant", "*S-1-5-32-544:F", "/T", "/C", "/Q"], capture_output=True, creationflags=NO_WINDOW)
    shutil.rmtree(p, ignore_errors=True)


def clean(names, progress=None):
    freed = 0
    cats = categories(deep=True)
    for name in names:
        if progress:
            progress(f"Nettoyage : {name}…")
        if name == "Corbeille":
            freed += recycle_bin_size()
            empty_recycle_bin()
            continue
        if name.startswith("Composants Windows obsolètes"):
            if IS_WIN:
                subprocess.run(["Dism.exe", "/Online", "/Cleanup-Image", "/StartComponentCleanup"],
                               capture_output=True, creationflags=NO_WINDOW, timeout=3600)
            continue
        for r in cats.get(name, []):
            if r.name.lower() == "windows.old" and IS_WIN:
                before = sum(os.path.getsize(f) for f in _files(r) if os.path.exists(f))
                _force_remove_tree(r)
                freed += before if not r.exists() else 0
                continue
            pat = "thumbcache" if r.name == "Explorer" else None
            for f in _files(r, pat):
                try:
                    st = os.stat(f)
                    if _keep_recent(name, st):
                        continue
                    os.remove(f)
                    freed += st.st_size
                except OSError:
                    continue
            if pat is None and r.is_dir():
                for dirpath, dirs, _ in os.walk(r, topdown=False):
                    for d in dirs:
                        try:
                            os.rmdir(os.path.join(dirpath, d))
                        except OSError:
                            pass
    return freed


def recycle_bin_size():
    if not IS_WIN:
        return 0
    import ctypes
    from ctypes import wintypes

    class SHQUERYRBINFO(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("i64Size", ctypes.c_longlong), ("i64NumItems", ctypes.c_longlong)]
    info = SHQUERYRBINFO(); info.cbSize = ctypes.sizeof(info)
    ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
    return info.i64Size


def empty_recycle_bin():
    if IS_WIN:
        import ctypes
        ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x1 | 0x2 | 0x4)


def human(n):
    n = n or 0
    for u in ("o", "Ko", "Mo", "Go"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "o" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} To"
