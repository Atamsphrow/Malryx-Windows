"""Libération d'espace : doublons, gros fichiers oubliés, restes de désinstallation.

Toutes les suppressions passent par la Corbeille (récupérables), sauf mention contraire.
Les restes de désinstallation sont sauvegardés (dossiers déplacés + export .reg) avant suppression.
"""
import hashlib
import os
import re
import shutil
import subprocess
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from .paths import IS_WIN, data_dir

SKIP_DIRS = {"appdata", "$recycle.bin", "system volume information", "node_modules", ".git", "__pycache__",
             "windows", "program files", "program files (x86)", "programdata", ".cache", "venv", ".venv"}


def user_roots():
    home = Path.home()
    roots = [home / d for d in ("Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music", "OneDrive")]
    return [r for r in roots if r.exists()]


def _walk(roots, cancel=None):
    for root in roots:
        for dirpath, dirs, files in os.walk(root):
            if cancel and cancel():
                return
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS and not d.startswith(".")]
            for fn in files:
                p = os.path.join(dirpath, fn)
                try:
                    st = os.stat(p, follow_symlinks=False)
                except OSError:
                    continue
                yield p, st


# ---------------------------------------------------------------------------- doublons
def _hash(path, limit=None):
    h = hashlib.blake2b(digest_size=20)
    with open(path, "rb") as f:
        if limit:
            h.update(f.read(limit))
        else:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    return h.hexdigest()


def find_duplicates(roots=None, min_size=1024 * 100, progress=None, cancel=None):
    """Groupes de fichiers identiques : taille → empreinte des 64 premiers Ko → empreinte complète."""
    by_size = defaultdict(list)
    n = 0
    for p, st in _walk(roots or user_roots(), cancel):
        if st.st_size >= min_size:
            by_size[st.st_size].append((p, st.st_mtime))
        n += 1
        if progress and n % 2000 == 0:
            progress(f"{n} fichiers inventoriés…")
    groups = []
    candidates = [v for v in by_size.values() if len(v) > 1]
    for i, files in enumerate(candidates):
        if cancel and cancel():
            break
        if progress and i % 20 == 0:
            progress(f"Comparaison {i}/{len(candidates)}…")
        partial = defaultdict(list)
        for p, mt in files:
            try:
                partial[_hash(p, 65536)].append((p, mt))
            except OSError:
                continue
        for same in partial.values():
            if len(same) < 2:
                continue
            full = defaultdict(list)
            for p, mt in same:
                try:
                    full[_hash(p)].append((p, mt))
                except OSError:
                    continue
            for g in full.values():
                if len(g) > 1:
                    g.sort(key=lambda x: x[1])  # le plus ancien = l'original conservé
                    size = os.path.getsize(g[0][0])
                    groups.append({"size": size, "files": [x[0] for x in g], "keep": g[0][0],
                                   "waste": size * (len(g) - 1)})
    return sorted(groups, key=lambda g: -g["waste"])


# ---------------------------------------------------------------------------- gros fichiers
def find_big_files(roots=None, min_mb=200, limit=300, progress=None, cancel=None):
    roots = roots or ([Path.home()] if not IS_WIN else [Path.home()] + [Path(f"{d}:/") for d in "DEFGH" if Path(f"{d}:/").exists()])
    out, n = [], 0
    now = time.time()
    for p, st in _walk(roots, cancel):
        n += 1
        if progress and n % 5000 == 0:
            progress(f"{n} fichiers parcourus…")
        if st.st_size >= min_mb * 1024 * 1024:
            last = max(st.st_mtime, st.st_atime)
            out.append({"path": p, "size": st.st_size, "modified": st.st_mtime,
                        "age_days": int((now - last) / 86400)})
    out.sort(key=lambda x: -x["size"])
    return out[:limit]


# ---------------------------------------------------------------------------- corbeille
def recycle(paths):
    """Envoie vers la Corbeille (Windows) ; sinon suppression classique. Renvoie (ok, erreurs)."""
    paths = [str(p) for p in paths if os.path.exists(p)]
    if not paths:
        return 0, []
    if IS_WIN:
        import ctypes
        from ctypes import wintypes

        class SHFILEOPSTRUCTW(ctypes.Structure):
            _fields_ = [("hwnd", wintypes.HWND), ("wFunc", wintypes.UINT), ("pFrom", wintypes.LPCWSTR),
                        ("pTo", wintypes.LPCWSTR), ("fFlags", ctypes.c_ushort), ("fAnyOperationsAborted", wintypes.BOOL),
                        ("hNameMappings", ctypes.c_void_p), ("lpszProgressTitle", wintypes.LPCWSTR)]
        ok, errors = 0, []
        for p in paths:  # un par un pour savoir lesquels ont échoué
            op = SHFILEOPSTRUCTW(None, 3, os.path.abspath(p) + "\0\0", None, 0x0040 | 0x0010 | 0x0004 | 0x0400, False, None, None)
            if ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op)) == 0 and not os.path.exists(p):
                ok += 1
            else:
                errors.append(p)
        return ok, errors
    ok, errors = 0, []
    for p in paths:
        try:
            shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
            ok += 1
        except OSError:
            errors.append(p)
    return ok, errors


# ---------------------------------------------------------------------------- restes de désinstallation
KEEP_NAMES = {
    "microsoft", "windows", "windowsapps", "packages", "common files", "internet explorer", "windows defender",
    "windows nt", "windows mail", "windows media player", "windows photo viewer", "windows portable devices",
    "windows sidebar", "windowspowershell", "reference assemblies", "msbuild", "dotnet", "microsoft.net",
    "intel", "amd", "nvidia", "nvidia corporation", "realtek", "temp", "comms", "connecteddevicesplatform",
    "d3dscache", "crashdumps", "virtualstore", "programs", "publishers", "package cache", "regid.1991-06.com.microsoft",
    "ssh", "usoshared", "uso", "soft", "malryx", "google", "mozilla", "adobe", "apple", "oracle", "java", "python",
    "pip", "npm", "nuget", "jetbrains", "github", "zoom", "steam", "epic games", "chocolatey", "winget", "docker",
    "git", "code", "visual studio", "dell", "hp", "lenovo", "asus", "acer", "msi", "logitech", "synaptics",
    "elevateddiagnostics", "history", "identities", "fontcache", "squirreltemp", "cache", "diagnostics", "device stage",
    "desktop.ini", "default", "all users", "public", "application data", "start menu", "templates", "favorites",
}


def installed_programs():
    if not IS_WIN:
        return []
    import winreg
    out = []
    for hive, key in ((winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                      (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                      (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")):
        try:
            with winreg.OpenKey(hive, key) as k:
                for i in range(winreg.QueryInfoKey(k)[0]):
                    try:
                        with winreg.OpenKey(k, winreg.EnumKey(k, i)) as sk:
                            def val(n):
                                try:
                                    return str(winreg.QueryValueEx(sk, n)[0])
                                except OSError:
                                    return ""
                            name = val("DisplayName")
                            if name:
                                out.append({"name": name, "publisher": val("Publisher"), "location": val("InstallLocation"),
                                            "version": val("DisplayVersion")})
                    except OSError:
                        continue
        except OSError:
            continue
    return out


def _tokens(text):
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= 4}


def _dir_size(p):
    total = 0
    for dirpath, _, files in os.walk(p):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(dirpath, f))
            except OSError:
                pass
    return total


def find_leftovers(progress=None, cancel=None):
    """Dossiers et clés de registre de logiciels qui ne sont plus installés (approche prudente)."""
    if not IS_WIN:
        return []
    progs = installed_programs()
    known = set()
    locations = set()
    for p in progs:
        known |= _tokens(p["name"]) | _tokens(p["publisher"])
        if p["location"]:
            locations.add(os.path.normcase(p["location"].rstrip("\\/")))
    try:
        import psutil
        running = {os.path.normcase(os.path.dirname(x.info["exe"])) for x in psutil.process_iter(["exe"]) if x.info["exe"]}
    except Exception:
        running = set()

    env = os.environ.get
    bases = [Path(env("ProgramFiles", r"C:\Program Files")), Path(env("ProgramFiles(x86)", r"C:\Program Files (x86)")),
             Path(env("ProgramData", r"C:\ProgramData")), Path(env("APPDATA", "")), Path(env("LOCALAPPDATA", ""))]
    found = []
    now = time.time()
    for base in bases:
        if not base.exists() or str(base) in ("", "."):
            continue
        if progress:
            progress(f"Analyse de {base}…")
        try:
            entries = list(base.iterdir())
        except OSError:
            continue
        for d in entries:
            if cancel and cancel():
                return found
            if not d.is_dir():
                continue
            low = d.name.lower()
            if low in KEEP_NAMES or low.startswith((".", "microsoft", "windows", "{")) or _tokens(d.name) & known:
                continue
            nd = os.path.normcase(str(d))
            if any(loc.startswith(nd) or nd.startswith(loc) for loc in locations):
                continue
            if any(r.startswith(nd) for r in running):
                continue
            try:
                mtime = max((e.stat().st_mtime for e in d.rglob("*") if e.is_file()), default=d.stat().st_mtime)
            except OSError:
                continue
            if now - mtime < 90 * 86400:
                continue  # utilisé récemment : probablement encore utile
            size = _dir_size(d)
            found.append({"kind": "dossier", "path": str(d), "size": size,
                          "age_days": int((now - mtime) / 86400)})
    # clés HKCU\Software\<Éditeur> orphelines
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software") as k:
            for i in range(winreg.QueryInfoKey(k)[0]):
                name = winreg.EnumKey(k, i)
                low = name.lower()
                if low in KEEP_NAMES or low.startswith(("microsoft", "windows", "classes", "policies", "wow6432", "appdatalow",
                                                         "clients", "registeredapplications", "malryx")):
                    continue
                if _tokens(name) & known or not _tokens(name):
                    continue
                found.append({"kind": "registre", "path": f"HKCU\\Software\\{name}", "size": 0, "age_days": None})
    except OSError:
        pass
    return sorted(found, key=lambda x: -x["size"])


def remove_leftovers(items):
    """Sauvegarde puis supprime. Dossiers → Corbeille ; registre → export .reg dans le dossier de Malryx."""
    backup = data_dir("sauvegardes_restes")
    ok, errors = 0, []
    folders = [i["path"] for i in items if i["kind"] == "dossier"]
    n, errs = recycle(folders)
    ok += n; errors += errs
    for it in items:
        if it["kind"] != "registre":
            continue
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", it["path"])
        reg_file = backup / f"{datetime.now():%Y%m%d_%H%M%S}_{safe}.reg"
        exp = subprocess.run(["reg", "export", it["path"], str(reg_file), "/y"], capture_output=True, creationflags=0x08000000)
        if exp.returncode != 0:
            errors.append(it["path"]); continue
        rm = subprocess.run(["reg", "delete", it["path"], "/f"], capture_output=True, creationflags=0x08000000)
        if rm.returncode == 0:
            ok += 1
        else:
            errors.append(it["path"])
    return ok, errors
