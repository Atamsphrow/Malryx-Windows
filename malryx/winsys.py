"""Analyse du système Windows local : dossiers à risque, démarrage automatique, processus, clés USB."""
import os
import re
import sys
from pathlib import Path

IS_WIN = sys.platform == "win32"

try:
    import psutil  # pip install psutil
except ImportError:
    psutil = None


def risky_dirs():
    """Les endroits où les malwares se cachent le plus souvent."""
    env = os.environ.get
    home = Path.home()
    dirs = [home / "Downloads", home / "Desktop", home / "Documents", home / "Pictures"]
    if IS_WIN:
        dirs += [
            Path(env("TEMP", "")), Path(env("APPDATA", "")), Path(env("LOCALAPPDATA", "")) / "Temp",
            Path(env("PROGRAMDATA", "C:/ProgramData")),
            Path(env("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
            Path(env("PROGRAMDATA", "C:/ProgramData")) / r"Microsoft\Windows\Start Menu\Programs\StartUp",
            Path(env("PUBLIC", "C:/Users/Public")),
        ]
    else:
        dirs += [Path("/tmp"), Path("/var/tmp"), home / ".config/autostart"]
    seen, out = set(), []
    for d in dirs:
        if str(d) not in ("", ".") and d.exists() and str(d).lower() not in seen:
            seen.add(str(d).lower()); out.append(d)
    return out


def full_scan_dirs():
    if IS_WIN:
        return [Path(f"{l}:/") for l in "CDEFGHIJKLMNOPQRSTUVWXYZ" if Path(f"{l}:/").exists()]
    return [Path("/")]


def _exe_from_command(cmd):
    cmd = os.path.expandvars(cmd.strip())
    m = re.match(r'^"([^"]+)"', cmd) or re.match(r"^(\S+\.(?:exe|bat|cmd|vbs|js|ps1|dll|scr))", cmd, re.I)
    return m.group(1) if m else None


def autoruns():
    """Programmes lancés au démarrage (clés Run/RunOnce du registre)."""
    items = []
    if not IS_WIN:
        return items
    import winreg
    keys = [
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    for hname, hive, sub in keys:
        try:
            with winreg.OpenKey(hive, sub) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    items.append({"key": sub, "hive": hname, "name": name, "command": value,
                                  "exe": _exe_from_command(str(value))})
                    i += 1
        except OSError:
            continue
    return items


def running_executables():
    exes = {}
    if psutil is None:
        return exes
    for p in psutil.process_iter(["pid", "name", "exe"]):
        try:
            if p.info["exe"]:
                exes.setdefault(p.info["exe"], []).append(p.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return exes


def kill_process(exe_path):
    if psutil is None:
        return 0
    n = 0
    for p in psutil.process_iter(["exe"]):
        try:
            if p.info["exe"] and os.path.normcase(p.info["exe"]) == os.path.normcase(exe_path):
                p.kill(); n += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return n


def removable_drives():
    """Lettres des clés USB / disques amovibles (Windows)."""
    if not IS_WIN:
        return []
    import ctypes
    drives = []
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if mask & (1 << i):
            root = f"{chr(65 + i)}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(root) == 2:  # DRIVE_REMOVABLE
                drives.append(Path(root))
    return drives


def set_autostart(enable, exe_path, args="--minimized"):
    """Démarrage automatique avec Windows (clé HKCU\\...\\Run, sans droits administrateur)."""
    if not IS_WIN:
        return False
    import winreg
    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as k:
        if enable:
            winreg.SetValueEx(k, "Malryx", 0, winreg.REG_SZ, f'"{exe_path}" {args}')
        else:
            try:
                winreg.DeleteValue(k, "Malryx")
            except FileNotFoundError:
                pass
    return True


def is_admin():
    if not IS_WIN:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    import ctypes
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(exe, args=""):
    if IS_WIN:
        import ctypes
        ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, None, 1)


def defender_status():
    """État de Windows Defender (informatif)."""
    if not IS_WIN:
        return None
    import subprocess
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              "(Get-MpComputerStatus).RealTimeProtectionEnabled"],
                             capture_output=True, text=True, timeout=15, creationflags=0x08000000).stdout.strip()
        return {"True": True, "False": False}.get(out)
    except Exception:
        return None


def count_files(roots, cancel=None):
    n = 0
    for r in roots:
        for _, _, files in os.walk(r):
            n += len(files)
            if cancel and cancel():
                return n
    return n


# ---------------------------------------------------------------------------
# Éléments de démarrage : registre, dossiers Startup, tâches planifiées
# ---------------------------------------------------------------------------
def _ps_json(script, timeout=40):
    """Exécute PowerShell et renvoie le JSON produit (liste)."""
    if not IS_WIN:
        return []
    import json
    import subprocess
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                              f"[Console]::OutputEncoding=[Text.Encoding]::UTF8; {script} | ConvertTo-Json -Depth 3 -Compress"],
                             capture_output=True, text=True, encoding="utf-8", errors="ignore",
                             timeout=timeout, creationflags=0x08000000).stdout.strip()
        if not out:
            return []
        data = json.loads(out)
        return data if isinstance(data, list) else [data]
    except Exception:
        return []


def startup_folder_items():
    items = []
    env = os.environ.get
    for scope, d in (("Utilisateur", Path(env("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup"),
                     ("Tous", Path(env("PROGRAMDATA", "C:/ProgramData")) / r"Microsoft\Windows\Start Menu\Programs\StartUp")):
        if IS_WIN and d.exists():
            for f in d.iterdir():
                if f.is_file() and f.name.lower() != "desktop.ini":
                    items.append({"source": f"Dossier Démarrage ({scope})", "name": f.stem, "command": str(f),
                                  "exe": str(f), "kind": "folder", "location": str(d)})
    return items


def scheduled_tasks():
    """Tâches planifiées non-Microsoft (endroit favori des malwares pour la persistance)."""
    rows = _ps_json("Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\\Microsoft\\*'} | "
                    "Select-Object TaskName,TaskPath,State,@{n='Exe';e={($_.Actions | Select-Object -First 1).Execute}},"
                    "@{n='Args';e={($_.Actions | Select-Object -First 1).Arguments}}")
    out = []
    for r in rows:
        exe = os.path.expandvars((r.get("Exe") or "").strip('"'))
        out.append({"source": "Tâche planifiée", "name": r.get("TaskName"), "path": r.get("TaskPath"),
                    "command": f"{exe} {r.get('Args') or ''}".strip(), "exe": exe or None,
                    "state": str(r.get("State")), "kind": "task"})
    return out


def all_startup_items(include_tasks=True):
    items = []
    for a in autoruns():
        a.update({"source": "Registre " + ("HKCU" if a["hive"] == "HKCU" else "HKLM"), "kind": "registry"})
        items.append(a)
    items += startup_folder_items()
    items += disabled_autoruns()
    if include_tasks:
        items += scheduled_tasks()
    return items


_RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
_BACKUP = r"Software\Malryx\DisabledAutoruns"


def disabled_autoruns():
    if not IS_WIN:
        return []
    import winreg
    out = []
    for hive_name in ("HKCU", "HKLM"):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _BACKUP + "\\" + hive_name) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    out.append({"source": f"Registre {hive_name}", "name": name, "command": value, "hive": hive_name,
                                "exe": _exe_from_command(str(value)), "kind": "registry", "disabled": True, "key": _RUN})
                    i += 1
        except OSError:
            pass
    disabled_dir = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Malryx" / "demarrage_desactive"
    if disabled_dir.exists():
        for f in disabled_dir.iterdir():
            out.append({"source": "Dossier Démarrage", "name": f.stem, "command": str(f), "exe": str(f),
                        "kind": "folder", "disabled": True})
    return out


def set_startup_item(item, enable):
    """Active / désactive un élément de démarrage (réversible)."""
    if not IS_WIN:
        return False
    import shutil
    import subprocess
    import winreg
    if item["kind"] == "registry":
        hive = winreg.HKEY_CURRENT_USER if item.get("hive") == "HKCU" else winreg.HKEY_LOCAL_MACHINE
        bk = _BACKUP + "\\" + item.get("hive", "HKCU")
        if enable:
            with winreg.CreateKey(hive, item.get("key", _RUN)) as k:
                winreg.SetValueEx(k, item["name"], 0, winreg.REG_SZ, item["command"])
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, bk, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, item["name"])
        else:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, bk) as k:
                winreg.SetValueEx(k, item["name"], 0, winreg.REG_SZ, item["command"])
            with winreg.OpenKey(hive, item.get("key", _RUN), 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, item["name"])
        return True
    if item["kind"] == "folder":
        disabled_dir = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Malryx" / "demarrage_desactive"
        disabled_dir.mkdir(parents=True, exist_ok=True)
        src = Path(item["command"])
        if enable:
            dest = Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup" / src.name
        else:
            dest = disabled_dir / src.name
        shutil.move(str(src), str(dest))
        return True
    if item["kind"] == "task":
        flag = "/ENABLE" if enable else "/DISABLE"
        tn = (item.get("path") or "\\") + item["name"]
        r = subprocess.run(["schtasks", "/Change", "/TN", tn, flag], capture_output=True, creationflags=0x08000000)
        return r.returncode == 0
    return False


def startup_snapshot():
    """Signature de l'état du démarrage (pour détecter les nouveaux éléments)."""
    return {f"{i['source']}|{i['name']}": i for i in autoruns_with_source() + startup_folder_items()}


def autoruns_with_source():
    out = []
    for a in autoruns():
        a.update({"source": "Registre " + a["hive"], "kind": "registry"})
        out.append(a)
    return out


# ---------------------------------------------------------------------------
# Registre : détournements classiques (Winlogon, IFEO, AppInit_DLLs)
# ---------------------------------------------------------------------------
REG_CHECKS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", "explorer.exe"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit", "C:\\Windows\\system32\\userinit.exe,"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", ""),
    ("HKCU", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", None),
]
IFEO = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
SENSITIVE_IFEO = {"taskmgr.exe", "regedit.exe", "msconfig.exe", "cmd.exe", "explorer.exe", "msmpeng.exe",
                  "mbam.exe", "sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "procexp.exe"}


def registry_findings():
    """Renvoie la liste des modifications suspectes du registre."""
    if not IS_WIN:
        return []
    import winreg
    hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
    found = []
    for hive, key, value, expected in REG_CHECKS:
        try:
            with winreg.OpenKey(hives[hive], key) as k:
                v, _ = winreg.QueryValueEx(k, value)
        except OSError:
            continue
        v = str(v).strip()
        if expected is None:  # la valeur ne devrait pas exister
            found.append({"hive": hive, "key": key, "value": value, "data": v, "fix": "delete",
                          "reason": f"{value} redéfini pour l'utilisateur ({v})"})
        elif v.lower().rstrip(",") != expected.lower().rstrip(",") and v:
            found.append({"hive": hive, "key": key, "value": value, "data": v, "fix": expected,
                          "reason": f"{value} modifié : « {v} » au lieu de « {expected or '(vide)'} »"})
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, IFEO) as k:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(k, sub) as sk:
                        dbg, _ = winreg.QueryValueEx(sk, "Debugger")
                        sev = "élevé" if sub.lower() in SENSITIVE_IFEO else "moyen"
                        found.append({"hive": "HKLM", "key": IFEO + "\\" + sub, "value": "Debugger", "data": dbg,
                                      "fix": "delete", "severity": sev,
                                      "reason": f"Détournement IFEO de {sub} vers « {dbg} »"})
                except OSError:
                    continue
    except OSError:
        pass
    return found


def fix_registry(f):
    import winreg
    hive = winreg.HKEY_LOCAL_MACHINE if f["hive"] == "HKLM" else winreg.HKEY_CURRENT_USER
    with winreg.OpenKey(hive, f["key"], 0, winreg.KEY_SET_VALUE) as k:
        if f["fix"] == "delete":
            winreg.DeleteValue(k, f["value"])
        else:
            winreg.SetValueEx(k, f["value"], 0, winreg.REG_SZ, f["fix"])
    return True


# ---------------------------------------------------------------------------
# Processus
# ---------------------------------------------------------------------------
def process_list():
    out = []
    if psutil is None:
        return out
    for p in psutil.process_iter(["pid", "name", "exe", "username", "memory_info", "create_time"]):
        try:
            mem = p.info["memory_info"].rss / 1e6 if p.info["memory_info"] else 0
            out.append({"pid": p.info["pid"], "name": p.info["name"], "exe": p.info["exe"] or "",
                        "user": (p.info["username"] or "").split("\\")[-1], "mem": mem})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sorted(out, key=lambda x: -x["mem"])


def kill_pid(pid):
    if psutil is None:
        return False
    try:
        psutil.Process(pid).kill()
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def open_location(path):
    import subprocess
    if IS_WIN:
        subprocess.Popen(["explorer", "/select,", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(Path(path).parent)])


def open_uri(uri):
    if IS_WIN:
        os.startfile(uri)


def open_folder(path):
    import subprocess
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    if IS_WIN:
        os.startfile(str(path))
    else:
        subprocess.Popen(["xdg-open", str(path)])


def set_explorer_menu(enable, command):
    """Ajoute « Analyser avec Malryx » au clic droit (fichiers, dossiers, lecteurs). HKCU : pas besoin d'admin."""
    if not IS_WIN:
        return False
    import winreg
    icon_path = command.split('"')[1] if command.startswith('"') else command
    for base in (r"Software\Classes\*\shell\Malryx", r"Software\Classes\Directory\shell\Malryx",
                 r"Software\Classes\Drive\shell\Malryx"):
        if enable:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base) as k:
                winreg.SetValueEx(k, "MUIVerb", 0, winreg.REG_SZ, "Analyser avec Malryx")
                winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, icon_path)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r"\command") as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, f'{command} --scan "%1"')
        else:
            for sub in (base + r"\command", base):
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
                except OSError:
                    pass
    return True
