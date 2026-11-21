"""Confidentialité : traces de navigation, télémétrie et publicités Windows, accès webcam/micro,
destructeur de fichiers."""
import json
import os
import secrets
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

from .paths import IS_WIN, data_dir

NO_WINDOW = 0x08000000 if IS_WIN else 0

try:
    import psutil
except ImportError:
    psutil = None


# ---------------------------------------------------------------------------- navigateurs
def _chromium(name, base, exe):
    return {"name": name, "base": Path(base), "exe": exe, "kind": "chromium"}


def browsers():
    la, ra = Path(os.environ.get("LOCALAPPDATA", "")), Path(os.environ.get("APPDATA", ""))
    if not IS_WIN:
        la = Path.home() / ".config"
    lst = [
        _chromium("Google Chrome", la / r"Google\Chrome\User Data" if IS_WIN else la / "google-chrome", "chrome.exe"),
        _chromium("Microsoft Edge", la / r"Microsoft\Edge\User Data" if IS_WIN else la / "microsoft-edge", "msedge.exe"),
        _chromium("Brave", la / r"BraveSoftware\Brave-Browser\User Data", "brave.exe"),
        _chromium("Opera", ra / r"Opera Software\Opera Stable", "opera.exe"),
        {"name": "Mozilla Firefox", "base": ra / r"Mozilla\Firefox\Profiles" if IS_WIN else Path.home() / ".mozilla/firefox",
         "exe": "firefox.exe", "kind": "firefox"},
    ]
    return [b for b in lst if b["base"].exists()]


TRACE_FILES = {
    "chromium": {"Historique": ["History", "History-journal", "Visited Links", "Top Sites", "Top Sites-journal", "Shortcuts"],
                 "Cookies": ["Network/Cookies", "Network/Cookies-journal", "Cookies", "Cookies-journal"],
                 "Cache": ["Cache", "Code Cache", "GPUCache", "Service Worker/CacheStorage"],
                 "Sessions": ["Sessions", "Current Session", "Last Session", "Current Tabs", "Last Tabs"]},
    "firefox": {"Historique": ["places.sqlite", "places.sqlite-wal", "formhistory.sqlite"],
                "Cookies": ["cookies.sqlite", "cookies.sqlite-wal"],
                "Cache": ["cache2", "startupCache", "thumbnails"],
                "Sessions": ["sessionstore.jsonlz4", "sessionstore-backups"]},
}
# Firefox : places.sqlite contient aussi les favoris → on ne supprime que l'historique via SQL
FIREFOX_HISTORY_SQL = ("DELETE FROM moz_historyvisits; DELETE FROM moz_places WHERE id NOT IN "
                       "(SELECT fk FROM moz_bookmarks WHERE fk IS NOT NULL);")


def _profiles(b):
    if b["kind"] == "firefox":
        return [p for p in b["base"].iterdir() if p.is_dir()]
    if b["name"] == "Opera":
        return [b["base"]]
    return [p for p in b["base"].iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile "))]


def _size(p):
    if p.is_file():
        return p.stat().st_size
    total = 0
    for dp, _, fs in os.walk(p):
        for f in fs:
            try:
                total += os.path.getsize(os.path.join(dp, f))
            except OSError:
                pass
    return total


def browser_running(b):
    if psutil is None:
        return False
    return any((p.info["name"] or "").lower() == b["exe"] for p in psutil.process_iter(["name"]))


def browser_traces():
    out = []
    for b in browsers():
        entry = {"browser": b["name"], "running": browser_running(b), "items": {}}
        for kind, names in TRACE_FILES[b["kind"]].items():
            size = 0
            for prof in _profiles(b):
                for n in names:
                    p = prof / n
                    if p.exists():
                        size += _size(p)
            entry["items"][kind] = size
        out.append(entry)
    return out


def clean_browser(browser_name, kinds):
    b = next((x for x in browsers() if x["name"] == browser_name), None)
    if not b:
        return 0
    if browser_running(b):
        raise RuntimeError(f"Fermez {browser_name} avant de nettoyer ses traces.")
    freed = 0
    import shutil
    for prof in _profiles(b):
        for kind in kinds:
            for n in TRACE_FILES[b["kind"]].get(kind, []):
                p = prof / n
                if not p.exists():
                    continue
                if b["kind"] == "firefox" and n == "places.sqlite":
                    import sqlite3
                    before = p.stat().st_size
                    try:
                        con = sqlite3.connect(str(p))
                        con.executescript(FIREFOX_HISTORY_SQL)
                        con.commit(); con.execute("VACUUM"); con.close()
                        freed += max(0, before - p.stat().st_size)
                    except sqlite3.Error:
                        pass
                    continue
                try:
                    s = _size(p)
                    shutil.rmtree(p) if p.is_dir() else p.unlink()
                    freed += s
                except OSError:
                    continue
    return freed


# ---------------------------------------------------------------------------- télémétrie / publicités
CDM = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
TWEAKS = [
    # id, titre, description, ruche, clé, valeur, donnée « privée », admin
    ("ads_id", "Identifiant publicitaire", "Les applications ne peuvent plus vous suivre pour vous montrer des publicités ciblées.",
     "HKCU", r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0, False),
    ("tailored", "Expériences personnalisées", "Microsoft n'utilise plus vos données de diagnostic pour des conseils et publicités.",
     "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", 0, False),
    ("tips", "Suggestions et publicités dans Windows", "Plus de suggestions d'applications dans le menu Démarrer ni d'astuces publicitaires.",
     "HKCU", CDM, "SystemPaneSuggestionsEnabled", 0, False),
    ("tips2", "Applications installées sans demander", "Windows n'installe plus d'applications « suggérées » en arrière-plan.",
     "HKCU", CDM, "SilentInstalledAppsEnabled", 0, False),
    ("lock_ads", "Publicités sur l'écran de verrouillage", "Désactive les astuces et publicités de l'écran de verrouillage.",
     "HKCU", CDM, "RotatingLockScreenOverlayEnabled", 0, False),
    ("settings_ads", "Contenu suggéré dans les Paramètres", "Plus de contenu promotionnel dans l'application Paramètres.",
     "HKCU", CDM, "SubscribedContent-338393Enabled", 0, False),
    ("track_progs", "Suivi des lancements d'applications", "Windows ne mémorise plus les applications que vous ouvrez.",
     "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Start_TrackProgs", 0, False),
    ("feedback", "Demandes de commentaires", "Windows ne vous demande plus votre avis.",
     "HKCU", r"Software\Microsoft\Siuf\Rules", "NumberOfSIUFInPeriod", 0, False),
    ("telemetry", "Télémétrie Windows (niveau minimal)", "Réduit les données de diagnostic envoyées à Microsoft au minimum autorisé.",
     "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0, True),
    ("activity", "Historique des activités", "Windows n'enregistre plus l'historique de vos activités.",
     "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", 0, True),
    ("diagtrack", "Service de télémétrie (DiagTrack)", "Arrête et désactive le service « Expériences des utilisateurs connectés et télémétrie ».",
     "SERVICE", "DiagTrack", None, None, True),
]
BACKUP = data_dir("confidentialite_sauvegarde.json")


def _hive(h):
    import winreg
    return winreg.HKEY_CURRENT_USER if h == "HKCU" else winreg.HKEY_LOCAL_MACHINE


def _read(h, key, name):
    import winreg
    try:
        with winreg.OpenKey(_hive(h), key) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def _service_start(name):
    v = _read("HKLM", rf"SYSTEM\CurrentControlSet\Services\{name}", "Start")
    return v  # 2 auto, 3 manuel, 4 désactivé


def tweak_states():
    if not IS_WIN:
        return [{"id": t[0], "title": t[1], "desc": t[2], "admin": t[7], "applied": False, "available": False} for t in TWEAKS]
    out = []
    for tid, title, desc, hive, key, name, private, admin in TWEAKS:
        if hive == "SERVICE":
            st = _service_start(key)
            applied, avail = st == 4, st is not None
        else:
            cur = _read(hive, key, name)
            applied, avail = cur == private, True
        out.append({"id": tid, "title": title, "desc": desc, "admin": admin, "applied": applied, "available": avail})
    return out


def apply_tweak(tid, enable=True):
    """enable=True : réglage confidentiel ; False : restaure la valeur d'origine sauvegardée."""
    import winreg
    t = next(x for x in TWEAKS if x[0] == tid)
    _, _, _, hive, key, name, private, _ = t
    backup = json.loads(BACKUP.read_text(encoding="utf-8")) if BACKUP.exists() else {}
    if hive == "SERVICE":
        if enable:
            backup.setdefault(tid, _service_start(key))
            subprocess.run(["sc", "stop", key], capture_output=True, creationflags=NO_WINDOW)
            r = subprocess.run(["sc", "config", key, "start=", "disabled"], capture_output=True, creationflags=NO_WINDOW)
        else:
            mode = {2: "auto", 3: "demand"}.get(backup.pop(tid, 2) or 2, "auto")
            r = subprocess.run(["sc", "config", key, "start=", mode], capture_output=True, creationflags=NO_WINDOW)
            subprocess.run(["sc", "start", key], capture_output=True, creationflags=NO_WINDOW)
        if r.returncode != 0:
            raise PermissionError("droits administrateur requis")
    else:
        if enable:
            backup.setdefault(tid, _read(hive, key, name))
            with winreg.CreateKeyEx(_hive(hive), key, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, private)
        else:
            old = backup.pop(tid, None)
            with winreg.CreateKeyEx(_hive(hive), key, 0, winreg.KEY_SET_VALUE) as k:
                if old is None:
                    try:
                        winreg.DeleteValue(k, name)
                    except OSError:
                        pass
                else:
                    winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(old))
    BACKUP.write_text(json.dumps(backup, indent=2), encoding="utf-8")
    return True


# ---------------------------------------------------------------------------- webcam / micro
CAP = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"


def _filetime(v):
    if not v:
        return None
    return datetime.fromtimestamp((v - 116444736000000000) / 1e7)


def device_access(device):
    """Applications ayant utilisé « webcam » ou « microphone » (registre CapabilityAccessManager)."""
    if not IS_WIN:
        return []
    import winreg
    out = []

    def scan(root, sub, packaged):
        try:
            with winreg.OpenKey(root, sub) as k:
                for i in range(winreg.QueryInfoKey(k)[0]):
                    name = winreg.EnumKey(k, i)
                    if name == "NonPackaged":
                        continue
                    try:
                        with winreg.OpenKey(k, name) as ak:
                            start = winreg.QueryValueEx(ak, "LastUsedTimeStart")[0]
                            stop = winreg.QueryValueEx(ak, "LastUsedTimeStop")[0]
                    except OSError:
                        continue
                    app = name.replace("#", "\\") if not packaged else name.split("_")[0]
                    out.append({"app": app, "name": Path(app).name if not packaged else app,
                                "in_use": bool(start) and stop == 0, "last": _filetime(stop or start)})
        except OSError:
            pass
    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        scan(root, rf"{CAP}\{device}", True)
        scan(root, rf"{CAP}\{device}\NonPackaged", False)
    out.sort(key=lambda x: (not x["in_use"], -(x["last"].timestamp() if x["last"] else 0)))
    return out


class DeviceMonitor:
    """Alerte dès qu'une application commence à utiliser la caméra ou le micro."""

    def __init__(self, settings, emit):
        self.settings, self.emit = settings, emit
        self.stop_evt = threading.Event()
        self.active = set()

    def _loop(self):
        while not self.stop_evt.is_set():
            if self.settings["camera_monitor"]:
                now = set()
                for dev, label in (("webcam", "caméra"), ("microphone", "micro")):
                    for a in device_access(dev):
                        if a["in_use"]:
                            key = (dev, a["app"])
                            now.add(key)
                            allowed = a["name"].lower() in {x.lower() for x in self.settings["camera_allowed"]}
                            if key not in self.active and not allowed:
                                self.emit("device_access", {"device": label, "app": a["app"], "name": a["name"]})
                self.active = now
            self.stop_evt.wait(3)

    def start(self):
        if IS_WIN:
            self.stop_evt.clear()
            threading.Thread(target=self._loop, daemon=True, name="device-monitor").start()

    def stop(self):
        self.stop_evt.set()


# ---------------------------------------------------------------------------- destructeur
def is_ssd(path):
    if not IS_WIN:
        return False
    from . import winsys
    drive = os.path.splitdrive(os.path.abspath(path))[0].rstrip(":")
    rows = winsys._ps_json(f"(Get-Partition -DriveLetter {drive} | Get-Disk | Get-PhysicalDisk).MediaType", timeout=20)
    return any(str(r) in ("SSD", "4") for r in rows)


def shred(paths, passes=1, progress=None):
    """Écrase le contenu (données aléatoires), renomme, tronque puis supprime. Renvoie (fichiers, erreurs)."""
    files = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            files += [Path(dp) / f for dp, _, fs in os.walk(p) for f in fs]
        elif p.exists():
            files.append(p)
    done, errors = 0, []
    for i, f in enumerate(files):
        if progress:
            progress(f"Destruction {i + 1}/{len(files)} : {f.name}")
        try:
            size = f.stat().st_size
            with open(f, "r+b", buffering=0) as fh:
                for _ in range(max(1, passes)):
                    fh.seek(0)
                    left = size
                    while left > 0:
                        n = min(left, 1 << 20)
                        fh.write(secrets.token_bytes(n))
                        left -= n
                    os.fsync(fh.fileno())
                fh.truncate(0)
            new = f.with_name(secrets.token_hex(8))
            f.rename(new)
            new.unlink()
            done += 1
        except OSError as e:
            errors.append(f"{f} ({e})")
    for p in paths:  # dossiers vides restants
        p = Path(p)
        if p.is_dir():
            for dp, dirs, _ in os.walk(p, topdown=False):
                for d in dirs:
                    try:
                        os.rmdir(os.path.join(dp, d))
                    except OSError:
                        pass
            try:
                p.rmdir()
            except OSError:
                pass
    return done, errors
