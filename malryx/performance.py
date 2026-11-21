"""Performances : temps de démarrage, impact des programmes au démarrage, mode veille des applications,
mise à jour des logiciels (winget), santé du disque et du système."""
import os
import re
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

from . import winsys
from .paths import IS_WIN

try:
    import psutil
except ImportError:
    psutil = None

NO_WINDOW = 0x08000000 if IS_WIN else 0


# ---------------------------------------------------------------------------- démarrage
def boot_info():
    """Durée des derniers démarrages (journal Diagnostics-Performance, admin) + allumé depuis."""
    info = {"uptime_h": None, "boot_ms": [], "last_boot": None}
    if psutil:
        bt = psutil.boot_time()
        info["last_boot"] = datetime.fromtimestamp(bt).isoformat(timespec="minutes")
        info["uptime_h"] = round((time.time() - bt) / 3600, 1)
    if IS_WIN:
        rows = winsys._ps_json(
            "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Diagnostics-Performance/Operational';Id=100} "
            "-MaxEvents 5 -ErrorAction SilentlyContinue | ForEach-Object { $x=[xml]$_.ToXml(); "
            "[pscustomobject]@{Date=$_.TimeCreated.ToString('s'); Ms=[int]($x.Event.EventData.Data | Where-Object Name -eq 'BootTime').'#text'} }")
        info["boot_ms"] = [r for r in rows if r.get("Ms")]
    return info


def startup_impact(items):
    """Impact estimé de chaque élément de démarrage (CPU consommé depuis l'ouverture de session, mémoire, taille)."""
    procs = {}
    if psutil:
        for p in psutil.process_iter(["exe", "cpu_times", "memory_info"]):
            try:
                exe = os.path.normcase(p.info["exe"] or "")
                if exe:
                    cpu = sum(p.info["cpu_times"][:2]) if p.info["cpu_times"] else 0
                    mem = p.info["memory_info"].rss if p.info["memory_info"] else 0
                    c, m = procs.get(exe, (0, 0))
                    procs[exe] = (c + cpu, m + mem)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    out = []
    for it in items:
        exe = os.path.normcase(it.get("exe") or "")
        cpu, mem = procs.get(exe, (0, 0))
        try:
            size = os.path.getsize(exe) if exe else 0
        except OSError:
            size = 0
        score = cpu / 10 + mem / 50e6 + size / 30e6
        impact = "Élevé" if score > 6 else "Moyen" if score > 2 else "Faible" if exe else "Inconnu"
        out.append({**it, "impact": impact, "cpu_s": round(cpu, 1), "mem_mb": round(mem / 1e6), "running": exe in procs})
    return out


# ---------------------------------------------------------------------------- mode veille
PROTECTED_PROCS = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "svchost.exe", "explorer.exe", "dwm.exe", "fontdrvhost.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe",
    "searchhost.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe", "runtimebroker.exe", "msmpeng.exe",
    "audiodg.exe", "conhost.exe", "malryx.exe", "python.exe", "pythonw.exe", "clamd.exe", "adb.exe", "spoolsv.exe",
    "securityhealthsystray.exe", "securityhealthservice.exe", "textinputhost.exe", "lockapp.exe", "nvcontainer.exe",
    "rtkauduservice64.exe", "systemsettings.exe", "applicationframehost.exe", "widgets.exe", "onedrive.exe",
    "spotify.exe", "vlc.exe", "teams.exe", "ms-teams.exe", "zoom.exe", "discord.exe", "obs64.exe",
}


class SleepManager:
    """Suspend les applications inactives gourmandes et les réveille dès qu'on revient dessus."""

    def __init__(self, settings, emit):
        self.settings, self.emit = settings, emit
        self.sleeping = {}          # pid -> {"name", "exe", "mem", "since"}
        self.idle_since = {}
        self._cpu_prev = {}         # pid -> (temps CPU cumulé, horodatage) pour mesurer l'activité réelle
        self.stop_evt = threading.Event()
        self.thread = None
        self.my_pid = os.getpid()

    def _foreground_pid(self):
        if not IS_WIN:
            return None
        import ctypes
        from ctypes import wintypes
        hwnd = ctypes.windll.user32.GetForegroundWindow()
        pid = wintypes.DWORD()
        ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return pid.value

    def candidates(self):
        """Applications d'arrière-plan qui consomment de la mémoire sans rien faire."""
        out = []
        if psutil is None:
            return out
        fg = self._foreground_pid()
        user = None
        try:
            user = psutil.Process(self.my_pid).username()
        except Exception:
            pass
        wl = {w.lower() for w in self.settings["sleep_whitelist"]}
        for p in psutil.process_iter(["pid", "name", "exe", "memory_info", "username", "status"]):
            try:
                name = (p.info["name"] or "").lower()
                if (p.pid in (self.my_pid, fg) or name in PROTECTED_PROCS or name in wl or not p.info["exe"]
                        or (user and p.info["username"] != user) or p.pid in self.sleeping):
                    continue
                if p.info["exe"].lower().startswith(("c:\\windows\\",)):
                    continue
                mem = p.info["memory_info"].rss if p.info["memory_info"] else 0
                if mem < 150e6:
                    continue
                now = time.time()
                t = sum(p.cpu_times()[:2])
                prev = self._cpu_prev.get(p.pid)
                self._cpu_prev[p.pid] = (t, now)
                cpu = (t - prev[0]) / max(0.1, now - prev[1]) * 100 if prev else None  # None = pas encore mesuré
                out.append({"pid": p.pid, "name": p.info["name"], "exe": p.info["exe"], "mem": mem, "cpu": cpu})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        # regroupe par application (ex. 20 processus Chrome)
        apps = {}
        for c in out:
            a = apps.setdefault(c["name"].lower(), {"name": c["name"], "exe": c["exe"], "pids": [], "mem": 0, "cpu": 0})
            a["pids"].append(c["pid"]); a["mem"] += c["mem"]
            a["cpu"] = None if c["cpu"] is None or a["cpu"] is None else a["cpu"] + c["cpu"]
        return sorted(apps.values(), key=lambda a: -a["mem"])

    def sleep_app(self, app):
        n = 0
        for pid in app["pids"]:
            try:
                psutil.Process(pid).suspend()
                self.sleeping[pid] = {"name": app["name"], "exe": app["exe"], "since": time.time(),
                                      "mem": app["mem"] / max(1, len(app["pids"]))}
                n += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return n

    def wake(self, name=None, pid=None):
        for p, info in list(self.sleeping.items()):
            if (name and info["name"].lower() == name.lower()) or p == pid or (name is None and pid is None):
                try:
                    psutil.Process(p).resume()
                except Exception:
                    pass
                self.sleeping.pop(p, None)

    def sleeping_apps(self):
        apps = {}
        for pid, i in self.sleeping.items():
            a = apps.setdefault(i["name"], {"name": i["name"], "exe": i["exe"], "pids": [], "mem": 0, "since": i["since"]})
            a["pids"].append(pid); a["mem"] += i["mem"]
        return list(apps.values())

    def _loop(self):
        tick = 0
        while not self.stop_evt.is_set():
            # réveil automatique : l'utilisateur clique sur la fenêtre d'une appli endormie
            fg = self._foreground_pid()
            if fg in self.sleeping:
                name = self.sleeping[fg]["name"]
                self.wake(name=name)
                self.emit("sleep_wake", name)
            for pid in list(self.sleeping):
                if not psutil.pid_exists(pid):
                    self.sleeping.pop(pid, None)
            # mise en veille automatique
            if self.settings["sleep_auto"] and tick % 30 == 0:
                limit = self.settings["sleep_minutes"] * 60
                now = time.time()
                for app in self.candidates():
                    key = app["name"].lower()
                    if app["cpu"] is not None and app["cpu"] < 0.5:
                        self.idle_since.setdefault(key, now)
                        if now - self.idle_since[key] > limit:
                            if self.sleep_app(app):
                                self.emit("sleep_auto", {"name": app["name"], "mem": app["mem"]})
                            self.idle_since.pop(key, None)
                    else:
                        self.idle_since.pop(key, None)
            tick += 1
            self.stop_evt.wait(1)

    def start(self):
        if psutil and (self.thread is None or not self.thread.is_alive()):
            self.stop_evt.clear()
            self.thread = threading.Thread(target=self._loop, daemon=True, name="sleep-mode")
            self.thread.start()

    def stop(self):
        self.stop_evt.set()
        self.wake()   # ne jamais laisser une application gelée en quittant Malryx


# ---------------------------------------------------------------------------- mises à jour des logiciels
SECURITY_SENSITIVE = ("chrome", "firefox", "edge", "brave", "opera", "java", "jre", "jdk", "adobe", "acrobat", "reader",
                      "vlc", "7-zip", "7zip", "winrar", "zoom", "teams", "skype", "putty", "filezilla", "notepad++",
                      "python", "node", "git", "openssl", "teamviewer", "anydesk", "thunderbird", "libreoffice", "keepass")


def _winget():
    if not IS_WIN:
        return None
    from shutil import which
    w = which("winget")
    if w:
        return w
    p = Path(os.environ.get("LOCALAPPDATA", "")) / r"Microsoft\WindowsApps\winget.exe"
    return str(p) if p.exists() else None


def _parse_table(text):
    """Analyse le tableau de « winget upgrade » (colonnes repérées par leur position, quelle que soit la langue)."""
    lines = [l.rstrip() for l in text.replace("\r", "\n").split("\n")]
    for i, l in enumerate(lines):
        if re.fullmatch(r"-{20,}", l.strip()) and i > 0:
            header = lines[i - 1]
            starts = [m.start() for m in re.finditer(r"\S+", header)]
            if len(starts) < 4:
                continue
            rows = []
            for row in lines[i + 1:]:
                if not row.strip() or re.match(r"^\d+ ", row) and len(row) < len(header) // 2:
                    break
                cols = [row[s:e].strip() for s, e in zip(starts, starts[1:] + [None])]
                if len(cols) >= 4 and cols[1]:
                    rows.append(cols)
            return rows
    return []


def outdated_software():
    w = _winget()
    if not w:
        return None  # winget absent
    r = subprocess.run([w, "upgrade", "--include-unknown", "--accept-source-agreements", "--disable-interactivity"],
                       capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=180, creationflags=NO_WINDOW)
    apps = []
    for cols in _parse_table(r.stdout):
        name, pid, ver, avail = cols[0], cols[1], cols[2], cols[3]
        if not avail or avail.lower() in ("unknown", "inconnu"):
            continue
        sensitive = any(k in (name + pid).lower() for k in SECURITY_SENSITIVE)
        apps.append({"name": name, "id": pid, "version": ver, "available": avail,
                     "priority": "Sécurité" if sensitive else "Normale"})
    return sorted(apps, key=lambda a: (a["priority"] != "Sécurité", a["name"].lower()))


def update_software(app_id, progress=None):
    w = _winget()
    if not w:
        return False, "winget introuvable (installez « App Installer » depuis le Microsoft Store)"
    r = subprocess.run([w, "upgrade", "--id", app_id, "--exact", "--silent", "--accept-package-agreements",
                        "--accept-source-agreements", "--disable-interactivity"],
                       capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=1800, creationflags=NO_WINDOW)
    tail = (r.stdout.strip().splitlines() or [""])[-1]
    return r.returncode == 0, tail


# ---------------------------------------------------------------------------- santé
def health():
    """État du disque (SMART via Windows Storage), espace, mémoire, processeur, batterie, durée d'allumage."""
    res = {"disks": [], "volumes": [], "alerts": []}
    if IS_WIN:
        res["disks"] = winsys._ps_json(
            "Get-PhysicalDisk | ForEach-Object { $r = $_ | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue; "
            "[pscustomobject]@{Name=$_.FriendlyName; Media=[string]$_.MediaType; Health=[string]$_.HealthStatus; "
            "SizeGB=[math]::Round($_.Size/1GB); Temp=$r.Temperature; Wear=$r.Wear; ReadErr=$r.ReadErrorsTotal; "
            "WriteErr=$r.WriteErrorsTotal; Hours=$r.PowerOnHours} }", timeout=60)
    for d in res["disks"]:
        if d.get("Health") and d["Health"] not in ("Healthy", "0"):
            res["alerts"].append(("bad", f"Disque {d['Name']} : état « {d['Health']} » – sauvegardez vos données"))
        if d.get("Temp") and d["Temp"] > 60:
            res["alerts"].append(("warn", f"Disque {d['Name']} : {d['Temp']} °C (trop chaud)"))
        if d.get("Wear") and d["Wear"] > 80:
            res["alerts"].append(("warn", f"SSD {d['Name']} : usure {d['Wear']} %"))
        if (d.get("ReadErr") or 0) + (d.get("WriteErr") or 0) > 0:
            res["alerts"].append(("warn", f"Disque {d['Name']} : erreurs de lecture/écriture détectées"))
    if psutil:
        for part in psutil.disk_partitions(all=False):
            if "cdrom" in part.opts or not part.fstype:
                continue
            try:
                u = psutil.disk_usage(part.mountpoint)
            except OSError:
                continue
            res["volumes"].append({"mount": part.mountpoint, "total": u.total, "free": u.free, "percent": u.percent})
            if u.total > 5e9 and u.free / u.total < 0.10:
                res["alerts"].append(("bad" if u.free / u.total < 0.05 else "warn",
                                      f"Disque {part.mountpoint} presque plein ({u.free / 1e9:.1f} Go libres)"))
        vm = psutil.virtual_memory()
        res["ram"] = {"total": vm.total, "used": vm.used, "percent": vm.percent}
        if vm.percent > 90:
            res["alerts"].append(("warn", f"Mémoire vive utilisée à {vm.percent:.0f} % : fermez ou mettez en veille des applications"))
        res["cpu"] = psutil.cpu_percent(interval=0.5)
        res["cpu_count"] = psutil.cpu_count()
        bat = psutil.sensors_battery() if hasattr(psutil, "sensors_battery") else None
        if bat:
            res["battery"] = {"percent": bat.percent, "plugged": bat.power_plugged}
        up = (time.time() - psutil.boot_time()) / 86400
        res["uptime_days"] = round(up, 1)
        if up > 7:
            res["alerts"].append(("warn", f"PC allumé depuis {up:.0f} jours sans redémarrage : redémarrez pour appliquer les mises à jour"))
    return res
