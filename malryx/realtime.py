"""Protection en temps réel : dossiers sensibles, clés USB et téléphones Android.

Tous les événements passent par `emit(kind, data)` :
  log, threat, suspect, usb, android_device, android_app, state
"""
import os
import queue
import tempfile
import threading
import time
from pathlib import Path

from . import quarantine, winsys
from .engine import MALWARE, PERSONAL_DIRS, SUSPECT, is_interesting, is_noisy

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # pragma: no cover
    Observer = None
    FileSystemEventHandler = object

IGNORE_PARTS = ("\\malryx\\", "/malryx/", ".crdownload", ".part", ".partial", ".tmp", "~$", "\\$recycle.bin\\")


class _Handler(FileSystemEventHandler):
    def __init__(self, q, hook=None):
        self.q, self.hook = q, hook

    def _h(self, kind, path, dest=None):
        if self.hook:
            try:
                self.hook(kind, path, dest)
            except Exception:
                pass

    def on_created(self, e):
        if not e.is_directory:
            self.q.put(e.src_path)

    def on_modified(self, e):
        if not e.is_directory:
            self.q.put(e.src_path)
            self._h("modified", e.src_path)

    def on_moved(self, e):
        if not e.is_directory:
            self.q.put(e.dest_path)
            self._h("moved", e.src_path, e.dest_path)

    def on_deleted(self, e):
        if not e.is_directory:
            self._h("deleted", e.src_path)


class RealTimeProtection:
    def __init__(self, engine, settings, emit, android=None, ransomware=None):
        self.engine, self.settings, self.emit, self.android = engine, settings, emit, android
        self.ransomware = ransomware
        self.startup_state = None
        self.q = queue.Queue()
        self.recent = {}
        self.observer = None
        self.watched = {}
        self.known_pkgs = {}
        self.known_devices = set()
        self.stop_evt = threading.Event()
        self.running = False
        self.files_checked = 0

    # ---------- surveillance des dossiers ----------
    def target_dirs(self):
        return winsys.risky_dirs() + [Path(d) for d in self.settings["extra_dirs"] if Path(d).exists()]

    def _watch(self, d, label=""):
        key = os.path.normcase(str(d))
        if key in self.watched or not Path(d).exists():
            return
        try:
            hook = self.ransomware.on_event if self.ransomware else None
            self.watched[key] = self.observer.schedule(_Handler(self.q, hook), str(d), recursive=True)
            self.emit("log", f"Surveillance : {d} {label}".strip())
        except (OSError, RuntimeError) as e:
            self.emit("log", f"Impossible de surveiller {d} : {e}")

    def _unwatch(self, key):
        w = self.watched.pop(key, None)
        if w:
            try:
                self.observer.unschedule(w)
            except (KeyError, RuntimeError):
                pass

    def refresh_dirs(self):
        if not self.running:
            return
        for d in self.target_dirs():
            self._watch(d)

    # ---------- traitement ----------
    def _wait_stable(self, path, tries=12):
        last = -1
        for _ in range(tries):
            try:
                size = os.path.getsize(path)
            except OSError:
                return False
            if size == last:
                return True
            last = size
            time.sleep(0.4)
        return True

    def _handle(self, path):
        low = path.lower()
        if any(x in low for x in IGNORE_PARTS) or is_noisy(low) or self.engine.is_excluded(path):
            return
        personal = any(d in low for d in PERSONAL_DIRS) or len(low) > 3 and low[1:3] == ":\\" and low[:3] in self._usb_roots()
        if not personal and not any(low.startswith(os.path.normcase(e)) for e in self.settings["extra_dirs"]):
            if not is_interesting(path):
                return  # AppData / ProgramData / Temp : seulement les exécutables, scripts et archives
        now = time.time()
        if now - self.recent.get(low, 0) < 3:
            return
        self.recent[low] = now
        if len(self.recent) > 5000:
            self.recent.clear()
        if not self._wait_stable(path):
            return
        res = self.engine.scan_file(path)
        self.files_checked += 1
        self.settings.data["stats"]["scanned"] += 1
        if res["verdict"] == MALWARE:
            action = "détecté"
            if self.settings["auto_quarantine"]:
                killed = winsys.kill_process(path)
                try:
                    quarantine.quarantine(path, res)
                    action = "mis en quarantaine" + (f", {killed} processus arrêté(s)" if killed else "")
                except OSError as e:
                    action = f"quarantaine impossible ({e})"
            self.settings.bump("threats")
            res["action"] = action
            self.emit("threat", res)
        elif res["verdict"] == SUSPECT:
            res["action"] = "signalé"
            self.emit("suspect", res)

    def _usb_roots(self):
        return {k for k in self.watched if len(k) <= 3}

    def _worker(self):
        while not self.stop_evt.is_set():
            try:
                path = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._handle(path)
            except Exception as e:
                self.emit("log", f"Erreur sur {path} : {e}")

    # ---------- appareils ----------
    def _poll(self):
        tick = 0
        while not self.stop_evt.is_set():
            if self.settings["usb_monitor"]:
                try:
                    current = {os.path.normcase(str(d)): d for d in winsys.removable_drives()}
                    for key, d in current.items():
                        if key not in self.watched:
                            self._watch(d, "(clé USB)")
                            self.emit("usb", {"drive": str(d), "event": "connectée"})
                            if self.settings["usb_autoscan"]:
                                threading.Thread(target=self._scan_tree, args=(d,), daemon=True).start()
                    for key in [k for k in self.watched if len(k) <= 3 and k not in current]:
                        self._unwatch(key)
                        self.emit("usb", {"drive": key.upper(), "event": "retirée"})
                except Exception as e:
                    self.emit("log", f"USB : {e}")
            if self.android and self.settings["android_monitor"] and tick % 3 == 0:
                self._poll_android()
            if self.settings["startup_guard"] and tick % 2 == 0:
                self._poll_startup()
            tick += 1
            self.stop_evt.wait(5)

    def _poll_android(self):
        try:
            devs = [d for d in self.android.devices() if d["state"] == "device"]
        except Exception as e:
            self.emit("log", f"ADB : {e}")
            return
        serials = {d["serial"] for d in devs}
        for gone in self.known_devices - serials:
            self.emit("android_device", {"serial": gone, "event": "déconnecté"})
            self.known_pkgs.pop(gone, None)
        self.known_devices = serials
        for dev in devs:
            s = dev["serial"]
            try:
                pkgs = {p["name"]: p for p in self.android.packages(s)}
            except Exception:
                continue
            if s not in self.known_pkgs:
                self.emit("android_device", {**dev, "event": "connecté", "apps": len(pkgs)})
                new = list(pkgs.values())
            else:
                new = [p for n, p in pkgs.items() if n not in self.known_pkgs[s]]
                for p in new:
                    self.emit("log", f"Nouvelle application sur {dev['model']} : {p['name']}")
            self.known_pkgs[s] = set(pkgs)
            if not new:
                continue
            from .android import scan_app
            acc = self.android.accessibility_services(s)
            with tempfile.TemporaryDirectory(prefix="tg_") as tmp:
                for p in new:
                    if self.stop_evt.is_set():
                        return
                    r = scan_app(self.android, self.engine, s, p, tmp, acc)
                    r["model"] = dev["model"]
                    if r["verdict"] in (MALWARE, SUSPECT):
                        if r["verdict"] == MALWARE:
                            self.settings.bump("threats")
                        self.emit("android_app", r)

    def _poll_startup(self):
        """Protection du démarrage : tout nouveau programme ajouté au démarrage est analysé."""
        try:
            snap = winsys.startup_snapshot()
        except Exception:
            return
        if self.startup_state is None:
            self.startup_state = snap
            return
        for key, item in snap.items():
            if key in self.startup_state:
                continue
            res = (self.engine.scan_file(item["exe"]) if item.get("exe") and os.path.exists(item["exe"])
                   else {"verdict": SUSPECT, "reasons": ["programme de démarrage introuvable"], "path": item["command"],
                         "sha256": None, "threat": "Démarrage"})
            res["reasons"].append(f"ajouté au démarrage ({item['source']} : {item['name']})")
            action = "signalé"
            if res["verdict"] == MALWARE and self.settings["auto_quarantine"]:
                try:
                    winsys.set_startup_item(item, False)
                    action = "retiré du démarrage"
                    if os.path.exists(res["path"]):
                        winsys.kill_process(res["path"])
                        quarantine.quarantine(res["path"], res)
                        action += " + quarantaine"
                except Exception as e:
                    action = f"blocage impossible ({e})"
            res["action"] = action
            res["startup_item"] = item
            self.emit("startup", res)
        self.startup_state = snap

    def _scan_tree(self, root):
        for dirpath, _, files in os.walk(root):
            for fn in files:
                if self.stop_evt.is_set():
                    return
                self.q.put(os.path.join(dirpath, fn))

    # ---------- cycle de vie ----------
    def start(self):
        if self.running:
            return True
        if Observer is None:
            self.emit("log", "Module watchdog absent : protection en temps réel indisponible")
            return False
        self.stop_evt.clear()
        self.observer = Observer()
        self.watched = {}
        for d in self.target_dirs():
            self._watch(d)
        self.observer.start()
        if self.ransomware and self.settings["ransomware"]:
            n = self.ransomware.deploy()
            self.emit("log", f"Anti-ransomware : {n} fichiers-appâts déployés")
        threading.Thread(target=self._worker, daemon=True, name="rt-worker").start()
        threading.Thread(target=self._poll, daemon=True, name="rt-poll").start()
        self.running = True
        self.emit("state", True)
        return True

    def stop(self):
        if not self.running:
            return
        self.stop_evt.set()
        try:
            self.observer.stop()
            self.observer.join(3)
        except Exception:
            pass
        self.running = False
        self.known_pkgs.clear()
        self.known_devices.clear()
        self.emit("state", False)
