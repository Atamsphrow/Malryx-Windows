"""Bouclier anti-ransomware.

Deux détecteurs complémentaires :
1. Fichiers-appâts (canaris) cachés dans Documents, Bureau, Images. Aucun programme légitime
   ne les touche : s'ils sont modifiés, renommés ou supprimés, c'est un chiffrement en cours.
2. Comportement : rafale de fichiers modifiés/renommés dans les dossiers personnels, avec
   contenu à forte entropie (chiffré) ou extensions inconnues.

En cas d'alerte, le processus qui écrit le plus sur le disque est SUSPENDU (pas tué) et
l'utilisateur choisit : arrêter + quarantaine, ou reprendre.
"""
import os
import threading
import time
from collections import deque
from pathlib import Path

from .engine import entropy
from .paths import IS_WIN

try:
    import psutil
except ImportError:
    psutil = None

CANARY_NAMES = ["!_Malryx_Factures_2024.docx", "~Malryx_Releve_bancaire.xlsx", "zz_Malryx_photos.jpg"]
KNOWN_EXT = {".docx", ".doc", ".xlsx", ".xls", ".pptx", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".txt",
             ".mp3", ".mp4", ".zip", ".rar", ".7z", ".csv", ".odt", ".psd", ".mov", ".avi", ".heic", ".webp",
             ".tmp", ".lnk", ".ini", ".json", ".xml", ".html", ".py", ".js", ".log", ".bak", ".svg", ".md"}
SAFE_PROCS = {"system", "registry", "svchost.exe", "msmpeng.exe", "searchindexer.exe", "explorer.exe",
              "onedrive.exe", "dropbox.exe", "googledrivefs.exe", "malryx.exe", "python.exe", "pythonw.exe",
              "tiworker.exe", "trustedinstaller.exe", "mbamservice.exe", "csrss.exe", "smss.exe", "wininit.exe",
              "lsass.exe", "services.exe", "memcompression"}
BURST_WINDOW, BURST_COUNT = 10, 30


def _hide(path):
    if IS_WIN:
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x2 | 0x4)  # caché + système


class RansomwareShield:
    def __init__(self, settings, emit):
        self.settings, self.emit = settings, emit
        self.canaries = set()
        self.events = deque()
        self.lock = threading.Lock()
        self.last_alert = 0
        self.suspended = {}
        self._io_prev = {}
        self.armed_at = 0

    # ---------- fichiers-appâts ----------
    def canary_dirs(self):
        home = Path.home()
        return [d for d in (home / "Documents", home / "Desktop", home / "Pictures", home / "Downloads") if d.exists()]

    CONTENT = b"Malryx canary - ne pas supprimer. " * 120

    def _intact(self, path):
        try:
            with open(path, "rb") as f:
                return f.read().endswith(self.CONTENT)
        except OSError:
            return False

    def deploy(self):
        self.armed_at = time.time() + 5  # ignore les événements dus à notre propre écriture
        self.canaries.clear()
        for d in self.canary_dirs():
            for name in CANARY_NAMES:
                p = d / name
                try:
                    if not p.exists():
                        head = b"PK\x03\x04" if name.endswith(("docx", "xlsx")) else b"\xff\xd8\xff\xe0"
                        p.write_bytes(head + self.CONTENT)
                        _hide(p)
                    self.canaries.add(os.path.normcase(str(p)))
                except OSError:
                    continue
        return len(self.canaries)

    def remove(self):
        for c in list(self.canaries):
            try:
                if IS_WIN:
                    import ctypes
                    ctypes.windll.kernel32.SetFileAttributesW(c, 0x80)
                os.remove(c)
            except OSError:
                pass
        self.canaries.clear()

    # ---------- événements disque ----------
    def on_event(self, kind, path, dest=None):
        if not self.settings["ransomware"]:
            return
        if time.time() < self.armed_at:
            return
        np = os.path.normcase(path)
        if np in self.canaries or (dest and os.path.normcase(dest) in self.canaries):
            if kind == "modified" and self._intact(path):
                return  # simple accès / mise à jour des attributs
            self._alert(f"fichier-appât {('modifié' if kind == 'modified' else 'supprimé ou renommé')} : {Path(path).name}")
            return
        if not any(np.startswith(os.path.normcase(str(d))) for d in self.canary_dirs()):
            return
        now = time.time()
        target = dest or path
        weird = Path(target).suffix.lower() not in KNOWN_EXT and len(Path(target).suffix) > 0
        with self.lock:
            self.events.append((now, target, weird))
            while self.events and now - self.events[0][0] > BURST_WINDOW:
                self.events.popleft()
            n = len(self.events)
            n_weird = sum(1 for e in self.events if e[2])
        if n >= BURST_COUNT:
            sample = [e[1] for e in list(self.events)[-8:]]
            high = sum(1 for f in sample if self._encrypted(f))
            if high >= 5 or n_weird >= BURST_COUNT // 2:
                self._alert(f"{n} fichiers personnels modifiés en {BURST_WINDOW} s "
                            f"({high}/8 au contenu chiffré, {n_weird} extensions inconnues)")

    @staticmethod
    def _encrypted(path):
        try:
            with open(path, "rb") as f:
                data = f.read(65536)
            # les formats déjà compressés (zip, jpg…) ont une forte entropie : on exige > 7.9
            return len(data) > 1024 and entropy(data) > 7.9 and data[:2] not in (b"PK", b"\xff\xd8", b"\x89P")
        except OSError:
            return False

    # ---------- réaction ----------
    def top_writers(self, n=3):
        if psutil is None:
            return []
        snap = {}
        for p in psutil.process_iter(["pid", "name", "exe"]):
            try:
                io = p.io_counters()
                snap[p.pid] = (io.write_bytes, p.info["name"], p.info["exe"])
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue
        time.sleep(1.0)
        deltas = []
        for p in psutil.process_iter(["pid"]):
            try:
                if p.pid in snap and p.pid != os.getpid():
                    w0, name, exe = snap[p.pid]
                    if (name or "").lower() in SAFE_PROCS:
                        continue
                    d = p.io_counters().write_bytes - w0
                    if d > 0:
                        deltas.append((d, p.pid, name, exe))
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue
        return sorted(deltas, reverse=True)[:n]

    def _alert(self, reason):
        if time.time() - self.last_alert < 20:
            return
        self.last_alert = time.time()
        threading.Thread(target=self._respond, args=(reason,), daemon=True).start()

    def _respond(self, reason):
        culprits = self.top_writers()
        suspended = []
        for d, pid, name, exe in culprits[:1]:
            try:
                psutil.Process(pid).suspend()
                self.suspended[pid] = exe
                suspended.append({"pid": pid, "name": name, "exe": exe, "written_mb": round(d / 1e6, 1)})
            except Exception:
                continue
        self.emit("ransomware", {"reason": reason, "suspended": suspended,
                                 "candidates": [{"pid": p, "name": n, "exe": e} for _, p, n, e in culprits]})
        self.deploy()

    def resume(self, pid):
        try:
            psutil.Process(pid).resume()
        except Exception:
            pass
        self.suspended.pop(pid, None)

    def terminate(self, pid):
        try:
            psutil.Process(pid).kill()
        except Exception:
            pass
        return self.suspended.pop(pid, None)
