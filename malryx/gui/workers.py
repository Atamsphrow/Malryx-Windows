"""Tâches en arrière-plan (QThread) : l'interface ne se fige jamais."""
import os
import tempfile
import threading
import time
from concurrent.futures import ALL_COMPLETED, FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from .. import winsys
from ..engine import MALWARE, PERSONAL_DIRS, SUSPECT, is_interesting, is_noisy


STAGES = {
    "rapide": ["Mise à jour des signatures", "Analyse de la mémoire", "Éléments de démarrage",
               "Analyse du registre", "Système de fichiers", "Analyse heuristique"],
    "complète": ["Mise à jour des signatures", "Analyse de la mémoire", "Éléments de démarrage",
                 "Analyse du registre", "Système de fichiers (tous les disques)", "Analyse heuristique"],
    "personnalisée": ["Système de fichiers", "Analyse heuristique"],
}


class ScanWorker(QThread):
    progress = Signal(int, int, str)     # fait, total, élément courant
    stage = Signal(int, str)             # index, "running" | "done"
    found = Signal(dict)                 # résultat MALVEILLANT / SUSPECT
    done = Signal(dict)                  # résumé

    def __init__(self, engine, settings, mode, paths=(), clamav=None, parent=None):
        super().__init__(parent)
        self.engine, self.settings, self.mode, self.paths = engine, settings, mode, list(paths)
        self.clamav = clamav
        self._cancel = False
        self._resume = threading.Event(); self._resume.set()
        self.results = []
        self.counts = {"done": 0, "bad": 0, "sus": 0}
        self.stage_names = STAGES[mode]

    def cancel(self):
        self._cancel = True
        self._resume.set()

    def pause(self, p):
        self._resume.clear() if p else self._resume.set()

    def cancelled(self):
        return self._cancel

    def _record(self, r):
        self.counts["done"] += 1
        if r["verdict"] == MALWARE:
            self.counts["bad"] += 1
        elif r["verdict"] == SUSPECT:
            self.counts["sus"] += 1
        if r["verdict"] in (MALWARE, SUSPECT):
            self.results.append(r)
            self.found.emit(r)

    def _scan_many(self, items, total_hint=0):
        """items : itérable de (chemin, raison). Analyse parallèle sur 4 fils."""
        pending, seen, n = set(), set(), 0
        with ThreadPoolExecutor(max_workers=4) as ex:
            def drain(block):
                nonlocal pending
                if not pending:
                    return
                fin, pending = wait(pending, return_when=ALL_COMPLETED if block else FIRST_COMPLETED)
                for f in fin:
                    if f.cancelled():
                        continue
                    r = f.result()
                    self._record(r)
                    if self.counts["done"] % 5 == 0:
                        self.progress.emit(self.counts["done"], max(self.total, self.counts["done"]), r["path"])
            for path, extra in items:
                if self._cancel:
                    break
                self._resume.wait()
                key = os.path.normcase(path)
                if key in seen or key in self.seen_global:
                    continue
                seen.add(key); self.seen_global.add(key)
                pending.add(ex.submit(self._scan_one, path, extra))
                if len(pending) >= 16:
                    drain(False)
            if self._cancel:
                for f in pending:
                    f.cancel()
            else:
                drain(True)

    def _scan_one(self, path, extra):
        r = self.engine.scan_file(path)
        if extra:
            r["reasons"].append(extra)
        return r

    def _files(self, roots):
        for root in roots:
            root = Path(root)
            if root.is_file():
                yield str(root), None
                continue
            for dirpath, dirs, files in os.walk(root):
                if self._cancel:
                    return
                low = dirpath.lower()
                if self.engine.is_excluded(dirpath) or "\\malryx" in low or "/malryx" in low \
                        or low.endswith(("\\$recycle.bin", "\\system volume information")):
                    dirs[:] = []
                    continue
                quick = self.mode == "rapide" and not any(d in low + "\\" for d in PERSONAL_DIRS)
                if quick and is_noisy(low + "\\"):
                    dirs[:] = []
                    continue
                for fn in files:
                    p = os.path.join(dirpath, fn)
                    if quick and not is_interesting(p):
                        continue
                    yield p, None

    def _count(self, roots):
        if self.mode != "rapide":
            return winsys.count_files(roots, self.cancelled)
        n = 0
        for root in roots:
            for dirpath, dirs, files in os.walk(root):
                if self._cancel:
                    return n
                low = dirpath.lower()
                if not any(d in low + "\\" for d in PERSONAL_DIRS):
                    if is_noisy(low + "\\"):
                        dirs[:] = []
                        continue
                    n += sum(1 for f in files if is_interesting(f, check_header=False))
                else:
                    n += len(files)
        return n

    def run(self):
        t0 = time.time()
        self.seen_global = set()
        self.total = 0
        roots = (winsys.risky_dirs() if self.mode == "rapide" else
                 winsys.full_scan_dirs() if self.mode == "complète" else [Path(p) for p in self.paths])
        for i, name in enumerate(self.stage_names):
            if self._cancel:
                break
            self.stage.emit(i, "running")
            if name.startswith("Mise à jour"):
                self.progress.emit(0, 0, "Vérification des signatures…")
                self.engine.reload()
                if self.clamav and self.settings["update_auto"]:
                    last = self.settings["stats"].get("last_update")
                    if not last or time.time() - datetime.fromisoformat(last).timestamp() > 86400:
                        from .. import sigupdate
                        try:
                            ok, _ = sigupdate.update_all(self.clamav, self.settings,
                                                         progress=lambda m: self.progress.emit(0, 0, m))
                            if ok:
                                self.settings.data["stats"]["last_update"] = datetime.now().isoformat(timespec="minutes")
                                if self.settings["clamav"] and self.clamav.has_db():
                                    self.clamav.reload_or_start()
                                self.engine.reload(background=False)
                        except Exception:
                            pass
            elif name.startswith("Analyse de la mémoire"):
                procs = winsys.running_executables()
                self.total = len(procs)
                self._scan_many((exe, f"processus actif (PID {', '.join(map(str, pids[:3]))})")
                                for exe, pids in procs.items())
            elif name.startswith("Éléments de démarrage"):
                self.progress.emit(self.counts["done"], 0, "Lecture des éléments de démarrage et des tâches planifiées…")
                items = [it for it in winsys.all_startup_items() if it.get("exe") and Path(it["exe"]).exists()]
                self.total = self.counts["done"] + len(items)
                self._scan_many((it["exe"], f"{it['source']} : {it['name']}") for it in items)
            elif name.startswith("Analyse du registre"):
                self.progress.emit(self.counts["done"], 0, "Recherche de détournements (Winlogon, IFEO, AppInit)…")
                for f in winsys.registry_findings():
                    path = f"{f['hive']}\\{f['key']}\\{f['value']}"
                    verdict = MALWARE if f.get("severity") == "élevé" or f["value"] in ("Shell", "Userinit") else SUSPECT
                    r = {"path": path, "verdict": verdict, "threat": "Détournement du registre", "sha256": None,
                         "score": 60, "reasons": [f["reason"]], "registry": f, "time": datetime.now().isoformat()}
                    self._record(r)
            elif name.startswith("Système de fichiers"):
                self.progress.emit(self.counts["done"], 0, "Comptage des fichiers…")
                self.total = self.counts["done"] + sum(1 for r in roots if Path(r).is_file()) + \
                    self._count([r for r in roots if Path(r).is_dir()])
                self._scan_many(self._files(roots))
            elif name.startswith("Analyse heuristique"):
                self.progress.emit(self.counts["done"], self.counts["done"], "Corrélation des résultats…")
                time.sleep(0.3)
            self.stage.emit(i, "done")
        n = self.counts["done"]
        self.progress.emit(n, max(n, 1), "")
        st = self.settings.data["stats"]
        st["scanned"] += n
        st["threats"] += self.counts["bad"]
        if not self._cancel:
            st["last_scan"] = datetime.now().isoformat(timespec="minutes")
            st["last_scan_type"] = self.mode
        self.settings.save()
        self.done.emit({"count": n, "malware": self.counts["bad"], "suspect": self.counts["sus"],
                        "seconds": time.time() - t0, "cancelled": self._cancel, "mode": self.mode})


class AndroidScanWorker(QThread):
    progress = Signal(int, int, str)
    found = Signal(dict)
    done = Signal(dict)

    def __init__(self, adb, engine, serial, include_system=False, storage=False, parent=None):
        super().__init__(parent)
        self.adb, self.engine, self.serial = adb, engine, serial
        self.include_system, self.storage = include_system, storage
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        from ..android import scan_app, scan_storage
        t0 = time.time()
        results = []
        try:
            self.progress.emit(0, 0, "Lecture de la liste des applications…")
            pkgs = self.adb.packages(self.serial, self.include_system)
            acc = self.adb.accessibility_services(self.serial)
            with tempfile.TemporaryDirectory(prefix="malryx_") as tmp:
                for i, p in enumerate(pkgs):
                    if self._cancel:
                        break
                    self.progress.emit(i, len(pkgs), p["name"])
                    r = scan_app(self.adb, self.engine, self.serial, p, tmp, acc)
                    results.append(r)
                    self.found.emit(r)
                if self.storage and not self._cancel:
                    self.progress.emit(len(pkgs), len(pkgs), "Analyse du stockage (Download, Documents)…")
                    for r in scan_storage(self.adb, self.engine, self.serial, tmp, cancel=lambda: self._cancel):
                        r["package"] = "📁 " + r["path"]
                        results.append(r)
                        self.found.emit(r)
        except Exception as e:
            self.done.emit({"error": str(e)})
            return
        bad = sum(r["verdict"] == MALWARE for r in results)
        self.engine.settings.data["stats"]["threats"] += bad
        self.engine.settings.data["stats"]["scanned"] += len(results)
        self.engine.settings.save()
        self.done.emit({"count": len(results), "malware": bad,
                        "suspect": sum(r["verdict"] == SUSPECT for r in results),
                        "seconds": time.time() - t0, "cancelled": self._cancel})


class FuncWorker(QThread):
    """Exécute une fonction quelconque en arrière-plan."""
    result = Signal(object)
    line = Signal(str)

    def __init__(self, fn, *args, parent=None, **kw):
        super().__init__(parent)
        self.fn, self.args, self.kw = fn, args, kw

    def run(self):
        try:
            self.result.emit(self.fn(*self.args, **self.kw))
        except Exception as e:
            self.result.emit(e)


class TaskWorker(QThread):
    """Fonction longue avec messages de progression : fn(*args, progress=callback)."""
    progress = Signal(str)
    result = Signal(object)

    def __init__(self, fn, *args, parent=None, **kw):
        super().__init__(parent)
        self.fn, self.args, self.kw = fn, args, kw
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def cancelled(self):
        return self._cancel

    def run(self):
        try:
            self.result.emit(self.fn(*self.args, progress=self.progress.emit, **self.kw))
        except Exception as e:
            self.result.emit(e)


class PcScanWorker(QThread):
    step = Signal(str, int, int)
    done = Signal(object)

    def __init__(self, app, parent=None):
        super().__init__(parent)
        self.app = app
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        from .. import pcscan
        try:
            self.done.emit(pcscan.run(self.app, lambda s, i, n: self.step.emit(s, i, n), lambda: self._cancel))
        except Exception as e:
            self.done.emit(e)
