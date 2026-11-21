"""Fenêtre principale de Malryx : navigation, zone de notification, événements temps réel, planificateur."""
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

from PySide6.QtCore import QObject, QPointF, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap, QLinearGradient
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import (QApplication, QButtonGroup, QFrame, QHBoxLayout, QMainWindow, QMenu, QPushButton,
                               QStackedWidget, QSystemTrayIcon, QVBoxLayout, QWidget)

from .. import history, paths, winsys
from ..android import Adb
from ..clamav import ClamAV
from ..engine import MALWARE, Engine
from ..execguard import ExecGuard
from ..paths import APP_NAME, VERSION, data_dir
from ..ransomware import RansomwareShield
from ..realtime import RealTimeProtection
from ..settings import Settings
from .common import RansomwareDialog, confirm, info
from .pages_dashboard import DashboardPage
from .pages_devices import DevicesPage
from .pages_history import HistoryPage
from .pages_protection import ProtectionPage
from .pages_scan import ScanPage
from .pages_settings import SettingsPage
from .pages_cleanup import CleanupPage
from .pages_pcscan import PcScanPage
from .pages_performance import PerformancePage
from .pages_privacy import PrivacyPage
from ..performance import SleepManager
from ..privacy import DeviceMonitor
from ..network import NetworkMonitor
from .pages_tools import ToolsPage
from .theme import C, QSS, icon
from .widgets import StatusDot, label
from .workers import FuncWorker

SERVER = f"Malryx-{os.environ.get('USERNAME', os.environ.get('USER', 'u'))}"
NAV = [("dashboard", "home", "Tableau de bord"), ("scan", "search", "Analyse"), ("protection", "shield-check", "Protection"),
       ("devices", "phone", "Appareils"), ("cleanup", "trash", "Nettoyage"), ("performance", "zap", "Performances"),
       ("privacy", "eye", "Confidentialité"), ("history", "box", "Historique"), ("tools", "cpu", "Outils"),
       ("settings", "sliders", "Réglages")]


def app_icon(color=C["accent"], size=256):
    """Logo Malryx : bouclier en dégradé avec un « M » stylisé."""
    pm = QPixmap(size, size); pm.fill(Qt.transparent)
    p = QPainter(pm); p.setRenderHint(QPainter.Antialiasing)
    s = size / 24.0
    path = QPainterPath()
    path.moveTo(12 * s, 1.5 * s); path.lineTo(21 * s, 5 * s); path.lineTo(21 * s, 11.5 * s)
    path.cubicTo(21 * s, 17.5 * s, 17 * s, 21 * s, 12 * s, 22.7 * s)
    path.cubicTo(7 * s, 21 * s, 3 * s, 17.5 * s, 3 * s, 11.5 * s)
    path.lineTo(3 * s, 5 * s); path.closeSubpath()
    g = QLinearGradient(0, 0, size, size)
    base = QColor(color)
    g.setColorAt(0, base.lighter(130)); g.setColorAt(1, base.darker(140))
    p.setPen(Qt.NoPen); p.setBrush(g); p.drawPath(path)
    pen = QPen(QColor("white"), 2.3 * s, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    p.setPen(pen); p.setBrush(Qt.NoBrush)
    m = QPainterPath()
    m.moveTo(7.6 * s, 15.5 * s); m.lineTo(7.6 * s, 8.3 * s); m.lineTo(12 * s, 12.8 * s)
    m.lineTo(16.4 * s, 8.3 * s); m.lineTo(16.4 * s, 15.5 * s)
    p.drawPath(m)
    p.end()
    return pm


class Bridge(QObject):
    event = Signal(str, object)


class MainWindow(QMainWindow):
    def __init__(self, start_minimized=False, scan_paths=None):
        super().__init__()
        self.settings = Settings()
        self.bridge = Bridge()
        self.bridge.event.connect(self._on_event)
        self.clamav = ClamAV(log=lambda m: self.bridge.event.emit("log", m))
        self.engine = Engine(self.settings, self.clamav, log=lambda m: self.bridge.event.emit("log", m))
        self.ransomware = RansomwareShield(self.settings, lambda k, d: self.bridge.event.emit(k, d))
        self.adb = None
        self.rtp = RealTimeProtection(self.engine, self.settings, lambda k, d: self.bridge.event.emit(k, d),
                                      android=None, ransomware=self.ransomware)
        self.execguard = ExecGuard(self.engine, self.settings, lambda k, d: self.bridge.event.emit(k, d))
        self.sleep_mgr = SleepManager(self.settings, lambda k, d: self.bridge.event.emit(k, d))
        self.devmon = DeviceMonitor(self.settings, lambda k, d: self.bridge.event.emit(k, d))
        self.netmon = NetworkMonitor(self.settings, lambda k, d: self.bridge.event.emit(k, d))
        self.pending_threats = 0
        self.audit_score = None
        self.android_devices, self.usb_drives = [], []
        self._clam_sigs = 0
        self._quitting = False
        self._tray_hint = False

        self.setWindowTitle(f"{APP_NAME} – Sécurité")
        self.setWindowIcon(QIcon(app_icon()))
        self.resize(1320, 860)
        self.setMinimumSize(1080, 700)
        self._build()
        self._tray()
        self._single_instance()

        if self.settings["realtime"]:
            self.rtp.start()
            if self.settings["exec_guard"] or self.settings["behavior_guard"]:
                self.execguard.start()
        self.sleep_mgr.start()
        self.devmon.start()
        self.netmon.start()
        self._init_worker = FuncWorker(self._background_init)
        self._init_worker.result.connect(self._init_done)
        self._init_worker.start()

        self.timer = QTimer(self); self.timer.timeout.connect(self._tick); self.timer.start(3000)
        self.sched = QTimer(self); self.sched.timeout.connect(self._check_schedule); self.sched.start(60_000)
        self.log(f"Malryx {VERSION} démarré" + (" (administrateur)" if winsys.is_admin() else ""))
        if scan_paths:
            QTimer.singleShot(300, lambda: self.start_scan("personnalisée", scan_paths))
        if not start_minimized:
            self.show()

    # ------------------------------------------------------------------ UI
    def _build(self):
        root = QWidget(); root.setObjectName("Root")
        h = QHBoxLayout(root); h.setContentsMargins(0, 0, 0, 0); h.setSpacing(0)
        side = QFrame(); side.setObjectName("Sidebar"); side.setFixedWidth(232)
        sv = QVBoxLayout(side); sv.setContentsMargins(16, 20, 16, 18); sv.setSpacing(4)
        brand = QHBoxLayout()
        logo = label(); logo.setPixmap(app_icon(size=80).scaled(38, 38, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        brand.addWidget(logo)
        bv = QVBoxLayout(); bv.setSpacing(0)
        bv.addWidget(label("Malryx", "Brand")); bv.addWidget(label("Anti-Malware", "BrandSub"))
        brand.addLayout(bv); brand.addStretch()
        sv.addLayout(brand); sv.addSpacing(22)
        self.nav = {}
        grp = QButtonGroup(self); grp.setExclusive(True)
        for key, ic, text in NAV:
            b = QPushButton(f"   {text}"); b.setObjectName("Nav"); b.setCheckable(True)
            b.setIcon(icon(ic, C["muted"], 19)); b.setIconSize(QSize(19, 19)); b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(lambda _=False, k=key: self.go(k))
            grp.addButton(b); sv.addWidget(b); self.nav[key] = b
        sv.addStretch()
        st = QFrame(); st.setObjectName("Card")
        sl = QHBoxLayout(st); sl.setContentsMargins(12, 10, 12, 10)
        self.side_dot = StatusDot(C["ok"]); sl.addWidget(self.side_dot)
        tv = QVBoxLayout(); tv.setSpacing(0)
        self.side_state = label("Protégé"); self.side_state.setStyleSheet("font-weight:700")
        self.side_sub = label("Temps réel actif", muted=True, wrap=True)
        tv.addWidget(self.side_state); tv.addWidget(self.side_sub)
        sl.addLayout(tv, 1)
        sv.addWidget(st)
        sv.addWidget(label(f"Version {VERSION}", muted=True))
        h.addWidget(side)

        self.stack = QStackedWidget()
        self.pages = {
            "dashboard": DashboardPage(self), "scan": ScanPage(self), "protection": ProtectionPage(self),
            "devices": DevicesPage(self), "history": HistoryPage(self), "tools": ToolsPage(self),
            "settings": SettingsPage(self), "cleanup": CleanupPage(self), "performance": PerformancePage(self),
            "privacy": PrivacyPage(self), "pcscan": PcScanPage(self),
        }
        for k in self.pages:
            self.stack.addWidget(self.pages[k])
        h.addWidget(self.stack, 1)
        self.setCentralWidget(root)
        self.go("dashboard")

    def go(self, key):
        nav_key = key if key in self.nav else "dashboard"
        self.nav[nav_key].setChecked(True)
        for k, (b) in self.nav.items():
            b.setIcon(icon(dict((a, i) for a, i, _ in NAV)[k], C["text"] if k == nav_key else C["muted"], 19))
        page = self.pages[key]
        self.stack.setCurrentWidget(page)
        page.on_show()
        if self.isHidden() or self.isMinimized():
            self.show_window()

    def show_window(self):
        self.showNormal(); self.raise_(); self.activateWindow()

    # ------------------------------------------------------------------ zone de notification
    def _tray(self):
        self.tray = QSystemTrayIcon(QIcon(app_icon()), self)
        self.tray.setToolTip("Malryx – protection active")
        m = QMenu()
        m.addAction(QAction("Ouvrir Malryx", self, triggered=self.show_window))
        m.addAction(QAction("Analyser mon PC", self, triggered=lambda: self.pages["pcscan"].start()))
        m.addAction(QAction("Analyse des menaces", self, triggered=lambda: self.start_scan("rapide")))
        m.addSeparator()
        self.tray_rt = QAction("Protection en temps réel", self, checkable=True, triggered=self.set_realtime)
        self.tray_rt.setChecked(self.settings["realtime"])
        m.addAction(self.tray_rt)
        m.addSeparator()
        m.addAction(QAction("Quitter Malryx", self, triggered=self.quit))
        self.tray.setContextMenu(m)
        self.tray.activated.connect(lambda r: self.show_window() if r in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick) else None)
        self.tray.messageClicked.connect(lambda: self.go("history"))
        self.tray.show()

    def tray_status(self, text):
        self.tray.setToolTip(f"Malryx – {text}")

    def notify(self, title, msg, critical=False):
        if self.settings["notifications"] or critical:
            self.tray.showMessage(title, msg, QSystemTrayIcon.Critical if critical else QSystemTrayIcon.Information, 7000)

    # ------------------------------------------------------------------ instance unique
    def _single_instance(self):
        self.server = QLocalServer(self)
        QLocalServer.removeServer(SERVER)
        self.server.listen(SERVER)
        self.server.newConnection.connect(self._remote)

    def _remote(self):
        c = self.server.nextPendingConnection()
        c.waitForReadyRead(1000)
        msg = bytes(c.readAll()).decode("utf-8", "ignore")
        if msg.startswith("scan\t"):
            self.start_scan("personnalisée", [p for p in msg.split("\t")[1:] if p])
        else:
            self.show_window()

    # ------------------------------------------------------------------ initialisation en arrière-plan
    def _background_init(self):
        paths.install_vendor(progress=lambda m: self.bridge.event.emit("log", m))   # bases embarquées → AppData
        self.engine.reload()
        adb = None
        try:
            adb = Adb()
        except RuntimeError:
            pass
        sigs = 0
        for f in self.clamav.db_dir.glob("*.c[vl]d"):
            try:
                with open(f, "rb") as fh:
                    head = fh.read(512).decode("ascii", "ignore").split(":")
                sigs += int(head[3])
            except (OSError, ValueError, IndexError):
                continue
        self._clam_sigs = sigs
        if self.settings["clamav"]:
            self.clamav.start()
            self.engine._cache.clear()  # les verdicts d'avant ClamAV sont réévalués
        return adb

    def _init_done(self, adb):
        if isinstance(adb, Adb):
            self.adb = adb
            self.rtp.android = adb
        self.refresh_all()
        self._maybe_auto_update()
        QTimer.singleShot(4000, self.pages["tools"].run_audit)

    def _maybe_auto_update(self):
        """Mise à jour automatique : seulement si une connexion autorisée (Wi-Fi) est disponible."""
        if self.settings["offline"] or not self.settings["update_auto"]:
            return
        if getattr(self, "_uw", None) and self._uw.isRunning():
            return
        last = self.settings["stats"].get("last_update")
        if not last or datetime.now() - datetime.fromisoformat(last) > timedelta(hours=24):
            self.log("Connexion autorisée détectée : mise à jour automatique des signatures")
            self.update_signatures()

    def clam_sig_count(self):
        return self._clam_sigs if self.clamav.ready else 0

    # ------------------------------------------------------------------ actions globales
    def log(self, msg):
        line = f"{datetime.now():%Y-%m-%d %H:%M:%S}  {msg}"
        try:
            with open(data_dir("malryx.log"), "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass

    def start_scan(self, mode, paths_=()):
        self.pages["scan"].start(mode, list(paths_))

    def set_realtime(self, v):
        self.settings["realtime"] = bool(v)
        if v:
            self.rtp.start()
            if self.settings["exec_guard"] or self.settings["behavior_guard"]:
                self.execguard.start()
        else:
            if confirm(self, "Désactiver la protection", "Votre ordinateur ne sera plus protégé en temps réel. Continuer ?",
                       "Désactiver", True):
                self.rtp.stop()
                self.execguard.stop()
                self.ransomware.remove()
            else:
                self.settings["realtime"] = True
        self.tray_rt.setChecked(self.settings["realtime"])
        self.log(f"Protection en temps réel {'activée' if self.settings['realtime'] else 'désactivée'}")
        self.refresh_all()

    def set_clamav(self, v):
        if v:
            w = FuncWorker(self.clamav.start)
            w.result.connect(lambda _: (self.engine._cache.clear(), self.refresh_all()))
            self._cw = w; w.start()
        else:
            self.clamav.stop()
        self.refresh_all()

    def update_signatures(self):
        """Chaîne de mise à jour : ClamAV officiel → miroir Malryx (GitHub) → DNS-over-HTTPS si besoin.
        Hors ligne : propose d'importer un pack de signatures (clé USB)."""
        from .. import sigupdate
        sp = self.pages["settings"]
        if self.settings["offline"]:
            sp.import_pack()
            return
        sp.upd_btn.setEnabled(False); sp.upd_btn.setText("Mise à jour…")
        self.log("Mise à jour des signatures…")

        def work():
            ok, summary = sigupdate.update_all(self.clamav, self.settings,
                                               progress=lambda m: self.bridge.event.emit("update_progress", m))
            if self.settings["clamav"] and self.clamav.has_db():
                self.clamav.reload_or_start()
            self.engine.reload()
            return ok, summary
        self._uw = FuncWorker(work)
        self._uw.result.connect(self._updated)
        self._uw.start()

    def _updated(self, r):
        sp = self.pages["settings"]
        sp.upd_btn.setEnabled(True); sp.upd_btn.setText("Mettre à jour")
        if isinstance(r, Exception):
            r = (False, str(r))
        ok, summary = r
        self.log(f"Mise à jour des signatures : {'réussie' if ok else 'échec'} – {summary}")
        if ok:
            self.settings.data["stats"]["last_update"] = datetime.now().isoformat(timespec="minutes"); self.settings.save()
            self.notify("Signatures à jour", summary[:200])
        else:
            self.notify("Mise à jour impossible", (summary or "Vérifiez la connexion Internet.")[:200])
        sp.on_show()
        self.refresh_all()

    def set_autostart(self, v):
        try:
            winsys.set_autostart(v, *self._self_command())
        except OSError as e:
            info(self, "Démarrage", str(e))

    def _self_command(self):
        if paths.FROZEN:
            return sys.executable, "--minimized"
        main = Path(__file__).resolve().parents[2] / "main.py"
        exe = Path(sys.executable).with_name("pythonw.exe")
        return str(exe if exe.exists() else sys.executable), f'"{main}" --minimized'

    def set_explorer_menu(self, v):
        exe, args = self._self_command()
        cmd = f'"{exe}"' if paths.FROZEN else f'"{exe}" {args.replace(" --minimized", "")}'
        try:
            winsys.set_explorer_menu(v, cmd)
        except OSError as e:
            info(self, "Menu contextuel", str(e))

    def relaunch_admin(self):
        exe, args = self._self_command()
        self.cleanup()
        winsys.relaunch_as_admin(exe, args.replace("--minimized", ""))
        QApplication.quit()

    def after_scan(self, s):
        title = "Analyse terminée"
        if s["malware"]:
            self.notify(title, f"{s['malware']} menace(s) détectée(s). Ouvrez Malryx pour les traiter.", True)
        else:
            self.notify(title, f"Aucune menace · {s['count']} éléments analysés.")
        self.pages["dashboard"].add_activity(f"Analyse {s['mode']} : {s['malware']} menace(s), {s['count']} éléments",
                                             "bad" if s["malware"] else "ok")
        self.tray_status("protection active")
        self.refresh_all()

    def refresh_all(self):
        self._tick()
        for k in ("dashboard",):
            self.pages[k].refresh()

    def _tick(self):
        s = self.settings
        on = s["realtime"] and self.rtp.running
        col = C["bad"] if self.pending_threats else C["ok"] if on else C["warn"]
        self.side_dot.setColor(col)
        self.side_state.setText("Menaces à traiter" if self.pending_threats else "Protégé" if on else "Non protégé")
        net = self.netmon.state
        nets = ("En ligne · " + (f"Wi-Fi {net['ssid']}" if net.get("ssid") else "connecté")) if net.get("online") else "Hors ligne"
        self.side_sub.setText(("Temps réel actif" if on else "Temps réel désactivé") + f"\n{nets}")
        self.side_sub.setToolTip(net.get("reason", ""))
        self.tray.setIcon(QIcon(app_icon(C["bad"] if self.pending_threats else C["accent"] if on else C["muted"], 64)))
        if self.stack.currentWidget() is self.pages["dashboard"]:
            self.pages["dashboard"].refresh()

    # ------------------------------------------------------------------ planificateur
    def _check_schedule(self):
        sc = self.settings["schedule"]
        if not sc.get("enabled") or (self.pages["scan"].worker and self.pages["scan"].worker.isRunning()):
            return
        now = datetime.now()
        h, m = map(int, sc["time"].split(":"))
        due = now.replace(hour=h, minute=m, second=0, microsecond=0)
        if sc["freq"] == "hebdomadaire":
            due -= timedelta(days=(now.weekday() - sc["day"]) % 7)
        last = datetime.fromisoformat(sc["last"]) if sc.get("last") else None
        if now >= due and (last is None or last < due) and now - due < timedelta(hours=12 if sc["freq"] == "quotidienne" else 72):
            sc = dict(sc); sc["last"] = now.isoformat(timespec="minutes"); self.settings["schedule"] = sc
            self.log("Analyse planifiée démarrée")
            self.notify("Analyse planifiée", f"Analyse {sc['type']} en cours…")
            self.start_scan(sc["type"])
            if not self.isVisible():
                self.hide()

    # ------------------------------------------------------------------ événements temps réel
    def _on_event(self, kind, d):
        if not hasattr(self, "pages"):   # événement reçu pendant la construction de la fenêtre
            if kind == "log":
                self.log(d)
            else:
                QTimer.singleShot(500, lambda: self._on_event(kind, d))
            return
        prot, dash = self.pages["protection"], self.pages["dashboard"]
        if kind == "log":
            self.log(d)
        elif kind == "threat":
            name = Path(d["path"]).name
            history.add("Temps réel", d, d.get("action", ""))
            self.notify("Menace bloquée", f"{d.get('threat')}\n{name} : {d.get('action')}", True)
            prot.add_live("Menace", d["path"], d.get("action", ""), C["bad"])
            dash.add_activity(f"Menace bloquée : {d.get('threat')} ({name})", "bad")
            self.log(f"[TEMPS RÉEL] {d.get('threat')} – {d['path']} – {d.get('action')}")
        elif kind == "suspect":
            history.add("Temps réel", d, "signalé")
            self.notify("Fichier suspect", f"{Path(d['path']).name}\n{(d['reasons'] or [''])[0]}")
            prot.add_live("Suspect", d["path"], "signalé", C["warn"])
            dash.add_activity(f"Fichier suspect : {Path(d['path']).name}", "warn")
        elif kind == "usb":
            self.notify("Périphérique USB", f"{d['drive']} {d['event']}" + (" · analyse automatique" if d["event"] == "connectée" and self.settings["usb_autoscan"] else ""))
            if d["event"] == "connectée":
                QTimer.singleShot(1500, lambda drv=d["drive"]: self._offer_pack(drv))
            prot.add_live("USB", d["drive"], d["event"])
            dash.add_activity(f"Clé USB {d['drive']} {d['event']}")
        elif kind == "android_device":
            txt = f"{d.get('model', d['serial'])} {d['event']}" + (f" · {d['apps']} applications analysées" if d.get("apps") else "")
            self.notify("Téléphone Android", txt)
            prot.add_live("Android", d.get("model", d["serial"]), d["event"])
            dash.add_activity(f"Android : {txt}")
        elif kind == "android_app":
            history.add(f"Android ({d.get('model', '')})", d, "signalé")
            self.notify(f"Application {d['verdict'].lower()} sur {d.get('model', 'le téléphone')}",
                        f"{d['package']}\n{(d['reasons'] or [''])[0]}", d["verdict"] == MALWARE)
            prot.add_live("Android", d["package"], d["verdict"].lower(), C["bad"] if d["verdict"] == MALWARE else C["warn"])
            dash.add_activity(f"Application à risque : {d['package']}", "bad" if d["verdict"] == MALWARE else "warn")
        elif kind == "startup":
            it = d.get("startup_item", {})
            bad = d["verdict"] in ("MALVEILLANT", "SUSPECT")
            history.add("Protection du démarrage", d, d.get("action", "")) if bad else None
            self.notify("Nouveau programme au démarrage" if not bad else "Démarrage : programme dangereux",
                        f"{it.get('name')} ({it.get('source')})\n{d.get('action')}", d["verdict"] == "MALVEILLANT")
            prot.add_live("Démarrage", f"{it.get('name')} → {d['path']}", d.get("action", ""), C["bad"] if bad else None)
            dash.add_activity(f"Démarrage : {it.get('name')} ({d['verdict'].lower()})", "bad" if bad else "info")
        elif kind == "exec_blocked":
            name = Path(d.get("path") or "?").name
            history.add("Protection à l'exécution", d, d.get("action", ""))
            self.notify("Exécution bloquée", f"{d.get('threat')}\n{name} : {d.get('action')}", True)
            prot.add_live("Exécution", f"{name}  {d.get('cmdline', '')[:120]}", d.get("action", ""), C["bad"])
            dash.add_activity(f"Exécution bloquée : {name} ({d.get('threat')})", "bad")
            self.log(f"[EXÉCUTION BLOQUÉE] {d.get('threat')} – {d.get('path')} – {d.get('cmdline', '')[:300]}")
        elif kind == "exec_suspect":
            name = Path(d.get("path") or "?").name
            history.add("Protection à l'exécution", d, "autorisé (suspect)")
            prot.add_live("Exécution", name, "suspect, autorisé", C["warn"])
        elif kind == "ransomware":
            self._ransomware(d)
        elif kind == "device_access":
            self.notify(f"Accès au {d['device']}", f"{d['name']} utilise votre {d['device']}.\n"
                        "Si ce n'est pas vous, ouvrez Malryx → Confidentialité.", True)
            history.add("Webcam et micro", {"path": d["app"], "verdict": "SUSPECT", "threat": f"Accès au {d['device']}"}, "signalé")
            dash.add_activity(f"{d['name']} utilise le {d['device']}", "warn")
            prot.add_live("Confidentialité", d["app"], f"accès au {d['device']}", C["warn"])
        elif kind == "network":
            self.log(f"Réseau : {'EN LIGNE' if d['online'] else 'hors ligne'} – {d['reason']}")
            if d.get("went_online"):
                self.notify("Malryx en ligne", f"{d['reason']} : mises à jour, VirusTotal et winget disponibles.")
                QTimer.singleShot(3000, self._maybe_auto_update)
            self.refresh_all()
            if self.stack.currentWidget() is self.pages["settings"]:
                self.pages["settings"].on_show()
        elif kind == "update_progress":
            self.pages["settings"].clam_info.setText(str(d)[:160])
        elif kind == "sleep_auto":
            dash.add_activity(f"Mode veille : {d['name']} endormi ({d['mem'] / 1e6:.0f} Mo libérés pour le processeur)")
        elif kind == "sleep_wake":
            dash.add_activity(f"Mode veille : {d} réveillé")
        elif kind == "state":
            self.refresh_all()

    def _offer_pack(self, drive):
        """Clé USB branchée contenant un pack de signatures plus récent : proposer l'installation."""
        from .. import packs
        for p in packs.find_on(drive)[:1]:
            try:
                inf = packs.inspect(p)
            except packs.PackError as e:
                self.notify("Pack de signatures refusé", f"{p.name} : {e}", True)
                return
            if inf["newer"]:
                self.show_window()
                self.go("settings")
                self.pages["settings"].import_pack(str(p))

    def _ransomware(self, d):
        self.log(f"[RANSOMWARE] {d['reason']} – suspendu : {d.get('suspended')}")
        self.notify("Ransomware bloqué", d["reason"], True)
        self.pages["dashboard"].add_activity("Activité de ransomware bloquée", "bad")
        self.pages["protection"].add_live("Ransomware", d["reason"], "processus suspendu" if d.get("suspended") else "alerte", C["bad"])
        self.show_window()
        dlg = RansomwareDialog(self, d)
        dlg.exec()
        sus = (d.get("suspended") or [None])[0]
        if dlg.choice == "kill" and sus:
            exe = self.ransomware.terminate(sus["pid"])
            res = {"path": exe, "verdict": MALWARE, "threat": "Ransomware (comportement)", "reasons": [d["reason"]], "sha256": None}
            try:
                if exe and Path(exe).exists():
                    from .. import quarantine
                    quarantine.quarantine(exe, res)
                    history.add("Anti-ransomware", res, "arrêté + quarantaine")
                    self.settings.bump("threats")
            except OSError as e:
                history.add("Anti-ransomware", res, f"arrêté (quarantaine impossible : {e})")
            self.start_scan("rapide")
        elif dlg.choice == "resume" and sus:
            self.ransomware.resume(sus["pid"])
            if sus.get("exe"):
                self.settings["exclusions"] = self.settings["exclusions"] + [sus["exe"]]
            history.add("Anti-ransomware", {"path": sus.get("exe"), "verdict": "SUSPECT", "threat": "Ransomware (comportement)"},
                        "autorisé par l'utilisateur")
        elif dlg.choice == "scan":
            self.start_scan("rapide")

    # ------------------------------------------------------------------ fermeture
    def closeEvent(self, e):
        if self._quitting or not self.settings["minimize_to_tray"]:
            self.cleanup()
            e.accept()
            QApplication.quit()
            return
        e.ignore()
        self.hide()
        if not self._tray_hint:
            self.notify("Malryx continue de vous protéger", "Malryx reste actif dans la zone de notification.")
            self._tray_hint = True

    def cleanup(self):
        for comp in (self.execguard, self.sleep_mgr, self.devmon, self.netmon):
            try:
                comp.stop()   # le mode veille réveille toutes les applications endormies
            except Exception:
                pass
        try:
            self.rtp.stop()
        except Exception:
            pass
        self.clamav.stop()
        if self.adb:
            self.adb.kill_server()
        self.tray.hide()

    def quit(self):
        self._quitting = True
        self.close()


def send_to_running(args):
    """Si Malryx est déjà ouvert, lui transmet la demande et renvoie True."""
    s = QLocalSocket()
    s.connectToServer(SERVER)
    if not s.waitForConnected(400):
        return False
    msg = "scan\t" + "\t".join(args.scan) if args.scan else "show"
    s.write(msg.encode("utf-8")); s.flush(); s.waitForBytesWritten(1000); s.disconnectFromServer()
    return True
