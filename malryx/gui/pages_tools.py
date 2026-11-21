"""Page Outils : audit de sécurité, nettoyage, gestionnaire de démarrage, processus, journal."""
from pathlib import Path

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (QCheckBox, QHBoxLayout, QPlainTextEdit, QTabWidget, QVBoxLayout, QWidget,
                               QTableWidgetItem)

from .. import audit, cleaner, history, quarantine, winsys
from ..engine import MALWARE, SUSPECT
from ..paths import data_dir
from .common import Page, btn, confirm, info
from .theme import C, icon
from .widgets import Card, Table, icon_label, label
from .workers import FuncWorker


class Gauge(QWidget):
    def __init__(self):
        super().__init__()
        self.value = None
        self.setFixedSize(150, 150)

    def set(self, v):
        self.value = v
        self.update()

    def paintEvent(self, _):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(12, 12, 126, 126)
        p.setPen(QPen(QColor(C["border"]), 12, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(r, 225 * 16, -270 * 16)
        if self.value is not None:
            col = C["ok"] if self.value >= 80 else C["warn"] if self.value >= 50 else C["bad"]
            p.setPen(QPen(QColor(col), 12, Qt.SolidLine, Qt.RoundCap))
            p.drawArc(r, 225 * 16, int(-270 * 16 * self.value / 100))
        p.setPen(QColor(C["text"]))
        f = p.font(); f.setPointSize(22); f.setBold(True); p.setFont(f)
        p.drawText(r, Qt.AlignCenter, "—" if self.value is None else f"{self.value}")


class ToolsPage(Page):
    def __init__(self, app):
        super().__init__(app, "Outils", "Audit de sécurité, processus et journal", scroll=False)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._audit(), "Audit de sécurité")
        self.tabs.addTab(self._procs(), "Processus")
        self.tabs.addTab(self._journal(), "Journal")
        self._clean(); self._startup()  # désormais dans les pages Nettoyage et Performances
        self.tabs.currentChanged.connect(self._tab)
        self.body.addWidget(self.tabs, 1)

    def _box(self):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(0, 12, 0, 0); v.setSpacing(12)
        return w, v

    def _tab(self, i):
        if i == 1 and not self.p_table.rowCount():
            self._load_procs()
        elif i == 2:
            self._load_journal()

    # ---------- audit ----------
    def _audit(self):
        w, v = self._box()
        top = Card(); h = QHBoxLayout(); top.lay.addLayout(h)
        self.gauge = Gauge(); h.addWidget(self.gauge)
        tv = QVBoxLayout()
        tv.addWidget(label("Score de sécurité", "Section"))
        self.a_sum = label("Vérifie Windows Defender, le pare-feu, l'UAC, SMBv1, le Bureau à distance, les mises à jour, "
                           "BitLocker, le fichier hosts et les détournements du registre.", muted=True, wrap=True)
        tv.addWidget(self.a_sum)
        self.a_btn = btn("  Lancer l'audit", "shield-check", "Primary", slot=self.run_audit)
        tv.addWidget(self.a_btn, 0, Qt.AlignLeft); tv.addStretch()
        h.addLayout(tv, 1)
        v.addWidget(top)
        self.a_table = Table(["", "Point de contrôle", "État", ""], stretch_col=2)
        self.a_table.setColumnWidth(0, 34)
        v.addWidget(self.a_table, 1)
        return w

    def run_audit(self):
        self.a_btn.setEnabled(False); self.a_btn.setText("  Audit en cours…")
        self._aw = FuncWorker(audit.run, self.app.settings, self.app.clamav)
        self._aw.result.connect(self._audit_done)
        self._aw.start()

    def _audit_done(self, checks):
        self.a_btn.setEnabled(True); self.a_btn.setText("  Relancer l'audit")
        if isinstance(checks, Exception):
            info(self, "Audit", str(checks)); return
        sc = audit.score(checks)
        self.app.audit_score = sc
        self.gauge.set(sc)
        bad = sum(c["status"] != "ok" for c in checks)
        self.a_sum.setText(f"{len(checks)} points vérifiés · {bad} à améliorer" if bad else f"{len(checks)} points vérifiés · tout est en ordre")
        self.a_table.setRowCount(0)
        col = {"ok": C["ok"], "warn": C["warn"], "bad": C["bad"]}
        for c in sorted(checks, key=lambda c: {"bad": 0, "warn": 1, "ok": 2}[c["status"]]):
            r = self.a_table.add_row(["", c["name"], c["detail"], ""], data=c)
            self.a_table.item(r, 0).setIcon(icon("check" if c["status"] == "ok" else "alert", col[c["status"]], 16))
            if c["fix"] and c["status"] != "ok":
                b = btn(c["fix_label"], slot=lambda _=False, f=c["fix"]: self._fix(f))
                b.setObjectName("Small")
                self.a_table.setCellWidget(r, 3, b)
        self.a_table.resizeColumnToContents(3)
        self.app.refresh_all()

    def _fix(self, f):
        if f == "malryx:realtime":
            self.app.set_realtime(True)
        elif f == "malryx:update":
            self.app.update_signatures()
        elif f == "malryx:scan":
            self.app.start_scan("rapide")
        elif f == "malryx:admin":
            self.app.relaunch_admin()
        else:
            try:
                if f.startswith("ms-settings:") or f.endswith(":"):
                    winsys.open_uri(f)
                else:
                    import subprocess
                    subprocess.Popen(f, shell=True)
            except OSError as e:
                info(self, "Correction", str(e))

    # ---------- nettoyage ----------
    def _clean(self):
        w, v = self._box()
        top = QHBoxLayout()
        self.c_info = label("Libérez de l'espace en supprimant les fichiers inutiles. Vos documents ne sont jamais touchés.", muted=True, wrap=True)
        top.addWidget(self.c_info, 1)
        self.c_an = btn("Analyser", "search", slot=self._clean_scan)
        self.c_go = btn("  Nettoyer", "trash", "Primary", slot=self._clean_go); self.c_go.setEnabled(False)
        top.addWidget(self.c_an); top.addWidget(self.c_go)
        v.addLayout(top)
        self.c_table = Table(["", "Catégorie", "Fichiers", "Taille"], stretch_col=1)
        self.c_table.setColumnWidth(0, 34)
        v.addWidget(self.c_table, 1)
        return w

    def _clean_scan(self):
        self.c_an.setEnabled(False); self.c_info.setText("Analyse des fichiers inutiles…")
        self._cw = FuncWorker(cleaner.analyse); self._cw.result.connect(self._clean_list); self._cw.start()

    def _clean_list(self, res):
        self.c_an.setEnabled(True)
        if isinstance(res, Exception):
            self.c_info.setText(str(res)); return
        self.c_table.setRowCount(0)
        total = 0
        for c in res:
            r = self.c_table.add_row(["", c["name"], c["count"] if c["count"] is not None else "—", cleaner.human(c["size"])], data=c)
            it = self.c_table.item(r, 0)
            it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
            it.setCheckState(Qt.Checked if c["size"] and "Windows Update" not in c["name"] else Qt.Unchecked)
            total += c["size"]
        self.c_info.setText(f"{cleaner.human(total)} peuvent être libérés.")
        self.c_go.setEnabled(total > 0)

    def _clean_go(self):
        names = [d["name"] for r, d in self.c_table.all_data() if self.c_table.item(r, 0).checkState() == Qt.Checked]
        if not names or not confirm(self, "Nettoyage", "Supprimer définitivement les fichiers des catégories cochées ?", "Nettoyer"):
            return
        self.c_go.setEnabled(False); self.c_info.setText("Nettoyage en cours…")
        self._cw2 = FuncWorker(cleaner.clean, names)
        self._cw2.result.connect(lambda n: (self.c_info.setText(f"{cleaner.human(n) if not isinstance(n, Exception) else n} libérés."),
                                            self.app.log(f"Nettoyage : {cleaner.human(n) if not isinstance(n, Exception) else n} libérés"),
                                            self._clean_scan()))
        self._cw2.start()

    # ---------- démarrage ----------
    def _startup(self):
        w, v = self._box()
        top = QHBoxLayout()
        top.addWidget(label("Programmes lancés au démarrage de Windows. Désactivez ceux que vous ne connaissez pas.", muted=True, wrap=True), 1)
        top.addWidget(btn("Actualiser", "refresh", slot=self._load_startup))
        top.addWidget(btn("Analyser", "search", slot=self._scan_startup))
        top.addWidget(btn("Activer / Désactiver", "zap", slot=self._toggle_startup))
        v.addLayout(top)
        self.st_table = Table(["Nom", "État", "Source", "Commande", "Verdict"], stretch_col=3)
        v.addWidget(self.st_table, 1)
        return w

    def _load_startup(self):
        self._sw = FuncWorker(winsys.all_startup_items)
        self._sw.result.connect(self._startup_loaded); self._sw.start()

    def _startup_loaded(self, items):
        if isinstance(items, Exception):
            return
        self.st_table.setRowCount(0)
        for it in items:
            state = "Désactivé" if it.get("disabled") or str(it.get("state")) in ("1", "Disabled") else "Activé"
            self.st_table.add_row([it["name"], state, it["source"], it["command"], ""], data=it)

    def _scan_startup(self):
        def work():
            out = []
            for r, it in self.st_table.all_data():
                exe = it.get("exe")
                out.append((r, self.app.engine.scan_file(exe) if exe and Path(exe).exists()
                            else {"verdict": "INTROUVABLE" if exe else "—"}))
            return out
        self._ssw = FuncWorker(work)
        self._ssw.result.connect(self._startup_scanned); self._ssw.start()

    def _startup_scanned(self, res):
        if isinstance(res, Exception):
            return
        from .theme import VERDICT_COLORS
        for r, x in res:
            it = QTableWidgetItem(x["verdict"])
            it.setForeground(QColor(VERDICT_COLORS.get(x["verdict"], C["muted"])))
            it.setToolTip("\n".join(x.get("reasons", [])))
            self.st_table.setItem(r, 4, it)

    def _toggle_startup(self):
        sel = self.st_table.selected_data()
        if not sel:
            return
        for r, it in sel:
            enable = self.st_table.item(r, 1).text() == "Désactivé"
            try:
                if winsys.set_startup_item(it, enable):
                    self.app.log(f"Démarrage : {it['name']} {'activé' if enable else 'désactivé'}")
            except PermissionError:
                info(self, "Démarrage", "Droits administrateur requis pour cet élément.")
            except OSError as e:
                info(self, "Démarrage", str(e))
        self._load_startup()

    # ---------- processus ----------
    def _procs(self):
        w, v = self._box()
        top = QHBoxLayout()
        self.p_info = label("", muted=True); top.addWidget(self.p_info, 1)
        top.addWidget(btn("Actualiser", "refresh", slot=self._load_procs))
        top.addWidget(btn("Analyser tout", "search", slot=self._scan_procs))
        top.addWidget(btn("Ouvrir l'emplacement", "folder", slot=self._proc_loc))
        top.addWidget(btn("Arrêter le processus", "stop", "Danger", slot=self._kill))
        v.addLayout(top)
        self.p_table = Table(["Processus", "PID", "Utilisateur", "Mémoire", "Chemin", "Verdict"], stretch_col=4)
        v.addWidget(self.p_table, 1)
        return w

    def _load_procs(self):
        procs = winsys.process_list()
        self.p_table.setRowCount(0)
        for p in procs:
            self.p_table.add_row([p["name"], p["pid"], p["user"], f"{p['mem']:.0f} Mo", p["exe"], ""], data=p)
        self.p_info.setText(f"{len(procs)} processus en cours")

    def _scan_procs(self):
        self.p_info.setText("Analyse des processus…")
        rows = self.p_table.all_data()

        def work():
            cache, out = {}, []
            for r, p in rows:
                exe = p["exe"]
                if exe and exe not in cache and Path(exe).exists():
                    cache[exe] = self.app.engine.scan_file(exe)
                out.append((r, cache.get(exe)))
            return out
        self._pw = FuncWorker(work)
        self._pw.result.connect(self._procs_scanned); self._pw.start()

    def _procs_scanned(self, res):
        if isinstance(res, Exception):
            return
        from .theme import VERDICT_COLORS
        bad = 0
        for r, x in res:
            v = x["verdict"] if x else "—"
            bad += v in (MALWARE, SUSPECT)
            it = QTableWidgetItem(v); it.setForeground(QColor(VERDICT_COLORS.get(v, C["muted"])))
            if x:
                it.setToolTip("\n".join(x["reasons"])); it.setData(Qt.UserRole, x)
            self.p_table.setItem(r, 5, it)
        self.p_info.setText(f"Analyse terminée · {bad} processus à risque")

    def _proc_loc(self):
        sel = self.p_table.selected_data()
        if sel and sel[0][1]["exe"]:
            winsys.open_location(sel[0][1]["exe"])

    def _kill(self):
        sel = self.p_table.selected_data()
        if not sel:
            return
        names = ", ".join(p["name"] for _, p in sel)
        if not confirm(self, "Arrêter", f"Arrêter {names} ?\nLes données non enregistrées seront perdues.", "Arrêter", True):
            return
        for r, p in sel:
            res = self.p_table.item(r, 5).data(Qt.UserRole) if self.p_table.item(r, 5) else None
            winsys.kill_pid(p["pid"])
            if res and res.get("verdict") == MALWARE and confirm(self, "Quarantaine", f"Mettre {p['exe']} en quarantaine ?", "Oui"):
                try:
                    quarantine.quarantine(p["exe"], res); history.add("Processus", res, "arrêté + quarantaine")
                except OSError as e:
                    info(self, "Quarantaine", str(e))
        self._load_procs()

    # ---------- journal ----------
    def _journal(self):
        w, v = self._box()
        top = QHBoxLayout(); top.addStretch()
        top.addWidget(btn("Ouvrir le dossier de Malryx", "folder", slot=lambda: winsys.open_folder(data_dir())))
        top.addWidget(btn("Actualiser", "refresh", slot=self._load_journal))
        v.addLayout(top)
        self.j_text = QPlainTextEdit(); self.j_text.setReadOnly(True)
        v.addWidget(self.j_text, 1)
        return w

    def _load_journal(self):
        p = data_dir("malryx.log")
        text = p.read_text(encoding="utf-8", errors="ignore") if p.exists() else ""
        self.j_text.setPlainText("\n".join(text.splitlines()[-1500:]))
        self.j_text.verticalScrollBar().setValue(self.j_text.verticalScrollBar().maximum())

    def on_show(self):
        self._tab(self.tabs.currentIndex())
