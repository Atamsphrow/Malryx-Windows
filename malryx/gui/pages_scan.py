"""Page Analyse : choix du type, progression par étapes, résultats et traitement des menaces."""
import time
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QListWidgetItem, QFileDialog, QFrame, QHBoxLayout, QListWidget, QProgressBar, QPushButton,
                               QStackedWidget, QVBoxLayout, QWidget, QTableWidgetItem)

from .. import history, quarantine, winsys
from ..engine import MALWARE, SUSPECT
from .common import DetailDialog, Page, btn, confirm, info
from .theme import C, icon, pixmap
from .widgets import Card, Table, icon_label, label
from .workers import STAGES, ScanWorker


class ScanTypeCard(QPushButton):
    def __init__(self, ic, title, desc, badge=None):
        super().__init__()
        self.setObjectName("Big")
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(170)
        v = QVBoxLayout(self); v.setContentsMargins(20, 18, 20, 18)
        h = QHBoxLayout(); h.addWidget(icon_label(ic, C["accent"], 30)); h.addStretch()
        if badge:
            b = label(badge, "Chip"); b.setStyleSheet(f"color:{C['ok']}"); h.addWidget(b)
        v.addLayout(h)
        t = label(title, "Section"); t.setAttribute(Qt.WA_TransparentForMouseEvents)
        d = label(desc, muted=True, wrap=True); d.setAttribute(Qt.WA_TransparentForMouseEvents)
        v.addWidget(t); v.addWidget(d); v.addStretch()


class StageRow(QWidget):
    def __init__(self, name):
        super().__init__()
        h = QHBoxLayout(self); h.setContentsMargins(4, 6, 4, 6)
        self.ic = label(); self.ic.setFixedSize(22, 22)
        self.name = label(name)
        h.addWidget(self.ic); h.addWidget(self.name, 1)
        self.set("pending")

    def set(self, state):
        if state == "done":
            self.ic.setPixmap(pixmap("check", C["ok"], 18)); self.name.setStyleSheet(f"color:{C['text']}")
        elif state == "running":
            self.ic.setPixmap(pixmap("refresh", C["accent"], 18)); self.name.setStyleSheet("font-weight:700")
        else:
            self.ic.setPixmap(pixmap("minus", C["border"], 18)); self.name.setStyleSheet(f"color:{C['muted']}")


class ScanPage(Page):
    def __init__(self, app):
        super().__init__(app, "Analyse", "Recherchez les malwares, ransomwares, logiciels espions et programmes indésirables", scroll=False)
        self.worker = None
        self.custom_paths = []
        self.stack = QStackedWidget()
        self.body.addWidget(self.stack)
        self.stack.addWidget(self._build_choice())
        self.stack.addWidget(self._build_run())
        self.setAcceptDrops(True)

    # ---------- écran de choix ----------
    def _build_choice(self):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(0, 0, 0, 0); v.setSpacing(16)
        row = QHBoxLayout(); row.setSpacing(16)
        a = ScanTypeCard("zap", "Analyse des menaces",
                         "Mémoire, éléments de démarrage, registre et dossiers où se cachent la plupart des malwares. "
                         "Rapide et efficace au quotidien.", "Recommandée")
        a.clicked.connect(lambda: self.start("rapide"))
        b = ScanTypeCard("disk", "Analyse complète",
                         "Tout ce qui précède, plus chaque fichier de tous les disques. Peut prendre plus d'une heure.")
        b.clicked.connect(lambda: self.start("complète"))
        c = ScanTypeCard("folder", "Analyse personnalisée",
                         "Choisissez les dossiers, fichiers ou clés USB à analyser. Vous pouvez aussi les glisser-déposer ici.")
        c.clicked.connect(self._custom_focus)
        for x in (a, b, c):
            row.addWidget(x, 1)
        v.addLayout(row)

        cc = Card()
        h = QHBoxLayout(); h.addWidget(label("Éléments de l'analyse personnalisée", "Section")); h.addStretch()
        h.addWidget(btn("Ajouter un dossier", "plus", slot=self._add_dir))
        h.addWidget(btn("Ajouter des fichiers", "plus", slot=self._add_files))
        h.addWidget(btn("Retirer", "minus", slot=self._remove))
        cc.lay.addLayout(h)
        self.custom_list = QListWidget(); self.custom_list.setMinimumHeight(120)
        cc.lay.addWidget(self.custom_list)
        h2 = QHBoxLayout()
        h2.addWidget(label("Astuce : glissez des fichiers sur cette fenêtre, ou faites un clic droit → « Analyser avec Malryx » dans l'Explorateur.", muted=True, wrap=True), 1)
        self.custom_go = btn("  Lancer l'analyse personnalisée", "play", "Primary", slot=lambda: self.start("personnalisée", self.custom_paths))
        h2.addWidget(self.custom_go)
        cc.lay.addLayout(h2)
        v.addWidget(cc, 1)
        return w

    def _custom_focus(self):
        if self.custom_paths:
            self.start("personnalisée", self.custom_paths)
        else:
            self._add_dir()

    def _add_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Dossier à analyser")
        if d:
            self._add_paths([d])

    def _add_files(self):
        fs, _ = QFileDialog.getOpenFileNames(self, "Fichiers à analyser")
        self._add_paths(fs)

    def _add_paths(self, paths):
        for p in paths:
            if p and p not in self.custom_paths:
                self.custom_paths.append(p)
                self.custom_list.addItem(QListWidgetItem(icon("folder" if Path(p).is_dir() else "list", C["muted"], 16), p))

    def _remove(self):
        for it in self.custom_list.selectedItems():
            self.custom_paths.remove(it.text())
            self.custom_list.takeItem(self.custom_list.row(it))

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        paths = [u.toLocalFile() for u in e.mimeData().urls() if u.toLocalFile()]
        if paths:
            self.start("personnalisée", paths)

    # ---------- écran d'analyse ----------
    def _build_run(self):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(0, 0, 0, 0); v.setSpacing(16)
        top = QHBoxLayout(); top.setSpacing(16)
        self.stage_card = Card(); self.stage_card.setFixedWidth(300)
        self.stage_title = label("Analyse des menaces", "Section")
        self.stage_card.lay.addWidget(self.stage_title)
        self.stage_box = QVBoxLayout(); self.stage_box.setSpacing(0)
        self.stage_card.lay.addLayout(self.stage_box)
        self.stage_card.lay.addStretch()
        top.addWidget(self.stage_card)

        right = Card()
        self.status = label("", "HeroTitle"); self.status.setStyleSheet("font-size:16pt")
        right.lay.addWidget(self.status)
        nums = QHBoxLayout(); nums.setSpacing(30)
        self.n_items, self.n_bad, self.n_sus, self.n_time = (self._num(nums, t, c) for t, c in (
            ("Éléments analysés", C["text"]), ("Menaces", C["bad"]), ("Suspects", C["warn"]), ("Durée", C["text"])))
        nums.addStretch()
        right.lay.addLayout(nums)
        self.bar = QProgressBar(); self.bar.setFixedHeight(10); self.bar.setTextVisible(False)
        right.lay.addWidget(self.bar)
        self.current = label("", muted=True); self.current.setMinimumWidth(100)
        right.lay.addWidget(self.current)
        bl = QHBoxLayout(); bl.addStretch()
        self.pause_b = btn("Pause", "pause", slot=self._pause)
        self.cancel_b = btn("Annuler", "stop", "Danger", slot=self._cancel)
        self.new_b = btn("Nouvelle analyse", "refresh", slot=lambda: self.stack.setCurrentIndex(0))
        bl.addWidget(self.pause_b); bl.addWidget(self.cancel_b); bl.addWidget(self.new_b)
        right.lay.addLayout(bl)
        right.lay.addStretch()
        top.addWidget(right, 1)
        v.addLayout(top)

        res = Card()
        h = QHBoxLayout(); self.res_title = label("Détections", "Section"); h.addWidget(self.res_title); h.addStretch()
        self.sel_all = btn("Tout sélectionner", slot=lambda: self._check_all(True))
        self.q_btn = btn("  Mettre en quarantaine", "box", "Primary", slot=self._quarantine_selected)
        self.ign_btn = btn("Ignorer toujours", slot=self._allow_selected)
        self.loc_btn = btn("Ouvrir l'emplacement", "folder", slot=self._open_loc)
        for b in (self.sel_all, self.loc_btn, self.ign_btn, self.q_btn):
            h.addWidget(b)
        res.lay.addLayout(h)
        self.table = Table(["", "Verdict", "Menace", "Élément", "Raison principale"], stretch_col=3)
        self.table.setColumnWidth(0, 34)
        self.table.cellDoubleClicked.connect(self._details)
        res.lay.addWidget(self.table)
        v.addWidget(res, 1)
        self.timer = QTimer(self); self.timer.timeout.connect(self._tick)
        return w

    def _num(self, lay, title, color):
        v = QVBoxLayout(); v.setSpacing(0)
        n = label("0", "StatValue"); n.setStyleSheet(f"color:{color}")
        v.addWidget(n); v.addWidget(label(title, muted=True))
        lay.addLayout(v)
        return n

    # ---------- déroulement ----------
    def start(self, mode, paths=()):
        if self.worker and self.worker.isRunning():
            info(self, "Analyse en cours", "Une analyse est déjà en cours.")
            self.stack.setCurrentIndex(1)
            return
        if mode == "personnalisée" and not paths:
            self._add_dir()
            return
        self.app.go("scan")
        self.stack.setCurrentIndex(1)
        self.table.setRowCount(0)
        while self.stage_box.count():
            it = self.stage_box.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        names = STAGES[mode]
        self.stage_rows = [StageRow(n) for n in names]
        for r in self.stage_rows:
            self.stage_box.addWidget(r)
        self.stage_title.setText({"rapide": "Analyse des menaces", "complète": "Analyse complète",
                                  "personnalisée": "Analyse personnalisée"}[mode])
        self.status.setText("Analyse en cours…")
        self.status.setStyleSheet("font-size:16pt")
        for n in (self.n_items, self.n_bad, self.n_sus):
            n.setText("0")
        self.bar.setRange(0, 0)
        self.pause_b.show(); self.cancel_b.show(); self.new_b.hide()
        self.pause_b.setText("Pause"); self.paused = False
        self._actions(False)
        self.t0 = time.time()
        self.timer.start(1000)
        self.worker = ScanWorker(self.app.engine, self.app.settings, mode, paths, self.app.clamav)
        self.worker.progress.connect(self._progress)
        self.worker.stage.connect(lambda i, s: self.stage_rows[i].set(s))
        self.worker.found.connect(self._found)
        self.worker.done.connect(self._done)
        self.worker.start()
        self.app.log(f"Analyse {mode} démarrée")
        self.app.tray_status(f"Analyse {mode} en cours…")

    def _tick(self):
        s = int(time.time() - self.t0)
        self.n_time.setText(f"{s // 60:02d}:{s % 60:02d}")

    def _progress(self, done, total, cur):
        self.n_items.setText(f"{done:,}".replace(",", " "))
        if total:
            self.bar.setRange(0, total); self.bar.setValue(done)
        else:
            self.bar.setRange(0, 0)
        if cur:
            self.current.setText(self.current.fontMetrics().elidedText(cur, Qt.ElideMiddle, max(300, self.current.width())))

    def _found(self, r):
        row = self.table.add_row(["", r["verdict"], r.get("threat") or "", r["path"], (r["reasons"] or [""])[0]],
                                 data=r, verdict_col=1)
        it = self.table.item(row, 0)
        it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
        it.setCheckState(Qt.Checked if r["verdict"] == MALWARE else Qt.Unchecked)
        self.n_bad.setText(str(self.worker.counts["bad"]))
        self.n_sus.setText(str(self.worker.counts["sus"]))
        self.res_title.setText(f"Détections ({self.table.rowCount()})")
        history.add("Analyse", r, "détecté")

    def _done(self, s):
        self.timer.stop(); self._tick()
        self.pause_b.hide(); self.cancel_b.hide(); self.new_b.show()
        n = s["malware"] + s["suspect"]
        if s["cancelled"]:
            self.status.setText("Analyse annulée")
        elif s["malware"]:
            self.status.setText(f"{s['malware']} menace(s) détectée(s)")
            self.status.setStyleSheet(f"font-size:16pt;color:{C['bad']}")
        elif s["suspect"]:
            self.status.setText(f"Aucune menace · {s['suspect']} élément(s) suspect(s)")
            self.status.setStyleSheet(f"font-size:16pt;color:{C['warn']}")
        else:
            self.status.setText("Aucune menace détectée")
            self.status.setStyleSheet(f"font-size:16pt;color:{C['ok']}")
        self.current.setText(f"{s['count']:,} éléments analysés en {s['seconds']:.0f} s".replace(",", " "))
        self.bar.setRange(0, 1); self.bar.setValue(1)
        self._actions(n > 0)
        history.save_report(s, self.worker.results, self.worker.stage_names)
        self.app.pending_threats = s["malware"]
        self.app.after_scan(s)

    def _actions(self, on):
        for b in (self.sel_all, self.q_btn, self.ign_btn, self.loc_btn):
            b.setEnabled(on)

    def _pause(self):
        self.paused = not self.paused
        self.worker.pause(self.paused)
        self.pause_b.setText("Reprendre" if self.paused else "Pause")
        self.pause_b.setIcon(icon("play" if self.paused else "pause"))
        self.status.setText("Analyse en pause" if self.paused else "Analyse en cours…")

    def _cancel(self):
        if self.worker:
            self.worker.cancel()

    def _check_all(self, v):
        for r in range(self.table.rowCount()):
            it = self.table.item(r, 0)
            if it.flags() & Qt.ItemIsUserCheckable:
                it.setCheckState(Qt.Checked if v else Qt.Unchecked)

    def _checked(self):
        return [(r, self.table.item(r, 0).data(Qt.UserRole)) for r in range(self.table.rowCount())
                if self.table.item(r, 0).checkState() == Qt.Checked and self.table.item(r, 0).flags() & Qt.ItemIsUserCheckable]

    def _mark(self, row, text, color):
        it = self.table.item(row, 0)
        it.setFlags(it.flags() & ~Qt.ItemIsUserCheckable)
        it.setData(Qt.CheckStateRole, None)
        it.setIcon(icon("check", color, 16))
        self.table.item(row, 1).setText(text)
        self.table.item(row, 1).setForeground(Qt.gray)

    def _quarantine_selected(self):
        items = self._checked()
        if not items:
            info(self, "Quarantaine", "Cochez les éléments à mettre en quarantaine.")
            return
        ok = fail = 0
        for row, r in items:
            try:
                if r.get("registry"):
                    winsys.fix_registry(r["registry"])
                    self._mark(row, "RÉPARÉ", C["ok"]); action = "registre réparé"
                else:
                    winsys.kill_process(r["path"])
                    quarantine.quarantine(r["path"], r)
                    self._mark(row, "EN QUARANTAINE", C["ok"]); action = "mis en quarantaine"
                history.add("Analyse", r, action); ok += 1
            except PermissionError:
                fail += 1
            except OSError as e:
                fail += 1; self.app.log(f"Quarantaine impossible : {r['path']} ({e})")
        self.app.pending_threats = max(0, self.app.pending_threats - ok)
        msg = f"{ok} élément(s) traité(s)."
        if fail:
            msg += f"\n{fail} élément(s) n'ont pas pu être traités : relancez Malryx en administrateur."
        info(self, "Quarantaine", msg)
        self.app.refresh_all()

    def _allow_selected(self):
        items = self._checked() or self.table.selected_data()
        if not items or not confirm(self, "Liste autorisée",
                                    f"Ne plus jamais signaler ces {len(items)} élément(s) ?\nN'ajoutez que des fichiers dont vous êtes sûr."):
            return
        ex = list(self.app.settings["exclusions"])
        for row, r in items:
            if r["path"] not in ex:
                ex.append(r["path"])
            self._mark(row, "AUTORISÉ", C["muted"])
        self.app.settings["exclusions"] = ex

    def _open_loc(self):
        sel = self.table.selected_data()
        if sel and Path(sel[0][1]["path"]).exists():
            winsys.open_location(sel[0][1]["path"])

    def _details(self, row, _col):
        r = self.table.item(row, 0).data(Qt.UserRole)
        d = DetailDialog(self, r, [("Mettre en quarantaine", "q", "Primary")])
        if d.exec() and d.choice == "q":
            self.table.item(row, 0).setCheckState(Qt.Checked)
            self.table.selectRow(row)
            for rr in range(self.table.rowCount()):
                if rr != row and self.table.item(rr, 0).flags() & Qt.ItemIsUserCheckable:
                    self.table.item(rr, 0).setCheckState(Qt.Unchecked)
            self._quarantine_selected()
