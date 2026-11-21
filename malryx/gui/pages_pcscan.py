"""« Analyser mon PC » : analyse globale façon AVG, problèmes réels par catégorie, « Tout corriger »."""
from PySide6.QtCore import QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QFrame, QGridLayout, QHBoxLayout, QStackedWidget, QTableWidgetItem, QVBoxLayout, QWidget

from .. import pcscan
from .common import Page, btn, fmt_date, info
from .theme import C, icon
from .widgets import Card, Table, icon_label, label
from .workers import PcScanWorker, TaskWorker

CAT_ICON = {"Sécurité": ("shield", C["bad"]), "Performances": ("zap", C["warn"]),
            "Espace disque": ("disk", C["info"]), "Confidentialité": ("eye", C["accent"])}
NAV_FOR = {"review_threats": "history", "audit": "tools", "startup": "performance", "sleep": "performance",
           "health": "performance", "realtime": None}


class Ring(QWidget):
    def __init__(self, size=210):
        super().__init__()
        self.setFixedSize(size, size)
        self.value, self.text, self.sub, self.color, self.spin = 0.0, "", "", C["accent"], 0
        self.t = QTimer(self); self.t.timeout.connect(self._step)

    def _step(self):
        self.spin = (self.spin + 6) % 360; self.update()

    def set(self, value, text, sub="", color=C["accent"], busy=False):
        self.value, self.text, self.sub, self.color = value, text, sub, color
        self.t.start(16) if busy else self.t.stop()
        self.update()

    def paintEvent(self, _):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w = self.width(); r = QRectF(14, 14, w - 28, w - 28)
        p.setPen(QPen(QColor(C["border"]), 14)); p.drawEllipse(r)
        p.setPen(QPen(QColor(self.color), 14, Qt.SolidLine, Qt.RoundCap))
        if self.t.isActive():
            p.drawArc(r, -self.spin * 16, 90 * 16)
        else:
            p.drawArc(r, 90 * 16, int(-360 * 16 * self.value))
        p.setPen(QColor(C["text"]))
        f = p.font(); f.setPointSize(26); f.setBold(True); p.setFont(f)
        p.drawText(QRectF(0, w / 2 - 34, w, 44), Qt.AlignCenter, self.text)
        f.setPointSize(9); f.setBold(False); p.setFont(f); p.setPen(QColor(C["muted"]))
        p.drawText(QRectF(10, w / 2 + 10, w - 20, 40), Qt.AlignCenter | Qt.TextWordWrap, self.sub)


class PcScanPage(Page):
    def __init__(self, app):
        super().__init__(app, "Analyse du PC", "Menaces, sécurité, espace, performances et confidentialité en une seule analyse", scroll=False)
        self.problems = []
        top = Card(); h = QHBoxLayout(); top.lay.addLayout(h)
        self.ring = Ring(); h.addWidget(self.ring); h.addSpacing(20)
        v = QVBoxLayout(); v.addStretch()
        self.title = label("Votre PC n'a pas encore été analysé", "HeroTitle")
        self.sub = label("Malryx vérifie les menaces, la sécurité de Windows, les fichiers inutiles, les traces de navigation, "
                         "la télémétrie, les logiciels obsolètes, le démarrage et la santé du système. Seuls de vrais problèmes sont comptés.",
                         muted=True, wrap=True)
        v.addWidget(self.title); v.addWidget(self.sub); v.addSpacing(8)
        bl = QHBoxLayout()
        self.go_btn = btn("  Analyser mon PC", "search", "Primary", slot=self.start)
        self.go_btn.setMinimumHeight(46); self.go_btn.setMinimumWidth(200)
        self.fix_btn = btn("  Tout corriger", "check", "Primary", slot=self.fix_all)
        self.fix_btn.setMinimumHeight(46); self.fix_btn.hide()
        self.stop_btn = btn("Arrêter", "stop", "Danger", slot=lambda: self.worker.cancel()); self.stop_btn.hide()
        bl.addWidget(self.go_btn); bl.addWidget(self.fix_btn); bl.addWidget(self.stop_btn); bl.addStretch()
        v.addLayout(bl); v.addStretch()
        h.addLayout(v, 1)
        self.body.addWidget(top)

        grid = QHBoxLayout(); grid.setSpacing(16)
        self.cards = {}
        for cat in pcscan.CATEGORIES:
            c = Card(pad=16, spacing=4)
            hh = QHBoxLayout(); ic, col = CAT_ICON[cat]
            hh.addWidget(icon_label(ic, col, 22)); hh.addWidget(label(cat, "Section")); hh.addStretch()
            c.lay.addLayout(hh)
            n = label("—", "StatValue"); c.lay.addWidget(n)
            d = label("", muted=True); c.lay.addWidget(d)
            self.cards[cat] = (n, d)
            grid.addWidget(c, 1)
        self.body.addLayout(grid)

        res = Card()
        hh = QHBoxLayout(); hh.addWidget(label("Problèmes détectés", "Section")); hh.addStretch()
        self.res_info = label("", muted=True); hh.addWidget(self.res_info)
        res.lay.addLayout(hh)
        self.table = Table(["", "Catégorie", "Problème", "Détail", "Action"], stretch_col=3)
        self.table.setColumnWidth(0, 34)
        res.lay.addWidget(self.table)
        self.body.addWidget(res, 1)
        self._show_last()

    def _show_last(self):
        ps = self.app.settings["pcscan"]
        if ps.get("last"):
            self.sub.setText(f"Dernière analyse : {fmt_date(ps['last'])} · {ps['problems']} problème(s). Relancez pour un état à jour.")
        self.ring.set(0, "?", "non analysé", C["muted"])

    # ---------- analyse ----------
    def start(self):
        self.app.go("pcscan")
        self.table.setRowCount(0)
        self.go_btn.hide(); self.fix_btn.hide(); self.stop_btn.show()
        self.title.setText("Analyse en cours…")
        for n, d in self.cards.values():
            n.setText("…"); d.setText("")
        self.ring.set(0, "", "", C["accent"], busy=True)
        self.worker = PcScanWorker(self.app)
        self.worker.step.connect(lambda s, i, n: (self.sub.setText(f"Étape {min(i + 1, n)}/{n} : {s}"),
                                                  self.ring.set(i / n, f"{int(100 * i / n)} %", s, C["accent"], busy=i < n)))
        self.worker.done.connect(self._done)
        self.worker.start()

    def _done(self, problems):
        self.stop_btn.hide(); self.go_btn.show(); self.go_btn.setText("  Analyser à nouveau")
        if isinstance(problems, Exception):
            self.title.setText("L'analyse a échoué"); self.sub.setText(str(problems)); return
        self.problems = problems
        n = len(problems)
        bad = sum(p["severity"] == "bad" for p in problems)
        col = C["ok"] if n == 0 else C["bad"] if bad else C["warn"]
        self.ring.set(1, str(n), "problème(s)" if n else "tout va bien", col)
        if n == 0:
            self.title.setText("Aucun problème détecté")
            self.sub.setText("Votre PC est sain, rapide et protégé.")
        else:
            autos = sum(p["auto"] for p in problems)
            self.title.setText(f"{n} problème(s) à résoudre")
            self.sub.setText(f"{bad} important(s). {autos} peuvent être corrigés automatiquement avec « Tout corriger », "
                             "les autres demandent votre choix (bouton « Voir »).")
            self.fix_btn.setVisible(autos > 0)
        for cat, (num, d) in self.cards.items():
            items = [p for p in problems if p["category"] == cat]
            num.setText(str(len(items)))
            num.setStyleSheet(f"color:{C['ok'] if not items else C['bad'] if any(p['severity'] == 'bad' for p in items) else C['warn']}")
            d.setText("Rien à signaler" if not items else items[0]["title"][:38])
        self.table.setRowCount(0)
        for p in problems:
            r = self.table.add_row(["", p["category"], p["title"], p["detail"], ""], data=p)
            it = self.table.item(r, 0)
            it.setIcon(icon("alert", C["bad"] if p["severity"] == "bad" else C["warn"], 16))
            if p["auto"]:
                it.setFlags(it.flags() | Qt.ItemIsUserCheckable); it.setCheckState(Qt.Checked)
            b = btn("Corriger" if p["auto"] else "Voir", slot=lambda _=False, row=r: self._action(row))
            b.setObjectName("Small")
            self.table.setCellWidget(r, 4, b)
        self.table.setColumnWidth(4, 130)
        self.res_info.setText(f"{len(problems)} problème(s)")
        self.app.refresh_all()

    # ---------- corrections ----------
    def _action(self, row):
        p = self.table.item(row, 0).data(Qt.UserRole)
        if p["auto"]:
            self._run_fixes([(row, p)])
        elif p["fix"] == "realtime":
            self.app.set_realtime(True)
        else:
            target = NAV_FOR.get(p["fix"])
            if p["fix"] == "audit":
                self.app.go("tools"); self.app.pages["tools"].tabs.setCurrentIndex(0)
            elif p["fix"] in ("startup", "sleep", "health"):
                self.app.go("performance")
                self.app.pages["performance"].tabs.setCurrentIndex({"startup": 0, "sleep": 1, "health": 3}[p["fix"]])
            elif target:
                self.app.go(target)

    def fix_all(self):
        rows = [(r, d) for r, d in self.table.all_data()
                if self.table.item(r, 0).flags() & Qt.ItemIsUserCheckable and self.table.item(r, 0).checkState() == Qt.Checked]
        if rows:
            self._run_fixes(rows)

    def _run_fixes(self, rows):
        self.fix_btn.setEnabled(False); self.go_btn.setEnabled(False)

        def work(progress):
            out = []
            for r, p in rows:
                progress(f"Correction : {p['title']}…")
                if p["fix"] == "realtime":
                    out.append((r, "protection réactivée")); continue
                try:
                    out.append((r, pcscan.fix(self.app, p, progress) or "corrigé"))
                except Exception as e:
                    out.append((r, f"échec : {e}"))
            return out
        self._fw = TaskWorker(work)
        self._fw.progress.connect(lambda m: self.sub.setText(m))
        self._fw.result.connect(self._fixed)
        self._fw.start()

    def _fixed(self, res):
        self.fix_btn.setEnabled(True); self.go_btn.setEnabled(True)
        if isinstance(res, Exception):
            info(self, "Correction", str(res)); return
        for r, msg in res:
            it = self.table.item(r, 0)
            it.setFlags(it.flags() & ~Qt.ItemIsUserCheckable); it.setData(Qt.CheckStateRole, None)
            ok = not msg.startswith("échec")
            it.setIcon(icon("check" if ok else "alert", C["ok"] if ok else C["bad"], 16))
            self.table.removeCellWidget(r, 4)
            cell = QTableWidgetItem(msg); cell.setForeground(QColor(C["ok"] if ok else C["bad"]))
            self.table.setItem(r, 4, cell)
            p = self.table.item(r, 0).data(Qt.UserRole)
            if p and p["fix"] == "realtime":
                self.app.set_realtime(True)
        self.table.resizeColumnToContents(4)
        remaining = [d for r, d in self.table.all_data() if self.table.cellWidget(r, 4)]
        left = len(remaining)
        for cat, (num, d) in self.cards.items():
            items = [p for p in remaining if p["category"] == cat]
            num.setText(str(len(items)))
            num.setStyleSheet(f"color:{C['ok'] if not items else C['warn']}")
            d.setText("Rien à signaler" if not items else items[0]["title"][:38])
        self.fix_btn.setVisible(any(p["auto"] for p in remaining))
        self.title.setText("Corrections appliquées" + (f" · {left} problème(s) demandent votre choix" if left else ""))
        self.sub.setText("Relancez l'analyse pour vérifier le résultat.")
        self.ring.set(1, str(left), "restant(s)", C["ok"] if not left else C["warn"])
        self.app.pending_threats = 0
        self.app.refresh_all()
