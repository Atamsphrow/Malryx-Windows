"""Page Historique : quarantaine, historique des détections, rapports d'analyse, liste autorisée."""
import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QPlainTextEdit, QTabWidget, QVBoxLayout, QWidget

from .. import history, quarantine
from .common import DetailDialog, Page, btn, confirm, fmt_date, info
from .widgets import Card, Table, label


class HistoryPage(Page):
    def __init__(self, app):
        super().__init__(app, "Historique des détections", "Quarantaine, journal des menaces et rapports d'analyse", scroll=False)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._quar(), "Quarantaine")
        self.tabs.addTab(self._hist(), "Historique")
        self.tabs.addTab(self._reports(), "Rapports d'analyse")
        self.tabs.addTab(self._allow(), "Liste autorisée")
        self.tabs.currentChanged.connect(lambda _: self.on_show())
        self.body.addWidget(self.tabs, 1)

    def _wrap(self, *widgets, bar=None):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(0, 12, 0, 0); v.setSpacing(12)
        if bar:
            v.addLayout(bar)
        for x in widgets:
            v.addWidget(x, 1)
        return w

    # ---------- quarantaine ----------
    def _quar(self):
        bar = QHBoxLayout()
        self.q_info = label("", muted=True); bar.addWidget(self.q_info); bar.addStretch()
        bar.addWidget(btn("Restaurer", "restore", slot=self._restore))
        bar.addWidget(btn("Supprimer", "trash", "Danger", slot=self._delete))
        bar.addWidget(btn("Tout supprimer", slot=self._delete_all))
        self.q_table = Table(["Date", "Menace", "Emplacement d'origine", "Taille"], stretch_col=2)
        self.q_table.cellDoubleClicked.connect(lambda r, _: DetailDialog(self, {**self.q_table.item(r, 0).data(Qt.UserRole),
                                                                                "verdict": "EN QUARANTAINE"}).exec())
        return self._wrap(self.q_table, bar=bar)

    def _restore(self):
        sel = self.q_table.selected_data()
        if not sel or not confirm(self, "Restaurer", "Restaurer ces fichiers à leur emplacement d'origine ?\n"
                                  "Ils pourront à nouveau s'exécuter.", "Restaurer", True):
            return
        for _, m in sel:
            try:
                p = quarantine.restore(m["sha256"])
                history.add("Quarantaine", m, f"restauré vers {p}")
                if confirm(self, "Liste autorisée", f"Ajouter {Path(p).name} à la liste autorisée pour ne plus le signaler ?", "Ajouter"):
                    self.app.settings["exclusions"] = self.app.settings["exclusions"] + [str(p)]
            except OSError as e:
                info(self, "Restaurer", str(e))
        self.on_show()

    def _delete(self):
        sel = self.q_table.selected_data()
        if sel and confirm(self, "Supprimer", f"Supprimer définitivement {len(sel)} élément(s) ?", "Supprimer", True):
            for _, m in sel:
                quarantine.delete(m["sha256"])
                history.add("Quarantaine", m, "supprimé définitivement")
            self.on_show()

    def _delete_all(self):
        items = quarantine.list_items()
        if items and confirm(self, "Vider la quarantaine", f"Supprimer définitivement les {len(items)} éléments ?", "Tout supprimer", True):
            for m in items:
                quarantine.delete(m["sha256"])
            self.on_show()

    # ---------- historique ----------
    def _hist(self):
        bar = QHBoxLayout(); bar.addStretch()
        bar.addWidget(btn("Exporter", "download", slot=self._export))
        bar.addWidget(btn("Effacer l'historique", "trash", slot=self._clear_hist))
        self.h_table = Table(["Date", "Source", "Menace", "Élément", "Action"], stretch_col=3)
        self.h_table.cellDoubleClicked.connect(lambda r, _: DetailDialog(self, self.h_table.item(r, 0).data(Qt.UserRole)).exec())
        return self._wrap(self.h_table, bar=bar)

    def _export(self):
        p, _ = QFileDialog.getSaveFileName(self, "Exporter l'historique", "historique_malryx.csv", "CSV (*.csv)")
        if p:
            import csv
            with open(p, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f, delimiter=";")
                w.writerow(["date", "source", "menace", "verdict", "élément", "sha256", "action", "raisons"])
                for e in history.entries():
                    w.writerow([e["date"], e["source"], e["threat"], e["verdict"], e["path"], e["sha256"], e["action"], " | ".join(e["reasons"])])

    def _clear_hist(self):
        if confirm(self, "Effacer", "Effacer tout l'historique des détections ?", "Effacer", True):
            history.clear(); self.on_show()

    # ---------- rapports ----------
    def _reports(self):
        w = QWidget(); h = QHBoxLayout(w); h.setContentsMargins(0, 12, 0, 0); h.setSpacing(12)
        self.r_table = Table(["Date", "Type", "Éléments", "Menaces", "Durée"], stretch_col=0)
        self.r_table.itemSelectionChanged.connect(self._show_report)
        h.addWidget(self.r_table, 3)
        self.r_text = QPlainTextEdit(); self.r_text.setReadOnly(True)
        h.addWidget(self.r_text, 4)
        return w

    def _show_report(self):
        sel = self.r_table.selected_data()
        if not sel:
            return
        rep = sel[0][1]
        s = rep["summary"]
        lines = [f"Analyse {s.get('mode', '')} du {fmt_date(rep['date'])}", f"Éléments analysés : {s['count']}",
                 f"Menaces : {s['malware']}   Suspects : {s['suspect']}", f"Durée : {s['seconds']:.0f} s",
                 "Étapes : " + " → ".join(rep.get("stages", [])), "", "Détections :"]
        for d in rep["detections"]:
            lines.append(f"  [{d['verdict']}] {d.get('threat') or ''} – {d['path']}")
            for r in d["reasons"][:4]:
                lines.append(f"      · {r}")
        if not rep["detections"]:
            lines.append("  Aucune")
        self.r_text.setPlainText("\n".join(lines))

    # ---------- liste autorisée ----------
    def _allow(self):
        bar = QHBoxLayout()
        bar.addWidget(label("Les éléments de cette liste ne sont jamais analysés ni signalés.", muted=True)); bar.addStretch()
        bar.addWidget(btn("Ajouter un dossier", "plus", slot=self._allow_dir))
        bar.addWidget(btn("Ajouter un fichier", "plus", slot=self._allow_file))
        bar.addWidget(btn("Retirer", "minus", slot=self._allow_rm))
        self.a_table = Table(["Élément autorisé"], stretch_col=0)
        return self._wrap(self.a_table, bar=bar)

    def _allow_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Dossier à autoriser")
        if d:
            self.app.settings["exclusions"] = self.app.settings["exclusions"] + [d]; self.on_show()

    def _allow_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Fichier à autoriser")
        if f:
            self.app.settings["exclusions"] = self.app.settings["exclusions"] + [f]; self.on_show()

    def _allow_rm(self):
        rm = {d for _, d in self.a_table.selected_data()}
        self.app.settings["exclusions"] = [e for e in self.app.settings["exclusions"] if e not in rm]
        self.on_show()

    # ---------- rafraîchissement ----------
    def on_show(self):
        i = self.tabs.currentIndex()
        if i == 0:
            items = quarantine.list_items()
            self.q_table.setRowCount(0)
            for m in items:
                self.q_table.add_row([fmt_date(m["date"]), m.get("threat") or (m.get("reasons") or ["?"])[0],
                                      m["original"], f"{m.get('size', 0) / 1e6:.2f} Mo"], data=m)
            self.q_info.setText(f"{len(items)} élément(s) isolé(s) et chiffré(s) : ils ne peuvent plus s'exécuter.")
        elif i == 1:
            self.h_table.setRowCount(0)
            for e in history.entries():
                self.h_table.add_row([fmt_date(e["date"]), e["source"], e["threat"], e["path"], e["action"]], data=e)
        elif i == 2:
            self.r_table.setRowCount(0)
            for rep in history.reports():
                s = rep["summary"]
                self.r_table.add_row([fmt_date(rep["date"]), s.get("mode", ""), s["count"], s["malware"] + s["suspect"],
                                      f"{s['seconds']:.0f} s"], data=rep)
        else:
            self.a_table.setRowCount(0)
            for e in self.app.settings["exclusions"]:
                self.a_table.add_row([e], data=e)
