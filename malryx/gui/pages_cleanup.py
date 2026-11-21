"""Page Nettoyage : fichiers inutiles (standard + approfondi), doublons, gros fichiers, restes de désinstallation."""
import os
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QCheckBox, QComboBox, QHBoxLayout, QTabWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from .. import cleaner, diskspace, winsys
from .common import Page, btn, confirm, info
from .theme import C, icon
from .widgets import Table, label
from .workers import TaskWorker

H = cleaner.human


class CleanupPage(Page):
    def __init__(self, app):
        super().__init__(app, "Nettoyage", "Libérez de l'espace disque sans toucher à vos documents", scroll=False)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._junk(), "Fichiers inutiles")
        self.tabs.addTab(self._dups(), "Doublons")
        self.tabs.addTab(self._big(), "Gros fichiers")
        self.tabs.addTab(self._left(), "Restes de désinstallation")
        self.body.addWidget(self.tabs, 1)

    def _box(self):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(0, 12, 0, 0); v.setSpacing(12)
        return w, v

    def _checkable(self, table, row, checked):
        it = table.item(row, 0)
        it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
        it.setCheckState(Qt.Checked if checked else Qt.Unchecked)

    def _checked(self, table):
        return [d for r, d in table.all_data() if table.item(r, 0).checkState() == Qt.Checked]

    # ------------------------------------------------------------------ fichiers inutiles
    def _junk(self):
        w, v = self._box()
        top = QHBoxLayout()
        self.j_info = label("Temporaires, caches des navigateurs, miniatures, rapports d'erreurs, corbeille.", muted=True, wrap=True)
        top.addWidget(self.j_info, 1)
        self.j_deep = QCheckBox("Nettoyage approfondi"); self.j_deep.setToolTip(
            "Ajoute Windows.old, journaux de Windows, cache de distribution, vidages mémoire et composants obsolètes (DISM). Administrateur requis.")
        top.addWidget(self.j_deep)
        self.j_an = btn("Analyser", "search", slot=self._junk_scan)
        self.j_go = btn("  Nettoyer", "trash", "Primary", slot=self._junk_clean); self.j_go.setEnabled(False)
        top.addWidget(self.j_an); top.addWidget(self.j_go)
        v.addLayout(top)
        self.j_table = Table(["", "Catégorie", "Fichiers", "Taille", "Type"], stretch_col=1)
        self.j_table.setColumnWidth(0, 34)
        v.addWidget(self.j_table, 1)
        return w

    def _junk_scan(self):
        self.j_an.setEnabled(False); self.j_info.setText("Analyse…")
        self._jw = TaskWorker(lambda progress: cleaner.analyse(self.j_deep.isChecked()))
        self._jw.result.connect(self._junk_list); self._jw.start()

    def _junk_list(self, res):
        self.j_an.setEnabled(True)
        if isinstance(res, Exception):
            self.j_info.setText(str(res)); return
        self.j_table.setRowCount(0)
        total = 0
        for c in res:
            r = self.j_table.add_row(["", c["name"], c["count"] if c["count"] is not None else "—",
                                      c.get("note") or H(c["size"]), "Approfondi" if c.get("deep") else "Standard"], data=c)
            self._checkable(self.j_table, r, (c["size"] > 0 or c.get("note")) and "Windows Update" not in c["name"])
            total += c["size"]
        self.j_info.setText(f"{H(total)} peuvent être libérés.")
        self.j_go.setEnabled(True)

    def _junk_clean(self):
        names = [d["name"] for d in self._checked(self.j_table)]
        if not names or not confirm(self, "Nettoyage", f"Supprimer définitivement les fichiers de {len(names)} catégorie(s) ?", "Nettoyer"):
            return
        if any("Windows.old" in n or "DISM" in n for n in names) and not winsys.is_admin():
            info(self, "Nettoyage approfondi", "Windows.old et les composants obsolètes nécessitent les droits administrateur "
                 "(Réglages → Relancer en administrateur). Les autres catégories vont être nettoyées.")
        self.j_go.setEnabled(False)
        self._jw2 = TaskWorker(cleaner.clean, names)
        self._jw2.progress.connect(self.j_info.setText)
        self._jw2.result.connect(lambda n: (self.j_info.setText(f"{H(n) if not isinstance(n, Exception) else n} libérés."),
                                            self.app.log(f"Nettoyage : {H(n) if not isinstance(n, Exception) else n}"),
                                            self._junk_scan()))
        self._jw2.start()

    # ------------------------------------------------------------------ doublons
    def _dups(self):
        w, v = self._box()
        top = QHBoxLayout()
        self.d_info = label("Recherche les fichiers identiques (contenu, pas seulement le nom) dans Bureau, Documents, "
                            "Téléchargements, Images, Vidéos et Musique. Le plus ancien de chaque groupe est conservé.",
                            muted=True, wrap=True)
        top.addWidget(self.d_info, 1)
        top.addWidget(btn("Ajouter un dossier", "folder", slot=self._dup_folder))
        self.d_an = btn("Rechercher", "search", slot=self._dup_scan)
        self.d_go = btn("  Supprimer les copies cochées", "trash", "Primary", slot=self._dup_clean); self.d_go.setEnabled(False)
        top.addWidget(self.d_an); top.addWidget(self.d_go)
        v.addLayout(top)
        self.d_tree = QTreeWidget(); self.d_tree.setHeaderLabels(["Fichier", "Taille", "Modifié le"])
        self.d_tree.setColumnWidth(0, 650)
        self.d_tree.setStyleSheet(f"QTreeWidget{{background:{C['card']};border:1px solid {C['border']};border-radius:12px}}"
                                  f"QHeaderView::section{{background:{C['card']};color:{C['muted']};border:none;padding:8px}}")
        v.addWidget(self.d_tree, 1)
        self.dup_roots = None
        return w

    def _dup_folder(self):
        from PySide6.QtWidgets import QFileDialog
        d = QFileDialog.getExistingDirectory(self, "Dossier où chercher les doublons")
        if d:
            self.dup_roots = (self.dup_roots or diskspace.user_roots()) + [Path(d)]
            self.d_info.setText("Dossiers : " + ", ".join(str(p) for p in self.dup_roots))

    def _dup_scan(self):
        self.d_an.setEnabled(False); self.d_tree.clear()
        self._dw = TaskWorker(diskspace.find_duplicates, self.dup_roots)
        self._dw.progress.connect(self.d_info.setText)
        self._dw.result.connect(self._dup_list); self._dw.start()

    def _dup_list(self, groups):
        self.d_an.setEnabled(True)
        if isinstance(groups, Exception):
            self.d_info.setText(str(groups)); return
        waste = sum(g["waste"] for g in groups)
        self.d_info.setText(f"{len(groups)} groupe(s) de doublons · {H(waste)} récupérables")
        for g in groups:
            top = QTreeWidgetItem([f"{Path(g['keep']).name}  ({len(g['files'])} exemplaires)", H(g["size"]), ""])
            top.setIcon(0, icon("list", C["accent"], 16))
            self.d_tree.addTopLevelItem(top)
            for f in g["files"]:
                try:
                    mt = datetime.fromtimestamp(os.path.getmtime(f)).strftime("%d/%m/%Y")
                except OSError:
                    mt = ""
                ch = QTreeWidgetItem([f, H(g["size"]), mt])
                ch.setData(0, Qt.UserRole, f)
                ch.setCheckState(0, Qt.Unchecked if f == g["keep"] else Qt.Checked)
                if f == g["keep"]:
                    ch.setForeground(0, QColor(C["ok"])); ch.setToolTip(0, "Original conservé (le plus ancien)")
                top.addChild(ch)
            top.setExpanded(len(groups) < 40)
        self.d_go.setEnabled(bool(groups))

    def _dup_clean(self):
        files, guard = [], []
        for i in range(self.d_tree.topLevelItemCount()):
            top = self.d_tree.topLevelItem(i)
            kids = [top.child(j) for j in range(top.childCount())]
            sel = [k.data(0, Qt.UserRole) for k in kids if k.checkState(0) == Qt.Checked]
            if len(sel) == len(kids):
                guard.append(top.text(0))  # on garde toujours au moins un exemplaire
                sel = sel[1:]
            files += sel
        if not files:
            return
        msg = f"Envoyer {len(files)} copie(s) à la Corbeille ?"
        if guard:
            msg += f"\n\n{len(guard)} groupe(s) étaient entièrement cochés : un exemplaire de chacun est conservé."
        if confirm(self, "Doublons", msg, "Supprimer"):
            ok, err = diskspace.recycle(files)
            self.app.log(f"Doublons : {ok} copie(s) envoyée(s) à la Corbeille")
            info(self, "Doublons", f"{ok} copie(s) envoyée(s) à la Corbeille." + (f"\n{len(err)} impossible(s) (fichier ouvert ?)." if err else ""))
            self._dup_scan()

    # ------------------------------------------------------------------ gros fichiers
    def _big(self):
        w, v = self._box()
        top = QHBoxLayout()
        self.b_info = label("Les plus gros fichiers de votre dossier personnel et des autres disques.", muted=True, wrap=True)
        top.addWidget(self.b_info, 1)
        self.b_min = QComboBox(); self.b_min.addItems(["> 100 Mo", "> 500 Mo", "> 1 Go"]); self.b_min.setCurrentIndex(0)
        top.addWidget(self.b_min)
        self.b_an = btn("Rechercher", "search", slot=self._big_scan)
        top.addWidget(self.b_an)
        top.addWidget(btn("Ouvrir l'emplacement", "folder", slot=lambda: self._loc(self.b_table)))
        top.addWidget(btn("  Corbeille", "trash", "Primary", slot=self._big_clean))
        v.addLayout(top)
        self.b_table = Table(["", "Fichier", "Taille", "Dernière utilisation"], stretch_col=1)
        self.b_table.setColumnWidth(0, 34)
        v.addWidget(self.b_table, 1)
        return w

    def _big_scan(self):
        mb = {0: 100, 1: 500, 2: 1024}[self.b_min.currentIndex()]
        self.b_an.setEnabled(False)
        self._bw = TaskWorker(diskspace.find_big_files, None, mb)
        self._bw.progress.connect(self.b_info.setText)
        self._bw.result.connect(self._big_list); self._bw.start()

    def _big_list(self, res):
        self.b_an.setEnabled(True)
        if isinstance(res, Exception):
            self.b_info.setText(str(res)); return
        self.b_table.setRowCount(0)
        for f in res:
            age = f["age_days"]
            r = self.b_table.add_row(["", f["path"], H(f["size"]), f"il y a {age} jour(s)" if age else "aujourd'hui"], data=f)
            self._checkable(self.b_table, r, False)
            if age > 365:
                self.b_table.item(r, 3).setForeground(QColor(C["warn"]))
        self.b_info.setText(f"{len(res)} fichier(s) · {H(sum(f['size'] for f in res))} · en orange : inutilisés depuis plus d'un an")

    def _big_clean(self):
        sel = self._checked(self.b_table)
        if sel and confirm(self, "Gros fichiers", f"Envoyer {len(sel)} fichier(s) ({H(sum(f['size'] for f in sel))}) à la Corbeille ?", "Supprimer"):
            ok, err = diskspace.recycle([f["path"] for f in sel])
            info(self, "Gros fichiers", f"{ok} fichier(s) envoyé(s) à la Corbeille.")
            self._big_scan()

    def _loc(self, table):
        sel = table.selected_data()
        if sel:
            winsys.open_location(sel[0][1]["path"])

    # ------------------------------------------------------------------ restes de désinstallation
    def _left(self):
        w, v = self._box()
        top = QHBoxLayout()
        self.l_info = label("Dossiers et clés de registre laissés par des logiciels désinstallés, inutilisés depuis plus de 90 jours. "
                            "Tout est sauvegardé avant suppression (Corbeille + export .reg).", muted=True, wrap=True)
        top.addWidget(self.l_info, 1)
        self.l_an = btn("Rechercher", "search", slot=self._left_scan)
        top.addWidget(self.l_an)
        top.addWidget(btn("Ouvrir l'emplacement", "folder", slot=lambda: self._loc(self.l_table)))
        top.addWidget(btn("  Supprimer la sélection", "trash", "Primary", slot=self._left_clean))
        v.addLayout(top)
        self.l_table = Table(["", "Type", "Emplacement", "Taille", "Inutilisé depuis"], stretch_col=2)
        self.l_table.setColumnWidth(0, 34)
        v.addWidget(self.l_table, 1)
        return w

    def _left_scan(self):
        if not winsys.IS_WIN:
            self.l_info.setText("Disponible sous Windows uniquement."); return
        self.l_an.setEnabled(False)
        self._lw = TaskWorker(diskspace.find_leftovers)
        self._lw.progress.connect(self.l_info.setText)
        self._lw.result.connect(self._left_list); self._lw.start()

    def _left_list(self, res):
        self.l_an.setEnabled(True)
        if isinstance(res, Exception):
            self.l_info.setText(str(res)); return
        self.l_table.setRowCount(0)
        for it in res:
            r = self.l_table.add_row(["", it["kind"].capitalize(), it["path"], H(it["size"]) if it["size"] else "—",
                                      f"{it['age_days']} jours" if it["age_days"] else "—"], data=it)
            self._checkable(self.l_table, r, False)
        self.l_info.setText(f"{len(res)} reste(s) trouvé(s) · {H(sum(i['size'] for i in res))}. Cochez ceux que vous reconnaissez "
                            "comme appartenant à un logiciel désinstallé.")

    def _left_clean(self):
        sel = self._checked(self.l_table)
        if sel and confirm(self, "Restes de désinstallation", f"Supprimer {len(sel)} élément(s) ?\n"
                           "Les dossiers vont à la Corbeille et les clés de registre sont exportées dans le dossier de Malryx.", "Supprimer", True):
            ok, err = diskspace.remove_leftovers(sel)
            info(self, "Restes de désinstallation", f"{ok} élément(s) supprimé(s)." + (f"\n{len(err)} impossible(s) : droits administrateur ?" if err else ""))
            self._left_scan()

    def on_show(self):
        pass
