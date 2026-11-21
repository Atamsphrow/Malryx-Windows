"""Page Confidentialité : traces de navigation, télémétrie et publicités, webcam/micro, destructeur de fichiers."""
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QCheckBox, QFileDialog, QGridLayout, QHBoxLayout, QListWidget, QListWidgetItem, QSpinBox,
                               QTabWidget, QVBoxLayout, QWidget)

from .. import cleaner, privacy, winsys
from .common import Page, btn, confirm, fmt_date, info
from .theme import C, icon
from .widgets import Card, SettingRow, Table, Toggle, icon_label, label
from .workers import FuncWorker, TaskWorker

H = cleaner.human
KINDS = ["Historique", "Cache", "Sessions", "Cookies"]


class PrivacyPage(Page):
    def __init__(self, app):
        super().__init__(app, "Confidentialité", "Effacez vos traces et reprenez le contrôle de vos données", scroll=False)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._traces(), "Navigation")
        self.tabs.addTab(self._telemetry(), "Télémétrie et publicités")
        self.tabs.addTab(self._devices(), "Webcam et micro")
        self.tabs.addTab(self._shredder(), "Destructeur de fichiers")
        self.tabs.currentChanged.connect(self._tab)
        self.body.addWidget(self.tabs, 1)

    def _box(self):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(0, 12, 0, 0); v.setSpacing(12)
        return w, v

    def _tab(self, i):
        [self._load_traces, self._load_tweaks, self._load_devices, lambda: None][i]()

    def on_show(self):
        self._tab(self.tabs.currentIndex())

    # ------------------------------------------------------------------ navigation
    def _traces(self):
        w, v = self._box()
        top = QHBoxLayout()
        self.t_info = label("", muted=True, wrap=True); top.addWidget(self.t_info, 1)
        self.t_kinds = {}
        for k in KINDS:
            cb = QCheckBox(k); cb.setChecked(k != "Cookies" or self.app.settings["traces_cookies"])
            if k == "Cookies":
                cb.setToolTip("Effacer les cookies vous déconnecte de vos sites (Gmail, Facebook…).")
                cb.toggled.connect(lambda val: self.app.settings.__setitem__("traces_cookies", val))
            self.t_kinds[k] = cb; top.addWidget(cb)
        top.addWidget(btn("Actualiser", "refresh", slot=self._load_traces))
        top.addWidget(btn("  Effacer", "trash", "Primary", slot=self._clean_traces))
        v.addLayout(top)
        self.t_table = Table(["", "Navigateur", "Historique", "Cache", "Sessions", "Cookies", "État"], stretch_col=1)
        self.t_table.setColumnWidth(0, 34)
        v.addWidget(self.t_table, 1)
        v.addWidget(label("Les mots de passe enregistrés et les favoris ne sont jamais supprimés.", muted=True))
        return w

    def _load_traces(self):
        self._tw = FuncWorker(privacy.browser_traces); self._tw.result.connect(self._traces_loaded); self._tw.start()

    def _traces_loaded(self, res):
        if isinstance(res, Exception):
            self.t_info.setText(str(res)); return
        self.t_table.setRowCount(0)
        for b in res:
            r = self.t_table.add_row(["", b["browser"]] + [H(b["items"].get(k, 0)) for k in KINDS] +
                                     ["Ouvert : à fermer" if b["running"] else "Fermé"], data=b)
            it = self.t_table.item(r, 0); it.setFlags(it.flags() | Qt.ItemIsUserCheckable); it.setCheckState(Qt.Checked)
            self.t_table.item(r, 6).setForeground(QColor(C["warn"] if b["running"] else C["ok"]))
        self.t_info.setText(f"{len(res)} navigateur(s) détecté(s)." if res else "Aucun navigateur détecté.")

    def _clean_traces(self):
        kinds = [k for k, cb in self.t_kinds.items() if cb.isChecked()]
        sel = [d for r, d in self.t_table.all_data() if self.t_table.item(r, 0).checkState() == Qt.Checked]
        if not kinds or not sel:
            return
        running = [b["browser"] for b in sel if b["running"]]
        if running and not confirm(self, "Navigateurs ouverts", f"Fermez d'abord : {', '.join(running)}.\n"
                                   "Continuer avec les autres navigateurs ?", "Continuer"):
            return

        def work(progress):
            freed, skipped = 0, []
            for b in sel:
                progress(f"Nettoyage de {b['browser']}…")
                try:
                    freed += privacy.clean_browser(b["browser"], kinds)
                except RuntimeError:
                    skipped.append(b["browser"])
            return freed, skipped
        self._tw2 = TaskWorker(work); self._tw2.progress.connect(self.t_info.setText)
        self._tw2.result.connect(lambda r: (self.t_info.setText(f"{H(r[0])} de traces effacées" +
                                                                (f" · ignorés (ouverts) : {', '.join(r[1])}" if r[1] else ""))
                                            if not isinstance(r, Exception) else self.t_info.setText(str(r)), self._load_traces()))
        self._tw2.start()

    # ------------------------------------------------------------------ télémétrie
    def _telemetry(self):
        w, v = self._box()
        top = QHBoxLayout()
        self.tl_info = label("Chaque réglage est réversible : Malryx sauvegarde la valeur d'origine.", muted=True, wrap=True)
        top.addWidget(self.tl_info, 1)
        top.addWidget(btn("  Tout appliquer", "shield-check", "Primary", slot=lambda: self._tweak_all(True)))
        top.addWidget(btn("Tout restaurer", "restore", slot=lambda: self._tweak_all(False)))
        v.addLayout(top)
        self.tl_card = Card(spacing=0)
        self.tl_rows = {}
        for tid, title, desc, *_rest in privacy.TWEAKS:
            admin = _rest[-1]
            tg = Toggle(False)
            tg.toggled.connect(lambda val, t=tid: self._tweak(t, val))
            row = SettingRow(title + ("  (administrateur)" if admin else ""), desc, tg)
            self.tl_rows[tid] = tg
            self.tl_card.lay.addWidget(row)
        from PySide6.QtWidgets import QScrollArea
        sa = QScrollArea(); sa.setWidgetResizable(True); sa.setWidget(self.tl_card)
        v.addWidget(sa, 1)
        return w

    def _load_tweaks(self):
        for t in privacy.tweak_states():
            tg = self.tl_rows[t["id"]]
            tg.setChecked(t["applied"]); tg.setEnabled(t["available"] and (winsys.is_admin() or not t["admin"]))
        n = sum(t["applied"] for t in privacy.tweak_states())
        self.tl_info.setText(f"{n}/{len(privacy.TWEAKS)} protections actives. Chaque réglage est réversible : "
                             "Malryx sauvegarde la valeur d'origine." + ("" if winsys.is_admin() else
                             " Les réglages « administrateur » nécessitent de relancer Malryx en administrateur."))

    def _tweak(self, tid, val):
        try:
            privacy.apply_tweak(tid, val)
            self.app.log(f"Confidentialité : {tid} {'appliqué' if val else 'restauré'}")
        except (OSError, ImportError) as e:
            info(self, "Confidentialité", f"Impossible de modifier ce réglage : {e}")
        self._load_tweaks()

    def _tweak_all(self, val):
        for t in privacy.tweak_states():
            if t["available"] and t["applied"] != val and (winsys.is_admin() or not t["admin"]):
                try:
                    privacy.apply_tweak(t["id"], val)
                except OSError:
                    continue
        self._load_tweaks()

    # ------------------------------------------------------------------ webcam / micro
    def _devices(self):
        w, v = self._box()
        c = Card(spacing=0)
        tg = Toggle(self.app.settings["camera_monitor"])
        tg.toggled.connect(lambda val: self.app.settings.__setitem__("camera_monitor", val))
        c.lay.addWidget(SettingRow("Alerte d'accès à la webcam et au micro",
                                   "Malryx vous prévient dès qu'une application allume la caméra ou le micro.", tg))
        v.addWidget(c)
        hh = QHBoxLayout(); hh.setSpacing(16)
        self.cam = Table(["Application", "Dernière utilisation", "État"], stretch_col=0)
        self.mic = Table(["Application", "Dernière utilisation", "État"], stretch_col=0)
        for title, t in (("Webcam", self.cam), ("Microphone", self.mic)):
            cc = Card()
            r = QHBoxLayout(); r.addWidget(icon_label("eye" if title == "Webcam" else "pulse", C["accent"], 20))
            r.addWidget(label(title, "Section")); r.addStretch()
            r.addWidget(btn("Autoriser sans alerte", slot=lambda _=False, tb=t: self._allow(tb)))
            cc.lay.addLayout(r); cc.lay.addWidget(t)
            hh.addWidget(cc, 1)
        v.addLayout(hh, 1)
        r = QHBoxLayout()
        r.addWidget(label("Pour retirer l'accès à une application :", muted=True))
        r.addWidget(btn("Paramètres de la caméra", slot=lambda: winsys.open_uri("ms-settings:privacy-webcam")))
        r.addWidget(btn("Paramètres du micro", slot=lambda: winsys.open_uri("ms-settings:privacy-microphone")))
        r.addStretch()
        v.addLayout(r)
        return w

    def _load_devices(self):
        allowed = {x.lower() for x in self.app.settings["camera_allowed"]}
        for dev, t in (("webcam", self.cam), ("microphone", self.mic)):
            t.setRowCount(0)
            items = privacy.device_access(dev)
            for a in items:
                state = "EN COURS" if a["in_use"] else ("autorisé" if a["name"].lower() in allowed else "")
                r = t.add_row([a["app"], fmt_date(a["last"].isoformat()) if a["last"] else "—", state], data=a)
                if a["in_use"]:
                    t.item(r, 2).setForeground(QColor(C["bad"]))
            if not items:
                t.add_row(["Aucun accès enregistré" if winsys.IS_WIN else "Disponible sous Windows", "", ""])

    def _allow(self, table):
        names = [d["name"] for _, d in table.selected_data() if d]
        if names:
            self.app.settings["camera_allowed"] = list(dict.fromkeys(self.app.settings["camera_allowed"] + names))
            self._load_devices()

    # ------------------------------------------------------------------ destructeur
    def _shredder(self):
        w, v = self._box()
        self.sh_warn = label("", wrap=True)
        v.addWidget(self.sh_warn)
        top = QHBoxLayout()
        top.addWidget(label("Les fichiers détruits sont écrasés par des données aléatoires puis supprimés : "
                            "ils ne passent pas par la Corbeille et ne sont pas récupérables.", muted=True, wrap=True), 1)
        top.addWidget(btn("Ajouter des fichiers", "plus", slot=self._sh_files))
        top.addWidget(btn("Ajouter un dossier", "folder", slot=self._sh_dir))
        top.addWidget(btn("Retirer", "minus", slot=lambda: [self.sh_list.takeItem(self.sh_list.row(i)) for i in self.sh_list.selectedItems()]))
        v.addLayout(top)
        self.sh_list = QListWidget(); self.sh_list.setAcceptDrops(True)
        v.addWidget(self.sh_list, 1)
        bot = QHBoxLayout()
        bot.addWidget(label("Passes d'écrasement :", muted=True))
        self.sh_pass = QSpinBox(); self.sh_pass.setRange(1, 7); self.sh_pass.setValue(self.app.settings["shred_passes"])
        self.sh_pass.valueChanged.connect(lambda val: self.app.settings.__setitem__("shred_passes", val))
        bot.addWidget(self.sh_pass); bot.addStretch()
        self.sh_info = label("", muted=True); bot.addWidget(self.sh_info)
        bot.addWidget(btn("  Détruire définitivement", "trash", "Danger", slot=self._shred))
        v.addLayout(bot)
        return w

    def _sh_add(self, paths):
        for p in paths:
            if p:
                self.sh_list.addItem(QListWidgetItem(icon("folder" if Path(p).is_dir() else "list", C["muted"], 16), p))
        if paths:
            self._sw = FuncWorker(privacy.is_ssd, paths[0])
            self._sw.result.connect(lambda ssd: self.sh_warn.setText(
                "⚠ Ce fichier est sur un SSD : à cause de la gestion interne des SSD (wear leveling), une copie peut subsister "
                "physiquement. Pour une confidentialité totale sur SSD, utilisez le chiffrement BitLocker." if ssd is True else ""))
            self._sw.start()

    def _sh_files(self):
        fs, _ = QFileDialog.getOpenFileNames(self, "Fichiers à détruire")
        self._sh_add(fs)

    def _sh_dir(self):
        self._sh_add([QFileDialog.getExistingDirectory(self, "Dossier à détruire")])

    def _shred(self):
        paths = [self.sh_list.item(i).text() for i in range(self.sh_list.count())]
        if not paths or not confirm(self, "Destructeur", f"Détruire définitivement {len(paths)} élément(s) ?\n"
                                    "Cette action est IRRÉVERSIBLE.", "Détruire", True):
            return
        self._shw = TaskWorker(privacy.shred, paths, self.sh_pass.value())
        self._shw.progress.connect(self.sh_info.setText)
        self._shw.result.connect(self._shredded); self._shw.start()

    def _shredded(self, r):
        if isinstance(r, Exception):
            info(self, "Destructeur", str(r)); return
        done, errors = r
        self.sh_list.clear()
        self.sh_info.setText(f"{done} fichier(s) détruit(s)")
        self.app.log(f"Destructeur : {done} fichier(s) détruit(s)")
        if errors:
            info(self, "Destructeur", f"{len(errors)} fichier(s) n'ont pas pu être détruits (ouverts ?) :\n" + "\n".join(errors[:5]))
