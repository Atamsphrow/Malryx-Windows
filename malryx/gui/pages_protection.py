"""Page Protection : couches de protection en temps réel + dossiers surveillés + activité en direct."""
from datetime import datetime

from PySide6.QtWidgets import QListWidgetItem, QFileDialog, QHBoxLayout, QInputDialog, QListWidget, QVBoxLayout

from .. import webprotect, winsys
from .common import Page, btn, confirm, info
from .theme import C, icon
from .widgets import Card, Table, Toggle, icon_label, label
from .workers import FuncWorker

LAYERS = [
    ("realtime", "shield-check", "Protection contre les malwares",
     "Analyse instantanée de chaque fichier téléchargé, créé, copié ou renommé dans les dossiers sensibles."),
    ("exec_guard", "stop", "Protection à l'exécution",
     "Chaque programme lancé est vérifié avant de pouvoir agir : s'il est malveillant, il est bloqué et mis en quarantaine."),
    ("behavior_guard", "alert", "Anti-exploit (comportement)",
     "Bloque les attaques sans fichier : document Office qui lance PowerShell, commandes encodées, mshta/regsvr32/certutil détournés, suppression des sauvegardes."),
    ("ransomware", "shield", "Anti-ransomware",
     "Fichiers-appâts cachés et détection des chiffrements massifs : le programme fautif est suspendu immédiatement."),
    ("web_protection", "eye", "Protection Web",
     "Bloque l'accès aux sites qui distribuent des malwares ou font de l'hameçonnage, dans tous les navigateurs."),
    ("startup_guard", "zap", "Protection du démarrage",
     "Signale et bloque tout programme qui s'ajoute au démarrage de Windows (persistance des malwares)."),
    ("usb_monitor", "usb", "Périphériques USB",
     "Surveille les clés USB et disques externes dès leur branchement."),
    ("android_monitor", "phone", "Téléphones Android",
     "Analyse les téléphones branchés (débogage USB) et chaque nouvelle application installée."),
    ("auto_quarantine", "box", "Quarantaine automatique",
     "Isole les menaces confirmées sans demander. Les éléments simplement suspects ne sont jamais isolés automatiquement."),
]


class ProtectionPage(Page):
    def __init__(self, app):
        super().__init__(app, "Protection en temps réel", "Malryx vous protège en continu, même quand la fenêtre est fermée")
        self.toggles = {}
        grid_card = Card(spacing=4)
        for key, ic, title, desc in LAYERS:
            row = QHBoxLayout(); row.setContentsMargins(0, 8, 0, 8)
            row.addWidget(icon_label(ic, C["accent"], 24))
            tv = QVBoxLayout(); tv.setSpacing(2)
            t = label(title); t.setStyleSheet("font-weight:700;font-size:10.5pt")
            tv.addWidget(t); tv.addWidget(label(desc, muted=True, wrap=True))
            if key == "web_protection":
                self.web_info = label("", muted=True)
                tv.addWidget(self.web_info)
                wb = QHBoxLayout()
                wb.addWidget(btn("Mettre à jour la liste", "download", slot=self._web_update))
                wb.addWidget(btn("Bloquer un site", "plus", slot=self._web_add))
                wb.addStretch()
                tv.addLayout(wb)
            if key == "exec_guard":
                self.exec_mode = label("", muted=True)
                tv.addWidget(self.exec_mode)
            if key == "usb_monitor":
                self.usb_auto = Toggle(app.settings["usb_autoscan"])
                self.usb_auto.toggled.connect(lambda v: app.settings.__setitem__("usb_autoscan", v))
                ul = QHBoxLayout(); ul.addWidget(self.usb_auto); ul.addWidget(label("Analyser automatiquement chaque clé branchée", muted=True)); ul.addStretch()
                tv.addLayout(ul)
            row.addLayout(tv, 1)
            tg = Toggle(app.settings[key] if key != "web_protection" else webprotect.is_enabled())
            tg.toggled.connect(lambda v, k=key: self._set(k, v))
            self.toggles[key] = tg
            row.addWidget(tg)
            grid_card.lay.addLayout(row)
            if key != LAYERS[-1][0]:
                sep = label(); sep.setFixedHeight(1); sep.setStyleSheet(f"background:{C['border']}")
                grid_card.lay.addWidget(sep)
        self.body.addWidget(grid_card)

        h = QHBoxLayout(); h.setSpacing(16)
        dirs = Card()
        hd = QHBoxLayout(); hd.addWidget(label("Dossiers surveillés", "Section")); hd.addStretch()
        hd.addWidget(btn("Ajouter", "plus", slot=self._add_dir)); hd.addWidget(btn("Retirer", "minus", slot=self._rm_dir))
        dirs.lay.addLayout(hd)
        self.dir_list = QListWidget(); self.dir_list.setMinimumHeight(220)
        dirs.lay.addWidget(self.dir_list)
        h.addWidget(dirs, 2)
        act = Card()
        act.lay.addWidget(label("Activité en direct", "Section"))
        self.live = Table(["Heure", "Type", "Élément", "Action"], stretch_col=2)
        self.live.setMinimumHeight(220)
        act.lay.addWidget(self.live)
        h.addWidget(act, 3)
        self.body.addLayout(h)
        self.on_show()

    def _set(self, key, v):
        a = self.app
        if key == "realtime":
            a.set_realtime(v)
        elif key == "web_protection":
            self._web_apply(v)
            return
        else:
            a.settings[key] = v
            if key == "ransomware" and a.rtp.running:
                (a.ransomware.deploy() if v else a.ransomware.remove())
            if key in ("exec_guard", "behavior_guard") and a.rtp.running:
                if a.settings["exec_guard"] or a.settings["behavior_guard"]:
                    a.execguard.start()
                else:
                    a.execguard.stop()
                self.on_show()
        a.log(f"{dict((k, t) for k, _, t, _ in LAYERS)[key]} : {'activé' if v else 'désactivé'}")
        a.refresh_all()

    def _web_apply(self, v):
        if v and not webprotect.domains():
            try:
                webprotect.update_list()
            except Exception as e:
                self.toggles["web_protection"].setChecked(False)
                info(self, "Protection Web", f"La liste des sites malveillants n'a pas pu être téléchargée : {e}")
                return
        try:
            n = webprotect.apply(v)
            self.app.settings["web_protection"] = v
            self.app.log(f"Protection Web {'activée' if v else 'désactivée'}" + (f" ({n} domaines)" if v else ""))
        except PermissionError:
            self.toggles["web_protection"].setChecked(webprotect.is_enabled())
            if winsys.IS_WIN and confirm(self, "Droits administrateur requis",
                                         "La protection Web modifie le fichier hosts de Windows.\nRelancer Malryx en administrateur ?",
                                         "Relancer"):
                self.app.relaunch_admin()
        except OSError as e:
            self.toggles["web_protection"].setChecked(webprotect.is_enabled())
            info(self, "Protection Web", f"Impossible de modifier le fichier hosts : {e}")
        self.on_show(); self.app.refresh_all()

    def _web_update(self):
        self.web_info.setText("Téléchargement de la liste URLhaus…")
        self._w = FuncWorker(webprotect.update_list)
        self._w.result.connect(self._web_updated)
        self._w.start()

    def _web_updated(self, r):
        if isinstance(r, Exception):
            info(self, "Protection Web", f"Mise à jour impossible : {r}")
        elif webprotect.is_enabled():
            try:
                webprotect.apply(True)
            except OSError:
                pass
        self.on_show()

    def _web_add(self):
        d, ok = QInputDialog.getText(self, "Bloquer un site", "Domaine à bloquer (ex. site-dangereux.com) :")
        if ok and d:
            try:
                webprotect.add_custom(d)
                if webprotect.is_enabled():
                    webprotect.apply(True)
            except (ValueError, OSError) as e:
                info(self, "Protection Web", str(e))
            self.on_show()

    def _add_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Dossier à surveiller")
        if d:
            s = self.app.settings
            s["extra_dirs"] = list(dict.fromkeys(s["extra_dirs"] + [d]))
            self.app.rtp.refresh_dirs()
            self.on_show()

    def _rm_dir(self):
        s = self.app.settings
        for it in self.dir_list.selectedItems():
            if it.text() in s["extra_dirs"]:
                s["extra_dirs"] = [x for x in s["extra_dirs"] if x != it.text()]
            else:
                info(self, "Dossiers surveillés", "Les dossiers système sensibles sont toujours surveillés.")
        self.on_show()

    def add_live(self, kind, item, action, color=None):
        self.live.insertRow(0)
        from PySide6.QtWidgets import QTableWidgetItem
        from PySide6.QtGui import QColor
        for c, v in enumerate((f"{datetime.now():%H:%M:%S}", kind, item, action)):
            it = QTableWidgetItem(v); it.setToolTip(v)
            if c == 1 and color:
                it.setForeground(QColor(color))
            self.live.setItem(0, c, it)
        if self.live.rowCount() > 300:
            self.live.removeRow(300)

    def on_show(self):
        s = self.app.settings
        for k, t in self.toggles.items():
            t.setChecked(webprotect.is_enabled() if k == "web_protection" else s[k])
        self.dir_list.clear()
        for d in winsys.risky_dirs():
            self.dir_list.addItem(QListWidgetItem(icon("shield", C["muted"], 16), str(d)))
        for d in s["extra_dirs"]:
            self.dir_list.addItem(QListWidgetItem(icon("folder", C["accent"], 16), d))
        eg = self.app.execguard
        self.exec_mode.setText(f"Mode : {eg.mode}" + ("" if eg.kernel else
                               " · installez le pilote noyau (Réglages → Avancé) pour bloquer avant même le démarrage"))
        n = len(webprotect.domains())
        self.web_info.setText(f"{n:,} domaines malveillants dans la liste".replace(",", " ") +
                              (" · active" if webprotect.is_enabled() else "") +
                              ("" if winsys.is_admin() or not winsys.IS_WIN else " · nécessite les droits administrateur"))
