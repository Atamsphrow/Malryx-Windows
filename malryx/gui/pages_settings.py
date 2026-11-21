"""Page Réglages."""
import sys

from PySide6.QtCore import QTime
from PySide6.QtWidgets import QComboBox, QFileDialog, QHBoxLayout, QLineEdit, QTimeEdit, QWidget

from .. import winsys
from ..engine import user_hashes_file, user_rules_dir
from ..paths import VERSION, data_dir
from .common import Page, btn, info
from .theme import C
from .widgets import Card, SettingRow, Toggle, label
from .workers import FuncWorker

DAYS = ["Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi", "Dimanche"]


class SettingsPage(Page):
    def __init__(self, app):
        super().__init__(app, "Réglages", "Personnalisez le comportement de Malryx")
        s = app.settings

        def toggle(key, cb=None):
            t = Toggle(s[key])
            t.toggled.connect(lambda v: (s.__setitem__(key, v), cb and cb(v)))
            return t

        # ---------- général ----------
        g = Card(spacing=0); g.lay.addWidget(label("Général", "Section"))
        g.lay.addWidget(SettingRow("Lancer Malryx au démarrage de Windows", "Recommandé : la protection démarre avec la session.",
                                   toggle("start_with_windows", app.set_autostart)))
        g.lay.addWidget(SettingRow("Réduire dans la zone de notification", "Fermer la fenêtre laisse la protection active.",
                                   toggle("minimize_to_tray")))
        g.lay.addWidget(SettingRow("Notifications", "Afficher une notification à chaque menace bloquée.", toggle("notifications")))
        g.lay.addWidget(SettingRow("Menu « Analyser avec Malryx »", "Ajoute l'analyse au clic droit de l'Explorateur Windows.",
                                   toggle("explorer_menu", app.set_explorer_menu)))
        self.body.addWidget(g)

        # ---------- planification ----------
        p = Card(spacing=0); p.lay.addWidget(label("Analyse planifiée", "Section"))
        sc = s["schedule"]
        en = Toggle(sc["enabled"]); en.toggled.connect(lambda v: self._sched("enabled", v))
        p.lay.addWidget(SettingRow("Activer l'analyse automatique", "Malryx doit être ouvert (dans la zone de notification).", en))
        row = QWidget(); h = QHBoxLayout(row); h.setContentsMargins(0, 6, 0, 6)
        self.freq = QComboBox(); self.freq.addItems(["quotidienne", "hebdomadaire"]); self.freq.setCurrentText(sc["freq"])
        self.freq.currentTextChanged.connect(lambda v: self._sched("freq", v))
        self.day = QComboBox(); self.day.addItems(DAYS); self.day.setCurrentIndex(sc["day"])
        self.day.currentIndexChanged.connect(lambda v: self._sched("day", v))
        self.time = QTimeEdit(QTime.fromString(sc["time"], "HH:mm")); self.time.setDisplayFormat("HH:mm")
        self.time.timeChanged.connect(lambda t: self._sched("time", t.toString("HH:mm")))
        self.stype = QComboBox(); self.stype.addItems(["rapide", "complète"]); self.stype.setCurrentText(sc["type"])
        self.stype.currentTextChanged.connect(lambda v: self._sched("type", v))
        for lab, wdg in (("Fréquence", self.freq), ("Jour", self.day), ("Heure", self.time), ("Type", self.stype)):
            h.addWidget(label(lab, muted=True)); h.addWidget(wdg); h.addSpacing(10)
        h.addStretch()
        p.lay.addWidget(row)
        self.body.addWidget(p)

        # ---------- moteurs ----------
        m = Card(spacing=0); m.lay.addWidget(label("Moteurs de détection", "Section"))
        self.clam_info = label("", muted=True, wrap=True)
        clam_row = QWidget(); ch = QHBoxLayout(clam_row); ch.setContentsMargins(0, 0, 0, 0)
        self.upd_btn = btn("Mettre à jour", "download", slot=app.update_signatures)
        ch.addWidget(self.upd_btn); ch.addWidget(toggle("clamav", app.set_clamav))
        m.lay.addWidget(SettingRow("Moteur ClamAV", "Des millions de signatures. Utilise environ 1 Go de mémoire vive.", clam_row))
        m.lay.addWidget(self.clam_info)
        m.lay.addWidget(SettingRow("Mises à jour automatiques", "Télécharge les nouvelles signatures une fois par jour.", toggle("update_auto")))
        mir = QLineEdit(s["mirror_repo"]); mir.setPlaceholderText("propriétaire/dépôt"); mir.setMinimumWidth(230); mir.setMaximumWidth(280)
        mir.editingFinished.connect(lambda: s.__setitem__("mirror_repo", mir.text().strip()))
        m.lay.addWidget(SettingRow("Miroir de signatures (GitHub)", "Utilisé si les serveurs ClamAV sont injoignables (DNS bloqué, "
                                   "limite atteinte). Publié chaque jour par le workflow « signatures » de votre dépôt.", mir))
        sens = QComboBox(); sens.addItems(["faible", "normal", "élevée"]); sens.setCurrentText(s["sensitivity"])
        sens.currentTextChanged.connect(lambda v: s.__setitem__("sensitivity", v))
        m.lay.addWidget(SettingRow("Sensibilité de l'heuristique", "Élevée : détecte plus de menaces inconnues, mais plus de faux positifs.", sens))
        self.body.addWidget(m)

        # ---------- VirusTotal ----------
        v = Card(spacing=0); v.lay.addWidget(label("VirusTotal (70 antivirus)", "Section"))
        v.lay.addWidget(label("Les fichiers douteux sont vérifiés auprès de VirusTotal. Seule l'empreinte SHA-256 est envoyée, jamais le fichier. "
                              "Clé gratuite sur virustotal.com (4 requêtes / minute).", muted=True, wrap=True))
        kr = QWidget(); kh = QHBoxLayout(kr); kh.setContentsMargins(0, 8, 0, 8)
        self.vt = QLineEdit(s["vt_key"]); self.vt.setEchoMode(QLineEdit.Password); self.vt.setPlaceholderText("Clé API VirusTotal")
        self.vt.editingFinished.connect(lambda: s.__setitem__("vt_key", self.vt.text().strip()))
        kh.addWidget(self.vt, 1); kh.addWidget(btn("Tester", slot=self._vt_test))
        v.lay.addWidget(kr)
        v.lay.addWidget(SettingRow("Utiliser VirusTotal", "", toggle("use_vt")))
        self.body.addWidget(v)

        # ---------- signatures personnalisées ----------
        c = Card(spacing=8); c.lay.addWidget(label("Signatures personnalisées", "Section"))
        c.lay.addWidget(label("Importez des listes de hashes (exports MalwareBazaar, CSV, TXT) ou ajoutez vos propres règles YARA.", muted=True, wrap=True))
        r = QHBoxLayout()
        r.addWidget(btn("Importer des hashes", "download", slot=self._import))
        r.addWidget(btn("Dossier des règles YARA", "folder", slot=lambda: winsys.open_folder(user_rules_dir())))
        r.addWidget(btn("Recharger les règles", "refresh", slot=self._reload))
        r.addStretch()
        c.lay.addLayout(r)
        self.sig_info = label("", muted=True)
        c.lay.addWidget(self.sig_info)
        self.body.addWidget(c)

        # ---------- avancé ----------
        a = Card(spacing=8); a.lay.addWidget(label("Avancé", "Section"))
        self.adm = label("", muted=True)
        a.lay.addWidget(self.adm)
        r = QHBoxLayout()
        self.adm_btn = btn("Relancer en administrateur", "shield", slot=app.relaunch_admin)
        r.addWidget(self.adm_btn)
        r.addWidget(btn("Dossier des données", "folder", slot=lambda: winsys.open_folder(data_dir())))
        r.addStretch()
        a.lay.addLayout(r)
        a.lay.addWidget(label("Pilote noyau Malryx (expérimental)", "Section"))
        a.lay.addWidget(label("Bloque les malwares AVANT leur démarrage : Windows demande l'avis de Malryx à chaque création de "
                              "processus. Nécessite le mode test de Windows (Secure Boot désactivé) : à réserver à une VM ou au PC de démonstration.",
                              muted=True, wrap=True))
        self.drv = label("", wrap=True)
        a.lay.addWidget(self.drv)
        r2 = QHBoxLayout()
        self.drv_inst = btn("Installer le pilote (mode test)", "download", slot=lambda: self._driver(False))
        self.drv_uninst = btn("Désinstaller le pilote", "trash", slot=lambda: self._driver(True))
        r2.addWidget(self.drv_inst); r2.addWidget(self.drv_uninst); r2.addStretch()
        a.lay.addLayout(r2)
        a.lay.addWidget(label(f"Malryx {VERSION} · Python {sys.version.split()[0]} · données : {data_dir()}", muted=True, wrap=True))
        self.body.addWidget(a)
        self.body.addStretch()
        self.on_show()

    def _driver(self, uninstall):
        from ..paths import resource
        d = resource("vendor", "driver")
        script, sys_file = d / "install-driver.ps1", d / "MalryxFlt.sys"
        if not script.exists() or (not uninstall and not sys_file.exists()):
            info(self, "Pilote noyau", "Cette version de Malryx n'embarque pas le pilote compilé.\n"
                 "Compilez-le avec driver\\build-driver.cmd puis relancez build.ps1 (voir driver\\README.md).")
            return
        args = f'-NoProfile -ExecutionPolicy Bypass -NoExit -File "{script}" -Sys "{sys_file}"' + (" -Uninstall" if uninstall else "")
        winsys.relaunch_as_admin("powershell.exe", args)
        info(self, "Pilote noyau", "Suivez les instructions dans la fenêtre PowerShell.\n"
             "Après l'installation, relancez Malryx en administrateur.")

    def _sched(self, k, v):
        sc = dict(self.app.settings["schedule"]); sc[k] = v
        self.app.settings["schedule"] = sc
        self.day.setEnabled(sc["freq"] == "hebdomadaire")

    def _vt_test(self):
        self.app.settings["vt_key"] = self.vt.text().strip()
        w = FuncWorker(self.app.engine.vt_lookup, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        w.result.connect(lambda r: info(self, "VirusTotal", f"Connexion réussie : le fichier de test EICAR est détecté par {r[0]} moteurs."
                                        if isinstance(r, tuple) else "Échec : vérifiez la clé et la connexion Internet."))
        self._vtw = w; w.start()

    def _import(self):
        f, _ = QFileDialog.getOpenFileName(self, "Liste de hashes SHA-256", "", "Listes (*.txt *.csv);;Tous (*)")
        if f:
            n = self.app.engine.add_hashes_from_file(f)
            info(self, "Signatures", f"{n} nouvelle(s) signature(s) importée(s).")
            self.on_show()

    def _reload(self):
        self.app.engine.reload()
        self.on_show()
        info(self, "Règles", f"{self.app.engine.rule_count} règles YARA et {len(self.app.engine.bad_hashes)} signatures chargées.")

    def on_show(self):
        cl = self.app.clamav
        st = self.app.engine.status()
        hdb = self.app.engine.hashdb
        self.clam_info.setText(f"ClamAV : {cl.state} · {cl.db_info()}" + ("" if cl.clamd else " (moteur non embarqué)") +
                               f"\nBase Malryx : {len(hdb):,} hashes".replace(",", " ") +
                               (f" (du {hdb.date:%d/%m/%Y})" if hdb.date else "") + f" · {st['yara']} règles YARA")
        self.sig_info.setText(f"{len(self.app.engine.bad_hashes)} signatures · {self.app.engine.rule_count} règles YARA · "
                              f"fichier perso : {user_hashes_file()}")
        admin = winsys.is_admin()
        self.adm.setText("Malryx fonctionne avec les droits administrateur." if admin else
                         "Malryx fonctionne en utilisateur standard : la protection Web, la réparation du registre et "
                         "l'analyse des dossiers système nécessitent les droits administrateur.")
        self.adm_btn.setVisible(not admin and winsys.IS_WIN)
        self.day.setEnabled(self.app.settings["schedule"]["freq"] == "hebdomadaire")
        eg = self.app.execguard
        if eg.kernel:
            self.drv.setText("● Pilote connecté : blocage avant exécution actif."); self.drv.setStyleSheet(f"color:{C['ok']}")
        else:
            from ..kernel import KernelClient
            loaded = winsys.IS_WIN and KernelClient.driver_loaded()
            self.drv.setText("● Pilote chargé, mais Malryx doit être lancé en administrateur pour s'y connecter." if loaded
                             else "● Pilote non installé : la protection à l'exécution fonctionne par surveillance des processus.")
            self.drv.setStyleSheet(f"color:{C['warn'] if loaded else C['muted']}")
        self.drv_inst.setVisible(winsys.IS_WIN); self.drv_uninst.setVisible(winsys.IS_WIN)
