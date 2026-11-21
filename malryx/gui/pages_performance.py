"""Page Performances : démarrage, mode veille des applications, mises à jour des logiciels, santé du système."""
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QGridLayout, QHBoxLayout, QProgressBar, QSpinBox, QTabWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from .. import cleaner, performance, winsys
from .common import Page, btn, confirm, fmt_date, info
from .theme import C, VERDICT_COLORS, icon
from .widgets import Card, StatCard, Table, Toggle, icon_label, label
from .workers import FuncWorker, TaskWorker

H = cleaner.human
IMPACT_COL = {"Élevé": C["bad"], "Moyen": C["warn"], "Faible": C["ok"], "Inconnu": C["muted"]}


class PerformancePage(Page):
    def __init__(self, app):
        super().__init__(app, "Performances", "Accélérez le démarrage et libérez la mémoire de votre PC", scroll=False)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._startup(), "Démarrage")
        self.tabs.addTab(self._sleep(), "Mode veille")
        self.tabs.addTab(self._updates(), "Logiciels")
        self.tabs.addTab(self._health(), "Santé du système")
        self.tabs.currentChanged.connect(self._tab)
        self.body.addWidget(self.tabs, 1)
        self.timer = QTimer(self); self.timer.timeout.connect(self._refresh_sleep)

    def _box(self):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(0, 12, 0, 0); v.setSpacing(12)
        return w, v

    def _tab(self, i):
        if i == 0 and not self.st_table.rowCount():
            self._load_startup()
        elif i == 1:
            self._refresh_sleep(); self.timer.start(5000)
        elif i == 3:
            self._load_health()
        if i != 1:
            self.timer.stop()

    def on_show(self):
        self._tab(self.tabs.currentIndex())

    def hideEvent(self, e):
        self.timer.stop(); super().hideEvent(e)

    # ------------------------------------------------------------------ démarrage
    def _startup(self):
        w, v = self._box()
        stats = QHBoxLayout()
        self.s_boot = StatCard("zap", "Dernier démarrage", "—", C["accent"])
        self.s_up = StatCard("pulse", "Allumé depuis", "—", C["info"])
        self.s_cnt = StatCard("list", "Programmes au démarrage", "—", C["warn"])
        for x in (self.s_boot, self.s_up, self.s_cnt):
            stats.addWidget(x)
        v.addLayout(stats)
        top = QHBoxLayout()
        top.addWidget(label("Impact estimé d'après le processeur et la mémoire consommés depuis l'ouverture de session. "
                            "Désactivez ce que vous n'utilisez pas : le programme reste installé et peut être réactivé.", muted=True, wrap=True), 1)
        top.addWidget(btn("Actualiser", "refresh", slot=self._load_startup))
        top.addWidget(btn("Analyser", "search", slot=self._scan_startup))
        top.addWidget(btn("  Activer / Désactiver", "zap", "Primary", slot=self._toggle_startup))
        v.addLayout(top)
        self.st_table = Table(["Programme", "Impact", "État", "Source", "Commande", "Verdict"], stretch_col=4)
        v.addWidget(self.st_table, 1)
        return w

    def _load_startup(self):
        def work():
            items = performance.startup_impact(winsys.all_startup_items())
            return items, performance.boot_info()
        self._sw = FuncWorker(work); self._sw.result.connect(self._startup_loaded); self._sw.start()

    def _startup_loaded(self, r):
        if isinstance(r, Exception):
            return
        items, boot = r
        if boot["boot_ms"]:
            self.s_boot.set(f"{boot['boot_ms'][0]['Ms'] / 1000:.0f} s")
            self.s_boot.setToolTip("\n".join(f"{b['Date']} : {b['Ms'] / 1000:.0f} s" for b in boot["boot_ms"]))
        elif boot["last_boot"]:
            self.s_boot.set(fmt_date(boot["last_boot"]).replace("Aujourd'hui à ", ""))
        if boot["uptime_h"] is not None:
            self.s_up.set(f"{boot['uptime_h']:.0f} h" if boot["uptime_h"] < 48 else f"{boot['uptime_h'] / 24:.0f} j")
        active = [i for i in items if not (i.get("disabled") or str(i.get("state")) in ("1", "Disabled"))]
        self.s_cnt.set(str(len(active)))
        self.st_table.setRowCount(0)
        order = {"Élevé": 0, "Moyen": 1, "Faible": 2, "Inconnu": 3}
        for it in sorted(items, key=lambda x: order.get(x["impact"], 4)):
            state = "Désactivé" if it.get("disabled") or str(it.get("state")) in ("1", "Disabled") else "Activé"
            r = self.st_table.add_row([it["name"], it["impact"], state, it["source"], it["command"], ""], data=it)
            self.st_table.item(r, 1).setForeground(QColor(IMPACT_COL.get(it["impact"], C["muted"])))
            if state == "Désactivé":
                self.st_table.item(r, 2).setForeground(QColor(C["muted"]))

    def _scan_startup(self):
        rows = self.st_table.all_data()

        def work():
            out = []
            for r, it in rows:
                exe = it.get("exe")
                out.append((r, self.app.engine.scan_file(exe) if exe and Path(exe).exists() else {"verdict": "INTROUVABLE" if exe else "—"}))
            return out
        self._ssw = FuncWorker(work); self._ssw.result.connect(self._startup_scanned); self._ssw.start()

    def _startup_scanned(self, res):
        if isinstance(res, Exception):
            return
        for r, x in res:
            it = QTableWidgetItem(x["verdict"]); it.setForeground(QColor(VERDICT_COLORS.get(x["verdict"], C["muted"])))
            it.setToolTip("\n".join(x.get("reasons", [])))
            self.st_table.setItem(r, 5, it)

    def _toggle_startup(self):
        for r, it in self.st_table.selected_data():
            enable = self.st_table.item(r, 2).text() == "Désactivé"
            try:
                if winsys.set_startup_item(it, enable):
                    self.app.log(f"Démarrage : {it['name']} {'activé' if enable else 'désactivé'}")
            except PermissionError:
                info(self, "Démarrage", "Droits administrateur requis pour cet élément.")
            except OSError as e:
                info(self, "Démarrage", str(e))
        self._load_startup()

    # ------------------------------------------------------------------ mode veille
    def _sleep(self):
        w, v = self._box()
        c = Card(spacing=6)
        h = QHBoxLayout()
        h.addWidget(icon_label("pause", C["accent"], 24))
        tv = QVBoxLayout()
        t = label("Mode veille automatique"); t.setStyleSheet("font-weight:700;font-size:10.5pt")
        tv.addWidget(t)
        tv.addWidget(label("Les applications gourmandes inactives sont mises en pause : elles ne consomment plus de processeur. "
                           "Elles se réveillent instantanément quand vous cliquez sur leur fenêtre.", muted=True, wrap=True))
        h.addLayout(tv, 1)
        h.addWidget(label("après", muted=True))
        self.sl_min = QSpinBox(); self.sl_min.setRange(5, 240); self.sl_min.setValue(self.app.settings["sleep_minutes"]); self.sl_min.setSuffix(" min")
        self.sl_min.valueChanged.connect(lambda v: self.app.settings.__setitem__("sleep_minutes", v))
        h.addWidget(self.sl_min)
        self.sl_auto = Toggle(self.app.settings["sleep_auto"])
        self.sl_auto.toggled.connect(lambda v: self.app.settings.__setitem__("sleep_auto", v))
        h.addWidget(self.sl_auto)
        c.lay.addLayout(h)
        v.addWidget(c)
        hh = QHBoxLayout(); hh.setSpacing(16)
        a = Card()
        r = QHBoxLayout(); r.addWidget(label("Applications actives en arrière-plan", "Section")); r.addStretch()
        r.addWidget(btn("Ne jamais endormir", slot=self._whitelist))
        r.addWidget(btn("  Mettre en veille", "pause", "Primary", slot=self._sleep_sel))
        a.lay.addLayout(r)
        self.sl_cand = Table(["Application", "Mémoire", "Processus"], stretch_col=0)
        a.lay.addWidget(self.sl_cand)
        hh.addWidget(a, 1)
        b = Card()
        r = QHBoxLayout(); r.addWidget(label("En veille", "Section")); r.addStretch()
        r.addWidget(btn("  Réveiller", "play", slot=self._wake_sel))
        b.lay.addLayout(r)
        self.sl_sleep = Table(["Application", "Mémoire", "Depuis"], stretch_col=0)
        b.lay.addWidget(self.sl_sleep)
        hh.addWidget(b, 1)
        v.addLayout(hh, 1)
        return w

    def _refresh_sleep(self):
        sm = self.app.sleep_mgr
        self.sl_cand.setRowCount(0)
        for a in sm.candidates():
            self.sl_cand.add_row([a["name"], H(a["mem"]), len(a["pids"])], data=a)
        self.sl_sleep.setRowCount(0)
        for a in sm.sleeping_apps():
            mins = int((datetime.now().timestamp() - a["since"]) / 60)
            self.sl_sleep.add_row([a["name"], H(a["mem"]), f"{mins} min"], data=a)

    def _sleep_sel(self):
        for _, a in self.sl_cand.selected_data():
            n = self.app.sleep_mgr.sleep_app(a)
            self.app.log(f"Mode veille : {a['name']} ({n} processus)")
        self._refresh_sleep()

    def _wake_sel(self):
        for _, a in self.sl_sleep.selected_data():
            self.app.sleep_mgr.wake(name=a["name"])
        self._refresh_sleep()

    def _whitelist(self):
        names = [a["name"] for _, a in self.sl_cand.selected_data()]
        if names:
            self.app.settings["sleep_whitelist"] = list(dict.fromkeys(self.app.settings["sleep_whitelist"] + names))
            self._refresh_sleep()

    # ------------------------------------------------------------------ logiciels
    def _updates(self):
        w, v = self._box()
        top = QHBoxLayout()
        self.u_info = label("Les logiciels obsolètes sont la porte d'entrée n°1 des malwares. Malryx utilise winget, "
                            "le gestionnaire officiel de Windows, pour les mettre à jour depuis leur source officielle.", muted=True, wrap=True)
        top.addWidget(self.u_info, 1)
        self.u_an = btn("Rechercher", "search", slot=self._upd_scan)
        self.u_go = btn("  Mettre à jour la sélection", "download", "Primary", slot=self._upd_go); self.u_go.setEnabled(False)
        top.addWidget(self.u_an); top.addWidget(self.u_go)
        v.addLayout(top)
        self.u_table = Table(["", "Logiciel", "Version installée", "Nouvelle version", "Priorité", "État"], stretch_col=1)
        self.u_table.setColumnWidth(0, 34)
        v.addWidget(self.u_table, 1)
        return w

    def _upd_scan(self):
        self.u_an.setEnabled(False); self.u_info.setText("Recherche des mises à jour (jusqu'à une minute)…")
        self._uw = FuncWorker(performance.outdated_software); self._uw.result.connect(self._upd_list); self._uw.start()

    def _upd_list(self, apps):
        self.u_an.setEnabled(True)
        if apps is None:
            self.u_info.setText("winget est introuvable : installez « Programme d'installation d'application » depuis le Microsoft Store.")
            return
        if isinstance(apps, Exception):
            self.u_info.setText(str(apps)); return
        self.u_table.setRowCount(0)
        for a in apps:
            r = self.u_table.add_row(["", a["name"], a["version"], a["available"], a["priority"], ""], data=a)
            it = self.u_table.item(r, 0); it.setFlags(it.flags() | Qt.ItemIsUserCheckable); it.setCheckState(Qt.Checked)
            if a["priority"] == "Sécurité":
                self.u_table.item(r, 4).setForeground(QColor(C["bad"]))
        crit = sum(a["priority"] == "Sécurité" for a in apps)
        self.u_info.setText(f"{len(apps)} mise(s) à jour disponible(s), dont {crit} importante(s) pour la sécurité." if apps
                            else "Tous vos logiciels sont à jour.")
        self.u_go.setEnabled(bool(apps))

    def _upd_go(self):
        rows = [(r, d) for r, d in self.u_table.all_data() if self.u_table.item(r, 0).checkState() == Qt.Checked]
        if not rows:
            return
        self.u_go.setEnabled(False)

        def work(progress):
            out = []
            for r, a in rows:
                progress(f"Mise à jour de {a['name']} ({len(out) + 1}/{len(rows)})…")
                out.append((r, *performance.update_software(a["id"])))
            return out
        self._uw2 = TaskWorker(work)
        self._uw2.progress.connect(self.u_info.setText)
        self._uw2.result.connect(self._upd_done); self._uw2.start()

    def _upd_done(self, res):
        self.u_go.setEnabled(True)
        if isinstance(res, Exception):
            self.u_info.setText(str(res)); return
        ok = 0
        for r, success, msg in res:
            it = QTableWidgetItem("À jour" if success else f"Échec : {msg[:60]}")
            it.setForeground(QColor(C["ok"] if success else C["bad"])); it.setToolTip(msg)
            self.u_table.setItem(r, 5, it); ok += success
        self.u_info.setText(f"{ok}/{len(res)} logiciel(s) mis à jour.")
        self.app.log(f"Mises à jour des logiciels : {ok}/{len(res)}")

    # ------------------------------------------------------------------ santé
    def _health(self):
        w, v = self._box()
        top = QHBoxLayout()
        self.h_info = label("", muted=True, wrap=True); top.addWidget(self.h_info, 1)
        top.addWidget(btn("Actualiser", "refresh", slot=self._load_health))
        v.addLayout(top)
        stats = QHBoxLayout()
        self.h_cpu = StatCard("cpu", "Processeur", "—", C["accent"])
        self.h_ram = StatCard("zap", "Mémoire vive", "—", C["info"])
        self.h_up = StatCard("pulse", "Allumé depuis", "—", C["warn"])
        self.h_bat = StatCard("check", "Batterie", "—", C["ok"])
        for x in (self.h_cpu, self.h_ram, self.h_up, self.h_bat):
            stats.addWidget(x)
        v.addLayout(stats)
        hh = QHBoxLayout(); hh.setSpacing(16)
        dc = Card(); dc.lay.addWidget(label("Disques (état SMART)", "Section"))
        self.h_disks = Table(["Disque", "Type", "État", "Température", "Usure", "Heures"], stretch_col=0)
        dc.lay.addWidget(self.h_disks)
        hh.addWidget(dc, 3)
        vc = Card(); vc.lay.addWidget(label("Espace", "Section"))
        self.h_vol = QVBoxLayout(); vc.lay.addLayout(self.h_vol); vc.lay.addStretch()
        hh.addWidget(vc, 2)
        v.addLayout(hh, 1)
        ac = Card(); ac.lay.addWidget(label("Alertes", "Section"))
        self.h_alerts = QVBoxLayout(); ac.lay.addLayout(self.h_alerts)
        v.addWidget(ac)
        return w

    def _load_health(self):
        self.h_info.setText("Lecture des capteurs…")
        self._hw = FuncWorker(performance.health); self._hw.result.connect(self._health_loaded); self._hw.start()

    def _clear(self, lay):
        while lay.count():
            it = lay.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
            elif it.layout():
                self._clear(it.layout())

    def _health_loaded(self, h):
        if isinstance(h, Exception):
            self.h_info.setText(str(h)); return
        self.h_info.setText("État SMART fourni par Windows (certaines valeurs nécessitent les droits administrateur).")
        if "cpu" in h:
            self.h_cpu.set(f"{h['cpu']:.0f} %")
        if "ram" in h:
            self.h_ram.set(f"{h['ram']['percent']:.0f} %"); self.h_ram.setToolTip(f"{H(h['ram']['used'])} / {H(h['ram']['total'])}")
        if "uptime_days" in h:
            self.h_up.set(f"{h['uptime_days']:.1f} j")
        self.h_bat.set(f"{h['battery']['percent']:.0f} %" + (" ⚡" if h["battery"]["plugged"] else "") if h.get("battery") else "Secteur")
        self.h_disks.setRowCount(0)
        for d in h["disks"]:
            ok = d.get("Health") in ("Healthy", "0")
            r = self.h_disks.add_row([d.get("Name"), d.get("Media"), "Bon" if ok else d.get("Health"),
                                      f"{d['Temp']} °C" if d.get("Temp") else "—", f"{d['Wear']} %" if d.get("Wear") is not None else "—",
                                      d.get("Hours") or "—"], data=d)
            self.h_disks.item(r, 2).setForeground(QColor(C["ok"] if ok else C["bad"]))
        if not h["disks"]:
            self.h_disks.add_row(["Informations SMART disponibles sous Windows", "", "", "", "", ""])
        self._clear(self.h_vol)
        for vol in h["volumes"][:6]:
            row = QVBoxLayout(); row.setSpacing(2)
            row.addWidget(label(f"{vol['mount']}   {H(vol['free'])} libres sur {H(vol['total'])}"))
            bar = QProgressBar(); bar.setTextVisible(False); bar.setFixedHeight(8); bar.setValue(int(vol["percent"]))
            if vol["percent"] > 90:
                bar.setStyleSheet(f"QProgressBar::chunk{{background:{C['bad']};border-radius:4px}}")
            row.addWidget(bar)
            self.h_vol.addLayout(row)
        self._clear(self.h_alerts)
        if not h["alerts"]:
            r = QHBoxLayout(); r.addWidget(icon_label("check", C["ok"], 18)); r.addWidget(label("Aucune alerte : votre système est en bonne santé.")); r.addStretch()
            self.h_alerts.addLayout(r)
        for sev, msg in h["alerts"]:
            r = QHBoxLayout(); r.addWidget(icon_label("alert", C["bad"] if sev == "bad" else C["warn"], 18))
            r.addWidget(label(msg, wrap=True), 1)
            self.h_alerts.addLayout(r)
