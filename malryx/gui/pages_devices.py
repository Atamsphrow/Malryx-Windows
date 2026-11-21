"""Page Appareils : téléphones Android (ADB) et clés USB."""
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QCheckBox, QGridLayout, QHBoxLayout, QListWidget, QListWidgetItem, QProgressBar, QStackedWidget, QVBoxLayout, QWidget

from .. import history, winsys
from ..engine import MALWARE, SUSPECT
from .common import DetailDialog, Page, btn, confirm, info
from .theme import C, icon
from .widgets import Card, EmptyState, Table, label
from .workers import AndroidScanWorker, FuncWorker

HELP = ("1. Sur le téléphone : Paramètres → À propos du téléphone → touchez 7 fois « Numéro de build ».\n"
        "2. Paramètres → Options pour les développeurs → activez « Débogage USB ».\n"
        "3. Branchez le câble USB et acceptez « Autoriser le débogage USB » sur le téléphone.")


class DevicesPage(Page):
    def __init__(self, app):
        super().__init__(app, "Appareils", "Analysez les téléphones Android et les clés USB connectés à ce PC", scroll=False)
        self.worker = None
        self.current = None
        self.head_actions.addWidget(btn("Actualiser", "refresh", slot=self.refresh_devices))

        h = QHBoxLayout(); h.setSpacing(16)
        left = Card(); left.setFixedWidth(290)
        left.lay.addWidget(label("Téléphones Android", "Section"))
        self.phones = QListWidget(); self.phones.setMinimumHeight(150)
        self.phones.currentRowChanged.connect(self._select_phone)
        left.lay.addWidget(self.phones)
        left.lay.addWidget(label("Clés USB et disques amovibles", "Section"))
        self.usb = QListWidget(); self.usb.setMinimumHeight(110)
        left.lay.addWidget(self.usb)
        left.lay.addWidget(btn("Analyser la clé sélectionnée", "search", slot=self._scan_usb))
        h.addWidget(left)

        self.right = QStackedWidget()
        self.right.addWidget(EmptyState("phone", "Aucun téléphone sélectionné",
                                        "Branchez un téléphone Android avec le débogage USB activé.\n\n" + HELP))
        self.right.addWidget(self._detail())
        h.addWidget(self.right, 1)
        self.body.addLayout(h, 1)
        self.timer = QTimer(self); self.timer.timeout.connect(self.refresh_devices)

    def _detail(self):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(0, 0, 0, 0); v.setSpacing(16)
        info_c = Card()
        top = QHBoxLayout()
        self.d_title = label("", "Section"); self.d_title.setStyleSheet("font-size:15pt;font-weight:700")
        top.addWidget(self.d_title); top.addStretch()
        info_c.lay.addLayout(top)
        g = QGridLayout(); g.setHorizontalSpacing(30)
        self.d_fields = {}
        for i, (k, t) in enumerate((("fabricant", "Fabricant"), ("android", "Version d'Android"), ("correctif", "Correctif de sécurité"),
                                    ("root", "Accès root"), ("sources_inconnues", "Sources inconnues"), ("serial", "N° de série"))):
            g.addWidget(label(t, muted=True), (i // 3) * 2, i % 3)
            lab = label("—"); self.d_fields[k] = lab
            g.addWidget(lab, (i // 3) * 2 + 1, i % 3)
        info_c.lay.addLayout(g)
        opt = QHBoxLayout()
        self.o_sys = QCheckBox("Inclure les applications système")
        self.o_sto = QCheckBox("Analyser aussi le stockage (Download, Documents)"); self.o_sto.setChecked(True)
        opt.addWidget(self.o_sys); opt.addWidget(self.o_sto); opt.addStretch()
        self.a_scan = btn("  Analyser le téléphone", "search", "Primary", slot=self._scan_phone)
        self.a_stop = btn("Arrêter", "stop", "Danger", slot=lambda: self.worker and self.worker.cancel())
        self.a_stop.hide()
        opt.addWidget(self.a_stop); opt.addWidget(self.a_scan)
        info_c.lay.addLayout(opt)
        self.p_bar = QProgressBar(); self.p_bar.setTextVisible(False); self.p_bar.setFixedHeight(10); self.p_bar.hide()
        self.p_lab = label("", muted=True)
        info_c.lay.addWidget(self.p_bar); info_c.lay.addWidget(self.p_lab)
        v.addWidget(info_c)

        res = Card()
        h = QHBoxLayout(); self.r_title = label("Applications", "Section"); h.addWidget(self.r_title); h.addStretch()
        self.only_risk = QCheckBox("Afficher uniquement les risques"); self.only_risk.setChecked(True)
        self.only_risk.toggled.connect(self._filter)
        h.addWidget(self.only_risk)
        h.addWidget(btn("Désinstaller", "trash", "Danger", slot=self._uninstall))
        res.lay.addLayout(h)
        self.table = Table(["Application", "Verdict", "Score", "Raisons"], stretch_col=3)
        self.table.cellDoubleClicked.connect(self._details)
        res.lay.addWidget(self.table)
        v.addWidget(res, 1)
        return w

    def on_show(self):
        self.refresh_devices()
        self.timer.start(6000)

    def hideEvent(self, e):
        self.timer.stop()
        super().hideEvent(e)

    def refresh_devices(self):
        if getattr(self, "_rw", None) and self._rw.isRunning():
            return
        def work():
            devs = []
            if self.app.adb:
                for d in self.app.adb.devices():
                    if d["state"] == "device":
                        d.update(self.app.adb.device_info(d["serial"]))
                    devs.append(d)
            return devs, winsys.removable_drives()
        self._rw = FuncWorker(work)
        self._rw.result.connect(self._devices_loaded)
        self._rw.start()

    def _devices_loaded(self, r):
        if isinstance(r, Exception):
            return
        devs, drives = r
        self.app.android_devices, self.app.usb_drives = devs, drives
        cur = self.current["serial"] if self.current else None
        self.phones.blockSignals(True); self.phones.clear()
        self.devs = devs
        for d in devs:
            if d["state"] == "device":
                text = f"{d.get('fabricant', '').capitalize()} {d.get('modele', d['model'])}\nAndroid {d.get('android', '?')}"
                it = QListWidgetItem(icon("phone", C["ok"], 20), text)
            else:
                it = QListWidgetItem(icon("phone", C["warn"], 20), f"{d['serial']}\nAutorisez le débogage sur le téléphone")
            self.phones.addItem(it)
        if not self.app.adb:
            self.phones.addItem(QListWidgetItem(icon("alert", C["muted"], 18), "ADB non disponible"))
        self.phones.blockSignals(False)
        idx = next((i for i, d in enumerate(devs) if d["serial"] == cur), 0 if devs else -1)
        self.phones.setCurrentRow(idx)
        if idx == -1:
            self.right.setCurrentIndex(0); self.current = None
        self.usb.clear()
        for d in drives:
            self.usb.addItem(QListWidgetItem(icon("usb", C["accent"], 18), str(d)))
        if not drives:
            self.usb.addItem(QListWidgetItem(icon("minus", C["muted"], 16), "Aucun disque amovible"))

    def _select_phone(self, i):
        if i < 0 or i >= len(getattr(self, "devs", [])):
            return
        d = self.devs[i]
        if d["state"] != "device":
            self.right.setCurrentIndex(0)
            return
        changed = not self.current or self.current["serial"] != d["serial"]
        self.current = d
        self.right.setCurrentIndex(1)
        self.d_title.setText(f"{d.get('fabricant', '').capitalize()} {d.get('modele', d['model'])}")
        for k, lab in self.d_fields.items():
            v = d.get(k, "—")
            if k == "root":
                lab.setText("Oui (risque élevé)" if v else "Non"); lab.setStyleSheet(f"color:{C['bad'] if v else C['ok']}")
            elif k == "sources_inconnues":
                lab.setText("Autorisées" if v else "Bloquées"); lab.setStyleSheet(f"color:{C['warn'] if v else C['ok']}")
            else:
                lab.setText(str(v))
        if changed:
            self.table.setRowCount(0)

    def _scan_phone(self):
        if not self.current:
            return
        self.table.setRowCount(0)
        self.results = []
        self.a_scan.hide(); self.a_stop.show(); self.p_bar.show(); self.p_bar.setRange(0, 0)
        self.worker = AndroidScanWorker(self.app.adb, self.app.engine, self.current["serial"],
                                        self.o_sys.isChecked(), self.o_sto.isChecked())
        self.worker.progress.connect(self._progress)
        self.worker.found.connect(self._found)
        self.worker.done.connect(self._done)
        self.worker.start()

    def _progress(self, i, n, cur):
        if n:
            self.p_bar.setRange(0, n); self.p_bar.setValue(i)
        self.p_lab.setText(f"{i}/{n} · {cur}" if n else cur)

    def _found(self, r):
        self.results.append(r)
        if r["verdict"] in (MALWARE, SUSPECT):
            history.add(f"Android ({self.current.get('modele', '')})", r, "détecté")
        self._add(r)

    def _add(self, r):
        if self.only_risk.isChecked() and r["verdict"] not in (MALWARE, SUSPECT):
            return
        reasons = "; ".join(x for x in r["reasons"] if not x.startswith("ignoré"))
        self.table.add_row([r.get("package", r["path"]), r["verdict"], r["score"], reasons], data=r, verdict_col=1)

    def _filter(self):
        self.table.setRowCount(0)
        order = {MALWARE: 0, SUSPECT: 1}
        for r in sorted(getattr(self, "results", []), key=lambda x: (order.get(x["verdict"], 2), -x["score"])):
            self._add(r)

    def _done(self, s):
        self.a_scan.show(); self.a_stop.hide(); self.p_bar.hide()
        if s.get("error"):
            self.p_lab.setText(f"Erreur : {s['error']}")
            return
        self.p_lab.setText(f"{s['count']} éléments analysés en {s['seconds']:.0f} s · "
                           f"{s['malware']} malveillant(s) · {s['suspect']} suspect(s)")
        self.r_title.setText(f"Applications ({s['count']})")
        self._filter()
        if s["malware"]:
            self.app.notify("Menaces sur le téléphone", f"{s['malware']} application(s) malveillante(s) détectée(s)", True)

    def _uninstall(self):
        sel = [d for _, d in self.table.selected_data() if d.get("package") and not d["package"].startswith("📁")]
        if not sel:
            info(self, "Désinstaller", "Sélectionnez une ou plusieurs applications dans la liste.")
            return
        names = "\n".join("• " + d["package"] for d in sel)
        if not confirm(self, "Désinstaller", f"Désinstaller ces applications du téléphone ?\n\n{names}", "Désinstaller", True):
            return
        for d in sel:
            out = self.app.adb.uninstall(self.current["serial"], d["package"])
            history.add("Android", d, f"désinstallé ({out})")
            self.app.log(f"Android : désinstallation de {d['package']} → {out}")
        self.results = [r for r in self.results if r not in sel]
        self._filter()

    def _details(self, row, _):
        r = self.table.item(row, 0).data(Qt.UserRole)
        d = DetailDialog(self, r, [("Désinstaller", "u", "Danger")] if r.get("package") else [])
        if d.exec() and d.choice == "u":
            self.table.selectRow(row)
            self._uninstall()

    def _scan_usb(self):
        it = self.usb.currentItem()
        drives = [str(d) for d in self.app.usb_drives]
        if it and it.text() in drives:
            self.app.start_scan("personnalisée", [it.text()])
        elif drives:
            self.app.start_scan("personnalisée", drives)
        else:
            info(self, "USB", "Aucune clé USB détectée.")
