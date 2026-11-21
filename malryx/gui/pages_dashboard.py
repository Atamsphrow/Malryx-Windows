"""Tableau de bord : état global, cartes Analyse / Protection / Détections, moteurs, activité."""
from datetime import datetime, timedelta

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QListWidget, QListWidgetItem, QVBoxLayout, QFrame

from .. import quarantine
from .common import Page, btn, fmt_date
from .theme import C, icon
from .widgets import Card, EngineRow, Shield, StatCard, StatusDot, Toggle, icon_label, label

DAYS = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]


def next_scheduled(s):
    sc = s["schedule"]
    if not sc.get("enabled"):
        return "Aucune analyse planifiée"
    h, m = map(int, sc["time"].split(":"))
    now = datetime.now()
    cand = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if sc["freq"] == "quotidienne":
        if cand <= now:
            cand += timedelta(days=1)
    else:
        cand += timedelta(days=(sc["day"] - now.weekday()) % 7)
        if cand <= now:
            cand += timedelta(days=7)
    return f"{DAYS[cand.weekday()].capitalize()} {cand:%d/%m} à {cand:%H:%M}"


class DashboardPage(Page):
    def __init__(self, app):
        super().__init__(app, "Tableau de bord", "Vue d'ensemble de la sécurité de votre ordinateur")

        # ---------- bandeau principal ----------
        self.hero = QFrame(); self.hero.setObjectName("Hero")
        hl = QHBoxLayout(self.hero); hl.setContentsMargins(26, 22, 30, 22); hl.setSpacing(24)
        self.shield = Shield(); self.shield.setFixedSize(170, 170)
        hl.addWidget(self.shield)
        tv = QVBoxLayout(); tv.setSpacing(6)
        self.h_title = label("", "HeroTitle")
        self.h_sub = label("", muted=True, wrap=True)
        tv.addStretch()
        tv.addWidget(self.h_title); tv.addWidget(self.h_sub)
        bl = QHBoxLayout(); bl.setSpacing(10)
        self.scan_btn = btn("  Analyser mon PC", "search", "Primary", slot=lambda: app.pages["pcscan"].start())
        self.scan_btn.setMinimumHeight(44); self.scan_btn.setMinimumWidth(200)
        self.scan_btn.setToolTip("Menaces, sécurité, espace, performances et confidentialité en une seule analyse")
        self.threat_btn = btn("Analyse des menaces", "zap", slot=lambda: app.start_scan("rapide"))
        self.threat_btn.setMinimumHeight(44)
        self.fix_btn = btn("Activer la protection", "shield-check", slot=self._fix)
        self.fix_btn.setMinimumHeight(44)
        bl.addWidget(self.scan_btn); bl.addWidget(self.threat_btn); bl.addWidget(self.fix_btn); bl.addStretch()
        tv.addSpacing(8); tv.addLayout(bl); tv.addStretch()
        hl.addLayout(tv, 1)
        self.body.addWidget(self.hero)

        # ---------- trois cartes ----------
        grid = QGridLayout(); grid.setSpacing(16)

        c1 = Card()
        h = QHBoxLayout(); h.addWidget(icon_label("search", C["accent"], 22)); h.addWidget(label("Analyse", "Section")); h.addStretch()
        c1.lay.addLayout(h)
        self.last_scan = label("", wrap=True)
        self.next_scan = label("", muted=True, wrap=True)
        c1.lay.addWidget(label("Dernière analyse", muted=True)); c1.lay.addWidget(self.last_scan)
        c1.lay.addWidget(label("Prochaine analyse planifiée", muted=True)); c1.lay.addWidget(self.next_scan)
        c1.lay.addStretch()
        r = QHBoxLayout()
        r.addWidget(btn("Analyse complète", "disk", slot=lambda: app.start_scan("complète")))
        r.addWidget(btn("Personnalisée", "folder", slot=lambda: app.go("scan")))
        c1.lay.addLayout(r)
        grid.addWidget(c1, 0, 0)

        c2 = Card()
        h = QHBoxLayout(); h.addWidget(icon_label("pulse", C["ok"], 22)); h.addWidget(label("Protection en temps réel", "Section")); h.addStretch()
        self.master = Toggle(app.settings["realtime"])
        self.master.toggled.connect(lambda v: app.set_realtime(v))
        h.addWidget(self.master)
        c2.lay.addLayout(h)
        self.layers = {}
        for key, name in (("realtime", "Protection contre les malwares"), ("exec_guard", "Protection à l'exécution"),
                          ("behavior_guard", "Anti-exploit"), ("ransomware", "Anti-ransomware"),
                          ("web_protection", "Protection Web"), ("startup_guard", "Protection du démarrage"),
                          ("usb_monitor", "Périphériques USB"), ("android_monitor", "Téléphones Android")):
            row = QHBoxLayout()
            d = StatusDot(); row.addWidget(d)
            row.addWidget(label(name)); row.addStretch()
            st = label("", muted=True); row.addWidget(st)
            c2.lay.addLayout(row)
            self.layers[key] = (d, st)
        c2.lay.addStretch()
        c2.lay.addWidget(btn("Gérer les protections", slot=lambda: app.go("protection")))
        grid.addWidget(c2, 0, 1)

        c3 = Card()
        h = QHBoxLayout(); h.addWidget(icon_label("box", C["warn"], 22)); h.addWidget(label("Détections", "Section")); h.addStretch()
        c3.lay.addLayout(h)
        self.d_threats = label("0", "StatValue")
        c3.lay.addWidget(label("Menaces neutralisées", muted=True)); c3.lay.addWidget(self.d_threats)
        self.d_quar = label("", wrap=True)
        c3.lay.addWidget(self.d_quar)
        c3.lay.addStretch()
        c3.lay.addWidget(btn("Historique et quarantaine", slot=lambda: app.go("history")))
        grid.addWidget(c3, 0, 2)
        for i in range(3):
            grid.setColumnStretch(i, 1)
        self.body.addLayout(grid)

        # ---------- statistiques ----------
        stats = QHBoxLayout(); stats.setSpacing(16)
        self.s_scanned = StatCard("cpu", "Éléments analysés", color=C["info"])
        self.s_sigs = StatCard("shield", "Signatures", color=C["accent"])
        self.s_audit = StatCard("check", "Score de sécurité", "—", color=C["ok"])
        self.s_devices = StatCard("phone", "Appareils connectés", "0", color=C["warn"])
        for w in (self.s_scanned, self.s_sigs, self.s_audit, self.s_devices):
            stats.addWidget(w)
        self.body.addLayout(stats)

        # ---------- moteurs + activité ----------
        bottom = QHBoxLayout(); bottom.setSpacing(16)
        eng = Card()
        eng.lay.addWidget(label("Moteurs de détection", "Section"))
        self.e = {k: EngineRow(i, n) for k, i, n in (
            ("sig", "shield", "Signatures SHA-256"), ("yara", "list", "Règles YARA"),
            ("clam", "cpu", "ClamAV"), ("heur", "zap", "Analyse heuristique"), ("vt", "eye", "VirusTotal"))}
        for w in self.e.values():
            eng.lay.addWidget(w)
        eng.lay.addStretch()
        bottom.addWidget(eng, 1)
        act = Card()
        h = QHBoxLayout(); h.addWidget(label("Activité récente", "Section")); h.addStretch()
        h.addWidget(btn("Tout voir", slot=lambda: app.go("history")))
        act.lay.addLayout(h)
        self.activity = QListWidget(); self.activity.setMinimumHeight(190)
        self.activity.setStyleSheet("QListWidget{background:transparent;border:none}")
        act.lay.addWidget(self.activity)
        bottom.addWidget(act, 1)
        self.body.addLayout(bottom)
        self.refresh()

    def _fix(self):
        if not self.app.settings["realtime"]:
            self.app.set_realtime(True)
        else:
            self.app.go("history")

    def add_activity(self, text, kind="info"):
        col = {"bad": C["bad"], "warn": C["warn"], "ok": C["ok"]}.get(kind, C["info"])
        it = QListWidgetItem(icon({"bad": "alert", "warn": "alert", "ok": "check"}.get(kind, "pulse"), col, 16),
                             f"{datetime.now():%H:%M}   {text}")
        self.activity.insertItem(0, it)
        while self.activity.count() > 60:
            self.activity.takeItem(self.activity.count() - 1)

    def refresh(self):
        a, s = self.app, self.app.settings
        st = s["stats"]
        rt = a.rtp.running if a.rtp else False
        pending = a.pending_threats
        if not s["realtime"] or not rt:
            state, title, sub = "off", "Protection désactivée", "Votre ordinateur n'est pas surveillé en temps réel. Activez la protection."
        elif pending:
            state, title, sub = "bad", f"{pending} menace(s) à traiter", "Des menaces ont été détectées lors de la dernière analyse."
        elif not st["last_scan"] or datetime.now() - datetime.fromisoformat(st["last_scan"]) > timedelta(days=14):
            state, title, sub = "warn", "Analyse recommandée", "Aucune analyse depuis plus de 14 jours. La protection en temps réel est active."
        else:
            state, title, sub = "ok", "Votre ordinateur est protégé", "La protection en temps réel est active et aucune menace n'est en attente."
        self.shield.setState(state)
        ps = s["pcscan"]
        if ps.get("last") and state != "off":
            sub += f"  Dernière analyse du PC : {fmt_date(ps['last']).lower()}, {ps['problems']} problème(s) trouvé(s)."
        elif not ps.get("last"):
            sub += "  Lancez « Analyser mon PC » pour un bilan complet."
        self.h_title.setText(title)
        self.h_sub.setText(sub)
        self.hero.setObjectName("HeroBad" if state == "bad" else "Hero")
        self.hero.style().unpolish(self.hero); self.hero.style().polish(self.hero)
        self.fix_btn.setVisible(state in ("off", "bad"))
        self.fix_btn.setText("Activer la protection" if state == "off" else "Traiter les menaces")
        self.master.setChecked(s["realtime"])

        self.last_scan.setText(f"{fmt_date(st['last_scan'])}" + (f" · analyse {st['last_scan_type']}" if st["last_scan_type"] else ""))
        self.next_scan.setText(next_scheduled(s))
        for key, (dot, lab) in self.layers.items():
            on = bool(s[key]) and (rt or key == "web_protection")
            if key == "web_protection":
                from .. import webprotect
                on = webprotect.is_enabled()
            dot.setColor(C["ok"] if on else C["muted"])
            lab.setText("Activée" if on else "Désactivée")
        self.d_threats.setText(f"{st['threats']:,}".replace(",", " "))
        nq = len(quarantine.list_items())
        self.d_quar.setText(f"{nq} élément(s) en quarantaine")
        self.s_scanned.set(f"{st['scanned']:,}".replace(",", " "))
        e = a.engine.status()
        self.s_sigs.set(f"{e['signatures'] + a.clam_sig_count():,}".replace(",", " "))
        if a.audit_score is not None:
            self.s_audit.set(f"{a.audit_score} %")
        self.s_devices.set(str(len(a.android_devices) + len(a.usb_drives)))
        self.e["sig"].set(f"{e['signatures']} hash", C["ok"] if e["signatures"] else C["muted"])
        self.e["yara"].set(f"{e['yara']} règles", C["ok"] if e["yara"] else C["warn"])
        cs = a.clamav.state if s["clamav"] else "désactivé"
        self.e["clam"].set({"prêt": "Actif", "chargement": "Chargement…"}.get(cs, cs.capitalize()),
                           {"prêt": C["ok"], "chargement": C["warn"]}.get(cs, C["muted"]))
        self.e["heur"].set(f"Sensibilité {s['sensitivity']}", C["ok"])
        self.e["vt"].set("Actif" if e["virustotal"] else "Désactivé", C["ok"] if e["virustotal"] else C["muted"])
