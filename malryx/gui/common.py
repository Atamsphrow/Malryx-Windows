"""Base des pages + boîtes de dialogue partagées."""
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QDialog, QHBoxLayout, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget,
                               QPlainTextEdit, QMessageBox)

from .theme import C, VERDICT_COLORS, icon
from .widgets import icon_label, label


class Page(QWidget):
    def __init__(self, app, title, sub="", scroll=True):
        super().__init__()
        self.app = app
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        inner = QWidget()
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(30, 24, 30, 24)
        lay.setSpacing(16)
        head = QHBoxLayout()
        tv = QVBoxLayout(); tv.setSpacing(2)
        tv.addWidget(label(title, "PageTitle"))
        if sub:
            tv.addWidget(label(sub, "PageSub"))
        head.addLayout(tv, 1)
        self.head_actions = QHBoxLayout()
        head.addLayout(self.head_actions)
        lay.addLayout(head)
        self.body = QVBoxLayout()
        self.body.setSpacing(16)
        lay.addLayout(self.body, 1)
        if scroll:
            sa = QScrollArea(); sa.setWidgetResizable(True); sa.setWidget(inner)
            sa.setStyleSheet("QScrollArea{background:transparent} QScrollArea > QWidget > QWidget{background:transparent}")
            outer.addWidget(sa)
        else:
            outer.addWidget(inner)

    def on_show(self):
        pass


def btn(text, icon_name=None, obj=None, slot=None, color=None):
    b = QPushButton(text)
    if icon_name:
        b.setIcon(icon(icon_name, color or ("white" if obj == "Primary" else C["text"])))
    if obj:
        b.setObjectName(obj)
    if slot:
        b.clicked.connect(slot)
    b.setCursor(Qt.PointingHandCursor)
    return b


def fmt_date(iso):
    if not iso:
        return "Jamais"
    try:
        d = datetime.fromisoformat(iso)
    except ValueError:
        return iso
    delta = datetime.now() - d
    if delta.days == 0:
        return f"Aujourd'hui à {d:%H:%M}"
    if delta.days == 1:
        return f"Hier à {d:%H:%M}"
    return f"{d:%d/%m/%Y à %H:%M}"


def confirm(parent, title, text, ok="Confirmer", danger=False):
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setText(text)
    box.setIcon(QMessageBox.Warning if danger else QMessageBox.Question)
    yes = box.addButton(ok, QMessageBox.AcceptRole)
    box.addButton("Annuler", QMessageBox.RejectRole)
    box.exec()
    return box.clickedButton() is yes


def info(parent, title, text):
    QMessageBox.information(parent, title, text)


class DetailDialog(QDialog):
    """Fiche détaillée d'une détection."""
    def __init__(self, parent, r, actions=()):
        super().__init__(parent)
        self.setWindowTitle("Détails de la détection")
        self.setMinimumWidth(620)
        self.choice = None
        v = QVBoxLayout(self)
        v.setContentsMargins(22, 20, 22, 20)
        h = QHBoxLayout()
        col = VERDICT_COLORS.get(r.get("verdict"), C["warn"])
        h.addWidget(icon_label("alert", col, 34))
        tv = QVBoxLayout()
        t = label(r.get("threat") or r.get("verdict", ""), "Section"); t.setStyleSheet(f"color:{col};font-size:14pt")
        tv.addWidget(t)
        tv.addWidget(label(r.get("verdict", ""), muted=True))
        h.addLayout(tv, 1)
        v.addLayout(h)
        for k, val in (("Élément", r.get("package") or r.get("path")), ("SHA-256", r.get("sha256") or "—"),
                       ("Taille", f"{r['size'] / 1e6:.2f} Mo" if r.get("size") else "—"),
                       ("Détecté le", fmt_date(r.get("time") or r.get("date")))):
            row = QHBoxLayout()
            kl = label(k, muted=True); kl.setFixedWidth(90)
            vl = QLabel(str(val)); vl.setWordWrap(True); vl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            row.addWidget(kl); row.addWidget(vl, 1)
            v.addLayout(row)
        v.addWidget(label("Pourquoi Malryx l'a signalé", "Section"))
        reasons = QPlainTextEdit("\n".join("• " + x for x in r.get("reasons", [])))
        reasons.setReadOnly(True); reasons.setMaximumHeight(150)
        v.addWidget(reasons)
        bar = QHBoxLayout()
        if r.get("sha256"):
            bar.addWidget(btn("Copier le hash", slot=lambda: QGuiApplication.clipboard().setText(r["sha256"])))
            bar.addWidget(btn("Voir sur VirusTotal", "eye", slot=lambda: __import__("webbrowser").open(
                f"https://www.virustotal.com/gui/file/{r['sha256']}")))
        bar.addStretch()
        for text, key, obj in actions:
            bar.addWidget(btn(text, obj=obj, slot=lambda _=False, k=key: self._pick(k)))
        bar.addWidget(btn("Fermer", slot=self.reject))
        v.addLayout(bar)

    def _pick(self, k):
        self.choice = k
        self.accept()


class RansomwareDialog(QDialog):
    def __init__(self, parent, data):
        super().__init__(parent)
        self.setWindowTitle("Malryx – Attaque de ransomware bloquée")
        self.setWindowFlag(Qt.WindowStaysOnTopHint)
        self.setMinimumWidth(560)
        self.choice = None
        v = QVBoxLayout(self)
        v.setContentsMargins(24, 22, 24, 22)
        h = QHBoxLayout()
        h.addWidget(icon_label("shield-off", C["bad"], 44))
        tv = QVBoxLayout()
        t = label("Activité de ransomware détectée", "HeroTitle"); t.setStyleSheet(f"color:{C['bad']};font-size:16pt")
        tv.addWidget(t)
        tv.addWidget(label(data["reason"], muted=True, wrap=True))
        h.addLayout(tv, 1)
        v.addLayout(h)
        sus = data.get("suspended") or []
        if sus:
            p = sus[0]
            v.addWidget(label(f"Le programme <b>{p['name']}</b> (PID {p['pid']}) a été <b>suspendu</b> : "
                              f"il a écrit {p['written_mb']} Mo en une seconde.<br><span style='color:{C['muted']}'>{p['exe']}</span>",
                              wrap=True))
        else:
            v.addWidget(label("Aucun processus n'a pu être identifié. Fermez les programmes inconnus et lancez une analyse.", wrap=True))
        bar = QHBoxLayout(); bar.addStretch()
        if sus:
            bar.addWidget(btn("C'est un programme de confiance", slot=lambda: self._pick("resume")))
            bar.addWidget(btn("Arrêter et mettre en quarantaine", "trash", "Danger", slot=lambda: self._pick("kill")))
        else:
            bar.addWidget(btn("Lancer une analyse", "search", "Primary", slot=lambda: self._pick("scan")))
        v.addLayout(bar)

    def _pick(self, k):
        self.choice = k
        self.accept()
