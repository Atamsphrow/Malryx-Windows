"""Composants visuels : bouclier animé, interrupteur, cartes, tableaux."""
from PySide6.QtCore import Property, QEasingCurve, QPointF, QPropertyAnimation, QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen, QRadialGradient
from PySide6.QtWidgets import (QAbstractItemView, QFrame, QHBoxLayout, QHeaderView, QLabel, QSizePolicy,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from .theme import C, VERDICT_COLORS, pixmap


class Card(QFrame):
    def __init__(self, parent=None, pad=18, spacing=10):
        super().__init__(parent)
        self.setObjectName("Card")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(pad, pad, pad, pad)
        self.lay.setSpacing(spacing)


def label(text="", obj=None, muted=False, wrap=False):
    l = QLabel(text)
    if obj:
        l.setObjectName(obj)
    if muted:
        l.setProperty("muted", True)
    if wrap:
        l.setWordWrap(True)
    return l


def icon_label(name, color=C["text"], size=20):
    l = QLabel()
    l.setPixmap(pixmap(name, color, size))
    l.setFixedSize(size + 4, size + 4)
    return l


class Toggle(QWidget):
    """Interrupteur animé façon Windows 11."""
    toggled = Signal(bool)

    def __init__(self, checked=False, parent=None):
        super().__init__(parent)
        self.setFixedSize(46, 26)
        self.setCursor(Qt.PointingHandCursor)
        self._checked = checked
        self._pos = 1.0 if checked else 0.0
        self.anim = QPropertyAnimation(self, b"pos", self)
        self.anim.setDuration(160)
        self.anim.setEasingCurve(QEasingCurve.OutCubic)

    def isChecked(self):
        return self._checked

    def setChecked(self, v, emit=False):
        v = bool(v)
        if v == self._checked:
            return
        self._checked = v
        self.anim.stop()
        self.anim.setStartValue(self._pos)
        self.anim.setEndValue(1.0 if v else 0.0)
        self.anim.start()
        if emit:
            self.toggled.emit(v)

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.LeftButton and self.isEnabled():
            self.setChecked(not self._checked, emit=True)

    def _get(self):
        return self._pos

    def _set(self, v):
        self._pos = v
        self.update()

    pos = Property(float, _get, _set)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        on = QColor(C["accent"]); off = QColor(C["border"])
        bg = QColor(int(off.red() + (on.red() - off.red()) * self._pos),
                    int(off.green() + (on.green() - off.green()) * self._pos),
                    int(off.blue() + (on.blue() - off.blue()) * self._pos))
        if not self.isEnabled():
            bg.setAlpha(90)
        p.setPen(Qt.NoPen); p.setBrush(bg)
        p.drawRoundedRect(QRectF(0, 0, 46, 26), 13, 13)
        p.setBrush(QColor("white"))
        p.drawEllipse(QRectF(3 + self._pos * 20, 3, 20, 20))


class SettingRow(QWidget):
    """Ligne : titre + description à gauche, contrôle à droite."""
    def __init__(self, title, desc, control, parent=None):
        super().__init__(parent)
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 6, 0, 6)
        v = QVBoxLayout(); v.setSpacing(2)
        t = QLabel(title); t.setStyleSheet("font-weight:600")
        v.addWidget(t)
        if desc:
            v.addWidget(label(desc, muted=True, wrap=True))
        h.addLayout(v, 1)
        h.addWidget(control, 0, Qt.AlignVCenter)
        self.control = control


class Shield(QWidget):
    """Grand bouclier lumineux dont la couleur reflète l'état de protection."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(170, 170)
        self.state = "ok"
        self._pulse = 0.0
        self.anim = QPropertyAnimation(self, b"pulse", self)
        self.anim.setDuration(2600)
        self.anim.setStartValue(0.0); self.anim.setKeyValueAt(0.5, 1.0); self.anim.setEndValue(0.0)
        self.anim.setLoopCount(-1)
        self.anim.setEasingCurve(QEasingCurve.InOutSine)
        self.anim.start()

    def setState(self, s):
        self.state = s
        self.update()

    def _gp(self):
        return self._pulse

    def _sp(self, v):
        self._pulse = v
        self.update()

    pulse = Property(float, _gp, _sp)

    def paintEvent(self, _):
        col = QColor({"ok": C["ok"], "warn": C["warn"], "bad": C["bad"], "off": C["muted"]}[self.state])
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        s = min(w, h)
        cx, cy = w / 2, h / 2
        glow = QRadialGradient(QPointF(cx, cy), s / 2)
        g = QColor(col); g.setAlpha(int(55 + 45 * self._pulse))
        glow.setColorAt(0, g); g2 = QColor(col); g2.setAlpha(0); glow.setColorAt(1, g2)
        p.setPen(Qt.NoPen); p.setBrush(QBrush(glow))
        p.drawEllipse(QPointF(cx, cy), s / 2, s / 2)

        k = s * 0.30
        path = QPainterPath()
        path.moveTo(cx, cy - k * 1.15)
        path.lineTo(cx + k, cy - k * 0.72)
        path.lineTo(cx + k, cy - k * 0.05)
        path.cubicTo(cx + k, cy + k * 0.7, cx + k * 0.45, cy + k * 1.05, cx, cy + k * 1.25)
        path.cubicTo(cx - k * 0.45, cy + k * 1.05, cx - k, cy + k * 0.7, cx - k, cy - k * 0.05)
        path.lineTo(cx - k, cy - k * 0.72)
        path.closeSubpath()
        fill = QColor(col); fill.setAlpha(235)
        p.setBrush(fill)
        p.setPen(QPen(QColor(255, 255, 255, 60), 2))
        p.drawPath(path)

        pen = QPen(QColor("white"), s * 0.045, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
        p.setPen(pen); p.setBrush(Qt.NoBrush)
        if self.state == "ok":
            m = QPainterPath(); m.moveTo(cx - k * 0.42, cy + k * 0.05)
            m.lineTo(cx - k * 0.1, cy + k * 0.38); m.lineTo(cx + k * 0.45, cy - k * 0.25)
            p.drawPath(m)
        elif self.state == "off":
            p.drawLine(QPointF(cx - k * 0.35, cy - k * 0.25), QPointF(cx + k * 0.35, cy + k * 0.45))
            p.drawLine(QPointF(cx + k * 0.35, cy - k * 0.25), QPointF(cx - k * 0.35, cy + k * 0.45))
        else:
            p.drawLine(QPointF(cx, cy - k * 0.4), QPointF(cx, cy + k * 0.2))
            p.drawPoint(QPointF(cx, cy + k * 0.55))


class StatCard(Card):
    def __init__(self, icon, title, value="0", color=C["accent"]):
        super().__init__(pad=16, spacing=4)
        top = QHBoxLayout()
        top.addWidget(icon_label(icon, color, 18))
        top.addWidget(label(title, muted=True))
        top.addStretch()
        self.lay.addLayout(top)
        self.value = label(value, "StatValue")
        self.lay.addWidget(self.value)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set(self, v):
        self.value.setText(str(v))


class StatusDot(QWidget):
    def __init__(self, color=C["muted"], parent=None):
        super().__init__(parent)
        self.color = color
        self.setFixedSize(12, 12)

    def setColor(self, c):
        self.color = c
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        g = QColor(self.color); g.setAlpha(60)
        p.setBrush(g); p.drawEllipse(0, 0, 12, 12)
        p.setBrush(QColor(self.color)); p.drawEllipse(3, 3, 6, 6)


class EngineRow(QWidget):
    def __init__(self, icon, name):
        super().__init__()
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 4, 0, 4)
        h.addWidget(icon_label(icon, C["muted"], 18))
        n = QLabel(name); n.setStyleSheet("font-weight:600")
        h.addWidget(n)
        h.addStretch()
        self.status = label("", muted=True)
        h.addWidget(self.status)
        self.dot = StatusDot()
        h.addWidget(self.dot)

    def set(self, text, color):
        self.status.setText(text)
        self.dot.setColor(color)


class Table(QTableWidget):
    def __init__(self, headers, stretch_col=None, parent=None):
        super().__init__(0, len(headers), parent)
        self.setHorizontalHeaderLabels(headers)
        self.verticalHeader().hide()
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.verticalHeader().setDefaultSectionSize(36)
        hh = self.horizontalHeader()
        hh.setHighlightSections(False)
        hh.setSectionResizeMode(QHeaderView.ResizeToContents)
        if stretch_col is not None:
            hh.setSectionResizeMode(stretch_col, QHeaderView.Stretch)
        hh.setStretchLastSection(stretch_col is None)
        self.setSortingEnabled(False)

    def add_row(self, values, data=None, verdict_col=None):
        r = self.rowCount()
        self.insertRow(r)
        for c, v in enumerate(values):
            it = QTableWidgetItem(str(v) if v is not None else "")
            it.setToolTip(str(v) if v is not None else "")
            if c == verdict_col:
                col = VERDICT_COLORS.get(str(v), C["text"])
                it.setForeground(QColor(col))
                f = QFont(); f.setBold(True); it.setFont(f)
            if c == 0 and data is not None:
                it.setData(Qt.UserRole, data)
            self.setItem(r, c, it)
        return r

    def selected_data(self):
        rows = sorted({i.row() for i in self.selectedItems()})
        return [(r, self.item(r, 0).data(Qt.UserRole)) for r in rows if self.item(r, 0)]

    def all_data(self):
        return [(r, self.item(r, 0).data(Qt.UserRole)) for r in range(self.rowCount()) if self.item(r, 0)]


class EmptyState(QWidget):
    def __init__(self, icon, title, text):
        super().__init__()
        v = QVBoxLayout(self)
        v.setAlignment(Qt.AlignCenter)
        il = icon_label(icon, C["muted"], 44)
        v.addWidget(il, 0, Qt.AlignHCenter)
        t = label(title, "Section"); t.setAlignment(Qt.AlignCenter)
        v.addWidget(t)
        d = label(text, muted=True, wrap=True); d.setAlignment(Qt.AlignCenter); d.setMaximumWidth(460)
        v.addWidget(d, 0, Qt.AlignHCenter)
