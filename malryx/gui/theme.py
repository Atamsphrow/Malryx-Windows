"""Thème sombre, couleurs et icônes vectorielles (SVG dessinés à la main, aucune dépendance)."""
from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

C = {
    "bg": "#0d1017", "side": "#11151d", "card": "#171c26", "card2": "#1d2330", "border": "#252c3a",
    "text": "#e7eaf0", "muted": "#8a93a6", "accent": "#4f8cff", "accent2": "#3a6fd8",
    "ok": "#22c55e", "warn": "#f59e0b", "bad": "#ef4444", "info": "#38bdf8",
}
VERDICT_COLORS = {"MALVEILLANT": C["bad"], "SUSPECT": C["warn"], "OK": C["ok"], "ERREUR": C["muted"]}

_P = {
    "shield": '<path d="M12 3l8 3v6c0 5-3.4 8.3-8 9.5C7.4 20.3 4 17 4 12V6z"/>',
    "shield-check": '<path d="M12 3l8 3v6c0 5-3.4 8.3-8 9.5C7.4 20.3 4 17 4 12V6z"/><path d="M8.5 12.2l2.4 2.4 4.6-4.8"/>',
    "shield-off": '<path d="M12 3l8 3v6c0 5-3.4 8.3-8 9.5C7.4 20.3 4 17 4 12V6z"/><path d="M3 3l18 18"/>',
    "home": '<path d="M3 11l9-7 9 7"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="M16.5 16.5L21 21"/>',
    "phone": '<rect x="7" y="2.5" width="10" height="19" rx="2.2"/><path d="M11 18h2"/>',
    "usb": '<path d="M12 2v14"/><path d="M8 6l4-4 4 4"/><circle cx="12" cy="19" r="2.5"/><path d="M12 12l-5-2V7"/><path d="M12 14l5-2V9"/><rect x="5.5" y="5" width="3" height="2"/><circle cx="17" cy="8" r="1.2"/>',
    "pulse": '<path d="M3 12h4l3-7 4 14 3-7h4"/>',
    "box": '<rect x="3" y="4" width="18" height="5" rx="1"/><path d="M5 9v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V9"/><path d="M10 13h4"/>',
    "list": '<path d="M8 6h13M8 12h13M8 18h13"/><circle cx="4" cy="6" r="1"/><circle cx="4" cy="12" r="1"/><circle cx="4" cy="18" r="1"/>',
    "sliders": '<path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>',
    "folder": '<path d="M3 6.5A1.5 1.5 0 0 1 4.5 5H9l2 2h8.5A1.5 1.5 0 0 1 21 8.5v9A1.5 1.5 0 0 1 19.5 19h-15A1.5 1.5 0 0 1 3 17.5z"/>',
    "play": '<path d="M7 4.5v15l12-7.5z"/>',
    "pause": '<path d="M8 5v14M16 5v14"/>',
    "stop": '<rect x="6" y="6" width="12" height="12" rx="1.5"/>',
    "trash": '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
    "restore": '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/>',
    "refresh": '<path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/>',
    "zap": '<path d="M13 2L4 14h7l-1 8 9-12h-7z"/>',
    "disk": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 15h18"/><circle cx="17" cy="17.5" r=".8"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "minus": '<path d="M5 12h14"/>',
    "alert": '<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18v.5"/>',
    "check": '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
    "cpu": '<rect x="6" y="6" width="12" height="12" rx="1.5"/><rect x="9.5" y="9.5" width="5" height="5"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
    "download": '<path d="M12 3v12M7 10l5 5 5-5M4 20h16"/>',
    "x": '<path d="M6 6l12 12M18 6L6 18"/>',
    "eye": '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
}

_cache = {}


def svg(name, color=C["text"], fill="none"):
    body = _P.get(name, _P["shield"])
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="{fill}" stroke="{color}" '
            f'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{body}</svg>')


def pixmap(name, color=C["text"], size=20, fill="none"):
    key = (name, color, size, fill)
    if key not in _cache:
        pm = QPixmap(size * 2, size * 2)
        pm.fill(Qt.transparent)
        r = QSvgRenderer(QByteArray(svg(name, color, fill).encode()))
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing)
        r.render(p, QRectF(0, 0, size * 2, size * 2))
        p.end()
        pm.setDevicePixelRatio(2)
        _cache[key] = pm
    return _cache[key]


def icon(name, color=C["text"], size=20):
    ic = QIcon()
    ic.addPixmap(pixmap(name, color, size), QIcon.Normal)
    ic.addPixmap(pixmap(name, C["muted"], size), QIcon.Disabled)
    return ic


QSS = f"""
* {{ font-family: "Segoe UI Variable", "Segoe UI", "Inter", "Noto Sans", sans-serif; font-size: 10pt; color: {C['text']}; }}
QMainWindow, #Root {{ background: {C['bg']}; }}
#Sidebar {{ background: {C['side']}; border-right: 1px solid {C['border']}; }}
#Brand {{ font-size: 15pt; font-weight: 700; }}
#BrandSub {{ color: {C['muted']}; font-size: 8.5pt; }}
QPushButton#Nav {{ text-align: left; padding: 10px 14px; border: none; border-radius: 9px;
    background: transparent; color: {C['muted']}; font-weight: 600; }}
QPushButton#Nav:hover {{ background: {C['card']}; color: {C['text']}; }}
QPushButton#Nav:checked {{ background: {C['card2']}; color: {C['text']}; border-left: 3px solid {C['accent']}; }}
#PageTitle {{ font-size: 19pt; font-weight: 700; }}
#PageSub {{ color: {C['muted']}; }}
#Card {{ background: {C['card']}; border: 1px solid {C['border']}; border-radius: 14px; }}
#Muted, QLabel[muted="true"] {{ color: {C['muted']}; }}
#StatValue {{ font-size: 20pt; font-weight: 700; }}
#HeroTitle {{ font-size: 21pt; font-weight: 700; }}
#Section {{ font-size: 11.5pt; font-weight: 700; }}
QPushButton {{ background: {C['card2']}; border: 1px solid {C['border']}; border-radius: 9px; padding: 8px 14px; font-weight: 600; }}
QPushButton:hover {{ border-color: {C['accent']}; }}
QPushButton:pressed {{ background: {C['border']}; }}
QPushButton:disabled {{ color: {C['muted']}; background: {C['card']}; }}
QPushButton#Primary {{ background: {C['accent']}; border: none; color: white; }}
QPushButton#Primary:hover {{ background: {C['accent2']}; }}
QPushButton#Small {{ padding: 3px 12px; font-size: 9pt; margin: 3px; }}
QPushButton#Danger {{ background: transparent; border: 1px solid {C['bad']}; color: {C['bad']}; }}
QPushButton#Danger:hover {{ background: {C['bad']}; color: white; }}
QPushButton#Big {{ padding: 16px; font-size: 10.5pt; text-align: left; border-radius: 12px; background: {C['card']}; }}
QPushButton#Big:hover {{ background: {C['card2']}; }}
QLineEdit, QComboBox, QPlainTextEdit, QListWidget {{ background: {C['bg']}; border: 1px solid {C['border']}; border-radius: 8px; padding: 6px 8px; selection-background-color: {C['accent']}; }}
QLineEdit:focus, QComboBox:focus {{ border-color: {C['accent']}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{ background: {C['card2']}; border: 1px solid {C['border']}; selection-background-color: {C['accent']}; }}
QPlainTextEdit {{ font-family: "Cascadia Mono", "Consolas", "DejaVu Sans Mono", monospace; font-size: 9pt; }}
QTableWidget {{ background: {C['card']}; border: 1px solid {C['border']}; border-radius: 12px; gridline-color: transparent;
    alternate-background-color: {C['card2']}; selection-background-color: #2b3a5c; }}
QTableWidget::item {{ padding: 6px; border: none; }}
QHeaderView::section {{ background: {C['card']}; color: {C['muted']}; border: none; border-bottom: 1px solid {C['border']};
    padding: 8px 6px; font-weight: 700; font-size: 8.5pt; text-transform: uppercase; }}
QTableCornerButton::section {{ background: {C['card']}; border: none; }}
QListWidget::item {{ padding: 8px; border-radius: 8px; }}
QListWidget::item:selected {{ background: #2b3a5c; }}
QProgressBar {{ background: {C['bg']}; border: none; border-radius: 5px; height: 10px; text-align: center; font-size: 0pt; }}
QProgressBar::chunk {{ border-radius: 5px; background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {C['accent']}, stop:1 {C['info']}); }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {C['border']}; border-radius: 4px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {C['muted']}; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {C['border']}; border-radius: 4px; min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{ width: 18px; height: 18px; border-radius: 5px; border: 1px solid {C['border']}; background: {C['bg']}; }}
QCheckBox::indicator:checked {{ background: {C['accent']}; border-color: {C['accent']}; }}
QToolTip {{ background: {C['card2']}; color: {C['text']}; border: 1px solid {C['border']}; padding: 6px; border-radius: 6px; }}
QMenu {{ background: {C['card2']}; border: 1px solid {C['border']}; padding: 6px; border-radius: 8px; }}
QMenu::item {{ padding: 7px 22px; border-radius: 6px; }}
QMenu::item:selected {{ background: {C['accent']}; }}
QScrollArea {{ border: none; background: transparent; }}
QMessageBox {{ background: {C['card']}; }}
QDialog {{ background: {C['card']}; }}
QTabWidget::pane {{ border: none; top: -1px; }}
QTabBar::tab {{ background: transparent; color: {C['muted']}; padding: 9px 16px; margin-right: 4px; border: none;
    border-bottom: 2px solid transparent; font-weight: 600; }}
QTabBar::tab:hover {{ color: {C['text']}; }}
QTabBar::tab:selected {{ color: {C['text']}; border-bottom: 2px solid {C['accent']}; }}
#Hero {{ border-radius: 18px; border: 1px solid {C['border']};
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #18213a, stop:0.6 #151b2b, stop:1 #12161f); }}
#HeroBad {{ border-radius: 18px; border: 1px solid #5a2330;
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #3a1620, stop:1 #161a23); }}
#Chip {{ background: {C['card2']}; border-radius: 10px; padding: 3px 10px; font-size: 8.5pt; font-weight: 600; }}
#Banner {{ border-radius: 12px; padding: 4px; }}
QTimeEdit, QSpinBox {{ background: {C['bg']}; border: 1px solid {C['border']}; border-radius: 8px; padding: 5px 8px; }}
"""
