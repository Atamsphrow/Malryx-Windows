"""Réglages persistants (JSON dans %LOCALAPPDATA%\\Malryx)."""
import json
import threading

from .paths import data_dir

DEFAULTS = {
    "network_mode": "wifi",   # wifi = en ligne seulement en Wi-Fi · any = toute connexion · never = jamais
    "metered_saver": True,    # connexion limitée : pas de gros téléchargements
    "offline": True,          # état courant (calculé par network.NetworkMonitor, ne pas modifier à la main)
    "metered": False,         # état courant
    "realtime": True,
    "ransomware": True,
    "exec_guard": True,
    "behavior_guard": True,
    "web_protection": False,
    "startup_guard": True,
    "explorer_menu": False,
    "schedule": {"enabled": True, "freq": "hebdomadaire", "day": 6, "time": "12:30", "type": "rapide", "last": None},
    "update_auto": True,
    "mirror_repo": "Atamsphrow/Malryx-Windows",   # miroir de signatures (GitHub Releases, tag « signatures »)
    "sleep_auto": False,
    "sleep_minutes": 15,
    "sleep_whitelist": [],
    "camera_monitor": True,
    "camera_allowed": [],
    "shred_passes": 1,
    "traces_cookies": False,
    "pcscan": {"last": None, "problems": 0},
    "auto_quarantine": True,
    "usb_monitor": True,
    "android_monitor": True,
    "usb_autoscan": True,
    "clamav": True,
    "use_vt": False,          # VirusTotal (en ligne) : ignoré en mode hors ligne
    "vt_key": "",
    "sensitivity": "normal",  # faible / normal / élevée
    "extra_dirs": [],
    "exclusions": [],
    "start_with_windows": False,
    "minimize_to_tray": True,
    "notifications": True,
    "stats": {"scanned": 0, "threats": 0, "last_scan": None, "last_scan_type": None, "last_update": None},
}
THRESHOLDS = {"faible": 60, "normal": 40, "élevée": 25}


class Settings:
    def __init__(self):
        self.path = data_dir("settings.json")
        self._lock = threading.Lock()
        self.data = json.loads(json.dumps(DEFAULTS))
        if self.path.exists():
            try:
                saved = json.loads(self.path.read_text(encoding="utf-8"))
                for k, v in saved.items():
                    if k in ("stats", "schedule", "pcscan") and isinstance(v, dict):
                        self.data[k].update(v)
                    else:
                        self.data[k] = v
            except (ValueError, OSError):
                pass

    def __getitem__(self, k):
        return self.data[k]

    def __setitem__(self, k, v):
        self.data[k] = v
        self.save()

    def get(self, k, default=None):
        return self.data.get(k, default)

    def bump(self, key, n=1):
        with self._lock:
            self.data["stats"][key] = self.data["stats"].get(key, 0) + n
        self.save()

    def save(self):
        with self._lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self.path)

    @property
    def threshold(self):
        return THRESHOLDS.get(self.data["sensitivity"], 40)
