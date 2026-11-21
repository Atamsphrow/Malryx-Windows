"""Politique réseau : Malryx est hors ligne par défaut et ne passe en ligne que sur une connexion autorisée.

Modes (réglage « network_mode ») :
  "wifi"   : en ligne uniquement quand un Wi-Fi est connecté ET qu'Internet répond (par défaut)
  "any"    : en ligne sur toute connexion (Wi-Fi, Ethernet…)
  "never"  : 100 % hors ligne, jamais aucune connexion (mises à jour par pack USB uniquement)

Connexion limitée (partage de connexion du téléphone, forfait mobile) : les gros téléchargements sont évités ;
seules les mises à jour incrémentales (quelques centaines de Ko) sont autorisées.
"""
import socket
import subprocess
import threading
import time
import urllib.request

from . import netfetch
from .paths import IS_WIN

NO_WINDOW = 0x08000000 if IS_WIN else 0


# ---------------------------------------------------------------------------- Wi-Fi (API WLAN native)
def wifi_status():
    """Renvoie (connecté, nom du réseau). API WLAN de Windows : indépendante de la langue du système."""
    if IS_WIN:
        try:
            return _wlan_status()
        except Exception:
            pass
    return _fallback_wifi()


def _wlan_status():
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("d1", wintypes.DWORD), ("d2", wintypes.WORD), ("d3", wintypes.WORD), ("d4", ctypes.c_ubyte * 8)]

    class WLAN_INTERFACE_INFO(ctypes.Structure):
        _fields_ = [("guid", GUID), ("desc", ctypes.c_wchar * 256), ("state", wintypes.DWORD)]

    wlan = ctypes.windll.wlanapi
    handle, ver = wintypes.HANDLE(), wintypes.DWORD()
    if wlan.WlanOpenHandle(2, None, ctypes.byref(ver), ctypes.byref(handle)) != 0:
        return False, None                      # pas de carte / service Wi-Fi
    try:
        plist = ctypes.c_void_p()
        if wlan.WlanEnumInterfaces(handle, None, ctypes.byref(plist)) != 0 or not plist.value:
            return False, None
        try:
            n = ctypes.c_uint32.from_address(plist.value).value
            base = plist.value + 8               # dwNumberOfItems + dwIndex
            for i in range(n):
                info = WLAN_INTERFACE_INFO.from_address(base + i * ctypes.sizeof(WLAN_INTERFACE_INFO))
                if info.state == 1:              # wlan_interface_state_connected
                    ssid = None
                    size, data, op = wintypes.DWORD(), ctypes.c_void_p(), wintypes.DWORD()
                    if wlan.WlanQueryInterface(handle, ctypes.byref(info.guid), 7, None, ctypes.byref(size),
                                               ctypes.byref(data), ctypes.byref(op)) == 0 and data.value:
                        ssid = ctypes.wstring_at(data.value + 8, 256).split("\x00")[0] or None   # strProfileName
                        wlan.WlanFreeMemory(data)
                    return True, ssid
            return False, None
        finally:
            wlan.WlanFreeMemory(plist)
    finally:
        wlan.WlanCloseHandle(handle, None)


def _fallback_wifi():
    try:
        import psutil
        for name, st in psutil.net_if_stats().items():
            low = name.lower()
            if st.isup and any(k in low for k in ("wi-fi", "wifi", "wlan", "wireless", "wl")):
                addrs = psutil.net_if_addrs().get(name, [])
                if any(a.family == socket.AF_INET and not a.address.startswith("169.254.") for a in addrs):
                    return True, name
    except Exception:
        pass
    return False, None


def any_connection():
    try:
        import psutil
        for name, st in psutil.net_if_stats().items():
            if st.isup and not name.lower().startswith(("lo", "loopback")):
                addrs = psutil.net_if_addrs().get(name, [])
                if any(a.family == socket.AF_INET and not a.address.startswith(("127.", "169.254.")) for a in addrs):
                    return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------- coût / accès Internet
def metered():
    """Connexion limitée selon Windows (forfait mobile, partage de connexion, réglage « Connexion limitée »)."""
    if not IS_WIN:
        return False
    ps = ("[void][Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime];"
          "$p=[Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile();"
          "if($p){$c=$p.GetConnectionCost(); [string]$c.NetworkCostType + '|' + [string]$c.Roaming}")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True,
                             text=True, timeout=15, creationflags=NO_WINDOW).stdout.strip()
        cost, _, roaming = out.partition("|")
        return cost in ("Fixed", "Variable") or roaming == "True"
    except Exception:
        return False


def internet_ok():
    """Vérification réelle (connexion TCP directe, puis test HTTP via le proxy système éventuel)."""
    for host in ("1.1.1.1", "8.8.8.8"):
        try:
            socket.create_connection((host, 443), timeout=3).close()
            return True
        except OSError:
            continue
    try:
        with urllib.request.urlopen("http://www.msftconnecttest.com/connecttest.txt", timeout=5) as r:
            return b"Microsoft Connect Test" in r.read(64)
    except Exception:
        return False


# ---------------------------------------------------------------------------- surveillance
class NetworkMonitor:
    """Recalcule l'état toutes les 20 s et bascule le verrou réseau global (netfetch.OFFLINE)."""

    def __init__(self, settings, emit):
        self.settings, self.emit = settings, emit
        self.state = {"online": False, "wifi": False, "ssid": None, "metered": False, "internet": False,
                      "reason": "démarrage"}
        self.stop_evt = threading.Event()
        self.wake = threading.Event()
        self._metered_at = 0
        netfetch.OFFLINE = True
        settings.data["offline"] = True

    def evaluate(self):
        mode = self.settings["network_mode"]
        wifi, ssid = wifi_status()
        st = {"wifi": wifi, "ssid": ssid, "metered": self.state.get("metered", False), "internet": False}
        if mode == "never":
            st.update(online=False, reason="mode 100 % hors ligne")
        elif mode == "wifi" and not wifi:
            st.update(online=False, reason="aucun Wi-Fi connecté")
        elif mode == "any" and not (wifi or any_connection()):
            st.update(online=False, reason="aucune connexion")
        else:
            st["internet"] = internet_ok()
            if not st["internet"]:
                st.update(online=False, reason=f"{'Wi-Fi « ' + ssid + ' »' if ssid else 'connexion'} sans accès Internet")
            else:
                if time.time() - self._metered_at > 300 or not self.state.get("online"):
                    st["metered"] = metered(); self._metered_at = time.time()
                where = f"Wi-Fi « {ssid} »" if wifi and ssid else ("Wi-Fi" if wifi else "réseau filaire")
                st.update(online=True, reason=where + (" (connexion limitée)" if st["metered"] else ""))
        return st

    def apply(self, st):
        changed = st["online"] != self.state.get("online") or st.get("reason") != self.state.get("reason")
        was_online = self.state.get("online")
        self.state = st
        netfetch.OFFLINE = not st["online"]
        self.settings.data["offline"] = not st["online"]
        self.settings.data["metered"] = bool(st.get("metered"))
        if changed:
            self.emit("network", dict(st, went_online=st["online"] and not was_online))

    def _loop(self):
        while not self.stop_evt.is_set():
            try:
                self.apply(self.evaluate())
            except Exception as e:
                self.emit("log", f"Réseau : {e}")
            self.wake.wait(20); self.wake.clear()

    def refresh(self):
        """Réévaluation immédiate (après un changement de réglage)."""
        self.wake.set()

    def start(self):
        threading.Thread(target=self._loop, daemon=True, name="network-monitor").start()

    def stop(self):
        self.stop_evt.set(); self.wake.set()
        netfetch.OFFLINE = True
