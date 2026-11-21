"""Scan d'appareils Android connectés en USB via ADB (débogage USB requis)."""
import re
import subprocess
import tempfile
from pathlib import Path

from .engine import MALWARE, SUSPECT
from .paths import IS_WIN, find_tool

NO_WINDOW = 0x08000000 if IS_WIN else 0

# Permissions souvent abusées par les malwares Android (banking trojans, stalkerware, spyware)
RISKY_PERMS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 25,
    "android.permission.BIND_DEVICE_ADMIN": 20,
    "android.permission.SEND_SMS": 15,
    "android.permission.RECEIVE_SMS": 10,
    "android.permission.READ_SMS": 15,
    "android.permission.REQUEST_INSTALL_PACKAGES": 10,
    "android.permission.SYSTEM_ALERT_WINDOW": 10,
    "android.permission.READ_CALL_LOG": 10,
    "android.permission.RECORD_AUDIO": 5,
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": 10,
    "android.permission.QUERY_ALL_PACKAGES": 5,
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": 5,
}
TRUSTED_INSTALLERS = {"com.android.vending", "com.google.android.packageinstaller.vending",
                      "com.sec.android.app.samsungapps", "com.huawei.appmarket", "com.xiaomi.market"}


class Adb:
    def __init__(self, adb=None):
        self.adb = adb or find_tool("adb", "adb")
        if not self.adb:
            raise RuntimeError("ADB n'est pas embarqué dans cette version.")

    def run(self, *args, serial=None, timeout=60):
        cmd = [self.adb] + (["-s", serial] if serial else []) + list(args)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="ignore", creationflags=NO_WINDOW)
        return r.stdout

    def devices(self):
        out = self.run("devices", "-l")
        devs = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                model = next((p.split(":", 1)[1] for p in parts if p.startswith("model:")), "?")
                devs.append({"serial": parts[0], "model": model})
            elif len(parts) >= 2 and parts[1] in ("unauthorized", "offline"):
                devs.append({"serial": parts[0], "model": "?", "state": parts[1]})
        for d in devs:
            d.setdefault("state", "device")
        return devs

    def device_info(self, serial):
        keys = {"ro.product.manufacturer": "fabricant", "ro.product.model": "modele",
                "ro.build.version.release": "android", "ro.build.version.security_patch": "correctif"}
        out = self.run("shell", "getprop", serial=serial, timeout=20)
        info = {}
        for k, label in keys.items():
            m = re.search(r"\[" + re.escape(k) + r"\]: \[(.*?)\]", out)
            info[label] = m.group(1) if m else "?"
        root = self.run("shell", "which", "su", serial=serial, timeout=10).strip()
        info["root"] = bool(root)
        unk = self.run("shell", "settings", "get", "secure", "install_non_market_apps", serial=serial, timeout=10).strip()
        info["sources_inconnues"] = unk == "1"
        return info

    def kill_server(self):
        try:
            self.run("kill-server", timeout=10)
        except Exception:
            pass

    def packages(self, serial, include_system=False):
        flags = ["-f", "-i"] + ([] if include_system else ["-3"])
        out = self.run("shell", "pm", "list", "packages", *flags, serial=serial)
        pkgs = []
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("package:"):
                continue
            line = line[len("package:"):]
            installer = None
            if "  installer=" in line:
                line, installer = line.split("  installer=", 1)
                installer = None if installer.strip() in ("", "null") else installer.strip()
            apk, name = line.rsplit("=", 1)
            pkgs.append({"name": name, "apk": apk, "installer": installer})
        return pkgs

    def permissions(self, serial, pkg):
        out = self.run("shell", "dumpsys", "package", pkg, serial=serial)
        return set(re.findall(r"(android\.permission\.[A-Z_]+)", out))

    def accessibility_services(self, serial):
        out = self.run("shell", "settings", "get", "secure", "enabled_accessibility_services", serial=serial)
        return out.strip()

    def pull(self, serial, remote, local):
        self.run("pull", remote, str(local), serial=serial, timeout=300)
        return Path(local).exists()

    def uninstall(self, serial, pkg):
        return self.run("shell", "pm", "uninstall", "--user", "0", pkg, serial=serial).strip()


def scan_app(adb, engine, serial, pkg, workdir, acc_services=""):
    score, reasons = 0, []
    perms = adb.permissions(serial, pkg["name"])
    risky = [p for p in perms if p in RISKY_PERMS]
    score += sum(RISKY_PERMS[p] for p in risky)
    if risky:
        reasons.append("permissions sensibles : " + ", ".join(p.split(".")[-1] for p in sorted(risky)))
    if pkg["installer"] not in TRUSTED_INSTALLERS:
        score += 15
        reasons.append(f"installée hors store officiel (installer={pkg['installer']})")
    if pkg["name"] in acc_services:
        score += 25
        reasons.append("service d'accessibilité ACTIVÉ (peut lire l'écran et cliquer)")

    local = Path(workdir) / f"{pkg['name']}.apk"
    if adb.pull(serial, pkg["apk"], local):
        res = engine.scan_file(local, extra_score=score, extra_reasons=reasons)
        if res["verdict"] != MALWARE and res["score"] >= max(60, engine.settings.threshold):
            res["verdict"] = SUSPECT; res["threat"] = "Comportement à risque"
        elif res["verdict"] == SUSPECT and res["score"] < 60:
            res["verdict"] = "OK"; res["threat"] = None
        local.unlink(missing_ok=True)
    else:
        res = {"path": pkg["apk"], "sha256": None, "score": score, "reasons": reasons + ["APK non récupérable"],
               "verdict": SUSPECT if score >= 60 else "OK", "threat": None}
    res["package"] = pkg["name"]
    res["device"] = serial
    return res


def scan_device(adb, engine, serial, include_system=False, storage=False, on_result=None, cancel=None):
    results = []
    acc = adb.accessibility_services(serial)
    with tempfile.TemporaryDirectory(prefix="am_android_") as tmp:
        pkgs = adb.packages(serial, include_system)
        for i, pkg in enumerate(pkgs):
            if cancel and cancel():
                break
            r = scan_app(adb, engine, serial, pkg, tmp, acc)
            r["index"], r["total"] = i + 1, len(pkgs)
            results.append(r)
            if on_result:
                on_result(r)
        if storage:
            results += scan_storage(adb, engine, serial, tmp, on_result, cancel)
    return results


def scan_storage(adb, engine, serial, tmp, on_result=None, cancel=None):
    """Récupère les fichiers à risque du stockage partagé (APK, scripts, exécutables) et les analyse."""
    out = adb.run("shell", "find", "/sdcard/Download", "/sdcard/Documents", "/sdcard/Android/media",
                  "-type", "f", "(", "-iname", "*.apk", "-o", "-iname", "*.exe", "-o", "-iname", "*.dex",
                  "-o", "-iname", "*.sh", "-o", "-iname", "*.jar", "-o", "-iname", "*.zip", ")",
                  serial=serial, timeout=120)
    results = []
    for i, remote in enumerate(l.strip() for l in out.splitlines() if l.strip().startswith("/")):
        if cancel and cancel():
            break
        local = Path(tmp) / f"f{i}_{Path(remote).name}"
        if adb.pull(serial, remote, local):
            r = engine.scan_file(local)
            r["path"] = remote; r["device"] = serial
            local.unlink(missing_ok=True)
            results.append(r)
            if on_result:
                on_result(r)
    return results
