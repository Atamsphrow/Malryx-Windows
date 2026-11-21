"""Protection à l'exécution + anti-exploit comportemental.

Deux modes :
- Pilote noyau Malryx chargé (voir driver/) : Windows demande l'avis de Malryx AVANT de créer
  chaque processus ; s'il est malveillant, la création est refusée (STATUS_ACCESS_DENIED).
- Sans pilote : chaque nouveau processus est détecté en ~30 ms, SUSPENDU immédiatement,
  analysé, puis tué (et mis en quarantaine) ou relancé. Les verdicts sont mis en cache :
  un fichier déjà analysé au téléchargement est bloqué instantanément.

Les règles anti-exploit bloquent les chaînes d'attaque classiques : document Office/PDF qui
lance un interpréteur, PowerShell encodé, LOLBins (mshta, regsvr32, certutil…), suppression
des sauvegardes par un ransomware, désactivation de Defender.
"""
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import quarantine
from .engine import MALWARE, SUSPECT
from .paths import IS_WIN

try:
    import psutil
except ImportError:
    psutil = None

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe",
          "visio.exe", "acrord32.exe", "acrobat.exe", "foxitpdfreader.exe", "foxitreader.exe", "wordpad.exe",
          "hwp.exe", "eqnedt32.exe"}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe", "iexplore.exe", "vivaldi.exe"}
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
          "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "msbuild.exe", "installutil.exe",
          "schtasks.exe", "bash.exe", "curl.exe"}
# outils système détournés par les malwares / ransomwares : leur ligne de commande est toujours vérifiée
LOLBINS = {"vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "wevtutil.exe", "netsh.exe", "reg.exe", "sc.exe",
           "net.exe", "net1.exe", "taskkill.exe", "icacls.exe", "takeown.exe", "fsutil.exe", "cipher.exe",
           "bash", "sh", "dash"}
WATCH = SHELLS | LOLBINS
SCRIPT_HOSTS = {"wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "cmd.exe"}
SCRIPT_EXT = (".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd")

RULES = [
    (r"\b(powershell|pwsh)(\.exe)?\b.*\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[a-z0-9+/=]{80,}",
     "PowerShell avec commande encodée (dissimulation)", 50),
    (r"\b(powershell|pwsh).*(downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer)",
     "PowerShell télécharge du code", 35),
    (r"\b(powershell|pwsh).*(invoke-expression|\biex\b|\|\s*iex)", "PowerShell exécute du code dynamique", 30),
    (r"\b(powershell|pwsh).*-w(indowstyle)?\s+h(idden)?\b", "PowerShell en fenêtre cachée", 15),
    (r"\bmshta(\.exe)?[\"']?\s+[\"']?(https?:|javascript:|vbscript:)", "mshta exécute du code distant", 80),
    (r"\bregsvr32(\.exe)?.*/i:\s*https?:", "regsvr32 charge un script distant (Squiblydoo)", 80),
    (r"\brundll32(\.exe)?.*(javascript:|mshtml,runhtmlapplication)", "rundll32 exécute du JavaScript", 80),
    (r"\bcertutil(\.exe)?.*(-urlcache|-verifyctl).*(https?:)", "certutil télécharge un fichier", 60),
    (r"\bcertutil(\.exe)?.*-decode\b", "certutil décode une charge cachée", 40),
    (r"\bbitsadmin(\.exe)?.*/transfer", "bitsadmin télécharge un fichier", 45),
    (r"\bvssadmin(\.exe)?.*delete\s+shadows", "suppression des clichés instantanés (ransomware)", 90),
    (r"\bwmic(\.exe)?.*shadowcopy\s+delete", "suppression des clichés instantanés (ransomware)", 90),
    (r"\bbcdedit(\.exe)?.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", "désactivation de la récupération Windows (ransomware)", 90),
    (r"\bwbadmin(\.exe)?.*delete\s+(catalog|systemstatebackup)", "suppression des sauvegardes (ransomware)", 90),
    (r"set-mppreference.*-disable(realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning)\s+\$?true",
     "désactivation de Windows Defender", 90),
    (r"add-mppreference.*-exclusion(path|process|extension)", "ajout d'une exclusion Windows Defender", 60),
    (r"\bwevtutil(\.exe)?\s+cl\b", "effacement des journaux Windows", 60),
    (r"\bnetsh(\.exe)?.*(advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+disable)", "désactivation du pare-feu", 70),
    (r"\breg(\.exe)?\s+add\s+.*\\(run|runonce)\b.*\\(appdata|temp|public|programdata)\\", "persistance au démarrage depuis un dossier temporaire", 45),
    (r"\bschtasks(\.exe)?\s+/create.*\\(appdata|temp|public)\\", "tâche planifiée depuis un dossier temporaire", 45),
]
_RULES = [(re.compile(p, re.I), label, pts) for p, label, pts in RULES]


def _risky_location(exe_low):
    return any(d in exe_low for d in ("\\downloads\\", "\\desktop\\", "\\temp\\", "\\appdata\\", "\\programdata\\",
                                       "\\users\\public\\", "\\$recycle.bin\\", "\\documents\\", "\\téléchargements\\",
                                       "/tmp/", "/downloads/")) \
        or (len(exe_low) > 2 and exe_low[1] == ":" and not exe_low.startswith(("c:\\windows\\", "c:\\program files")))


def _trusted_location(exe_low):
    return exe_low.startswith(("c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\"))


class ExecGuard:
    def __init__(self, engine, settings, emit):
        self.engine, self.settings, self.emit = engine, settings, emit
        self.stop_evt = threading.Event()
        self.running = False
        self.kernel = None
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="execguard")
        self.my_pid = os.getpid()
        self.blocked = 0

    # ------------------------------------------------------------------ décision
    def decide(self, exe, cmdline="", parent_name="", parent_exe=""):
        """Retourne (bloquer, résultat). Utilisé par le pilote noyau ET par la surveillance."""
        name = Path(exe).name.lower() if exe else (Path(cmdline.split()[0].strip('"')).name.lower() if cmdline.strip() else "")
        low = (exe or "").lower()
        cmd = cmdline or ""
        score, reasons = 0, []

        if self.settings["behavior_guard"]:
            if parent_name in OFFICE and name in SHELLS:
                score += 90; reasons.append(f"{parent_name} (document Office/PDF) lance {name} : macro malveillante ou exploit")
            if parent_name in BROWSERS and name in {"mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe"}:
                score += 70; reasons.append(f"le navigateur {parent_name} lance {name} : exploit probable")
            for rx, label, pts in _RULES:
                if rx.search(cmd):
                    score += pts; reasons.append(label)

        res = None
        if self.settings["exec_guard"] and exe and os.path.isfile(exe) and not self.engine.is_excluded(exe):
            if not _trusted_location(low):
                res = self.engine.scan_file(exe)  # résultat en cache si déjà analysé au téléchargement
            # script lancé par un interpréteur : on analyse aussi le script
            if name in SCRIPT_HOSTS:
                for m in re.finditer(r'"([^"]+\.(?:ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd))"|(\S+\.(?:ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd))\b', cmd, re.I):
                    script = m.group(1) or m.group(2)
                    if os.path.isfile(script) and not self.engine.is_excluded(script):
                        sres = self.engine.scan_file(script)
                        if sres["verdict"] in (MALWARE, SUSPECT):
                            res = sres
                            if sres["verdict"] == SUSPECT:
                                score += sres["score"]; reasons += sres["reasons"]
                            break

        if res is None:
            res = {"path": exe or cmd, "sha256": None, "verdict": "OK", "score": 0, "reasons": [], "threat": None}
        res = dict(res)
        res["cmdline"] = cmd
        res["parent"] = parent_name
        if res["verdict"] == MALWARE:
            return True, res
        if score >= 60:
            res["verdict"] = MALWARE
            res["threat"] = "Exploit / comportement malveillant"
            res["reasons"] = reasons + [r for r in res.get("reasons", []) if r not in reasons]
            res["behavior"] = True
            return True, res
        return False, res

    # ------------------------------------------------------------------ réaction
    def _block(self, pid, res, killed_before_start=False):
        action = "création du processus refusée (pilote noyau)" if killed_before_start else "exécution bloquée"
        if not killed_before_start and psutil:
            try:
                p = psutil.Process(pid)
                for c in p.children(recursive=True):
                    c.kill()
                p.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if self.settings["auto_quarantine"] and not res.get("behavior") and res.get("path") and os.path.isfile(res["path"]):
            try:
                time.sleep(0.2)
                quarantine.quarantine(res["path"], res)
                action += " + quarantaine"
            except OSError:
                pass
        self.blocked += 1
        self.settings.bump("threats")
        res["action"] = action
        self.emit("exec_blocked", res)

    # ------------------------------------------------------------------ mode surveillance (sans pilote)
    def _needs_check(self, name, exe_low, parent_name):
        if parent_name in OFFICE or parent_name in BROWSERS and name in SHELLS:
            return True
        if name in WATCH:
            return self.settings["behavior_guard"]
        return self.settings["exec_guard"] and (_risky_location(exe_low) or not _trusted_location(exe_low))

    def _handle_pid(self, pid):
        try:
            p = psutil.Process(pid)
            if p.ppid() == self.my_pid:
                return
            exe = p.exe() or ""
            name = (p.name() or "").lower()
            try:
                parent = p.parent()
                parent_name = (parent.name() or "").lower() if parent else ""
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                parent_name = ""
            if not self._needs_check(name, exe.lower(), parent_name):
                return
            suspended = False
            try:
                p.suspend(); suspended = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            try:
                cmd = " ".join(p.cmdline())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cmd = ""
            block, res = self.decide(exe, cmd, parent_name)
            if block:
                self._block(pid, res)
            elif suspended:
                p.resume()
                if res["verdict"] == SUSPECT:
                    res["action"] = "autorisé (suspect)"
                    self.emit("exec_suspect", res)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return
        except Exception as e:
            try:
                psutil.Process(pid).resume()
            except Exception:
                pass
            self.emit("log", f"Protection à l'exécution : erreur sur PID {pid} ({e})")

    def _loop(self):
        known = set(psutil.pids())
        while not self.stop_evt.is_set():
            try:
                pids = set(psutil.pids())
            except Exception:
                time.sleep(0.5); continue
            for pid in pids - known:
                self.pool.submit(self._handle_pid, pid)
            known = pids
            self.stop_evt.wait(0.03)

    # ------------------------------------------------------------------ pilote noyau
    def _kernel_decide(self, pid, ppid, path, cmd):
        parent_name = parent_exe = ""
        try:
            pp = psutil.Process(ppid)
            parent_name, parent_exe = (pp.name() or "").lower(), pp.exe() or ""
        except Exception:
            pass
        block, res = self.decide(path, cmd, parent_name, parent_exe)
        if block:
            threading.Thread(target=self._block, args=(pid, res, True), daemon=True).start()
        return block

    # ------------------------------------------------------------------ cycle de vie
    def start(self):
        if self.running or psutil is None:
            return
        self.stop_evt.clear()
        from .kernel import KernelClient
        self.kernel = KernelClient(self._kernel_decide, lambda m: self.emit("log", m))
        if self.kernel.connect():
            self.emit("log", "Pilote noyau Malryx connecté : blocage AVANT l'exécution actif")
            self.kernel.start()
        else:
            self.kernel = None
            threading.Thread(target=self._loop, daemon=True, name="execguard").start()
            self.emit("log", "Protection à l'exécution active (surveillance des processus)")
        self.running = True

    def stop(self):
        self.stop_evt.set()
        if self.kernel:
            self.kernel.stop()
            self.kernel = None
        self.running = False

    @property
    def mode(self):
        if not self.running:
            return "arrêtée"
        return "pilote noyau (avant exécution)" if self.kernel else "surveillance des processus"
