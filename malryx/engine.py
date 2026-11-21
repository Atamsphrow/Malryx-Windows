"""Moteur de détection multi-couches : signatures SHA-256, YARA, ClamAV, VirusTotal, heuristiques."""
import hashlib
import json
import math
import os
import re
import threading
import time
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path

from .hashdb import HashDB
from .paths import data_dir, resource

try:
    import yara
except ImportError:
    yara = None

MAX_SIZE = 200 * 1024 * 1024
EXEC_EXT = {".exe", ".dll", ".scr", ".com", ".pif", ".sys", ".cpl", ".msi", ".elf"}
SCRIPT_EXT = {".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".lnk"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".mp3", ".mp4", ".zip"}
RISKY_DIRS = ("\\temp\\", "/tmp/", "\\appdata\\", "\\startup\\", "\\démarrage\\", "\\downloads\\",
              "/downloads/", "\\public\\")

INTERESTING_EXT = EXEC_EXT | SCRIPT_EXT | {
    ".apk", ".xapk", ".jar", ".dex", ".so", ".zip", ".rar", ".7z", ".iso", ".img", ".cab", ".docm", ".xlsm",
    ".pptm", ".doc", ".xls", ".rtf", ".pdf", ".one", ".chm", ".reg", ".py", ".sh", ".inf", ".url", ".appx", ".msix"}
NOISY_PARTS = ("\\cache\\", "\\code cache\\", "\\gpucache\\", "\\indexeddb\\", "\\service worker\\",
               "\\cache2\\", "\\webcache", "\\packages\\microsoft.", "\\crashpad\\", "\\logs\\",
               "\\microsoft\\windows\\explorer\\", "\\windows defender\\", "/.cache/")
PERSONAL_DIRS = ("\\downloads\\", "\\desktop\\", "\\documents\\", "\\pictures\\", "\\téléchargements\\",
                 "\\bureau\\", "/downloads/", "/desktop/", "/documents/")


def is_noisy(path):
    p = str(path).lower()
    return any(n in p for n in NOISY_PARTS)


def is_interesting(path, check_header=True):
    """Fichier susceptible de contenir du code exécutable (filtre des analyses rapides et du temps réel)."""
    ext = os.path.splitext(str(path))[1].lower()
    if ext in INTERESTING_EXT:
        return True
    if ext in ("", ".tmp", ".dat", ".bin", ".bak") and check_header:
        try:
            with open(path, "rb") as f:
                h = f.read(4)
            return h[:2] == b"MZ" or h == b"\x7fELF"
        except OSError:
            return False
    return ext in ("", ".tmp", ".dat", ".bin", ".bak")


MALWARE, SUSPECT, OK, ERROR = "MALVEILLANT", "SUSPECT", "OK", "ERREUR"


def sha256_file(path):
    return hash_file(path)[0]


def hash_file(path):
    """SHA-256 et MD5 en une seule lecture (les bases publiques utilisent l'un ou l'autre)."""
    h, m = hashlib.sha256(), hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk); m.update(chunk)
    return h.hexdigest(), m.hexdigest()


def signatures_dir():
    """Signatures téléchargées (mises à jour) ; à défaut, celles embarquées dans l'exe."""
    return data_dir("signatures")


def _sig_file(*parts):
    p = signatures_dir().joinpath(*parts)
    return p if p.exists() else resource("signatures", *parts)


def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def user_hashes_file():
    return data_dir("signatures_utilisateur.txt")


def user_rules_dir():
    return data_dir("regles_yara")


class Engine:
    def __init__(self, settings, clamav=None, log=print):
        self.settings, self.clamav, self.log = settings, clamav, log
        self._vt_lock = threading.Lock()
        self._vt_last = 0.0
        self._vt_cache = {}
        self._cache = {}
        self._cache_lock = threading.Lock()
        self.reload()

    # ---------- chargement ----------
    def reload(self, background=True):
        self._cache = {}
        self.bad_hashes = {}
        for f in (resource("hashes.txt"), user_hashes_file()):
            self._load_hashes(f)
        self.hashdb = HashDB()
        db = _sig_file("malryx-hashes.bin")
        try:
            self.hashdb.open(db) if Path(db).exists() else None
        except (ValueError, OSError) as e:
            self.log(f"[Signatures] base de hashes ignorée : {e}")
        self.rules, self.rule_count = self._load_yara(background)

    def _load_hashes(self, f):
        if not Path(f).exists():
            return
        for line in Path(f).read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip().strip('"')
            if not line or line.startswith("#"):
                continue
            parts = re.split(r'[\s,;"]+', line)
            for i, p in enumerate(parts):  # accepte aussi les CSV de MalwareBazaar
                if re.fullmatch(r"[0-9a-fA-F]{64}", p):
                    name = next((x for x in parts[i + 1:] if x and not re.fullmatch(r"[0-9a-fA-F]{32,128}", x)), "hash connu")
                    self.bad_hashes[p.lower()] = name
                    break

    def _yara_sources(self):
        files = {}
        dirs = [("malryx", resource("rules")), ("forge", Path(_sig_file("yara"))), ("perso", user_rules_dir())]
        for ns, d in dirs:
            if Path(d).exists():
                for p in sorted(Path(d).rglob("*.yar*")):
                    files[f"{ns}_{p.stem}"] = str(p)
        return files

    def _load_yara(self, background=True):
        """Règles intégrées + YARA Forge + règles personnelles. La compilation (plusieurs milliers de règles)
        est mise en cache sur disque et refaite en arrière-plan seulement quand les sources changent."""
        if yara is None:
            return None, 0
        files = self._yara_sources()
        if not files:
            return None, 0
        key = hashlib.sha256(json.dumps({k: [v, os.path.getsize(v), os.path.getmtime(v)] for k, v in files.items()},
                                        sort_keys=True).encode()).hexdigest()
        cache, cache_key = data_dir("yara.compiled"), data_dir("yara.compiled.key")
        if cache.exists() and cache_key.exists() and cache_key.read_text() == key:
            try:
                rules = yara.load(str(cache))
                return rules, sum(1 for _ in rules)
            except yara.Error:
                pass
        own = {k: v for k, v in files.items() if k.startswith("malryx_")}
        try:
            quick = yara.compile(filepaths=own) if own else None
        except yara.Error:
            quick = None

        def full():
            try:
                rules = yara.compile(filepaths=files)
            except yara.Error as e:
                # une règle invalide ne doit pas tout bloquer : on écarte les fichiers fautifs un par un
                good = {}
                for k, v in files.items():
                    try:
                        yara.compile(filepath=v); good[k] = v
                    except yara.Error:
                        self.log(f"[YARA] règle ignorée ({Path(v).name}) : {e}")
                rules = yara.compile(filepaths=good) if good else quick
            try:
                rules.save(str(cache)); cache_key.write_text(key)
            except (yara.Error, OSError):
                pass
            self.rules, self.rule_count = rules, sum(1 for _ in rules)
            self._cache = {}
            self.log(f"[YARA] {self.rule_count} règles chargées")
        if background and len(files) > len(own):
            threading.Thread(target=full, daemon=True, name="yara-compile").start()
            return quick, sum(1 for _ in quick) if quick else 0
        full()
        return self.rules, self.rule_count

    def add_hashes_from_file(self, path):
        before = len(self.bad_hashes)
        self._load_hashes(path)
        new = {h: n for h, n in self.bad_hashes.items()}
        with open(user_hashes_file(), "a", encoding="utf-8") as out:
            for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
                m = re.search(r"\b[0-9a-fA-F]{64}\b", line)
                if m:
                    out.write(f"{m.group(0).lower()} {new.get(m.group(0).lower(), 'importé')}\n")
        return len(self.bad_hashes) - before

    def add_hash(self, sha, name):
        with open(user_hashes_file(), "a", encoding="utf-8") as out:
            out.write(f"{sha} {name}\n")
        self.bad_hashes[sha] = name

    def status(self):
        return {
            "signatures": len(self.bad_hashes) + len(self.hashdb),
            "hashdb_date": self.hashdb.date,
            "yara": self.rule_count,
            "clamav": self.clamav.state if self.clamav else "absent",
            "virustotal": bool(self.settings["use_vt"] and self.settings["vt_key"]),
        }

    def is_excluded(self, path):
        p = os.path.normcase(str(path))
        return any(p.startswith(os.path.normcase(e)) for e in self.settings["exclusions"] if e)

    # ---------- VirusTotal ----------
    def vt_lookup(self, sha):
        key = self.settings["vt_key"]
        if not key:
            return None
        if sha in self._vt_cache:
            return self._vt_cache[sha]
        with self._vt_lock:  # API gratuite : 4 requêtes / minute
            wait = 15 - (time.time() - self._vt_last)
            if wait > 0:
                time.sleep(wait)
            self._vt_last = time.time()
        req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha}", headers={"x-apikey": key})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                attrs = json.load(r)["data"]["attributes"]
                n = attrs["last_analysis_stats"].get("malicious", 0)
                label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
                self._vt_cache[sha] = (n, label)
                return n, label
        except urllib.error.HTTPError as e:
            if e.code == 404:
                self._vt_cache[sha] = (0, None)
                return 0, None
        except Exception:
            pass
        return None

    # ---------- heuristiques ----------
    def _heuristics(self, path, head):
        reasons, score = [], 0
        p = str(path).lower()
        name = Path(p).name
        suffixes = [s for s in Path(name).suffixes if len(s) <= 6]
        ext = suffixes[-1] if suffixes else ""

        if len(suffixes) >= 2 and suffixes[-2] in DOC_EXT and ext in EXEC_EXT | SCRIPT_EXT:
            score += 45; reasons.append(f"double extension trompeuse ({''.join(suffixes[-2:])})")
        if re.search(r"\s{5,}\.(exe|scr|bat|cmd|com)$", name) or "‮" in name:
            score += 45; reasons.append("nom de fichier maquillé (espaces/RTLO)")
        is_pe = head[:2] == b"MZ"
        is_elf = head[:4] == b"\x7fELF"
        if is_pe and ext not in EXEC_EXT:
            score += 30; reasons.append("exécutable Windows déguisé (en-tête MZ)")
        if (is_pe or is_elf or ext in EXEC_EXT | SCRIPT_EXT) and any(d in p for d in RISKY_DIRS):
            score += 15; reasons.append("exécutable/script dans un dossier à risque")
        if ("\\startup\\" in p or "\\démarrage\\" in p) and ext in SCRIPT_EXT | EXEC_EXT:
            score += 20; reasons.append("lancement automatique au démarrage")
        if is_pe or is_elf or ext in {".dex", ".so"}:
            e = entropy(head[:1024 * 1024])
            if e > 7.4:
                score += 20; reasons.append(f"entropie très élevée {e:.2f} (packé / chiffré)")
            if is_pe and len(head) > 0x40:
                low = head.lower()
                if b"upx0" in low and b"upx1" in low:
                    score += 10; reasons.append("compressé avec UPX")
        if ext in SCRIPT_EXT or ext in {".txt", ""} and head[:2] != b"MZ":
            text = head[:512 * 1024].decode("utf-8", "ignore").lower()
            for pat, label, pts in [
                (r"-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{60,}", "commande PowerShell encodée", 30),
                (r"downloadstring|downloadfile|invoke-webrequest|\biwr\s|bitsadmin\s+/transfer|certutil.+-urlcache", "téléchargement de code", 20),
                (r"invoke-expression|\biex\b", "exécution dynamique (IEX)", 15),
                (r"-w(indowstyle)?\s+hid", "fenêtre cachée", 15),
                (r"vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit.+recoveryenabled\s+no", "suppression des sauvegardes (ransomware)", 40),
                (r"set-mppreference.+-disable|add-mppreference.+-exclusion", "désactivation de Windows Defender", 40),
                (r"wscript\.shell|shell\.application", "accès au shell Windows", 10),
                (r"schtasks\s+/create|reg\s+add\s+.+\\run\b", "création de persistance", 20),
            ]:
                if re.search(pat, text):
                    score += pts; reasons.append(label)
        return score, reasons

    def _yara(self, res, malicious, path=None, data=None, origin=""):
        if not self.rules:
            return
        try:
            matches = self.rules.match(path, timeout=30) if path else self.rules.match(data=data, timeout=30)
        except yara.Error:
            return
        for m in matches:
            tag = f"YARA : {m.rule}{origin}"
            if "score" in m.meta:  # règles YARA Forge : score de 0 à 100
                sc = int(m.meta.get("score") or 0)
                if sc >= 75:
                    malicious.append(tag)
                else:
                    res["score"] += 40 if sc >= 60 else 15; res["reasons"].append(f"{tag} (score {sc})")
            elif m.meta.get("severity", "high") == "high":
                malicious.append(tag)
            else:
                res["score"] += 40; res["reasons"].append(tag)

    # ---------- scan ----------
    def scan_file(self, path, extra_score=0, extra_reasons=None, force_vt=False):
        """Analyse un fichier. Les verdicts sont mis en cache (chemin, taille, date) : un fichier déjà
        analysé (par exemple au téléchargement) est jugé instantanément lorsqu'il est exécuté."""
        key = None
        if not extra_score and not extra_reasons and not force_vt:
            try:
                st = os.stat(path)
                key = (os.path.normcase(str(path)), st.st_size, st.st_mtime_ns)
                cached = self._cache.get(key)
                if cached is not None:
                    return dict(cached, reasons=list(cached["reasons"]))
            except OSError:
                pass
        res = self._scan_file(path, extra_score, extra_reasons, force_vt)
        if key and res["verdict"] != ERROR:
            with self._cache_lock:
                if len(self._cache) > 50000:
                    self._cache.clear()
                self._cache[key] = dict(res, reasons=list(res["reasons"]))
        return res

    def _scan_file(self, path, extra_score=0, extra_reasons=None, force_vt=False):
        path = Path(path)
        res = {"path": str(path), "sha256": None, "verdict": OK, "score": extra_score, "threat": None,
               "reasons": list(extra_reasons or []), "time": datetime.now().isoformat(timespec="seconds")}
        try:
            size = path.stat().st_size
            res["size"] = size
            if size > MAX_SIZE:
                res["reasons"].append("ignoré (> 200 Mo)")
                return res
            if size == 0:
                return res
            sha, md5 = hash_file(path)
            res["sha256"] = sha
            with open(path, "rb") as f:
                head = f.read(2 * 1024 * 1024)
        except (OSError, PermissionError) as e:
            res["verdict"] = ERROR; res["reasons"].append(str(e))
            return res

        malicious = []
        if sha in self.bad_hashes:
            malicious.append(f"Signature : {self.bad_hashes[sha]}")
        elif self.hashdb.has_sha256(sha) or self.hashdb.has_md5(md5):
            malicious.append("Signature : malware connu (base Malryx)")
        self._yara(res, malicious, path=str(path))
        if head[:2] == b"PK" and path.suffix.lower() in (".apk", ".jar", ".xapk", ".aab"):
            try:
                with zipfile.ZipFile(path) as z:
                    for info in z.infolist():
                        if info.filename.endswith((".dex", ".so")) and info.file_size < 60 * 1024 * 1024:
                            data = z.read(info)
                            self._yara(res, malicious, data=data, origin=f" ({info.filename})")
            except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
                pass
        if self.clamav and self.settings["clamav"]:
            name = self.clamav.scan(path)
            if name:
                malicious.append(f"ClamAV : {name}")

        s, r = self._heuristics(path, head)
        res["score"] += s
        res["reasons"] += r

        if (force_vt or self.settings["use_vt"]) and not malicious and res["score"] > 0:
            vt = self.vt_lookup(sha)
            if vt:
                n, label = vt
                res["reasons"].append(f"VirusTotal : {n} moteurs positifs" + (f" ({label})" if label else ""))
                if n >= 3:
                    malicious.append(f"VirusTotal : {label or f'{n} détections'}")

        if malicious:
            res["verdict"] = MALWARE
            res["threat"] = malicious[0].split(" : ", 1)[-1]
            res["reasons"] = malicious + res["reasons"]
        elif res["score"] >= self.settings.threshold:
            res["verdict"] = SUSPECT
            res["threat"] = "Heuristique"
        return res
