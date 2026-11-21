"""Protection Web : bloque les domaines de distribution de malwares / hameçonnage via le fichier hosts.

La liste embarquée provient d'URLhaus (abuse.ch) et peut être mise à jour depuis l'application.
Modifier le fichier hosts nécessite les droits administrateur.
"""
import os
import re
import subprocess
import urllib.request
from pathlib import Path

from .paths import IS_WIN, data_dir, resource

HOSTS = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts" if IS_WIN else Path("/etc/hosts")
BEGIN, END = "# >>> Malryx Protection Web >>>", "# <<< Malryx Protection Web <<<"
SOURCES = ["https://urlhaus.abuse.ch/downloads/hostfile/"]
DOMAIN_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-z0-9.-]+\.[a-z]{2,})\s*$", re.I)


def user_list():
    return data_dir("blocage_personnalise.txt")


def cached_list():
    return data_dir("liste_web.txt")


def _parse(text):
    out = set()
    for line in text.splitlines():
        line = line.strip()
        m = DOMAIN_RE.match(line)
        if m:
            out.add(m.group(1).lower())
        elif re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", line, re.I):
            out.add(line.lower())
    out.discard("localhost")
    return out


def domains():
    src = cached_list() if cached_list().exists() else resource("vendor", "blocklist", "hosts.txt")
    d = _parse(Path(src).read_text(encoding="utf-8", errors="ignore")) if Path(src).exists() else set()
    if user_list().exists():
        d |= _parse(user_list().read_text(encoding="utf-8", errors="ignore"))
    return d


def update_list():
    text = ""
    for url in SOURCES:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Malryx"}), timeout=60) as r:
            text += r.read().decode("utf-8", "ignore") + "\n"
    found = _parse(text)
    if len(found) < 50:
        raise RuntimeError("liste téléchargée invalide")
    cached_list().write_text("\n".join(sorted(found)), encoding="utf-8")
    return len(found)


def is_enabled():
    try:
        return BEGIN in HOSTS.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False


def _strip(text):
    return re.sub(re.escape(BEGIN) + r".*?" + re.escape(END) + r"\n?", "", text, flags=re.S)


def apply(enable=True):
    """Écrit (ou retire) le bloc Malryx dans le fichier hosts. Lève PermissionError sans droits admin."""
    current = HOSTS.read_text(encoding="utf-8", errors="ignore") if HOSTS.exists() else ""
    base = _strip(current).rstrip() + "\n"
    if enable:
        ds = sorted(domains())
        block = [BEGIN, f"# {len(ds)} domaines malveillants bloqués"] + [f"0.0.0.0 {d}" for d in ds] + [END]
        base += "\n" + "\n".join(block) + "\n"
    HOSTS.write_text(base, encoding="utf-8")
    if IS_WIN:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, creationflags=0x08000000)
    return len(domains()) if enable else 0


def foreign_entries():
    """Entrées du fichier hosts qui ne viennent pas de Malryx (souvent ajoutées par des malwares)."""
    try:
        text = _strip(HOSTS.read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        return []
    out = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if line and not re.search(r"\blocalhost\b", line):
            out.append(line)
    return out


def add_custom(domain):
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", domain):
        raise ValueError("domaine invalide")
    with open(user_list(), "a", encoding="utf-8") as f:
        f.write(domain + "\n")
    return domain
