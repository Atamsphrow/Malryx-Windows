"""Construit le paquet de signatures Malryx (exécuté chaque jour par .github/workflows/signatures.yml,
ou localement par build.ps1).

Sorties dans --out :
  malryx-hashes.bin      base compacte SHA-256 / MD5 (MalwareBazaar + listes supplémentaires + hashes.txt)
  yara-forge-core.zip    règles YARA Forge « core » (chaque fichier compilé et validé)
  main.cvd daily.cvd bytecode.cvd   bases ClamAV officielles (option --clamav, via cvdupdate)
  web-blocklist.txt      domaines malveillants URLhaus
  manifest.json          empreintes SHA-256, tailles, versions → vérifiées par l'application

Variables d'environnement :
  MB_AUTH_KEY      clé gratuite abuse.ch (https://auth.abuse.ch) pour l'export MalwareBazaar
  MB_EXPORT_URL    URL de l'export SHA-256 complet (défaut ci-dessous ; {key} est remplacé par la clé)
  EXTRA_HASH_URLS  autres listes de hashes (une URL par ligne, .txt ou .zip, MD5 ou SHA-256)
"""
import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from malryx.hashdb import build as build_hashdb  # noqa: E402

UA = {"User-Agent": "Malryx-signatures-builder"}
MB_DEFAULT = "https://bazaar.abuse.ch/export/txt/sha256/full/"


def get(url, headers=None, timeout=300):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def texts_from(blob):
    """Contenu texte d'une réponse : brut, ou chaque fichier d'une archive zip."""
    if blob[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            for n in z.namelist():
                yield z.read(n).decode("utf-8", "ignore")
    else:
        yield blob.decode("utf-8", "ignore")


def hashes_in(text):
    sha, md5 = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for tok in re.split(r'[\s,;"]+', line):
            if re.fullmatch(r"[0-9a-fA-F]{64}", tok):
                sha.append(tok); break
            if re.fullmatch(r"[0-9a-fA-F]{32}", tok):
                md5.append(tok); break
    return sha, md5


def step_hashes(out):
    sha, md5, sources = [], [], []
    s, m = hashes_in((ROOT / "hashes.txt").read_text(encoding="utf-8"))
    sha += s; md5 += m
    key = os.environ.get("MB_AUTH_KEY", "").strip()
    if key:
        url = os.environ.get("MB_EXPORT_URL", MB_DEFAULT).replace("{key}", key)
        try:
            blob = get(url, {"Auth-Key": key})
            n0 = len(sha)
            for t in texts_from(blob):
                s, m = hashes_in(t); sha += s; md5 += m
            sources.append(f"MalwareBazaar ({len(sha) - n0} SHA-256)")
            print(f"MalwareBazaar : {len(sha) - n0} hashes")
        except Exception as e:
            print(f"::warning::MalwareBazaar indisponible : {e}")
    else:
        print("::notice::MB_AUTH_KEY absent : export MalwareBazaar ignoré (ajoutez le secret pour l'activer)")
    for url in [u.strip() for u in os.environ.get("EXTRA_HASH_URLS", "").splitlines() if u.strip()]:
        try:
            n0 = len(sha) + len(md5)
            for t in texts_from(get(url)):
                s, m = hashes_in(t); sha += s; md5 += m
            sources.append(f"{url} ({len(sha) + len(md5) - n0})")
        except Exception as e:
            print(f"::warning::{url} : {e}")
    n_sha, n_md5 = build_hashdb(out / "malryx-hashes.bin", sha, md5,
                                version=int(datetime.now(timezone.utc).strftime("%Y%m%d")))
    print(f"Base de hashes : {n_sha} SHA-256 + {n_md5} MD5")
    return sources


def step_yara(out):
    import yara
    rel = json.loads(get("https://api.github.com/repos/YARAHQ/yara-forge/releases/latest",
                         {"Accept": "application/vnd.github+json"}))
    asset = next(a for a in rel["assets"] if "core" in a["name"] and a["name"].endswith(".zip"))
    blob = get(asset["browser_download_url"])
    good, bad = {}, 0
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for n in z.namelist():
            if n.endswith((".yar", ".yara")):
                src = z.read(n)
                try:
                    yara.compile(source=src.decode("utf-8", "ignore"))
                    good[Path(n).name] = src
                except yara.Error as e:
                    bad += 1; print(f"::warning::YARA {n} ignoré : {e}")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, src in good.items():
            z.writestr(n, src)
    (out / "yara-forge-core.zip").write_bytes(buf.getvalue())
    print(f"YARA Forge {rel['tag_name']} : {len(good)} fichier(s) valides, {bad} ignoré(s)")
    return f"YARA Forge {rel['tag_name']}"


def step_clamav(out):
    """Bases officielles via cvdupdate (outil prévu par Cisco-Talos pour les miroirs privés)."""
    work = Path(tempfile.mkdtemp())
    subprocess.run(["cvd", "config", "set", "--dbdir", str(work)], check=True)
    subprocess.run(["cvd", "update"], check=True)
    versions = {}
    for n in ("main.cvd", "daily.cvd", "bytecode.cvd"):
        p = work / n
        if p.exists():
            shutil.copy2(p, out / n)
            with open(p, "rb") as f:
                versions[n] = int(f.read(512).decode("ascii", "ignore").split(":")[2])
    print(f"ClamAV : {versions}")
    return versions


def step_web(out):
    blob = get("https://urlhaus.abuse.ch/downloads/hostfile/")
    (out / "web-blocklist.txt").write_bytes(blob)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="signatures")
    ap.add_argument("--clamav", action="store_true", help="inclure les bases ClamAV (cvdupdate)")
    a = ap.parse_args()
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    sources, versions = step_hashes(out), {}
    try:
        sources.append(step_yara(out))
    except Exception as e:
        print(f"::warning::YARA Forge indisponible : {e}")
    if a.clamav:
        versions = step_clamav(out)
        sources.append("ClamAV (Cisco-Talos)")
    try:
        step_web(out)
    except Exception as e:
        print(f"::warning::URLhaus indisponible : {e}")
    files = {}
    for p in sorted(out.iterdir()):
        if p.name == "manifest.json" or p.is_dir():
            continue
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for c in iter(lambda: f.read(1 << 20), b""):
                h.update(c)
        files[p.name] = {"sha256": h.hexdigest(), "size": p.stat().st_size, **({"version": versions[p.name]} if p.name in versions else {})}
    man = {"generated": datetime.now(timezone.utc).isoformat(timespec="minutes"), "sources": sources, "files": files}
    (out / "manifest.json").write_text(json.dumps(man, indent=2), encoding="utf-8")
    print(json.dumps(man, indent=2))


if __name__ == "__main__":
    main()
