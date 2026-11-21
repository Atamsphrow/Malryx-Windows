"""Mises à jour des signatures, avec plusieurs chemins indépendants :

1. ClamAV officiel (freshclam) ;
2. si freshclam échoue (DNS, 403/429 du CDN…) : miroir Malryx sur GitHub Releases, publié chaque jour
   par .github/workflows/signatures.yml (bases ClamAV via cvdupdate + base de hashes + YARA Forge) ;
3. tous les téléchargements basculent automatiquement en DNS-over-HTTPS si le DNS local ne répond pas.

Intégrité : chaque fichier du miroir est vérifié par SHA-256 (manifest.json). Les bases ClamAV portent en
plus la signature numérique de Cisco-Talos, vérifiée par clamd au chargement.
"""
import hashlib
import json
import os
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

from . import netfetch
from .engine import signatures_dir

RELEASE_TAG = "signatures"


def mirror_base(repo):
    return f"https://github.com/{repo}/releases/download/{RELEASE_TAG}"


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def cvd_version(path):
    """Version d'une base ClamAV lue dans l'en-tête CVD/CLD (ClamAV-VDB:date:version:...)."""
    try:
        with open(path, "rb") as f:
            return int(f.read(512).decode("ascii", "ignore").split(":")[2])
    except (OSError, ValueError, IndexError):
        return 0


def local_manifest():
    p = signatures_dir() / "manifest.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


BIG = 20 * 1024 * 1024


def update_from_mirror(repo, clam_db_dir, progress=lambda m: None, want_clamav=True, max_size=None):
    """Télécharge depuis le miroir GitHub ce qui est plus récent que l'installation locale."""
    base = mirror_base(repo)
    progress("Lecture du manifeste du miroir Malryx…")
    with netfetch.open_url(f"{base}/manifest.json") as r:
        raw = r.read()
    from . import packs
    pub = packs.public_key()
    if pub:  # même exigence que les packs hors ligne : manifeste signé Ed25519
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        with netfetch.open_url(f"{base}/manifest.sig") as r:
            Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(r.read()), raw)
    man = json.loads(raw)
    local = local_manifest()
    changed = []
    sig = signatures_dir()

    def get(name, dest):
        info = man["files"][name]
        if max_size and info["size"] > max_size:
            progress(f"{name} ({info['size'] / 1e6:.0f} Mo) reporté : connexion limitée")
            return
        progress(f"Téléchargement de {name} ({info['size'] / 1e6:.0f} Mo)…")
        tmp = Path(str(dest) + ".new")
        netfetch.download(f"{base}/{name}", tmp, progress=lambda m: progress(f"{name} : {m}"))
        if _sha256(tmp) != info["sha256"]:
            tmp.unlink(missing_ok=True)
            raise ValueError(f"{name} : empreinte SHA-256 incorrecte, fichier rejeté")
        os.replace(tmp, dest)
        changed.append(name)

    # base de hashes + règles YARA Forge
    for name in ("malryx-hashes.bin", "yara-forge-core.zip"):
        if name in man.get("files", {}) and man["files"][name]["sha256"] != local.get("files", {}).get(name, {}).get("sha256"):
            dest = sig / name
            get(name, dest)
            if name.endswith(".zip"):
                ydir = sig / "yara"
                shutil.rmtree(ydir, ignore_errors=True); ydir.mkdir()
                with zipfile.ZipFile(dest) as z:
                    for m in z.namelist():
                        if m.endswith((".yar", ".yara")):
                            (ydir / Path(m).name).write_bytes(z.read(m))
    # bases ClamAV
    if want_clamav:
        for name in ("main.cvd", "daily.cvd", "bytecode.cvd"):
            if name not in man.get("files", {}):
                continue
            stem = name.split(".")[0]
            cur = max(cvd_version(Path(clam_db_dir) / f"{stem}.cvd"), cvd_version(Path(clam_db_dir) / f"{stem}.cld"))
            if man["files"][name].get("version", 0) > cur:
                get(name, Path(clam_db_dir) / name)
                (Path(clam_db_dir) / f"{stem}.cld").unlink(missing_ok=True)  # l'ancienne version incrémentale est remplacée
    (sig / "manifest.json").write_bytes(raw)
    return changed


def update_all(clamav, settings, progress=lambda m: None):
    """Chaîne complète. Renvoie (succès, résumé)."""
    if settings["offline"]:
        return False, "hors ligne : aucune connexion autorisée (Wi-Fi) – importez un pack de signatures ou connectez-vous au Wi-Fi"
    notes, ok_any = [], False
    clam_ok = False
    if settings["clamav"] and clamav.freshclam:
        progress("Mise à jour ClamAV (serveurs officiels)…")
        try:
            clam_ok, out = clamav.update(on_line=progress)
            notes.append("ClamAV officiel : " + ("à jour" if clam_ok else "échec"))
            if not clam_ok:
                notes.append(out.splitlines()[-1] if out else "")
        except Exception as e:
            notes.append(f"ClamAV officiel : {e}")
    repo = settings.get("mirror_repo") or ""
    if repo:
        try:
            limit = BIG if settings["metered"] and settings["metered_saver"] else None
            changed = update_from_mirror(repo, clamav.db_dir, progress, want_clamav=settings["clamav"] and not clam_ok,
                                         max_size=limit)
            ok_any = True
            notes.append("Miroir Malryx : " + (", ".join(changed) if changed else "déjà à jour"))
            if any(c.endswith(".cvd") for c in changed):
                clam_ok = True
        except Exception as e:
            notes.append(f"Miroir Malryx : {e}")
    return (clam_ok or ok_any), " · ".join(n for n in notes if n)
