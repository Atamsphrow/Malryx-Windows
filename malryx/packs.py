"""Packs de signatures hors ligne : mise à jour de Malryx sans Internet (clé USB, partage réseau…).

Un pack (malryx-signatures-AAAAMMJJ.zip) contient :
    manifest.json      liste des fichiers (SHA-256, taille, version), date de génération
    manifest.sig       signature Ed25519 du manifeste (clé privée détenue par le workflow GitHub)
    main.cvd daily.cvd bytecode.cvd   bases ClamAV (signées en plus par Cisco-Talos, vérifiées par clamd)
    malryx-hashes.bin  yara-forge-core.zip  web-blocklist.txt

Vérifications à l'import :
 1. signature Ed25519 du manifeste avec la clé publique embarquée dans Malryx (malryx/pack_pubkey.txt) ;
 2. SHA-256 de chaque fichier conforme au manifeste ;
 3. pack plus récent que les signatures installées (pas de retour en arrière silencieux).
Un pack non signé n'est accepté que si Malryx n'a pas de clé publique configurée, et après confirmation.
"""
import base64
import hashlib
import json
import os
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

from .paths import data_dir, resource

PACK_GLOB = "malryx-signatures*.zip"
CLAM_FILES = ("main.cvd", "daily.cvd", "bytecode.cvd")


class PackError(Exception):
    pass


def public_key():
    p = resource("malryx", "pack_pubkey.txt")
    if not p.exists():
        p = Path(__file__).resolve().parent / "pack_pubkey.txt"
    try:
        raw = p.read_text(encoding="utf-8").strip()
        return base64.b64decode(raw) if raw else None
    except OSError:
        return None


def installed_manifest():
    try:
        return json.loads((data_dir("signatures") / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def installed_date():
    m = installed_manifest()
    try:
        return datetime.fromisoformat(m["generated"].replace("Z", "+00:00")).replace(tzinfo=None)
    except (KeyError, ValueError, AttributeError):
        return None


def age_days():
    d = installed_date()
    return None if d is None else max(0, (datetime.now() - d).days)


def inspect(path):
    """Lit et vérifie un pack sans rien installer. Renvoie un dict d'informations ; lève PackError sinon."""
    try:
        z = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as e:
        raise PackError(f"archive illisible : {e}")
    with z:
        names = set(z.namelist())
        if "manifest.json" not in names:
            raise PackError("ce fichier n'est pas un pack de signatures Malryx (manifest.json absent)")
        raw = z.read("manifest.json")
        man = json.loads(raw)
        pub = public_key()
        signed = "manifest.sig" in names
        if pub:
            if not signed:
                raise PackError("pack NON signé : refusé (cette version de Malryx exige des packs signés)")
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            try:
                Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(z.read("manifest.sig")), raw)
            except (InvalidSignature, ValueError):
                raise PackError("signature du pack INVALIDE : fichier modifié ou contrefait, refusé")
        for name, info in man.get("files", {}).items():
            if name not in names:
                raise PackError(f"fichier manquant dans le pack : {name}")
            h = hashlib.sha256()
            with z.open(name) as f:
                for c in iter(lambda: f.read(1 << 20), b""):
                    h.update(c)
            if h.hexdigest() != info["sha256"]:
                raise PackError(f"{name} : empreinte SHA-256 incorrecte, pack corrompu")
    gen = man.get("generated", "")
    try:
        date = datetime.fromisoformat(gen.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        date = None
    cur = installed_date()
    return {"path": str(path), "manifest": man, "signed": signed and bool(pub), "unsigned_allowed": not pub,
            "date": date, "newer": cur is None or (date is not None and date > cur),
            "size": os.path.getsize(path), "files": list(man.get("files", {}))}


def install(path, clam_db_dir, progress=lambda m: None):
    """Installe un pack déjà vérifié par inspect(). Renvoie la liste des fichiers installés."""
    info = inspect(path)
    sig = data_dir("signatures")
    clam_db_dir = Path(clam_db_dir)
    clam_db_dir.mkdir(parents=True, exist_ok=True)
    done = []
    with zipfile.ZipFile(path) as z:
        for name in info["files"]:
            progress(f"Installation de {name}…")
            dest = clam_db_dir / name if name in CLAM_FILES else sig / name
            tmp = Path(str(dest) + ".new")
            with z.open(name) as src, open(tmp, "wb") as out:
                shutil.copyfileobj(src, out, 1 << 20)
            os.replace(tmp, dest)
            if name in CLAM_FILES:
                (clam_db_dir / name.replace(".cvd", ".cld")).unlink(missing_ok=True)
            done.append(name)
        for extra in ("manifest.json", "manifest.sig"):
            if extra in z.namelist():
                (sig / extra).write_bytes(z.read(extra))
    if (sig / "yara-forge-core.zip").exists():
        ydir = sig / "yara"
        shutil.rmtree(ydir, ignore_errors=True); ydir.mkdir()
        with zipfile.ZipFile(sig / "yara-forge-core.zip") as yz:
            for m in yz.namelist():
                if m.endswith((".yar", ".yara")):
                    (ydir / Path(m).name).write_bytes(yz.read(m))
    if (sig / "web-blocklist.txt").exists():
        shutil.copy2(sig / "web-blocklist.txt", data_dir("liste_web.txt"))
    return done


def export(dest_dir, clam_db_dir):
    """Recrée un pack à partir des signatures installées (pour mettre à jour un autre PC hors ligne).
    La signature d'origine reste valide tant que les fichiers n'ont pas été modifiés."""
    man = installed_manifest()
    if not man.get("files"):
        raise PackError("aucun pack installé à exporter (signatures d'origine de l'application)")
    sig = data_dir("signatures")
    date = (man.get("generated") or "")[:10].replace("-", "") or datetime.now().strftime("%Y%m%d")
    out = Path(dest_dir) / f"malryx-signatures-{date}.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        for name, info in man["files"].items():
            src = Path(clam_db_dir) / name if name in CLAM_FILES else sig / name
            if not src.exists():
                raise PackError(f"{name} introuvable sur ce PC : export impossible")
            h = hashlib.sha256()
            with open(src, "rb") as f:
                for c in iter(lambda: f.read(1 << 20), b""):
                    h.update(c)
            if h.hexdigest() != info["sha256"]:
                raise PackError(f"{name} a été modifié depuis l'import : export impossible")
            z.write(src, name)
        z.write(sig / "manifest.json", "manifest.json")
        if (sig / "manifest.sig").exists():
            z.write(sig / "manifest.sig", "manifest.sig")
    return out


def find_on(root):
    """Packs présents à la racine (ou dans un dossier « Malryx ») d'une clé USB."""
    root = Path(root)
    found = list(root.glob(PACK_GLOB)) + list((root / "Malryx").glob(PACK_GLOB))
    return sorted(found, key=lambda p: p.name, reverse=True)
