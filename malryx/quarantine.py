"""Quarantaine chiffrée AES-256-GCM.

- Clé aléatoire de 256 bits propre à chaque installation, protégée par Windows DPAPI
  (CryptProtectData, portée utilisateur) : sans la session Windows de l'utilisateur, la clé est inutilisable.
- Chiffrement par blocs de 4 Mo (la mémoire reste faible même pour un fichier de 200 Mo).
  Chaque bloc est authentifié avec son index et un drapeau « dernier bloc » : un fichier tronqué,
  réordonné ou modifié est rejeté à la restauration.
- Les anciens éléments (format XOR des versions ≤ 2.2) restent lisibles pour être restaurés ou supprimés.
"""
import hashlib
import json
import os
import secrets
import struct
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .paths import IS_WIN, data_dir

QDIR = data_dir("quarantaine")
MAGIC = b"MLRXQ2\x00\x00"
CHUNK = 4 * 1024 * 1024
LEGACY_XOR_KEY = 0x5A

PROTECTED = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\windows\\winsxs\\",
             "c:\\windows\\explorer.exe", "c:\\windows\\servicing\\", "/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/lib/")


def is_protected(path):
    """Fichiers système vitaux : jamais déplacés (un faux positif rendrait Windows inutilisable)."""
    p = os.path.normcase(os.path.abspath(str(path)))
    return p.lower().startswith(PROTECTED)


# ---------------------------------------------------------------------------- clé protégée
def _dpapi(data, protect):
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
    buf = ctypes.create_string_buffer(data, len(data))
    inp, out = BLOB(len(data), buf), BLOB()
    entropy_raw = b"Malryx-Quarantine-v2"
    ebuf = ctypes.create_string_buffer(entropy_raw, len(entropy_raw))
    ent = BLOB(len(entropy_raw), ebuf)
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    args = (ctypes.byref(inp), "Malryx" if protect else None, ctypes.byref(ent), None, None, 0x1, ctypes.byref(out))
    if not fn(*args):  # 0x1 = CRYPTPROTECT_UI_FORBIDDEN
        raise OSError("DPAPI a refusé l'opération")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


_KEY = None


def _key():
    global _KEY
    if _KEY:
        return _KEY
    kf = data_dir("quarantaine.key")
    if kf.exists():
        raw = kf.read_bytes()
        _KEY = _dpapi(raw, False) if IS_WIN else raw
    else:
        _KEY = secrets.token_bytes(32)
        if IS_WIN:
            kf.write_bytes(_dpapi(_KEY, True))
        else:
            kf.write_bytes(_KEY)
            os.chmod(kf, 0o600)
    return _KEY


# ---------------------------------------------------------------------------- chiffrement
def _aad(sha, idx, last):
    return sha.encode() + struct.pack(">I?", idx, last)


def _encrypt_file(src, dst, sha):
    aes = AESGCM(_key())
    base = secrets.token_bytes(8)
    size = os.path.getsize(src)
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fo.write(MAGIC + base)
        idx, done = 0, 0
        while True:
            chunk = fi.read(CHUNK)
            done += len(chunk)
            last = done >= size
            ct = aes.encrypt(base + struct.pack(">I", idx), chunk, _aad(sha, idx, last))
            fo.write(struct.pack(">I", len(ct)) + ct)
            idx += 1
            if last:
                break


def _decrypt_file(src, dst, sha):
    with open(src, "rb") as fi:
        head = fi.read(len(MAGIC))
        if head != MAGIC:  # ancien format XOR
            fi.seek(0)
            data = fi.read()
            Path(dst).write_bytes(bytes(b ^ LEGACY_XOR_KEY for b in data))
            return
        aes = AESGCM(_key())
        base = fi.read(8)
        tmp = Path(str(dst) + ".malryx-tmp")
        with open(tmp, "wb") as fo:
            idx = 0
            while True:
                n = fi.read(4)
                if len(n) < 4:
                    tmp.unlink(missing_ok=True)
                    raise ValueError("élément de quarantaine tronqué ou corrompu")
                ct = fi.read(struct.unpack(">I", n)[0])
                pos = fi.tell()
                last = fi.read(1) == b""
                fi.seek(pos)
                try:
                    fo.write(aes.decrypt(base + struct.pack(">I", idx), ct, _aad(sha, idx, last)))
                except Exception:
                    fo.close(); tmp.unlink(missing_ok=True)
                    raise ValueError("authentification AES-GCM échouée : élément modifié ou corrompu")
                idx += 1
                if last:
                    break
        os.replace(tmp, dst)


# ---------------------------------------------------------------------------- API
def quarantine(path, result):
    QDIR.mkdir(exist_ok=True)
    path = Path(path)
    if is_protected(path):
        raise PermissionError("fichier système protégé : il n'est pas déplacé (analyse manuelle recommandée)")
    sha = result.get("sha256")
    if not sha:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for c in iter(lambda: f.read(1 << 20), b""):
                h.update(c)
        sha = h.hexdigest()
    dest = QDIR / f"{sha}.qtn"
    size = path.stat().st_size
    _encrypt_file(path, dest, sha)
    meta = {"original": str(path), "sha256": sha, "reasons": result.get("reasons"), "threat": result.get("threat"),
            "size": size, "format": "AES-256-GCM", "date": datetime.now().isoformat(timespec="seconds")}
    (QDIR / f"{sha}.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        os.remove(path)
    except OSError:
        dest.unlink(missing_ok=True)
        (QDIR / f"{sha}.json").unlink(missing_ok=True)
        raise
    return dest


def list_items():
    items = []
    for p in sorted(QDIR.glob("*.json")):
        try:
            m = json.loads(p.read_text(encoding="utf-8"))
            m.setdefault("format", "XOR (ancien)")
            items.append(m)
        except ValueError:
            continue
    return sorted(items, key=lambda m: m.get("date", ""), reverse=True)


def restore(sha):
    meta_p, data_p = QDIR / f"{sha}.json", QDIR / f"{sha}.qtn"
    meta = json.loads(meta_p.read_text(encoding="utf-8"))
    orig = Path(meta["original"])
    if orig.exists():
        orig = orig.with_name(orig.stem + "_restauré" + orig.suffix)
    orig.parent.mkdir(parents=True, exist_ok=True)
    _decrypt_file(data_p, orig, sha)
    data_p.unlink(); meta_p.unlink()
    return orig


def delete(sha):
    for ext in (".qtn", ".json"):
        p = QDIR / f"{sha}{ext}"
        if p.exists():
            p.unlink()
