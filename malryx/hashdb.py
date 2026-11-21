"""Base de signatures compacte : millions de hashes MD5 / SHA-256 en mémoire partagée (mmap).

Format binaire « MLRXH1 » (produit par tools/build_signatures.py) :
    magic(8) | version(4) | date(8, epoch) | n_sha256(4) | n_md5(4) | [sha256 triés, 32 o] | [md5 triés, 16 o]
Recherche par dichotomie directement dans le fichier : ~32 Mo pour 1 million de SHA-256, aucun temps de chargement.
"""
import mmap
import os
import struct
from datetime import datetime
from pathlib import Path

MAGIC = b"MLRXH1\x00\x00"
HEADER = struct.Struct("<8sIqII")


class HashDB:
    def __init__(self, path=None):
        self.path, self.mm, self.fh = None, None, None
        self.n_sha = self.n_md5 = 0
        self.version, self.date = 0, None
        if path and Path(path).exists():
            self.open(path)

    def open(self, path):
        self.close()
        fh = open(path, "rb")
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        magic, ver, date, n_sha, n_md5 = HEADER.unpack_from(mm, 0)
        if magic != MAGIC or HEADER.size + n_sha * 32 + n_md5 * 16 != len(mm):
            mm.close(); fh.close()
            raise ValueError(f"base de signatures invalide : {path}")
        self.path, self.fh, self.mm = str(path), fh, mm
        self.version, self.n_sha, self.n_md5 = ver, n_sha, n_md5
        self.date = datetime.fromtimestamp(date) if date else None

    def close(self):
        if self.mm:
            self.mm.close(); self.fh.close()
        self.mm = self.fh = None
        self.n_sha = self.n_md5 = 0

    def __len__(self):
        return self.n_sha + self.n_md5

    def _search(self, offset, count, width, key):
        lo, hi = 0, count
        mm = self.mm
        while lo < hi:
            mid = (lo + hi) // 2
            pos = offset + mid * width
            v = mm[pos:pos + width]
            if v < key:
                lo = mid + 1
            elif v > key:
                hi = mid
            else:
                return True
        return False

    def has_sha256(self, hexdigest):
        if not self.mm or not self.n_sha:
            return False
        return self._search(HEADER.size, self.n_sha, 32, bytes.fromhex(hexdigest))

    def has_md5(self, hexdigest):
        if not self.mm or not self.n_md5:
            return False
        return self._search(HEADER.size + self.n_sha * 32, self.n_md5, 16, bytes.fromhex(hexdigest))


def build(out_path, sha256_iter=(), md5_iter=(), version=1):
    """Construit la base à partir d'itérables de hashes hexadécimaux (doublons et lignes invalides ignorés)."""
    def clean(it, n):
        s = set()
        for h in it:
            h = h.strip().lower()
            if len(h) == n * 2:
                try:
                    s.add(bytes.fromhex(h))
                except ValueError:
                    continue
        return sorted(s)
    sha, md5 = clean(sha256_iter, 32), clean(md5_iter, 16)
    tmp = Path(str(out_path) + ".tmp")
    with open(tmp, "wb") as f:
        f.write(HEADER.pack(MAGIC, version, int(datetime.now().timestamp()), len(sha), len(md5)))
        f.write(b"".join(sha))
        f.write(b"".join(md5))
    os.replace(tmp, out_path)
    return len(sha), len(md5)
