"""Génère la paire de clés Ed25519 qui signe les packs de signatures Malryx.

    python tools/gen_pack_key.py

- la clé PUBLIQUE est écrite dans malryx/pack_pubkey.txt (à committer : elle est embarquée dans l'app) ;
- la clé PRIVÉE est affichée UNE SEULE FOIS : copie-la dans GitHub → Settings → Secrets → Actions,
  secret « MALRYX_PACK_KEY ». Ne la committe jamais et ne la partage pas.
Dès que pack_pubkey.txt existe, Malryx REFUSE tout pack non signé ou mal signé.
"""
import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

key = Ed25519PrivateKey.generate()
priv = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
out = Path(__file__).resolve().parent.parent / "malryx" / "pack_pubkey.txt"
if out.exists() and out.read_text().strip():
    raise SystemExit(f"{out} existe déjà : supprime-le d'abord si tu veux vraiment changer de clé "
                     "(les packs déjà publiés deviendront invalides).")
out.write_text(base64.b64encode(pub).decode() + "\n")
print(f"Clé publique écrite dans {out}")
print("\nSecret GitHub MALRYX_PACK_KEY (clé privée, à garder secrète) :\n")
print(base64.b64encode(priv).decode())
