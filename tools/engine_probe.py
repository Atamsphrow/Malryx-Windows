"""Sonde W3 n.2 : quel moteur coute ~12 s par fichier ?

La sonde n.1 a etabli : scan complet des non-signes = 842 s pour 64
fichiers, avec un plancher de ~12 s meme pour un fichier de 0,1 Mo.
Cette sonde chronometre CHAQUE moteur separement sur les memes
fichiers, plus les sous-chemins ClamAV (PING, INSTREAM, binaire).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BACKEND = REPO / "backend"
sys.path.insert(0, str(BACKEND))
os.environ["MALRYX_NO_TOAST"] = "1"


def timed(label: str, fn):
    start = time.monotonic()
    out = fn()
    print(f"  {label} : {time.monotonic() - start:.2f} s -> {out!r:.120}",
          flush=True)
    return out


def main() -> int:
    if sys.platform != "win32":
        print("sonde Windows uniquement")
        return 0

    from core.app_state import init_state
    from core.models import ScanOptions
    from core.scan_engine import FileContext

    state = init_state()
    try:
        options = ScanOptions(
            use_clamav=True, use_yara=True, use_heuristics=True,
            use_hash_db=True, use_virustotal=False,
        )
        engines = state.scans.build_engines(options)
        by_name = {e.name: e for e in engines}
        print(f"moteurs : {list(by_name)}", flush=True)

        clam = by_name["clamav"]
        print(f"clamav._tcp = {clam._tcp}", flush=True)
        print(f"clamav._clamscan = {clam._clamscan}", flush=True)
        timed("daemon_available()", clam.daemon_available)
        timed("daemon_available() (2e appel)", clam.daemon_available)

        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        samples = [
            str(Path(system_root) / "system32" / "cmd.exe"),
            str(Path(system_root) / "system32" / "cscript.exe"),
            str(Path(system_root) / "explorer.exe"),
        ]
        for path in samples:
            if not os.path.exists(path):
                continue
            size = os.path.getsize(path)
            print(f"== {path} ({size} octets)", flush=True)
            ctx = FileContext(path, size=size)
            timed("clamav._scan_instream",
                  lambda: clam._scan_instream(ctx))
            for name, engine in by_name.items():
                timed(f"moteur {name}",
                      lambda e=engine: len(e.scan(ctx)))
    finally:
        state.shutdown()
    print("PROBE2_DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
