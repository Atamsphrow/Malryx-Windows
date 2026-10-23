"""Sonde de temps W3 : ou passe le temps d'un scan STARTUP ?

Les scans STARTUP/SMART depassaient 600/1200 s en CI malgre le triage
Authenticode. Cette sonde mesure, sur le runner, chaque phase avec des
temps reels au lieu d'hypotheses :

  1. enumeration des cibles de persistance ;
  2. verify_signature fichier par fichier (les 15 plus lents) ;
  3. scan complet (tous moteurs) des fichiers non signes — l'ensemble
     que le triage laisse passer — avec temps par fichier ;
  4. totaux et repartition par statut de signature.

Sortie progressive (python -u). Aucun verdict PASS/FAIL : PROBE_DONE.
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


def main() -> int:
    if sys.platform != "win32":
        print("sonde Windows uniquement")
        return 0

    from core.authenticode import verify_signature_debug
    from core.persistence_windows import persistence_targets

    t0 = time.monotonic()
    targets = persistence_targets()
    print(f"enumeration : {len(targets)} cibles en "
          f"{time.monotonic() - t0:.2f} s", flush=True)

    timings: list[tuple[float, str, str]] = []
    total_verify = 0.0
    by_status: dict[str, int] = {}
    unsigned: list[str] = []
    for path in targets:
        start = time.monotonic()
        status, code = verify_signature_debug(path)
        dt = time.monotonic() - start
        total_verify += dt
        by_status[status.value] = by_status.get(status.value, 0) + 1
        timings.append((dt, status.value, path))
        if status.value != "valid":
            unsigned.append(path)
    timings.sort(reverse=True)
    print(f"verify_signature : total {total_verify:.2f} s, "
          f"statuts {by_status}", flush=True)
    print("--- 15 verifications les plus lentes ---", flush=True)
    for dt, status, path in timings[:15]:
        print(f"  {dt:7.2f} s  {status:8s}  {path}", flush=True)
    print(f"fichiers a scanner en entier (non valides) : {len(unsigned)}",
          flush=True)

    # Scan complet des non-signes : temps par fichier, moteurs reels.
    from core.app_state import init_state
    from core.models import ScanOptions
    from core.scan_engine import FileContext

    state = init_state()
    try:
        options = ScanOptions(
            use_clamav=state.settings.clamav_enabled,
            use_yara=state.settings.yara_enabled,
            use_heuristics=state.settings.heuristics_enabled,
            use_hash_db=True,
            use_virustotal=False,
        )
        engines = state.scans.build_engines(options)
        print(f"moteurs : {[e.name for e in engines]}", flush=True)
        scan_timings: list[tuple[float, str, int]] = []
        total_scan = 0.0
        for path in unsigned:
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            ctx = FileContext(path, size=size)
            start = time.monotonic()
            for engine in engines:
                try:
                    engine.scan(ctx)
                except Exception as exc:
                    print(f"  erreur moteur {engine.name} sur {path} : {exc}",
                          flush=True)
            dt = time.monotonic() - start
            total_scan += dt
            scan_timings.append((dt, path, size))
        scan_timings.sort(reverse=True)
        print(f"scan complet des non-signes : total {total_scan:.2f} s",
              flush=True)
        print("--- 15 scans les plus lents ---", flush=True)
        for dt, path, size in scan_timings[:15]:
            print(f"  {dt:7.2f} s  {size/1e6:8.1f} Mo  {path}", flush=True)
    finally:
        state.shutdown()
    print("PROBE_DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
