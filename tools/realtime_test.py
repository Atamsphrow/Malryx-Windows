"""Test W2 : protection temps reel Windows de bout en bout.

Precondition : clamd en cours d'execution sur 127.0.0.1:3310
(voir .github/workflows/w2-service.yml).

Scenario :
  1. demarre l'AppState avec quarantaine automatique active et un
     dossier surveille temporaire (MALRYX_WATCH_DIRS) ;
  2. y depose un fichier sain -> il doit rester en place ;
  3. y depose EICAR -> il doit etre mis en quarantaine en moins de 10 s
     (critere W2), via ReadDirectoryChangesW.

Verdict final : REALTIME_VERDICT: PASS / FAIL. Code de sortie 0 si PASS.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BACKEND = REPO / "backend"
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

sys.path.insert(0, str(BACKEND))
os.environ["MALRYX_NO_TOAST"] = "1"


async def scenario(state, watch_dir: Path) -> tuple[bool, float]:
    state.realtime.start()
    await asyncio.sleep(2.0)  # laisser les threads RDW s'armer

    clean = watch_dir / "document.txt"
    clean.write_text("Fichier sain depose pendant le test.\n", encoding="utf-8")
    await asyncio.sleep(2.0)
    clean_ok = clean.exists()
    print(f"fichier sain conserve : {clean_ok}")

    eicar = watch_dir / "eicar.com"
    start = time.monotonic()
    eicar.write_bytes(EICAR)
    latency = -1.0
    while time.monotonic() - start < 15.0:
        await asyncio.sleep(0.25)
        entries = state.quarantine.list_entries()
        if not eicar.exists() and entries:
            latency = time.monotonic() - start
            break
    print(f"latence detection + quarantaine : {latency:.2f} s" if latency >= 0
          else "EICAR toujours present apres 15 s, quarantaine vide ou fichier intact")
    return clean_ok and 0 <= latency < 10.0, latency


def main() -> int:
    # Watchdog : si le scenario se bloque quelque part, on veut savoir OU
    # (piles de tous les threads dans les logs CI) plutot qu'un run qui
    # pend jusqu'au timeout GitHub. Ajoute apres le 1er passage W2, dont
    # l'etape temps reel ne rendait pas la main.
    import faulthandler

    faulthandler.dump_traceback_later(240, exit=True)
    watch_dir = Path(tempfile.mkdtemp(prefix="malryx-w2-watch-"))
    os.environ["MALRYX_WATCH_DIRS"] = str(watch_dir)
    print(f"dossier surveille : {watch_dir}")

    from core.app_state import init_state

    state = init_state()
    state.settings.auto_quarantine = True
    try:
        ok, _latency = asyncio.run(scenario(state, watch_dir))
    finally:
        state.shutdown()

    if ok:
        print("REALTIME_VERDICT: PASS")
        return 0
    print("REALTIME_VERDICT: FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
