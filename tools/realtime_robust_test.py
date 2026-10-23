"""Test W5 section 3 : robustesse du temps reel.

Scenarios :
  a. un fichier de 300 Mo (au-dela de la limite de scan) depose dans le
     dossier surveille ne bloque pas le watcher : un EICAR depose juste
     apres est quand meme mis en quarantaine rapidement ;
  b. EICAR ecrit en deux fois (moitie, pause, moitie) : la detection a
     lieu apres l'ecriture complete (deuxieme evenement RDW) ;
  c. un fichier sain renomme en .exe n'est pas mis en quarantaine.

Verdict : REALTIME_ROBUST_VERDICT: PASS / FAIL.
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


async def wait_quarantined(state, timeout: float = 20.0) -> bool:
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        await asyncio.sleep(0.25)
        if state.quarantine.list_entries():
            return True
    return False


async def scenario(state, watch_dir: Path) -> bool:
    state.realtime.start()
    await asyncio.sleep(2.0)

    # (a) gros fichier : 300 Mo de zeros, au-dela de max_file_size (256).
    big = watch_dir / "gros-fichier.bin"
    with open(big, "wb") as handle:
        chunk = b"\0" * (1024 * 1024)
        for _ in range(300):
            handle.write(chunk)
    print(f"gros fichier depose : {big.stat().st_size} octets", flush=True)

    eicar_a = watch_dir / "eicar-a.com"
    eicar_a.write_bytes(EICAR)
    ok_a = await wait_quarantined(state, 20.0)
    print(f"(a) EICAR apres gros fichier, quarantaine : {ok_a}", flush=True)
    if not ok_a:
        return False
    # Vider la quarantaine pour le scenario suivant.
    for entry in state.quarantine.list_entries():
        state.quarantine.delete(entry.id)

    # (b) EICAR en deux ecritures separees de 2 s.
    eicar_b = watch_dir / "eicar-b.com"
    half = len(EICAR) // 2
    with open(eicar_b, "wb") as handle:
        handle.write(EICAR[:half])
    await asyncio.sleep(2.0)
    with open(eicar_b, "ab") as handle:
        handle.write(EICAR[half:])
    ok_b = await wait_quarantined(state, 20.0)
    print(f"(b) EICAR ecrit en deux fois, quarantaine : {ok_b}", flush=True)
    if not ok_b:
        return False
    for entry in state.quarantine.list_entries():
        state.quarantine.delete(entry.id)

    # (c) fichier sain renomme en .exe : aucune quarantaine.
    clean = watch_dir / "document.txt"
    clean.write_text("contenu sain\n", encoding="utf-8")
    await asyncio.sleep(1.0)
    renamed = watch_dir / "document.exe"
    clean.rename(renamed)
    await asyncio.sleep(4.0)
    entries = state.quarantine.list_entries()
    ok_c = renamed.exists() and not entries
    print(f"(c) sain renomme .exe, conserve et pas de quarantaine : {ok_c}",
          flush=True)
    return ok_c


def main() -> int:
    # Watchdog identique au test W2 : piles dumpes a 300 s si blocage.
    import faulthandler

    faulthandler.dump_traceback_later(300, exit=True)
    watch_dir = Path(tempfile.mkdtemp(prefix="malryx-w5-robust-"))
    os.environ["MALRYX_WATCH_DIRS"] = str(watch_dir)
    print(f"dossier surveille : {watch_dir}", flush=True)

    from core.app_state import init_state

    state = init_state()
    state.settings.auto_quarantine = True
    try:
        ok = asyncio.run(scenario(state, watch_dir))
    finally:
        state.shutdown()
    print(f"REALTIME_ROBUST_VERDICT: {'PASS' if ok else 'FAIL'}", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
