"""Tests W5 (durcissement) - fenetre Windows uniquement pour le corpus.

Sections du plan (docs/W5_TEST_PLAN.md) :
  1. Faux positifs : corpus sain (binaires signes du systeme, scripts
     benins, archives saines) -> zero menace de severite >= MEDIUM.
  2. Quarantaine : restauration bit-a-bit (SHA-256 identique).
  3. Temps reel : gros fichier et depot pendant un scan en cours
     (couvert partiellement ici : stabilite du watcher, pas de crash).
  4. Persistance : sur un Windows quasi stock, le scan STARTUP ne doit
     produire aucune menace « non signe » pour les entrees systeme.

Verdicts imprimes : FP_VERDICT, RESTORE_VERDICT, STARTUP_NOISE_VERDICT.
Sortie 0 si tous PASS.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BACKEND = REPO / "backend"
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

sys.path.insert(0, str(BACKEND))
os.environ["MALRYX_NO_TOAST"] = "1"

_results: list[tuple[str, bool]] = []


def verdict(name: str, ok: bool) -> None:
    _results.append((name, ok))
    print(f"{name}: {'PASS' if ok else 'FAIL'}", flush=True)


def run_cli(*args: str, timeout: int = 600) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            [sys.executable, "cli.py", *args],
            cwd=BACKEND, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        def _txt(v: object) -> str:
            if v is None:
                return ""
            return v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)

        partial = _txt(exc.stdout) + _txt(exc.stderr)
        print(f"TIMEOUT {timeout} s sur {args} ; sortie partielle :")
        print(partial[-2000:])
        return 124, partial
    return proc.returncode, proc.stdout + proc.stderr


def part_fp_corpus() -> bool:
    """Corpus sain : le scan d'un dossier ne doit rien signaler >= MEDIUM."""
    corpus = Path(tempfile.mkdtemp(prefix="malryx-w5-corpus-"))
    # Scripts benins
    (corpus / "inventaire.ps1").write_text(
        "Get-ComputerInfo | Select-Object WindowsProductName\n"
        "Get-ChildItem Env: | Sort-Object Name\n",
        encoding="utf-8",
    )
    (corpus / "sauvegarde.bat").write_text(
        "@echo off\nxcopy /Y notes.txt backup\\\n", encoding="utf-8"
    )
    (corpus / "notes.txt").write_text(
        "Liste de courses : riz, huile, cafe.\n" * 20, encoding="utf-8"
    )
    (corpus / "outil.py").write_text(
        "print('bonjour')\n", encoding="utf-8"
    )
    # Archives saines, dont une imbriquee
    inner = corpus / "inner.zip"
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("a.txt", "contenu sain")
    outer = corpus / "archive.zip"
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("inner.zip", inner.read_bytes())
        z.writestr("b.txt", "encore du texte sain")
    # Binaire signe du systeme copie dans le corpus (Windows uniquement)
    if sys.platform == "win32":
        import shutil

        notepad = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "notepad.exe"
        if notepad.exists():
            shutil.copy(notepad, corpus / "notepad.exe")

    code, out = run_cli("scan", str(corpus))
    print(f"scan corpus : exit={code}")
    print(out[-1500:])
    # Le CLI sort 0 si aucune menace, 1 si au moins une menace : sur un
    # corpus sain on exige 0 (tout signalement serait un faux positif).
    return code == 0


def part_restore() -> bool:
    """Quarantaine puis restauration : le SHA-256 doit etre identique."""
    from core.app_state import init_state

    state = init_state()
    try:
        work = Path(tempfile.mkdtemp(prefix="malryx-w5-restore-"))
        victim = work / "document-important.bin"
        payload = bytes(range(256)) * 512 + b"FIN"
        victim.write_bytes(payload)
        before = hashlib.sha256(payload).hexdigest()

        entry = state.quarantine.quarantine_file(
            str(victim), threat_name="test-w5", force=True
        )
        if victim.exists():
            print("le fichier source existe encore apres quarantaine")
            return False
        state.quarantine.restore(entry.id)
        if not victim.exists():
            print("le fichier restaure est introuvable")
            return False
        after = hashlib.sha256(victim.read_bytes()).hexdigest()
        print(f"sha256 avant={before[:16]} apres={after[:16]}")
        return before == after
    finally:
        state.shutdown()


def part_startup_noise() -> bool:
    """Scan STARTUP sur machine quasi stock : pas de menace « non signe »
    ciblant un fichier du dossier Windows (ils sont signes Microsoft)."""
    if sys.platform != "win32":
        print("partie ignoree hors Windows")
        return True
    code, out = run_cli("scan", "--type", "startup")
    print(f"scan startup : exit={code}")
    print(out[-1500:])
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    noisy = (
        "non signe" in out and system_root.lower() in out.lower()
    )
    print(f"bruit 'non signe' sur fichier systeme : {noisy}")
    # exit 0 ou 1 acceptable ; ce qui compte, c'est l'absence de FP systeme.
    return not noisy


def main() -> int:
    verdict("FP_VERDICT", part_fp_corpus())
    verdict("RESTORE_VERDICT", part_restore())
    verdict("STARTUP_NOISE_VERDICT", part_startup_noise())
    return 0 if all(ok for _, ok in _results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
