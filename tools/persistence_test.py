"""Test W3 : persistance Windows + Authenticode + scans STARTUP / SMART.

Precondition : clamd en cours d'execution sur 127.0.0.1:3310
(voir .github/workflows/w3-persistence.yml).

Parties :
  A. extract_exe_path : cas unitaires (toutes plateformes).
  B. Windows reel : enumeration des points de persistance (les services
     doivent etre nombreux), Authenticode (explorer.exe = VALID,
     faux .exe dans Temp = UNSIGNED).
  C. Bout en bout : un faux point de demarrage (cle Run HKCU -> copie
     d'EICAR dans Temp, NON SIGNEE) doit etre attrape par
     `malryx scan --type startup` : signature EICAR + menace heuristique
     « executable non signe ». Nettoyage du registre a la fin.
  D. `malryx scan --type smart` doit se terminer sans erreur interne.

Verdicts imprimes : PERSISTENCE_VERDICT, AUTHENTICODE_VERDICT,
STARTUP_SCAN_VERDICT, SMART_VERDICT (PASS/FAIL chacun).
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BACKEND = REPO / "backend"
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

sys.path.insert(0, str(BACKEND))

failures: list[str] = []


def verdict(name: str, ok: bool) -> None:
    print(f"{name}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        failures.append(name)


def part_a() -> bool:
    from core.persistence_windows import extract_exe_path as ex

    os.environ.setdefault("APPDATA", r"C:\Users\x\AppData\Roaming")
    cases = [
        (r'"C:\Program Files\App\app.exe" /quiet', r"C:\Program Files\App\app.exe"),
        (r"C:\Users\x\AppData\Local\Temp\evil.exe -silent",
         r"C:\Users\x\AppData\Local\Temp\evil.exe"),
        (r"%APPDATA%\Microsoft\upd.exe",
         os.environ["APPDATA"] + r"\Microsoft\upd.exe"),
        (r"C:\Windows\System32\svchost.exe -k netsvcs",
         r"C:\Windows\System32\svchost.exe"),
        (r"powershell -File C:\scripts\run.ps1", r"C:\scripts\run.ps1"),
        (r"cmd /c C:\Temp\run.bat", r"C:\Temp\run.bat"),
        (r"C:\Windows\System32\rundll32.exe C:\bad\evil.dll,Entry",
         r"C:\Windows\System32\rundll32.exe"),
        (r"C:\Program Files\App\app.exe /quiet", r"C:\Program Files\App\app.exe"),
        ("", None),
        ("juste-un-mot", None),
    ]
    ok = True
    for command, want in cases:
        got = ex(command)
        if got != want:
            ok = False
            print(f"  KO: {command!r} -> {got!r} (attendu {want!r})")
    return ok


def part_b() -> tuple[bool, bool]:
    from core.authenticode import AuthStatus, verify_signature
    from core.persistence_windows import list_persistence_entries

    entries = list_persistence_entries()
    by_kind: dict[str, int] = {}
    for entry in entries:
        by_kind[entry.kind] = by_kind.get(entry.kind, 0) + 1
    print(f"entrees de persistance par type : {by_kind}")
    persistence_ok = by_kind.get("service", 0) > 20

    explorer = Path(os.environ["SystemRoot"]) / "explorer.exe"
    status_explorer = verify_signature(str(explorer))
    print(f"Authenticode explorer.exe : {status_explorer}")
    fake = Path(tempfile.gettempdir()) / "malryx-w3-fake.exe"
    fake.write_text("ceci n'est pas un vrai PE", encoding="utf-8")
    status_fake = verify_signature(str(fake))
    print(f"Authenticode faux exe Temp : {status_fake}")
    fake.unlink(missing_ok=True)
    auth_ok = (
        status_explorer == AuthStatus.VALID
        and status_fake == AuthStatus.UNSIGNED
    )
    return persistence_ok, auth_ok


def run_cli(*args: str, timeout: int = 900) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "cli.py", *args],
        cwd=BACKEND, capture_output=True, text=True, timeout=timeout,
    )
    return proc.returncode, proc.stdout + proc.stderr


def part_c() -> bool:
    import winreg

    evil = Path(tempfile.gettempdir()) / "malryx-w3-evil.exe"
    evil.write_bytes(EICAR)
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        winreg.SetValueEx(key, "MalryxW3Test", 0, winreg.REG_SZ, str(evil))
        winreg.CloseKey(key)
        code, out = run_cli("scan", "--type", "startup")
        print(f"scan startup : exit={code}")
        found_eicar = "eicar" in out.lower()
        found_unsigned = "non signe" in out.lower() or "non signé" in out.lower()
        print(f"  detection EICAR via persistance : {found_eicar}")
        print(f"  menace 'non signe' presente : {found_unsigned}")
        if not (found_eicar and found_unsigned):
            print("----- sortie CLI (fin) -----")
            print(out[-3000:])
        return code == 1 and found_eicar and found_unsigned
    finally:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE
            )
            winreg.DeleteValue(key, "MalryxW3Test")
            winreg.CloseKey(key)
        except OSError:
            pass
        evil.unlink(missing_ok=True)


def part_d() -> bool:
    code, out = run_cli("scan", "--type", "smart", timeout=1200)
    print(f"scan smart : exit={code}")
    ok = code in (0, 1) and "erreur interne" not in out.lower() \
        and "analyse" in out.lower()
    if not ok:
        print("----- sortie CLI (fin) -----")
        print(out[-3000:])
    return ok


def main() -> int:
    verdict("PERSISTENCE_UNIT", part_a())
    if sys.platform == "win32":
        persistence_ok, auth_ok = part_b()
        verdict("PERSISTENCE_VERDICT", persistence_ok)
        verdict("AUTHENTICODE_VERDICT", auth_ok)
        verdict("STARTUP_SCAN_VERDICT", part_c())
        verdict("SMART_VERDICT", part_d())
    else:
        print("parties B-D ignorees hors Windows")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
