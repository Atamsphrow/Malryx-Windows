"""Prototype W0 : ReadDirectoryChangesW (surveillance temps réel Windows).

Crée un dossier temporaire, le surveille dans un thread, crée un fichier
dedans, et vérifie qu'un événement arrive dans les 10 secondes.
Sortie : PASS/FAIL/SKIP + code de retour 0/1/2.
Hors Windows : SKIP (code 2), ce test n'a de sens que sur la cible.
"""

from __future__ import annotations

import sys
import tempfile
import threading
import time
from pathlib import Path

TIMEOUT_S = 10.0


def run_windows() -> int:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    FILE_LIST_DIRECTORY = 0x0001
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
    FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
    FILE_NOTIFY_CHANGE_CREATION = 0x00000100
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.ReadDirectoryChangesW.restype = wintypes.BOOL
    kernel32.ReadDirectoryChangesW.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
        ctypes.c_void_p,
    ]

    watch_dir = Path(tempfile.mkdtemp(prefix="malryx-w0-rdw-"))
    handle = kernel32.CreateFileW(
        str(watch_dir), FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None,
    )
    if handle == INVALID_HANDLE_VALUE:
        print(f"FAIL: CreateFileW a échoué (erreur {ctypes.get_last_error()})")
        return 1

    result: dict[str, object] = {}

    def reader() -> None:
        buffer = ctypes.create_string_buffer(32 * 1024)
        returned = wintypes.DWORD(0)
        ok = kernel32.ReadDirectoryChangesW(
            handle, buffer, len(buffer), False,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE
            | FILE_NOTIFY_CHANGE_CREATION,
            ctypes.byref(returned), None, None,
        )
        result["ok"] = bool(ok)
        result["bytes"] = returned.value

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    time.sleep(1.0)  # laisser la surveillance s'armer
    probe = watch_dir / "probe-malryx-w0.txt"
    probe.write_text("malryx w0 probe", encoding="utf-8")

    thread.join(TIMEOUT_S)
    kernel32.CloseHandle(handle)
    if thread.is_alive():
        print(f"FAIL: aucun événement en {TIMEOUT_S:.0f} s")
        return 1
    if not result.get("ok") or not result.get("bytes"):
        print(f"FAIL: ReadDirectoryChangesW ok={result.get('ok')} bytes={result.get('bytes')}")
        return 1
    print(f"PASS: événement reçu pour {probe.name} ({result['bytes']} octets de notification)")
    return 0


def main() -> int:
    if sys.platform != "win32":
        print(f"SKIP: plateforme {sys.platform}, ReadDirectoryChangesW est Windows-only")
        return 2
    return run_windows()


if __name__ == "__main__":
    raise SystemExit(main())
