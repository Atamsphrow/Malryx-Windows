"""Test W0 : clamd en TCP (le mode retenu pour Windows, faute d'AF_UNIX).

Envoie zPING puis zVERSION à un démon clamd (défaut 127.0.0.1:3310).
PASS si PING répond PONG. Usage : python clamd_tcp_test.py [hôte] [port] [attente_s]

L'attente (défaut 30 s) couvre le démarrage réel de clamd : le port TCP
s'ouvre avant la fin du chargement des signatures, et les premières
connexions sont alors interrompues (constaté en CI le 2026-10-23,
WinError 10053). Un client correct réessaie jusqu'à PONG.
"""

from __future__ import annotations

import socket
import sys
import time


def ask(sock: socket.socket, command: bytes) -> str:
    sock.sendall(command + b"\x00")
    data = b""
    while not data.endswith(b"\x00") and len(data) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.rstrip(b"\x00").decode("utf-8", errors="replace").strip()


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3310
    wait_s = float(sys.argv[3]) if len(sys.argv) > 3 else 30.0
    deadline = time.monotonic() + wait_s
    last_error: OSError | None = None
    while True:
        try:
            with socket.create_connection((host, port), timeout=5.0) as sock:
                pong = ask(sock, b"zPING")
            version = ""
            if pong == "PONG":
                with socket.create_connection((host, port), timeout=5.0) as sock:
                    version = ask(sock, b"zVERSION")
            if pong == "PONG":
                print(f"PASS: clamd {host}:{port} répond PONG, version = {version}")
                return 0
            last_error = OSError(f"zPING a répondu {pong!r} au lieu de PONG")
        except OSError as exc:
            last_error = exc
        if time.monotonic() >= deadline:
            print(f"FAIL: clamd {host}:{port} sans PONG après {wait_s:.0f} s ({last_error})")
            return 1
        time.sleep(2.0)


if __name__ == "__main__":
    raise SystemExit(main())
