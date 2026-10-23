"""Test W0 : clamd en TCP (le mode retenu pour Windows, faute d'AF_UNIX).

Envoie zPING puis zVERSION à un démon clamd (défaut 127.0.0.1:3310).
PASS si PING répond PONG. Usage : python clamd_tcp_test.py [hôte] [port]
"""

from __future__ import annotations

import socket
import sys


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
    try:
        with socket.create_connection((host, port), timeout=5.0) as sock:
            pong = ask(sock, b"zPING")
            version = ask(sock, b"zVERSION")
    except OSError as exc:
        print(f"FAIL: clamd injoignable sur {host}:{port} ({exc})")
        return 1
    if pong != "PONG":
        print(f"FAIL: zPING a répondu {pong!r} au lieu de PONG")
        return 1
    print(f"PASS: clamd {host}:{port} répond PONG, version = {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
