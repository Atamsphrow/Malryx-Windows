"""Moteur ClamAV embarqué : démon clamd local (TCP 127.0.0.1) + mises à jour freshclam.

clamd charge les signatures une seule fois en mémoire (~1 Go) : ensuite chaque fichier
est analysé en quelques millisecondes via le protocole INSTREAM.
"""
import socket
import struct
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

from .paths import IS_WIN, data_dir, find_tool

NO_WINDOW = 0x08000000 if IS_WIN else 0
CHUNK = 64 * 1024


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ClamAV:
    def __init__(self, log=print):
        self.log = log
        self.db_dir = data_dir("clamav-db")
        self.proc = None
        self.port = None
        self.state = "arrêté"  # arrêté / chargement / prêt / indisponible / erreur
        self.version = None
        self._lock = threading.Lock()

    # ---------- informations ----------
    @property
    def clamd(self):
        return find_tool("clamd", "clamav")

    @property
    def freshclam(self):
        return find_tool("freshclam", "clamav")

    def has_db(self):
        return any(self.db_dir.glob("*.c[vl]d")) or any(self.db_dir.glob("*.hdb"))

    def db_info(self):
        files = list(self.db_dir.glob("*.c[vl]d"))
        if not files:
            return "aucune signature"
        newest = max(f.stat().st_mtime for f in files)
        size = sum(f.stat().st_size for f in files) / 1e6
        return f"{len(files)} bases, {size:.0f} Mo, mises à jour le {datetime.fromtimestamp(newest):%d/%m/%Y %H:%M}"

    @property
    def ready(self):
        return self.state == "prêt"

    # ---------- démon ----------
    def _write_conf(self):
        conf = data_dir("clamd.conf")
        conf.write_text("\n".join([
            f'DatabaseDirectory "{self.db_dir}"',
            "TCPSocket %d" % self.port,
            "TCPAddr 127.0.0.1",
            "Foreground yes",
            "StreamMaxLength 200M",
            "MaxFileSize 200M",
            "MaxScanSize 400M",
            "MaxThreads 4",
            "ConcurrentDatabaseReload no",
            f'LogFile "{data_dir("clamd.log")}"',
            "LogFileMaxSize 5M",
        ]) + "\n", encoding="utf-8")
        return conf

    def start(self, wait=True, timeout=240):
        if not self.clamd:
            self.state = "indisponible"
            self.log("[ClamAV] moteur non embarqué dans cette version")
            return False
        if not self.has_db():
            self.state = "indisponible"
            self.log("[ClamAV] aucune signature : lance une mise à jour")
            return False
        self.stop()
        self._kill_stale()
        self.port = _free_port()
        conf = self._write_conf()
        self.state = "chargement"
        self.log("[ClamAV] chargement des signatures en mémoire…")
        try:
            self.proc = subprocess.Popen([self.clamd, f"--config-file={conf}"], stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL, creationflags=NO_WINDOW)
        except OSError as e:
            self.state = "erreur"; self.log(f"[ClamAV] démarrage impossible : {e}")
            return False
        try:
            data_dir("clamd.pid").write_text(str(self.proc.pid))
        except OSError:
            pass
        if not wait:
            return True
        t0 = time.time()
        while time.time() - t0 < timeout:
            if self.proc.poll() is not None:
                self.state = "erreur"
                self.log(f"[ClamAV] clamd s'est arrêté (voir {data_dir('clamd.log')})")
                return False
            if self._command(b"zPING\0", timeout=2) == "PONG":
                self.version = self._command(b"zVERSION\0")
                self.state = "prêt"
                self.log(f"[ClamAV] prêt en {time.time() - t0:.0f} s – {self.version}")
                return True
            time.sleep(1)
        self.state = "erreur"
        return False

    def _kill_stale(self):
        """Arrête un clamd resté orphelin après un plantage (il verrouille le journal et la mémoire)."""
        pidf = data_dir("clamd.pid")
        if not pidf.exists():
            return
        try:
            import psutil
            p = psutil.Process(int(pidf.read_text().strip()))
            if "clamd" in p.name().lower():
                p.kill(); p.wait(5)
        except Exception:
            pass
        pidf.unlink(missing_ok=True)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self._command(b"zSHUTDOWN\0", timeout=2)
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None
        if self.state != "indisponible":
            self.state = "arrêté"

    def _command(self, cmd, timeout=10):
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as s:
                s.sendall(cmd)
                return self._recv(s)
        except OSError:
            return None

    @staticmethod
    def _recv(s):
        data = b""
        while not data.endswith(b"\0"):
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.rstrip(b"\0").decode("utf-8", "ignore").strip()

    # ---------- analyse ----------
    def scan_bytes_stream(self, fileobj):
        with socket.create_connection(("127.0.0.1", self.port), timeout=120) as s:
            s.sendall(b"zINSTREAM\0")
            while True:
                chunk = fileobj.read(CHUNK)
                if not chunk:
                    break
                s.sendall(struct.pack("!L", len(chunk)) + chunk)
            s.sendall(struct.pack("!L", 0))
            return self._recv(s)

    def scan(self, path):
        """Retourne le nom de la menace, ou None."""
        if not self.ready:
            return None
        try:
            with open(path, "rb") as f:
                resp = self.scan_bytes_stream(f)
        except OSError:
            return None
        if resp and resp.endswith("FOUND"):
            return resp.split(":", 1)[-1].replace("FOUND", "").strip()
        return None

    def scan_data(self, data):
        if not self.ready:
            return None
        import io
        try:
            resp = self.scan_bytes_stream(io.BytesIO(data))
        except OSError:
            return None
        if resp and resp.endswith("FOUND"):
            return resp.split(":", 1)[-1].replace("FOUND", "").strip()
        return None

    # ---------- mise à jour ----------
    def update(self, on_line=None):
        if not self.freshclam:
            return False, "freshclam non embarqué"
        conf = data_dir("freshclam.conf")
        conf.write_text("\n".join([
            f'DatabaseDirectory "{self.db_dir}"',
            "DatabaseMirror database.clamav.net",
            "DNSDatabaseInfo no",          # pas de requête DNS TXT : vérification directe en HTTPS
            "ConnectTimeout 30",
            "ReceiveTimeout 0",
            "Checks 0",
        ]) + "\n", encoding="utf-8")
        cmd = [self.freshclam, f"--config-file={conf}", f"--datadir={self.db_dir}", "--stdout"]
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                 encoding="utf-8", errors="ignore", creationflags=NO_WINDOW)
        except OSError as e:
            return False, str(e)
        out = []
        for line in p.stdout:
            line = line.strip()
            if line:
                out.append(line)
                if on_line:
                    on_line(line)
        p.wait()
        ok = p.returncode in (0, 1) and self.has_db()  # 1 = déjà à jour
        if ok and self.ready:
            self._command(b"zRELOAD\0")
        return ok, "\n".join(out[-5:])

    def reload_or_start(self):
        if self.ready:
            self._command(b"zRELOAD\0")
            return True
        return self.start()
