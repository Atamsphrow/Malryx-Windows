"""Client du pilote noyau MalryxFlt (driver/) via le Filter Manager (fltlib.dll).

Le pilote envoie, pour chaque création de processus, une requête :
    MALRYX_REQUEST { ULONG ProcessId; ULONG ParentId; ULONG PathLength; WCHAR Path[520];
                     ULONG CmdLength; WCHAR Cmd[1024]; }
et attend MALRYX_REPLY { ULONG Block; } pendant 3 s maximum (au-delà : autorisé).
"""
import ctypes
import struct
import threading
from concurrent.futures import ThreadPoolExecutor

from .paths import IS_WIN

PORT = "\\MalryxPort"
HDR = 16                        # FILTER_MESSAGE_HEADER : ULONG ReplyLength + ULONGLONG MessageId
PATH_CH, CMD_CH = 520, 1024
REQ = 12 + PATH_CH * 2 + 4 + CMD_CH * 2
MSG = HDR + REQ


def nt_to_dos(path):
    """\\??\\C:\\x, \\Device\\HarddiskVolume3\\x  ->  C:\\x"""
    if path.startswith("\\??\\"):
        return path[4:]
    if not IS_WIN or not path.startswith("\\Device\\"):
        return path
    buf = ctypes.create_unicode_buffer(1024)
    for letter in "CDEFGHIJKLMNOPQRSTUVWXYZAB":
        if ctypes.windll.kernel32.QueryDosDeviceW(f"{letter}:", buf, 1024):
            dev = buf.value
            if path.lower().startswith(dev.lower() + "\\"):
                return f"{letter}:" + path[len(dev):]
    return path


class KernelClient:
    def __init__(self, decide, log=print):
        self.decide, self.log = decide, log
        self.port = None
        self.fltlib = None
        self.stop_evt = threading.Event()
        self.pool = ThreadPoolExecutor(max_workers=6, thread_name_prefix="kernel")

    @staticmethod
    def driver_loaded():
        if not IS_WIN:
            return False
        import subprocess
        out = subprocess.run(["fltmc"], capture_output=True, text=True, creationflags=0x08000000).stdout
        return "malryxflt" in out.lower()

    def connect(self):
        if not IS_WIN:
            return False
        try:
            self.fltlib = ctypes.WinDLL("fltlib.dll")
        except OSError:
            return False
        h = ctypes.c_void_p()
        hr = self.fltlib.FilterConnectCommunicationPort(ctypes.c_wchar_p(PORT), 0, None, 0, None, ctypes.byref(h))
        if hr != 0:
            return False  # pilote absent, ou Malryx sans droits administrateur
        self.port = h
        return True

    def start(self):
        threading.Thread(target=self._loop, daemon=True, name="kernel-client").start()

    def _loop(self):
        while not self.stop_evt.is_set():
            buf = ctypes.create_string_buffer(MSG)
            hr = self.fltlib.FilterGetMessage(self.port, buf, MSG, None)
            if hr != 0:
                if not self.stop_evt.is_set():
                    self.log(f"Pilote noyau : connexion perdue (0x{hr & 0xFFFFFFFF:08X})")
                return
            self.pool.submit(self._handle, bytes(buf))

    def _handle(self, raw):
        _, msg_id = struct.unpack_from("<L4xQ", raw, 0)
        pid, ppid, plen = struct.unpack_from("<LLL", raw, HDR)
        path = raw[HDR + 12: HDR + 12 + min(plen, PATH_CH - 1) * 2].decode("utf-16-le", "ignore")
        clen, = struct.unpack_from("<L", raw, HDR + 12 + PATH_CH * 2)
        off = HDR + 16 + PATH_CH * 2
        cmd = raw[off: off + min(clen, CMD_CH - 1) * 2].decode("utf-16-le", "ignore")
        block = False
        try:
            block = bool(self.decide(pid, ppid, nt_to_dos(path), cmd))
        except Exception as e:
            self.log(f"Pilote noyau : erreur d'analyse ({e})")
        # FILTER_REPLY_HEADER (NTSTATUS Status, ULONGLONG MessageId) + MALRYX_REPLY (ULONG Block)
        reply = struct.pack("<l4xQL", 0, msg_id, 1 if block else 0)
        self.fltlib.FilterReplyMessage(self.port, ctypes.c_char_p(reply), len(reply))

    def stop(self):
        self.stop_evt.set()
        if self.port:
            ctypes.windll.kernel32.CloseHandle(self.port)
            self.port = None
