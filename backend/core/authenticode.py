"""Verification de signature Authenticode (W3), via WinVerifyTrust.

Utilise wintrust.dll en ctypes : aucune dependance, fonctionne hors
ligne (aucune verification de revocation reseau : WTD_REVOKE_NONE —
un certificat revoque mais bien forme sera donc rapporte VALID ;
limite assumee et documentee, le controle CRL/OCSP viendra avec la
connectivite optionnelle).

Resultats :
- VALID    : signature presente et chaine de confiance verifiee ;
- UNSIGNED : aucune signature (TRUST_E_NOSIGNATURE et proches) ;
- INVALID  : signature presente mais non fiable (hash, chaine...) ;
- UNKNOWN  : hors Windows ou erreur d'appel inclassable.

Le resultat est mis en cache par (chemin, taille, mtime).
"""

from __future__ import annotations

import ctypes
import os
import sys
from enum import Enum

_cache: dict[tuple[str, int, int], "AuthStatus"] = {}


class AuthStatus(str, Enum):
    VALID = "valid"
    UNSIGNED = "unsigned"
    INVALID = "invalid"
    UNKNOWN = "unknown"


# Codes de retour WinVerifyTrust (winerror.h / trust.h)
_TRUST_CODES_UNSIGNED = {
    0x800B0100,  # TRUST_E_NOSIGNATURE
    0x800B0110,  # TRUST_E_NOSIGNATURE (variante)
    0x800B010E,  # TRUST_E_NO_SIGNER_CERT - traite comme non signe ici
}


def _to_signed(code: int) -> int:
    return code - 0x100000000 if code >= 0x80000000 else code


def verify_signature(path: str) -> AuthStatus:
    """Statut Authenticode d'un fichier. UNKNOWN hors Windows."""
    if sys.platform != "win32":
        return AuthStatus.UNKNOWN
    try:
        stat = os.stat(path)
        key = (path.lower(), stat.st_size, int(stat.st_mtime))
    except OSError:
        return AuthStatus.UNKNOWN
    cached = _cache.get(key)
    if cached is not None:
        return cached
    status = _verify_windows(path)
    _cache[key] = status
    return status


def _verify_windows(path: str) -> AuthStatus:
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.POINTER(GUID)),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
        ]

    # WINTRUST_ACTION_GENERIC_VERIFY_V2
    action = GUID(
        0x00AAC56B, 0xCD44, 0x11D0,
        (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )
    file_info = WINTRUST_FILE_INFO(
        cbStruct=ctypes.sizeof(WINTRUST_FILE_INFO),
        pcwszFilePath=path,
        hFile=None,
        pgKnownSubject=None,
    )
    data = WINTRUST_DATA(
        cbStruct=ctypes.sizeof(WINTRUST_DATA),
        pPolicyCallbackData=None,
        pSIPClientData=None,
        dwUIChoice=2,        # WTD_UI_NONE
        fdwRevocationChecks=0,  # WTD_REVOKE_NONE
        dwUnionChoice=1,     # WTD_CHOICE_FILE
        pFile=ctypes.pointer(file_info),
        dwStateAction=1,     # WTD_STATEACTION_VERIFY
        hWVTStateData=None,
        pwszURLReference=None,
        dwProvFlags=0,
        dwUIContext=0,
    )
    try:
        wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
        wintrust.WinVerifyTrust.restype = ctypes.c_long
        wintrust.WinVerifyTrust.argtypes = [
            wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p,
        ]
        result = wintrust.WinVerifyTrust(
            None, ctypes.byref(action), ctypes.byref(data)
        )
        # Fermeture propre de l'etat (WTD_STATEACTION_CLOSE = 2).
        data.dwStateAction = 2
        wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    except Exception:
        return AuthStatus.UNKNOWN

    code = result & 0xFFFFFFFF
    if code == 0:
        return AuthStatus.VALID
    if code in _TRUST_CODES_UNSIGNED:
        return AuthStatus.UNSIGNED
    return AuthStatus.INVALID


# Dossiers ou un executable de demarrage non signe est un vrai signal
# (ecriture libre par l'utilisateur et les malwares, rarement du logiciel
# installe proprement).
RISKY_DIR_MARKERS = ("\\temp\\", "\\tmp\\", "\\downloads\\", "\\telechargements\\")


def is_risky_unsigned_location(path: str) -> bool:
    lowered = path.lower().replace("/", "\\")
    if any(marker in lowered for marker in RISKY_DIR_MARKERS):
        return True
    # %TEMP% lui-meme peut etre ailleurs que ...\\Temp\\.
    temp = os.environ.get("TEMP", "")
    return bool(temp) and lowered.startswith(temp.lower().replace("/", "\\"))
