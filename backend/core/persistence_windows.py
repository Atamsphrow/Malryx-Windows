"""Points de persistance Windows (W3) : enumeration des mecanismes
classiques de demarrage automatique, pour le scan STARTUP / SMART.

Sources inspectees (lecture seule, aucun droit admin requis pour HKCU,
lecture HKLM / taches / services en acces standard) :
- cles registre Run et RunOnce (HKCU + HKLM, vues 64 et 32 bits) ;
- dossiers Demarrage (utilisateur et commun) ;
- taches planifiees (fichiers XML de %SystemRoot%\\System32\\Tasks) ;
- services (HKLM\\SYSTEM\\CurrentControlSet\\Services, valeur ImagePath).

Chaque entree expose le chemin de l'executable cible quand il peut etre
extrait de la ligne de commande, pour que les moteurs scannent le fichier
reel. Hors Windows, l'enumeration retourne une liste vide ; les fonctions
d'extraction restent testables partout.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

from core.config import IS_WINDOWS

log = logging.getLogger(__name__)

EXECUTABLE_SUFFIXES = (
    ".exe", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".hta", ".msi", ".dll",
)

_RUN_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
]


@dataclass
class PersistenceEntry:
    kind: str            # "run_key" | "startup_folder" | "scheduled_task" | "service"
    name: str            # nom de la valeur / du fichier / de la tache / du service
    command: str         # ligne de commande ou chemin brut, tel que lu
    target: str | None   # executable extrait (chemin developpe), si identifiable
    location: str        # ou l'entree a ete trouvee (cle, dossier...)


_ENV_PATTERN = re.compile(r"%([^%]+)%")


def _expand_env(text: str, env: dict[str, str] | None = None) -> str:
    source = env if env is not None else dict(os.environ)

    def repl(match: re.Match[str]) -> str:
        return source.get(match.group(1), source.get(match.group(1).upper(),
                                                     match.group(0)))

    return _ENV_PATTERN.sub(repl, text)


_PATH_PATTERN = re.compile(
    r"(?:[A-Za-z]:|\\\\)[^\s\"]+?(?:"
    + "|".join(re.escape(s) for s in EXECUTABLE_SUFFIXES)
    + r")(?=[\s,\"]|$)",
    re.IGNORECASE,
)


def extract_exe_path(command: str, env: dict[str, str] | None = None) -> str | None:
    """Extrait le chemin de l'executable d'une ligne de commande Windows.

    Gere : chemin entre guillemets, variables %VAR%, arguments apres le
    chemin, et wrappers (powershell -File script, cmd /c script...) ou le
    premier chemin complet de la ligne est retenu. Un chemin non quote
    contenant des espaces est intrinsequement ambigu : il retourne None
    plutot qu'un faux chemin. Retourne None si rien de plausible.
    """
    if not command:
        return None
    text = _expand_env(command.strip(), env)
    if not text:
        return None

    if text.startswith('"'):
        end_quote = text.find('"', 1)
        if end_quote > 1:
            candidate = text[1:end_quote]
            return candidate if _looks_like_path(candidate) else None
        return None

    match = _PATH_PATTERN.search(text)
    if match:
        candidate = match.group(0)
        return candidate if _looks_like_path(candidate) else None

    # Repli : chemin relatif avec separateurs, termine par une extension.
    lowered = text.lower()
    for suffix in EXECUTABLE_SUFFIXES:
        idx = lowered.find(suffix)
        if idx != -1:
            candidate = text[: idx + len(suffix)].strip().strip('"')
            return candidate if _looks_like_path(candidate) else None
    return None


def _looks_like_path(candidate: str) -> bool:
    if not candidate:
        return False
    # Chemin absolu (C:\..., \\partage\...) ou relatif avec separateur.
    return ":\\" in candidate or candidate.startswith("\\\\") or "\\" in candidate


def _startup_folders() -> list[Path]:
    folders: list[Path] = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        folders.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu"
                       / "Programs" / "Startup")
    program_data = os.environ.get("ProgramData")
    if program_data:
        folders.append(Path(program_data) / "Microsoft" / "Windows"
                       / "Start Menu" / "Programs" / "Startup")
    return folders


def _entries_from_registry() -> list[PersistenceEntry]:
    entries: list[PersistenceEntry] = []
    try:
        import winreg
    except ImportError:
        return entries
    roots = [
        (winreg.HKEY_CURRENT_USER, "HKCU"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
    ]
    for root, root_name in roots:
        for key_path in _RUN_KEYS:
            try:
                key = winreg.OpenKey(root, key_path)
            except OSError:
                continue
            try:
                index = 0
                while True:
                    try:
                        name, value, _type = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
                    if isinstance(value, str) and value.strip():
                        entries.append(PersistenceEntry(
                            kind="run_key",
                            name=name,
                            command=value,
                            target=extract_exe_path(value),
                            location=f"{root_name}\\{key_path}",
                        ))
            finally:
                winreg.CloseKey(key)
    return entries


def _entries_from_startup_folders() -> list[PersistenceEntry]:
    entries: list[PersistenceEntry] = []
    for folder in _startup_folders():
        if not folder.is_dir():
            continue
        for child in sorted(folder.iterdir()):
            if child.is_file() and child.name.lower() != "desktop.ini":
                entries.append(PersistenceEntry(
                    kind="startup_folder",
                    name=child.name,
                    command=str(child),
                    target=str(child),
                    location=str(folder),
                ))
    return entries


def _entries_from_tasks() -> list[PersistenceEntry]:
    entries: list[PersistenceEntry] = []
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    tasks_dir = Path(system_root) / "System32" / "Tasks"
    if not tasks_dir.is_dir():
        return entries
    import xml.etree.ElementTree as ET

    for task_file in tasks_dir.rglob("*"):
        if not task_file.is_file():
            continue
        try:
            tree = ET.parse(task_file)
        except Exception:
            continue
        for elem in tree.iter():
            if elem.tag.endswith("}Command") or elem.tag == "Command":
                command = (elem.text or "").strip()
                if command:
                    entries.append(PersistenceEntry(
                        kind="scheduled_task",
                        name=str(task_file.relative_to(tasks_dir)),
                        command=command,
                        target=extract_exe_path(command),
                        location=str(task_file),
                    ))
    return entries


def _entries_from_services() -> list[PersistenceEntry]:
    entries: list[PersistenceEntry] = []
    try:
        import winreg
    except ImportError:
        return entries
    base = r"SYSTEM\CurrentControlSet\Services"
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
    except OSError:
        return entries
    try:
        index = 0
        while True:
            try:
                service_name = winreg.EnumKey(key, index)
            except OSError:
                break
            index += 1
            try:
                sub = winreg.OpenKey(key, service_name)
                try:
                    image_path, _type = winreg.QueryValueEx(sub, "ImagePath")
                finally:
                    winreg.CloseKey(sub)
            except OSError:
                continue
            if isinstance(image_path, str) and image_path.strip():
                entries.append(PersistenceEntry(
                    kind="service",
                    name=service_name,
                    command=image_path,
                    target=extract_exe_path(image_path),
                    location=f"HKLM\\{base}\\{service_name}",
                ))
    finally:
        winreg.CloseKey(key)
    return entries


def list_persistence_entries() -> list[PersistenceEntry]:
    """Toutes les entrees de persistance lisibles. Vide hors Windows."""
    if not IS_WINDOWS:
        return []
    entries: list[PersistenceEntry] = []
    for source in (
        _entries_from_registry,
        _entries_from_startup_folders,
        _entries_from_tasks,
        _entries_from_services,
    ):
        try:
            entries.extend(source())
        except Exception as exc:
            log.debug("enumeration persistance (%s) : %s", source.__name__, exc)
    return entries


def persistence_targets() -> list[str]:
    """Chemins de fichiers existants references par la persistance."""
    seen: set[str] = set()
    targets: list[str] = []
    for folder in _startup_folders():
        if folder.is_dir():
            targets.append(str(folder))
    for entry in list_persistence_entries():
        if entry.target and os.path.isfile(entry.target):
            key = entry.target.lower()
            if key not in seen:
                seen.add(key)
                targets.append(entry.target)
    return targets
