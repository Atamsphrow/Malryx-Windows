"""Moteur heuristique : signaux de risque sans signature connue.

Chaque regle rend un score et une explication en francais destinee a etre
affichee telle quelle dans l'UI. Les scores s'additionnent, la severite finale
decoule du total. Une seule menace est emise par fichier, avec la liste des
raisons : c'est plus lisible qu'une avalanche d'alertes pour un meme fichier.

Une heuristique n'est pas une preuve. Le seuil est volontairement place assez
haut pour qu'un fichier legitime isole ne declenche rien, et aucune heuristique
seule ne peut atteindre la severite CRITICAL.
"""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from dataclasses import dataclass

from core.config import IS_LINUX, IS_WINDOWS
from core.models import DetectionSource, EngineStatus, Severity, Threat

from .base import Engine, FileContext

# Seuil d'emission. En dessous, on ne remonte rien.
SCORE_THRESHOLD = 40

# Extensions executables ou scriptables cote Windows (utile sur cle USB, 4.3/4.5).
WINDOWS_EXEC_EXT = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".msi", ".bat", ".cmd",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".hta", ".lnk",
}
# Extensions inoffensives en apparence, utilisees pour la double extension.
DECOY_EXT = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".gif",
    ".txt", ".mp3", ".mp4", ".avi", ".zip", ".rar",
}
SCRIPT_EXT = {".sh", ".bash", ".py", ".pl", ".rb", ".php", ".lua"}

# Dossiers ou un binaire executable n'a normalement rien a faire.
SUSPICIOUS_DIRS = ("/tmp", "/var/tmp", "/dev/shm", "/run/shm")

# Emplacements d'atterrissage classiques des droppers sous Windows.
# Un PE seul y vaut un signal modere (25-30) : des installeurs legitimes
# y transitent aussi, le seuil d'emission (40) exige une combinaison.
WINDOWS_SUSPICIOUS_MARKERS = (
    "\\temp\\",
    "\\tmp\\",
    "\\downloads\\",
    "\\telechargements\\",
    "\\users\\public\\",
    "\\appdata\\local\\temp\\",
    "\\programdata\\",
)

# Motifs d'obfuscation / telechargement-execution dans les scripts.
SCRIPT_PATTERNS: list[tuple[re.Pattern[bytes], int, str]] = [
    (
        re.compile(rb"(?:curl|wget)[^\n|;]{0,200}\|\s*(?:ba)?sh", re.I),
        35,
        "telecharge et execute directement du code distant (curl/wget | sh)",
    ),
    (
        re.compile(rb"base64\s+(?:-d|--decode)[^\n]{0,80}\|\s*(?:ba)?sh", re.I),
        35,
        "decode du base64 et l'execute immediatement",
    ),
    (
        re.compile(rb"eval\s*\(\s*base64_decode\s*\(", re.I),
        40,
        "eval(base64_decode(...)) : charge utile PHP obfusquee",
    ),
    (
        re.compile(rb"(?:exec|eval)\s*\(\s*(?:base64\.b64decode|__import__)", re.I),
        35,
        "execution de code Python obfusque (eval/exec sur du base64)",
    ),
    (
        re.compile(rb"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+", re.I),
        35,
        "ouvre un shell reseau via /dev/tcp (reverse shell)",
    ),
    (
        re.compile(rb"nc\s+(?:-[a-z]*e|-e)\s", re.I),
        30,
        "netcat avec execution de commande (-e) : reverse shell",
    ),
    (
        re.compile(rb"chattr\s+\+i|history\s+-c|unset\s+HISTFILE", re.I),
        20,
        "tente d'effacer ses traces (historique, attribut immuable)",
    ),
    (
        re.compile(rb"(?:crontab\s+-|/etc/cron\.d/)", re.I),
        15,
        "installe une tache planifiee",
    ),
    (
        re.compile(rb"FromBase64String|-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{40,}", re.I),
        35,
        "commande PowerShell encodee en base64",
    ),
    # -- Windows : telechargement-execution --------------------------------------
    (
        re.compile(rb"(?:Invoke-Expression|IEX)\s*\(?\s*(?:\(\s*)?New-Object\s+Net\.WebClient\s*\)?\s*\.\s*DownloadString", re.I),
        45,
        "PowerShell telecharge et execute du code distant (IEX + DownloadString)",
    ),
    (
        re.compile(rb"certutil(?:\.exe)?\s+[^-\n]{0,40}-urlcache|certutil(?:\.exe)?\s+[^\n]{0,40}-f\s+https?://", re.I),
        35,
        "certutil utilise pour telecharger un fichier distant (contournement classique)",
    ),
    (
        re.compile(rb"bitsadmin\s+/transfer|mshta\s+https?://|regsvr32\s+[^\n]{0,60}/i\s*:\s*https?://", re.I),
        35,
        "outil systeme detourne pour telecharger/executer du code distant (bitsadmin/mshta/regsvr32)",
    ),
    (
        re.compile(rb"powershell[^\n]{0,80}(?:-w\s+hidden|-windowstyle\s+hidden|-noprofile\s+-exec|-executionpolicy\s+(?:bypass|unrestricted))", re.I),
        30,
        "PowerShell lance en mode furtif ou avec execution libre (hidden/bypass)",
    ),
    # -- Windows : persistance et sabotage ---------------------------------------
    (
        re.compile(rb"reg\s+add\s+[^\n]{0,80}CurrentVersion\\Run|schtasks\s+/create", re.I),
        30,
        "installe une persistance Windows (cle Run ou tache planifiee)",
    ),
    (
        re.compile(rb"vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit\s+[^\n]{0,40}recoveryenabled\s+no", re.I),
        45,
        "supprime les copies d'ombre / desactive la recuperation (geste typique de ransomware)",
    ),
    (
        re.compile(rb"wevtutil\s+cl\s|net\s+user\s+\S+\s+\S+\s+/add|net\s+localgroup\s+administrators\s+\S+\s+/add", re.I),
        30,
        "efface les journaux d'evenements ou cree un compte administrateur",
    ),
    # -- cryptominer (xmrig, minerd) ------------------------------------------------
    (
        re.compile(rb"xmrig|minerd|stratum|pool\.monero\.org|xmr\.pool\.minergate\.com", re.I),
        45,
        "reference a un cryptomineur (stratum/pool) : signe d'infection par mineur",
    ),
    # -- webshell PHP -----------------------------------------------------------
    (
        re.compile(rb"eval\s*\(.*?base64_decode|system\s*\(.*?\$_(?:GET|POST|REQUEST)\)|shell_exec\s*\(.*?\$_GET", re.I),
        40,
        "webshell PHP detectee (eval + base64_decode / system avec parametres utilisateur)",
    ),
    # -- exfiltration script ----------------------------------------------------
    (
        re.compile(rb"curl\s+.*-F\s+[\"']?file|curl\s+.*-d\s+\$\(cat\s+.*?\)|curl\s+.*--upload-file", re.I),
        40,
        "script d'exfiltration (curl -F / --upload-file / -d avec contenu de fichiers)",
    ),
    # -- PE (executable Windows) camoufle dans document ------------------------
    (
        re.compile(rb"\.pdf\.exe|\.docx\.exe|\.doc\.exe|\.jpg\.exe", re.I),
        45,
        "PE camoufle avec double extension dans document (facture.pdf.exe)",
    ),
    # -- JS fortement obfusque ---------------------------------------------------
    (
        re.compile(rb"\b(?:(?:eval|Function|setTimeout)\s*\(\s*['\"].{100,}['\"]\s*\)|\bnew\s+Function\s*\(\s*['\"].{50,}\))", re.I),
        30,
        "JavaScript fortement obfusque (eval / Function avec chaine longue)",
    ),
]

# En-tetes de fichiers binaires.
MAGIC_ELF = b"\x7fELF"
MAGIC_PE = b"MZ"
MAGIC_SHEBANG = b"#!"


@dataclass
class Signal:
    score: int
    reason: str


class HeuristicEngine(Engine):
    name = "heuristics"
    source = DetectionSource.HEURISTIC

    def __init__(self, enabled: bool = True, removable_context: bool = False) -> None:
        self.enabled = enabled
        # Sur un media amovible, certains signaux (autorun, .lnk, exe Windows)
        # comptent davantage : c'est le vecteur classique de propagation.
        self.removable_context = removable_context

    def is_available(self) -> bool:
        return self.enabled

    def status(self) -> EngineStatus:
        return EngineStatus(
            name=self.name,
            available=self.enabled,
            signatures=len(SCRIPT_PATTERNS),
            detail="analyse comportementale statique (sans signature)",
        )

    def scan(self, ctx: FileContext) -> list[Threat]:
        if not self.enabled:
            return []
        signals: list[Signal] = []
        signals += self._check_name(ctx)
        signals += self._check_location_and_mode(ctx)
        signals += self._check_content(ctx)

        total = sum(s.score for s in signals)
        if total < SCORE_THRESHOLD:
            return []
        return [
            Threat(
                path=ctx.path,
                name=self._label(signals),
                severity=self._severity_for(total),
                source=self.source,
                sha256=ctx.sha256,
                size=ctx.size,
                details={
                    "score": total,
                    "reasons": [s.reason for s in signals],
                    "note": (
                        "Detection heuristique : signaux de risque, pas une "
                        "signature connue. A verifier avant suppression."
                    ),
                },
            )
        ]

    # -- regles sur le nom --------------------------------------------------- #

    def _check_name(self, ctx: FileContext) -> list[Signal]:
        signals: list[Signal] = []
        name = ctx.name
        lowered = name.lower()

        # Double extension : facture.pdf.exe
        parts = lowered.split(".")
        if len(parts) >= 3:
            inner, outer = f".{parts[-2]}", f".{parts[-1]}"
            if inner in DECOY_EXT and outer in (WINDOWS_EXEC_EXT | SCRIPT_EXT):
                signals.append(
                    Signal(
                        45,
                        f"double extension trompeuse : semble etre un {parts[-2]} "
                        f"mais est un fichier {parts[-1]}",
                    )
                )

        # Caracteres de reecriture bidirectionnelle : gpj.exe affiche exe.jpg
        if any(c in name for c in ("‮", "‭", "‏", "⁦", "⁧")):
            signals.append(
                Signal(50, "le nom contient un caractere qui inverse son affichage")
            )

        # Homoglyphes / caracteres invisibles
        if any(unicodedata.category(c) == "Cf" for c in name):
            signals.append(Signal(25, "le nom contient des caracteres invisibles"))

        # Autorun (4.5)
        if lowered in {"autorun.inf", "autorun.exe"}:
            signals.append(
                Signal(
                    50 if self.removable_context else 30,
                    "fichier autorun : execution automatique a l'insertion",
                )
            )
        if lowered.endswith(".lnk") and self.removable_context:
            signals.append(
                Signal(30, "raccourci Windows sur un media amovible (vecteur de vers)")
            )
        if lowered.endswith(".desktop") and lowered != ".desktop":
            signals.append(Signal(10, "lanceur .desktop : verifier la ligne Exec"))
        return signals

    # -- regles sur l'emplacement et les permissions ------------------------- #

    def _check_location_and_mode(self, ctx: FileContext) -> list[Signal]:
        signals: list[Signal] = []
        directory = os.path.dirname(os.path.abspath(ctx.path))
        header = ctx.header
        is_elf = header.startswith(MAGIC_ELF)
        is_pe = header.startswith(MAGIC_PE)

        if IS_LINUX and is_elf and directory.startswith(SUSPICIOUS_DIRS):
            signals.append(
                Signal(
                    35,
                    f"binaire executable dans un dossier temporaire ({directory})",
                )
            )

        if is_pe and self.removable_context:
            signals.append(
                Signal(15, "executable Windows sur un media amovible")
            )

        if IS_WINDOWS and is_pe:
            lowered_dir = directory.lower().replace("/", "\\")
            if any(marker in lowered_dir for marker in WINDOWS_SUSPICIOUS_MARKERS):
                signals.append(
                    Signal(
                        30,
                        f"executable dans un dossier d'atterrissage a risque ({directory})",
                    )
                )

        # Bits setuid/setgid : escalade de privileges.
        try:
            mode = os.stat(ctx.path).st_mode
        except OSError:
            return signals
        if IS_LINUX and mode & stat.S_ISUID:
            signals.append(
                Signal(
                    40,
                    "bit setuid actif : le fichier s'execute avec les droits de "
                    "son proprietaire",
                )
            )
        if IS_LINUX and mode & stat.S_ISGID:
            signals.append(Signal(20, "bit setgid actif"))
        # Fichier cache et executable dans le repertoire personnel.
        if ctx.name.startswith(".") and (is_elf or header.startswith(MAGIC_SHEBANG)):
            if mode & stat.S_IXUSR:
                signals.append(Signal(25, "fichier cache et executable"))
        return signals

    # -- regles sur le contenu ----------------------------------------------- #

    def _check_content(self, ctx: FileContext) -> list[Signal]:
        header = ctx.header
        if not header:
            return []
        # On n'inspecte le contenu que des scripts / fichiers texte.
        is_script = header.startswith(MAGIC_SHEBANG) or ctx.suffix in (
            SCRIPT_EXT | {".ps1", ".bat", ".cmd", ".vbs", ".desktop", ".service"}
        )
        if not is_script:
            return []
        blob = header
        if ctx.size > len(header) and ctx.size <= 2 * 1024 * 1024:
            # Script court : on lit tout, les charges utiles sont souvent en fin.
            try:
                with open(ctx.path, "rb") as handle:
                    blob = handle.read(2 * 1024 * 1024)
            except OSError:
                pass
        signals = [
            Signal(score, reason)
            for pattern, score, reason in SCRIPT_PATTERNS
            if pattern.search(blob)
        ]
        # Ligne unique tres longue : marqueur d'obfuscation.
        longest = max((len(line) for line in blob.splitlines()), default=0)
        if longest > 4000:
            signals.append(
                Signal(20, f"ligne de {longest} caracteres : contenu probablement obfusque")
            )
        return signals

    # -- synthese ------------------------------------------------------------ #

    @staticmethod
    def _label(signals: list[Signal]) -> str:
        """Nom court base sur le signal le plus fort."""
        strongest = max(signals, key=lambda s: s.score)
        return f"Heuristique: {strongest.reason[:60]}"

    @staticmethod
    def _severity_for(total: int) -> Severity:
        # Plafonne a HIGH : une heuristique ne suffit pas a affirmer CRITICAL.
        if total >= 90:
            return Severity.HIGH
        if total >= 60:
            return Severity.MEDIUM
        return Severity.LOW
