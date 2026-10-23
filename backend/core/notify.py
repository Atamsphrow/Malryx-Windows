"""Notifications systeme Windows (toasts) pour les alertes Malryx.

Best-effort uniquement : un toast qui echoue ne doit jamais empecher le
traitement d'une menace. Le canal principal reste le bus d'evenements
(WebSocket vers l'UI) ; le toast couvre le cas ou l'UI est fermee.

Technique : API WinRT Windows.UI.Notifications appelee via PowerShell,
en reutilisant l'AppId de PowerShell (aucune inscription d'application
requise). Limite connue v1 : un service Windows en session 0 ne peut pas
afficher de toast sur le bureau de l'utilisateur ; dans ce cas l'appel
echoue proprement et seule l'alerte UI / journal subsiste.

Desactivation : variable d'environnement MALRYX_NO_TOAST=1 (tests, CI).
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys

log = logging.getLogger(__name__)

_POWERSHELL_APP_ID = (
    r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"
    r"\WindowsPowerShell\v1.0\powershell.exe"
)


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def show_toast(title: str, body: str) -> bool:
    """Affiche un toast Windows. Retourne True si l'appel a abouti."""
    if sys.platform != "win32":
        return False
    if os.environ.get("MALRYX_NO_TOAST") == "1":
        return False
    script = (
        "[Windows.UI.Notifications.ToastNotificationManager, "
        "Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; "
        "$xml = [Windows.UI.Notifications.ToastNotificationManager]"
        "::GetTemplateContent("
        "[Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
        "$texts = $xml.GetElementsByTagName('text'); "
        f"$texts[0].AppendChild($xml.CreateTextNode({_ps_quote(title)})) > $null; "
        f"$texts[1].AppendChild($xml.CreateTextNode({_ps_quote(body)})) > $null; "
        "$toast = [Windows.UI.Notifications.ToastNotification]::new($xml); "
        "[Windows.UI.Notifications.ToastNotificationManager]"
        f"::CreateToastNotifier({_ps_quote(_POWERSHELL_APP_ID)}).Show($toast)"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode != 0:
            log.debug(
                "toast Windows en echec (%d) : %s",
                proc.returncode,
                proc.stderr.decode("utf-8", errors="replace")[:300],
            )
            return False
        return True
    except Exception as exc:
        log.debug("toast Windows impossible : %s", exc)
        return False


def notify_threat(name: str, path: str, quarantined: bool) -> bool:
    """Toast d'alerte menace, formule selon le sort du fichier."""
    if quarantined:
        body = f"{name} — fichier mis en quarantaine.\n{path}"
    else:
        body = f"{name} — menace detectee, a traiter.\n{path}"
    return show_toast("Malryx : menace detectee", body)
