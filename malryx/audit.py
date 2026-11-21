"""Audit de sécurité de Windows : points faibles fréquents et comment les corriger."""
from datetime import datetime

from . import webprotect, winsys
from .paths import IS_WIN

OK, WARN, BAD = "ok", "warn", "bad"

PS = r"""
$r = @{}
try { $m = Get-MpComputerStatus; $r.def_rt = $m.RealTimeProtectionEnabled; $r.def_age = $m.AntivirusSignatureAge; $r.tamper = $m.IsTamperProtected } catch {}
try { $r.fw = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | ForEach-Object Name) } catch {}
try { $r.smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol } catch {}
try { $h = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1; $r.hotfix = $h.InstalledOn.ToString('yyyy-MM-dd') } catch {}
try { $r.bitlocker = (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus.ToString() } catch {}
try { $r.guest = (Get-LocalUser -Name 'Invité','Guest' -ErrorAction SilentlyContinue | Where-Object Enabled).Count } catch {}
$r
"""


def _reg(hive, key, value, default=None):
    import winreg
    h = winreg.HKEY_LOCAL_MACHINE if hive == "HKLM" else winreg.HKEY_CURRENT_USER
    try:
        with winreg.OpenKey(h, key) as k:
            return winreg.QueryValueEx(k, value)[0]
    except OSError:
        return default


def run(settings=None, clamav=None):
    checks = []

    def add(name, status, detail, fix=None, fix_label="Ouvrir les paramètres"):
        checks.append({"name": name, "status": status, "detail": detail, "fix": fix, "fix_label": fix_label})

    if settings is not None:
        add("Protection en temps réel Malryx", OK if settings["realtime"] else BAD,
            "Active" if settings["realtime"] else "Désactivée : votre PC n'est pas surveillé", "malryx:realtime", "Activer")
    if clamav is not None:
        files = list(clamav.db_dir.glob("*.c[vl]d"))
        if files:
            age = (datetime.now().timestamp() - max(f.stat().st_mtime for f in files)) / 86400
            add("Signatures ClamAV", OK if age < 7 else WARN, f"Dernière mise à jour il y a {age:.0f} jour(s)",
                "malryx:update", "Mettre à jour")
        else:
            add("Signatures ClamAV", WARN, "Aucune base de signatures", "malryx:update", "Télécharger")

    if not IS_WIN:
        return checks
    r = (winsys._ps_json(PS, timeout=60) or [{}])[0]

    if r.get("def_rt") is not None:
        add("Windows Defender", OK if r["def_rt"] else WARN,
            "Protection en temps réel active" if r["def_rt"] else "Protection en temps réel désactivée",
            "windowsdefender:")
    fw = r.get("fw") or []
    if isinstance(fw, str):
        fw = [fw]
    add("Pare-feu Windows", BAD if fw else OK, f"Désactivé pour : {', '.join(fw)}" if fw else "Actif sur tous les profils",
        "ms-settings:windowsdefender")
    uac = _reg("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1)
    add("Contrôle de compte d'utilisateur (UAC)", OK if uac else BAD,
        "Actif" if uac else "Désactivé : n'importe quel programme obtient les droits administrateur", "useraccountcontrolsettings")
    rdp = _reg("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 1)
    add("Bureau à distance (RDP)", OK if rdp else WARN,
        "Désactivé" if rdp else "Activé : cible fréquente des attaques par force brute", "ms-settings:remotedesktop")
    if r.get("smb1") is not None:
        add("Protocole SMBv1", BAD if r["smb1"] else OK,
            "Activé : vulnérable (WannaCry, EternalBlue)" if r["smb1"] else "Désactivé", "optionalfeatures", "Fonctionnalités Windows")
    if r.get("hotfix"):
        days = (datetime.now() - datetime.strptime(r["hotfix"], "%Y-%m-%d")).days
        add("Mises à jour Windows", OK if days < 45 else WARN if days < 90 else BAD,
            f"Dernière mise à jour installée il y a {days} jours", "ms-settings:windowsupdate")
    autorun = _reg("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 0x91)
    add("Exécution automatique des supports", OK if autorun in (0xFF, 0xB5, 0x91, 0x95) else WARN,
        "Limitée" if autorun in (0xFF, 0xB5, 0x91, 0x95) else "Les clés USB peuvent lancer des programmes", "ms-settings:autoplay")
    if r.get("bitlocker"):
        add("Chiffrement du disque (BitLocker)", OK if r["bitlocker"] == "On" else WARN,
            "Actif" if r["bitlocker"] == "On" else "Désactivé : vos données sont lisibles en cas de vol du PC", "control /name Microsoft.BitLockerDriveEncryption")
    if r.get("guest"):
        add("Compte Invité", WARN, "Activé", "lusrmgr.msc")
    foreign = webprotect.foreign_entries()
    add("Fichier hosts", WARN if foreign else OK,
        f"{len(foreign)} redirection(s) inconnue(s) : {foreign[0]}" if foreign else "Aucune redirection suspecte", None)
    reg = winsys.registry_findings()
    add("Détournements du registre", BAD if reg else OK,
        f"{len(reg)} modification(s) dangereuse(s) : lancez une analyse" if reg else "Aucun détournement détecté",
        "malryx:scan" if reg else None, "Analyser")
    add("Droits de Malryx", OK if winsys.is_admin() else WARN,
        "Administrateur" if winsys.is_admin() else "Utilisateur standard : certaines protections sont limitées",
        None if winsys.is_admin() else "malryx:admin", "Relancer en administrateur")
    return checks


def score(checks):
    if not checks:
        return 100
    pts = sum({OK: 1, WARN: 0.5, BAD: 0}[c["status"]] for c in checks)
    return round(100 * pts / len(checks))
