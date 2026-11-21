/*
  Règles de base Malryx.
  severity = "high"   -> verdict MALVEILLANT
  severity = "medium" -> ajoute du score (peut donner SUSPECT)
  Ajoute d'autres règles : https://github.com/Yara-Rules/rules , https://github.com/Neo23x0/signature-base
*/

rule EICAR_Test_File
{
    meta:
        description = "Fichier de test antivirus EICAR (inoffensif)"
        severity = "high"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar and filesize < 1KB
}

rule Ransomware_Shadow_Copy_Deletion
{
    meta:
        description = "Suppression des clichés instantanés + note de rançon"
        severity = "high"
    strings:
        $a = "vssadmin delete shadows" nocase ascii wide
        $b = "wmic shadowcopy delete" nocase ascii wide
        $c = "bcdedit /set {default} recoveryenabled no" nocase ascii wide
        $n1 = "your files have been encrypted" nocase ascii wide
        $n2 = "bitcoin" nocase ascii wide
        $n3 = ".onion" nocase ascii wide
    condition:
        any of ($a, $b, $c) and any of ($n*)
}

rule PowerShell_Download_Execute
{
    meta:
        description = "Script qui télécharge puis exécute du code"
        severity = "medium"
    strings:
        $d1 = "DownloadString" nocase ascii wide
        $d2 = "DownloadFile" nocase ascii wide
        $d3 = "Invoke-WebRequest" nocase ascii wide
        $x1 = "Invoke-Expression" nocase ascii wide
        $x2 = "IEX" ascii wide
        $x3 = "Start-Process" nocase ascii wide
    condition:
        filesize < 2MB and any of ($d*) and any of ($x*)
}

rule Keylogger_API_Imports
{
    meta:
        description = "Exécutable utilisant des API typiques de keylogger"
        severity = "medium"
    strings:
        $a = "SetWindowsHookExA" ascii
        $b = "SetWindowsHookExW" ascii
        $c = "GetAsyncKeyState" ascii
        $d = "GetForegroundWindow" ascii
        $s1 = "smtp" nocase ascii
        $s2 = "api.telegram.org" nocase ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($a, $b, $c)) and $d and any of ($s*)
}

rule Android_SMS_Stealer
{
    meta:
        description = "Code Android (dex) qui lit les SMS et les envoie vers un serveur/Telegram"
        severity = "medium"
    strings:
        $sms = "content://sms" ascii wide
        $tg = "api.telegram.org/bot" ascii wide
        $gate = "/gate.php" ascii wide
    condition:
        $sms and ($tg or $gate)
}
