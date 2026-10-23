# Malryx for Windows - W0 feasibility check (une seule commande).
# Usage : powershell -ExecutionPolicy Bypass -File .\w0_check.ps1
# Produit w0_report.json et w0_report.txt dans le dossier du script.
# Aucune installation silencieuse : le script constate, il ne modifie rien,
# sauf un venv Python temporaire et un dossier de test, tous deux nettoyés.

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Results = New-Object System.Collections.ArrayList

function Add-Result {
    param([string]$Check, [string]$Status, [string]$Detail)
    [void]$Results.Add([ordered]@{ check = $Check; status = $Status; detail = $Detail })
    Write-Host ("[{0}] {1} - {2}" -f $Status, $Check, $Detail)
}

function Find-Exe {
    param([string[]]$Names, [string[]]$Dirs)
    foreach ($n in $Names) {
        $c = Get-Command $n -ErrorAction SilentlyContinue
        if ($c) { return $c.Source }
    }
    foreach ($d in $Dirs) {
        foreach ($n in $Names) {
            $p = Join-Path $d $n
            if (Test-Path $p) { return $p }
        }
    }
    return $null
}

# --- 1. Systeme -------------------------------------------------------------
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $arch = if ([Environment]::Is64BitOperatingSystem) { "64-bit" } else { "32-bit" }
    Add-Result "os" "INFO" ("{0} (build {1}), {2}" -f $os.Caption, $os.BuildNumber, $arch)
    if ([Environment]::Is64BitOperatingSystem) {
        Add-Result "os_64bit" "PASS" "Windows 64-bit"
    } else {
        Add-Result "os_64bit" "FAIL" "Windows 32-bit : cible 10/11 x64 non remplie"
    }
} catch {
    Add-Result "os" "FAIL" $_.Exception.Message
}

# --- 2. Visual Studio 2022 + workload C++ -----------------------------------
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath = $null
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Workload.VCTools -property installationPath 2>$null
}
if ($vsPath) {
    Add-Result "vs_cxx" "PASS" "Visual Studio + workload Desktop C++ : $vsPath"
} else {
    Add-Result "vs_cxx" "ACTION" "Visual Studio 2022 (ou Build Tools) avec le workload 'Desktop development with C++' introuvable. Requis pour compiler le runner Flutter Windows."
}

# --- 3. Flutter --------------------------------------------------------------
$flutter = Find-Exe @("flutter.bat", "flutter") @("C:\flutter\bin", "C:\src\flutter\bin", "$env:USERPROFILE\flutter\bin")
if ($flutter) {
    $ver = (& $flutter --version 2>&1 | Select-Object -First 1)
    Add-Result "flutter" "PASS" "$ver ($flutter)"
    $doctor = (& $flutter doctor 2>&1 | Out-String)
    if ($doctor -match "Visual Studio - develop Windows apps") {
        Add-Result "flutter_doctor_vs" "PASS" "flutter doctor voit Visual Studio pour Windows"
    } else {
        Add-Result "flutter_doctor_vs" "ACTION" "flutter doctor ne valide pas encore la partie Visual Studio (voir le check vs_cxx)."
    }
} else {
    Add-Result "flutter" "ACTION" "Flutter introuvable dans le PATH ni aux emplacements usuels. A installer (SDK stable, dossier sans droits admin, ex. C:\flutter)."
}

# --- 4. Python + yara-python --------------------------------------------------
$python = $null
foreach ($cand in @("py", "python", "python3")) {
    $c = Get-Command $cand -ErrorAction SilentlyContinue
    if ($c) { $python = $c.Source; break }
}
if (-not $python) {
    Add-Result "python" "FAIL" "Python introuvable. Requis : Python 3.12 64-bit (wheel yara-python verifiee pour 3.9 a 3.13)."
} else {
    $pyver = (& $python --version 2>&1)
    Add-Result "python" "INFO" "$pyver ($python)"
    $venv = Join-Path $env:TEMP "malryx-w0-venv"
    try {
        & $python -m venv $venv 2>&1 | Out-Null
        $venvPy = Join-Path $venv "Scripts\python.exe"
        & $venvPy -m pip install --quiet --disable-pip-version-check "yara-python==4.5.4" 2>&1 | Out-Null
        $yaraOut = (& $venvPy (Join-Path $ScriptDir "yara_test.py") 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -eq 0) {
            Add-Result "yara" "PASS" $yaraOut
        } else {
            Add-Result "yara" "FAIL" $yaraOut
        }
    } catch {
        Add-Result "yara" "FAIL" $_.Exception.Message
    } finally {
        Remove-Item $venv -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- 5. ReadDirectoryChangesW (prototype temps reel) --------------------------
if ($python) {
    $rdwOut = (& $python (Join-Path $ScriptDir "rdw_test.py") 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -eq 0) {
        Add-Result "realtime_rdw" "PASS" $rdwOut
    } else {
        Add-Result "realtime_rdw" "FAIL" $rdwOut
    }
} else {
    Add-Result "realtime_rdw" "FAIL" "Python absent, prototype non lance."
}

# --- 6. ClamAV / clamd TCP -----------------------------------------------------
$clamDirs = @("C:\Program Files\ClamAV", "C:\ClamAV", "$env:ProgramFiles\ClamAV")
$clamd = Find-Exe @("clamd.exe") $clamDirs
$clamscan = Find-Exe @("clamscan.exe") $clamDirs
if ($clamscan) {
    $clamVer = (& $clamscan --version 2>&1 | Select-Object -First 1)
    Add-Result "clamav_present" "PASS" "$clamVer ($clamscan)"
} else {
    Add-Result "clamav_present" "ACTION" "ClamAV for Windows absent. A installer depuis clamav.net (installeur officiel ou ZIP portable), puis configurer clamd en TCP 127.0.0.1:3310 (TCPSocket 3310 dans clamd.conf) et lancer freshclam une fois."
}
if ($clamd) {
    if ($python) {
        $tcpOut = (& $python (Join-Path $ScriptDir "clamd_tcp_test.py") 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -eq 0) {
            Add-Result "clamd_tcp" "PASS" $tcpOut
        } else {
            Add-Result "clamd_tcp" "ACTION" "clamd present mais ne repond pas en TCP : $tcpOut. Verifier TCPSocket 3310 + service clamd demarre + bases presentes (freshclam)."
        }
    }
} else {
    Add-Result "clamd_tcp" "ACTION" "Non testable tant que ClamAV n'est pas installe."
}

# --- 7. Authenticode ------------------------------------------------------------
try {
    $sig = Get-AuthenticodeSignature "$env:SystemRoot\explorer.exe"
    if ($sig.Status -eq "Valid") {
        Add-Result "authenticode" "PASS" ("Get-AuthenticodeSignature fonctionne, signer = {0}" -f $sig.SignerCertificate.Subject)
    } else {
        Add-Result "authenticode" "FAIL" ("Statut inattendu pour explorer.exe : {0}" -f $sig.Status)
    }
} catch {
    Add-Result "authenticode" "FAIL" $_.Exception.Message
}

# --- Rapport ---------------------------------------------------------------------
$jsonPath = Join-Path $ScriptDir "w0_report.json"
$txtPath = Join-Path $ScriptDir "w0_report.txt"
$Results | ConvertTo-Json -Depth 3 | Out-File $jsonPath -Encoding utf8
$lines = $Results | ForEach-Object { "[{0}] {1} - {2}" -f $_.status, $_.check, $_.detail }
$lines | Out-File $txtPath -Encoding utf8

$must = @("os_64bit", "yara", "realtime_rdw", "authenticode")
$mustFail = $Results | Where-Object { ($must -contains $_.check) -and ($_.status -eq "FAIL") }
$actions = $Results | Where-Object { $_.status -eq "ACTION" }
Write-Host ""
Write-Host ("Rapports : {0} / {1}" -f $jsonPath, $txtPath)
if ($mustFail) {
    Write-Host "W0 : ECHECS sur des points durs, voir ci-dessus."
    exit 1
}
if ($actions) {
    Write-Host "W0 : coeur OK, mais des installations restent a faire (lignes ACTION)."
    exit 2
}
Write-Host "W0 : TOUT EST VERT."
exit 0
