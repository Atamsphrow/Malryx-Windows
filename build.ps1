<#
  Malryx – construction (version lue dans le fichier VERSION)

  Produit dans dist\ :
    Malryx-Setup.exe   installateur – RECOMMANDÉ (~300 Mo, démarrage rapide, moins de faux positifs)
    Malryx.exe         portable, un seul fichier (~330 Mo ; décompressé à chaque lancement : démarrage plus lent)

  100 % HORS LIGNE : tout est embarqué, rien n'est téléchargé au premier lancement.
    interface, moteur ClamAV + ses bases (~230 Mo), base de hashes Malryx, YARA + YARA Forge, ADB,
    liste URLhaus, clé publique des packs de signatures, pilote noyau s'il est compilé.
  Ensuite, Malryx ne se connecte que sur Wi-Fi (réglable) ; sinon mise à jour par pack USB signé.
  Le build ÉCHOUE si les bases ClamAV n'ont pas pu être embarquées (pas de version « hors ligne » incomplète).

  Utilisation (PowerShell) :
      powershell -ExecutionPolicy Bypass -File build.ps1
      powershell -ExecutionPolicy Bypass -File build.ps1 -NoInstaller -SelfSign
      powershell -ExecutionPolicy Bypass -File build.ps1 -NoClamDB        # sans bases ClamAV (développement uniquement)
  Signature avec un vrai certificat : définir MALRYX_PFX et MALRYX_PFX_PASSWORD (voir sign.ps1).
  Miroir de signatures utilisé pour l'embarquement : -MirrorRepo propriétaire/dépôt (défaut : Atamsphrow/Malryx-Windows).
#>
param([switch]$NoClamDB, [switch]$NoClamAV, [switch]$NoInstaller, [switch]$SelfSign, [switch]$NoBootloaderRebuild,
      [string]$MirrorRepo = "Atamsphrow/Malryx-Windows")
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Set-Location $PSScriptRoot

function Step($t) { Write-Host "`n==> $t" -ForegroundColor Cyan }
$Version = (Get-Content "$PSScriptRoot\VERSION" -Raw).Trim()
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Fichier VERSION invalide : '$Version'" }
$v4 = ($Version.Split('.') + '0') -join ','
Write-Host "Malryx $Version" -ForegroundColor Green

$vendor = Join-Path $PSScriptRoot "vendor"
$sig = Join-Path $PSScriptRoot "signatures"
$tmp = Join-Path $env:TEMP "malryx_build"
New-Item -ItemType Directory -Force -Path $vendor, $sig, $tmp | Out-Null

# --------------------------------------------------------------------------- Python
Step "Dépendances Python"
python --version
python -m pip install --upgrade pip --quiet
python -m pip install -r requirements.txt --quiet
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = $null
if (Test-Path $vswhere) { $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath }
if ($vs -and -not $NoBootloaderRebuild) {
    Step "Recompilation du bootloader PyInstaller (réduit les faux positifs antivirus)"
    $env:PYINSTALLER_COMPILE_BOOTLOADER = "1"
    python -m pip install --force-reinstall --no-binary pyinstaller pyinstaller --quiet
    if ($LASTEXITCODE -ne 0) { Write-Warning "Échec : bootloader standard."; python -m pip install pyinstaller --quiet }
} else {
    if (-not $vs) { Write-Warning "Visual Studio C++ absent : bootloader standard (plus de faux positifs possibles)." }
    python -m pip install pyinstaller --quiet
}

# --------------------------------------------------------------------------- ADB
Step "ADB (Android Platform-Tools)"
$adbDir = Join-Path $vendor "adb"
if (-not (Test-Path "$adbDir\adb.exe")) {
    Invoke-WebRequest "https://dl.google.com/android/repository/platform-tools-latest-windows.zip" -OutFile "$tmp\pt.zip"
    Expand-Archive "$tmp\pt.zip" -DestinationPath "$tmp\pt" -Force
    New-Item -ItemType Directory -Force -Path $adbDir | Out-Null
    Copy-Item "$tmp\pt\platform-tools\adb.exe", "$tmp\pt\platform-tools\AdbWinApi.dll", "$tmp\pt\platform-tools\AdbWinUsbApi.dll", "$tmp\pt\platform-tools\NOTICE.txt" $adbDir -ErrorAction SilentlyContinue
}

# --------------------------------------------------------------------------- Moteur ClamAV
$clamDir = Join-Path $vendor "clamav"
$dbDir = Join-Path $vendor "clamav-db"
Remove-Item $dbDir -Recurse -Force -ErrorAction SilentlyContinue
if ($NoClamAV) {
    Remove-Item $clamDir -Recurse -Force -ErrorAction SilentlyContinue
} else {
    Step "Moteur ClamAV (Cisco-Talos)"
    if (-not (Test-Path "$clamDir\clamd.exe")) {
        $rel = Invoke-RestMethod "https://api.github.com/repos/Cisco-Talos/clamav/releases/latest" -Headers @{ "User-Agent" = "Malryx-build" }
        $asset = $rel.assets | Where-Object { $_.name -match "win\.x64\.zip$" } | Select-Object -First 1
        if (-not $asset) { throw "Archive ClamAV Windows x64 introuvable ($($rel.tag_name))" }
        Invoke-WebRequest $asset.browser_download_url -OutFile "$tmp\clamav.zip"
        Expand-Archive "$tmp\clamav.zip" -DestinationPath "$tmp\clamav" -Force
        $root = Get-ChildItem "$tmp\clamav" -Recurse -Filter "clamd.exe" | Select-Object -First 1
        New-Item -ItemType Directory -Force -Path $clamDir | Out-Null
        Copy-Item "$($root.DirectoryName)\*" $clamDir -Recurse -Force
        Remove-Item "$clamDir\conf_examples", "$clamDir\docs", "$clamDir\*.pdb" -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --------------------------------------------------------------------------- Signatures embarquées
Step "Signatures embarquées (ClamAV + base de hashes + YARA Forge + URLhaus)"
Remove-Item $sig -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $sig | Out-Null
$pack = "$tmp\malryx-signatures-latest.zip"
$base = "https://github.com/$MirrorRepo/releases/download/signatures"
$havePack = $false
try {
    Invoke-WebRequest "$base/malryx-signatures-latest.zip" -OutFile $pack
    # vérification complète (SHA-256 de chaque fichier + signature Ed25519 si la clé publique est configurée)
    python -c "import sys; sys.path.insert(0, '.'); from malryx import packs; i = packs.inspect(sys.argv[1]); print('Pack du', i['date'], '- signé :', i['signed'])" $pack
    if ($LASTEXITCODE -ne 0) { throw "pack invalide" }
    $havePack = $true
} catch {
    Write-Warning "Pack du miroir $MirrorRepo indisponible ($_) : construction locale (cvdupdate + YARA Forge + URLhaus)."
    python -m pip install cvdupdate --quiet
    $sb = "$tmp\sigbuild"; Remove-Item $sb -Recurse -Force -ErrorAction SilentlyContinue
    python tools\build_signatures.py --out $sb $(if (-not $NoClamDB -and -not $NoClamAV) { "--clamav" }) --pack
    $pack = Get-ChildItem $sb -Filter "malryx-signatures-latest.zip" | Select-Object -First 1 -ExpandProperty FullName
    if ($pack) { $havePack = $true }
}
if ($havePack) {
    Expand-Archive $pack -DestinationPath "$tmp\packx" -Force
    New-Item -ItemType Directory -Force -Path $dbDir | Out-Null
    Get-ChildItem "$tmp\packx" -File | ForEach-Object {
        if ($_.Name -like "*.cvd") { if (-not $NoClamDB) { Copy-Item $_.FullName $dbDir -Force } }
        else { Copy-Item $_.FullName $sig -Force }
    }
    Remove-Item "$tmp\packx" -Recurse -Force
}
if (-not $NoClamDB -and -not $NoClamAV -and -not (Test-Path "$dbDir\main.cvd")) {
    throw "Bases ClamAV absentes : la version 100 % hors ligne ne peut pas être produite. Lancez d'abord le workflow « Signatures Malryx » ou vérifiez la connexion."
}
if (Test-Path "$sig\yara-forge-core.zip") {
    Remove-Item "$sig\yara" -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive "$sig\yara-forge-core.zip" -DestinationPath "$sig\yara" -Force
}
if (Test-Path "$sig\web-blocklist.txt") {
    New-Item -ItemType Directory -Force -Path "$vendor\blocklist" | Out-Null
    Copy-Item "$sig\web-blocklist.txt" "$vendor\blocklist\hosts.txt" -Force
}
if (-not (Test-Path "malryx\pack_pubkey.txt")) {
    Write-Warning "malryx\pack_pubkey.txt absent : les packs NON signés seront acceptés (après confirmation). Lancez tools\gen_pack_key.py."
}
Get-ChildItem $dbDir, $sig -File -ErrorAction SilentlyContinue | ForEach-Object { "  {0,-24} {1,8:N1} Mo" -f $_.Name, ($_.Length / 1MB) }

# --------------------------------------------------------------------------- Pilote noyau (optionnel)
$drvOut = Join-Path $vendor "driver"
New-Item -ItemType Directory -Force -Path $drvOut | Out-Null
Copy-Item "driver\install-driver.ps1" $drvOut -Force
(Get-Content "driver\MalryxFlt.inf") -replace '^DriverVer\s*=.*', ("DriverVer   = {0},{1}.0" -f (Get-Date -Format "MM/dd/yyyy"), $Version) |
    Set-Content "$drvOut\MalryxFlt.inf" -Encoding ASCII
if (Test-Path "driver\x64\MalryxFlt.sys") { Copy-Item "driver\x64\MalryxFlt.sys" $drvOut -Force; Write-Host "Pilote noyau embarqué." }

# --------------------------------------------------------------------------- Informations de version
@"
VSVersionInfo(
  ffi=FixedFileInfo(filevers=($v4), prodvers=($v4), mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040C04B0', [
      StringStruct('CompanyName', 'Malryx'),
      StringStruct('FileDescription', 'Malryx - Sécurité et optimisation'),
      StringStruct('FileVersion', '$Version'),
      StringStruct('InternalName', 'Malryx'),
      StringStruct('LegalCopyright', 'Malryx'),
      StringStruct('OriginalFilename', 'Malryx.exe'),
      StringStruct('ProductName', 'Malryx'),
      StringStruct('ProductVersion', '$Version')])]),
    VarFileInfo([VarStruct('Translation', [1036, 1200])])
  ]
)
"@ | Set-Content -Path "$tmp\version.txt" -Encoding UTF8
$env:MALRYX_VERSION_FILE = "$tmp\version.txt"

function Sign-Exe($f) {
    if ($env:MALRYX_PFX) { & "$PSScriptRoot\sign.ps1" -File $f }
    elseif ($SelfSign) { & "$PSScriptRoot\sign.ps1" -File $f -SelfSigned }
}

# --------------------------------------------------------------------------- Exe portable
Step "Malryx.exe (portable)"
$env:MALRYX_ONEDIR = "0"
python -m PyInstaller --noconfirm --clean Malryx.spec
if (-not (Test-Path "dist\Malryx.exe")) { throw "La compilation a échoué." }
Sign-Exe "dist\Malryx.exe"

# --------------------------------------------------------------------------- Installateur
if (-not $NoInstaller) {
    Step "Malryx-Setup.exe (installateur)"
    $env:MALRYX_ONEDIR = "1"
    Move-Item "dist\Malryx.exe" "$tmp\Malryx-portable.exe" -Force
    python -m PyInstaller --noconfirm Malryx.spec
    Sign-Exe "dist\Malryx\Malryx.exe"
    $iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $iscc) {
        Write-Host "Installation d'Inno Setup…"
        winget install --id JRSoftware.InnoSetup -e --silent --accept-package-agreements --accept-source-agreements 2>$null
        if ($LASTEXITCODE -ne 0) { choco install innosetup -y --no-progress 2>$null }
        $iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    Move-Item "$tmp\Malryx-portable.exe" "dist\Malryx.exe" -Force
    if ($iscc) {
        & $iscc "/DAppVersion=$Version" "installer\Malryx.iss"
        Sign-Exe "dist\Malryx-Setup.exe"
    } else {
        Write-Warning "Inno Setup introuvable : installateur non généré (https://jrsoftware.org/isdl.php)."
    }
}

Step "Résultat"
Get-ChildItem dist -File | ForEach-Object {
    "{0,-22} {1,8:N1} Mo   SHA-256 {2}" -f $_.Name, ($_.Length / 1MB), (Get-FileHash $_.FullName -Algorithm SHA256).Hash
}
