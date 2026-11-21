<#
  Installation du pilote noyau Malryx en MODE TEST (VM ou PC de démonstration).

  Windows refuse les pilotes non signés par Microsoft. Pour un projet étudiant, on utilise le
  « mode test » officiel de Windows : le pilote est signé avec un certificat de test créé ici.
  Une signature de production exige un certificat EV d'entreprise + la signature d'attestation
  Microsoft (Partner Center).

  Usage (PowerShell en ADMINISTRATEUR) :
      .\install-driver.ps1             # étape 1 : active le mode test (redémarrage), étape 2 : installe
      .\install-driver.ps1 -Uninstall  # désinstalle le pilote
      .\install-driver.ps1 -DisableTestMode
#>
param([switch]$Uninstall, [switch]$DisableTestMode, [string]$Sys = "$PSScriptRoot\x64\MalryxFlt.sys")
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Lance ce script dans un PowerShell en administrateur."
}
$inf = Join-Path (Split-Path $Sys) "MalryxFlt.inf"
if (-not (Test-Path $inf)) { $inf = "$PSScriptRoot\MalryxFlt.inf" }

if ($Uninstall) {
    fltmc unload MalryxFlt 2>$null
    sc.exe delete MalryxFlt | Out-Null
    Remove-Item "$env:SystemRoot\System32\drivers\MalryxFlt.sys" -Force -ErrorAction SilentlyContinue
    Write-Host "Pilote Malryx désinstallé." -ForegroundColor Green
    return
}
if ($DisableTestMode) {
    bcdedit /set testsigning off | Out-Null
    Write-Host "Mode test désactivé. Redémarre le PC." -ForegroundColor Green
    return
}

# --- 1. Mode test --------------------------------------------------------------------------
$bcd = bcdedit /enum "{current}"
if ($bcd -notmatch "testsigning\s+Yes") {
    $sb = $false
    try { $sb = Confirm-SecureBootUEFI } catch {}
    if ($sb) {
        Write-Warning "Secure Boot est actif : désactive-le dans le BIOS/UEFI (ou dans les réglages de la VM) avant d'activer le mode test."
        return
    }
    bcdedit /set testsigning on | Out-Null
    Write-Host "Mode test activé. REDÉMARRE le PC, puis relance ce script pour installer le pilote." -ForegroundColor Yellow
    return
}

# --- 2. Certificat de test + signature ----------------------------------------------------
if (-not (Test-Path $Sys)) { throw "Pilote introuvable : $Sys (compile-le avec build-driver.cmd)" }
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=Malryx Driver Test" } | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Malryx Driver Test" `
            -CertStoreLocation Cert:\LocalMachine\My -KeyUsage DigitalSignature -NotAfter (Get-Date).AddYears(5)
    $cer = "$env:TEMP\malryx_driver_test.cer"
    Export-Certificate -Cert $cert -FilePath $cer | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
}
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
if ($signtool) {
    & $signtool.FullName sign /fd sha256 /sha1 $cert.Thumbprint /sm /s My $Sys
} else {
    Set-AuthenticodeSignature -FilePath $Sys -Certificate $cert -HashAlgorithm SHA256 | Out-Null
}

# --- 3. Installation et chargement -------------------------------------------------------
fltmc unload MalryxFlt 2>$null
Copy-Item $Sys "$env:SystemRoot\System32\drivers\MalryxFlt.sys" -Force
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall.NTamd64 132 $inf
Start-Sleep 2
fltmc load MalryxFlt
fltmc filters | Select-String -Pattern "MalryxFlt"
Write-Host "`nPilote chargé. Lance (ou relance) Malryx EN ADMINISTRATEUR : Protection → « pilote noyau (avant exécution) »." -ForegroundColor Green
Write-Host "Pour qu'il se charge à chaque démarrage : sc.exe config MalryxFlt start= system"
