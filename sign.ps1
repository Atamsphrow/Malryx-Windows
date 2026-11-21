<#
  Signature numérique de Malryx.exe

  1) Avec un VRAI certificat de signature de code (recommandé pour distribuer Malryx) :
       $env:MALRYX_PFX = "C:\chemin\certificat.pfx"      (ou le contenu du .pfx encodé en base64)
       $env:MALRYX_PFX_PASSWORD = "motdepasse"
       .\sign.ps1
     → l'exe affiche « Éditeur : <ton nom> » et accumule de la réputation SmartScreen au fil des téléchargements.

  2) Certificat AUTO-SIGNÉ (gratuit, pour ton PC de démonstration / les PC de l'école) :
       .\sign.ps1 -SelfSigned                 # signe l'exe
       .\sign.ps1 -SelfSigned -TrustOnThisPC  # (administrateur) fait aussi confiance au certificat sur ce PC
     Le fichier dist\Malryx-certificat.cer permet de faire confiance à Malryx sur d'autres PC :
       Import-Certificate dist\Malryx-certificat.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
       Import-Certificate dist\Malryx-certificat.cer -CertStoreLocation Cert:\LocalMachine\Root
     ⚠ Un certificat auto-signé ne supprime PAS l'avertissement SmartScreen sur les PC des autres.
#>
param([string]$File = "$PSScriptRoot\dist\Malryx.exe", [switch]$SelfSigned, [switch]$TrustOnThisPC)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $File)) { throw "Fichier introuvable : $File" }
$timestamp = "http://timestamp.digicert.com"

function Find-SignTool {
    $c = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    $t = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
         Sort-Object FullName -Descending | Select-Object -First 1
    if ($t) { return $t.FullName }
    return $null
}

if ($env:MALRYX_PFX) {
    $pfx = $env:MALRYX_PFX
    if (-not (Test-Path $pfx)) {                       # contenu base64 (secret GitHub)
        $tmp = Join-Path $env:TEMP "malryx_sign.pfx"
        [IO.File]::WriteAllBytes($tmp, [Convert]::FromBase64String($pfx))
        $pfx = $tmp
    }
    $st = Find-SignTool
    if ($st) {
        & $st sign /f $pfx /p $env:MALRYX_PFX_PASSWORD /fd sha256 /tr $timestamp /td sha256 /d "Malryx Anti-Malware" $File
    } else {
        $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($pfx, $env:MALRYX_PFX_PASSWORD)
        Set-AuthenticodeSignature -FilePath $File -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $timestamp | Out-Null
    }
    if ($tmp) { Remove-Item $tmp -Force }
}
elseif ($SelfSigned) {
    $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -eq "CN=Malryx" } | Select-Object -First 1
    if (-not $cert) {
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Malryx" -FriendlyName "Malryx (auto-signé)" `
                -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 3072 -NotAfter (Get-Date).AddYears(5)
    }
    Set-AuthenticodeSignature -FilePath $File -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $timestamp | Out-Null
    $cer = Join-Path (Split-Path $File) "Malryx-certificat.cer"
    Export-Certificate -Cert $cert -FilePath $cer | Out-Null
    if ($TrustOnThisPC) {
        Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
        Write-Host "Certificat Malryx approuvé sur ce PC."
    }
}
else {
    Write-Host "Aucun certificat : définis MALRYX_PFX (vrai certificat) ou utilise -SelfSigned." -ForegroundColor Yellow
    return
}
$sig = Get-AuthenticodeSignature $File
Write-Host ("Signature : {0} – {1}" -f $sig.Status, $sig.SignerCertificate.Subject) -ForegroundColor Green
