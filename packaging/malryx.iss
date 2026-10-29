; Malryx for Windows — script Inno Setup (W6).
; Disposition produite par le job CI w6-installer (chemins relatifs a
; ce fichier, donc dans packaging\) :
;   ..\staging\app\      <- build Flutter Windows (malryx.exe + DLL + data)
;                           + malryx-backend.exe copie a cote
;   ..\staging\clamav\   <- binaires ClamAV officiels (arbre Chocolatey)
; Sortie : ..\dist\Malryx-Setup-1.0.2.exe
;
; A l'installation (section [Run], dans l'ordre) :
;   1. generation de clamd.conf / freshclam.conf avec les chemins reels ;
;   2. exclusions Defender pour ClamAV (recette CI du 2026-10-23) ;
;   3. taches planifiees SYSTEM : clamd au demarrage, backend au demarrage ;
;   4. premier freshclam (telechargement des signatures) ;
;   5. lancement propose de l'interface.

#define AppName "Malryx"
#define AppVersion "1.0.2"
#define AppPublisher "Atamsphrow"

[Setup]
AppId={{7C9E2A54-3B1D-4F6E-A2C5-9D8B1E4F7A03}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Malryx
DefaultGroupName=Malryx
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=Malryx-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
; Pas de signature de code en v1 : SmartScreen affichera un avertissement,
; c'est documente dans la doc utilisateur (docs/UTILISATION.md).

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "Raccourci sur le Bureau"; GroupDescription: "Raccourcis :"
Name: "contextmenu"; Description: "« Analyser avec Malryx » dans le menu contextuel de l'Explorateur"; GroupDescription: "Intégration :"

[Files]
Source: "..\staging\app\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
Source: "..\staging\clamav\*"; DestDir: "{app}\clamav"; Flags: recursesubdirs ignoreversion

[Dirs]
Name: "{commonappdata}\Malryx\clamav-db"; Permissions: users-modify service-modify
Name: "{commonappdata}\Malryx\logs"; Permissions: users-modify service-modify

[Icons]
Name: "{group}\Malryx"; Filename: "{app}\malryx.exe"
Name: "{autodesktop}\Malryx"; Filename: "{app}\malryx.exe"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
  ValueType: string; ValueName: "Malryx"; ValueData: """{app}\malryx.exe"""; \
  Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Classes\*\shell\MalryxScan"; ValueType: string; \
  ValueData: "Analyser avec Malryx"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKLM; Subkey: "Software\Classes\*\shell\MalryxScan"; ValueType: string; \
  ValueName: "Icon"; ValueData: "{app}\malryx.exe"; Tasks: contextmenu
Root: HKLM; Subkey: "Software\Classes\*\shell\MalryxScan\command"; ValueType: string; \
  ValueData: """{app}\malryx.exe"" --scan ""%1"""; Tasks: contextmenu
Root: HKLM; Subkey: "Software\Classes\Directory\shell\MalryxScan"; ValueType: string; \
  ValueData: "Analyser avec Malryx"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKLM; Subkey: "Software\Classes\Directory\shell\MalryxScan"; ValueType: string; \
  ValueName: "Icon"; ValueData: "{app}\malryx.exe"; Tasks: contextmenu
Root: HKLM; Subkey: "Software\Classes\Directory\shell\MalryxScan\command"; ValueType: string; \
  ValueData: """{app}\malryx.exe"" --scan ""%1"""; Tasks: contextmenu

[Run]
; 1. Exclusions Defender : sans elles, le chargement des signatures
;    ClamAV est perturbe (constate en CI le 2026-10-23).
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -Command ""Add-MpPreference -ExclusionPath '{app}\clamav','{commonappdata}\Malryx\clamav-db'"""; \
  Flags: runhidden waituntilterminated
; 2. Demons au demarrage (SYSTEM) : clamd puis le backend Malryx.
Filename: "schtasks.exe"; \
  Parameters: "/Create /F /TN MalryxClamd /SC ONSTART /RU SYSTEM /TR ""\""{app}\clamav\clamd.exe\"" --config-file=\""{app}\clamav\clamd.conf\"""""; \
  Flags: runhidden waituntilterminated
Filename: "schtasks.exe"; \
  Parameters: "/Create /F /TN MalryxBackend /SC ONSTART /RU SYSTEM /TR ""\""{app}\malryx-backend.exe\"" --port 8765"""; \
  Flags: runhidden waituntilterminated
; 3. Premier telechargement des signatures (peut prendre plusieurs minutes).
Filename: "{app}\clamav\freshclam.exe"; \
  Parameters: "--config-file=""{app}\clamav\freshclam.conf"""; \
  BeforeInstall: WriteClamAVConfigs; \
  Flags: runhidden waituntilterminated; \
  StatusMsg: "Téléchargement des définitions antivirus (peut prendre plusieurs minutes)..."
; 2b. Demarrage immediat (v1.0.1) : sans cela, clamd et le backend
; n'attendent que le prochain redemarrage, d'ou un moteur ClamAV
; « non installe » apres une installation sans redemarrage. L'ordre
; compte : apres freshclam (etape 3), donc avec les bases presentes.
Filename: "schtasks.exe"; \
  Parameters: "/Run /TN MalryxClamd"; \
  Flags: runhidden waituntilterminated
Filename: "schtasks.exe"; \
  Parameters: "/Run /TN MalryxBackend"; \
  Flags: runhidden waituntilterminated
; 4. Lancement propose en fin d'installation.
Filename: "{app}\malryx.exe"; Description: "Lancer Malryx"; \
  Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "schtasks.exe"; Parameters: "/Delete /F /TN MalryxBackend"; Flags: runhidden
Filename: "schtasks.exe"; Parameters: "/Delete /F /TN MalryxClamd"; Flags: runhidden

[Code]
{ v1.0.2 : les configurations ClamAV sont ecrites en Pascal, pas par une
  commande PowerShell (la generation PowerShell produisait des fichiers
  mono-ligne sur le PC de l'utilisateur : toutes les directives jointes
  par des espaces, donc illisibles par ClamAV). SaveStringToFile ecrit
  exactement la chaine donnee : les #13#10 garantissent une directive
  par ligne. Appelee via BeforeInstall sur l'entree freshclam, donc
  apres la copie des fichiers et juste avant freshclam et le demarrage
  des taches (la section [Run] s'execute AVANT ssPostInstall). }
procedure WriteClamAVConfigs();
var
  DbDir, LogDir, ClamDir: String;
  ClamdConf, FreshConf: String;
begin
  DbDir := ExpandConstant('{commonappdata}\Malryx\clamav-db');
  LogDir := ExpandConstant('{commonappdata}\Malryx\logs');
  ClamDir := ExpandConstant('{app}\clamav');
  ClamdConf :=
    'DatabaseDirectory ' + DbDir + #13#10 +
    'TCPSocket 3310' + #13#10 +
    'TCPAddr 127.0.0.1' + #13#10 +
    'LogFile ' + LogDir + '\clamd.log' + #13#10 +
    'Foreground yes' + #13#10;
  FreshConf :=
    'DatabaseDirectory ' + DbDir + #13#10 +
    'DatabaseMirror database.clamav.net' + #13#10 +
    'Checks 4' + #13#10;
  if not SaveStringToFile(ClamDir + '\clamd.conf', ClamdConf, False) then
    RaiseException('Malryx : impossible d''ecrire ' + ClamDir + '\clamd.conf');
  if not SaveStringToFile(ClamDir + '\freshclam.conf', FreshConf, False) then
    RaiseException('Malryx : impossible d''ecrire ' + ClamDir + '\freshclam.conf');
end;
