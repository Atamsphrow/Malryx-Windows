; Malryx for Windows — script Inno Setup (W6, brouillon structurel).
; Les chemins sources correspondent a la disposition produite par le
; job CI w6 : 
;   staging\app\        <- build Flutter Windows (malryx.exe + DLL + data)
;   staging\app\malryx-backend.exe  <- PyInstaller (a cote de l'UI,
;                                      trouve par BackendProcess)
;   staging\clamav\     <- binaires ClamAV officiels extraits du ZIP
; Le script est ajuste et valide dans le job w6-installer.

#define AppName "Malryx"
#define AppVersion "1.0.0"
#define AppPublisher "Atamsphrow"

[Setup]
AppId={{6A298D72-9A55-4A26-8D02-E9AB76535B6C}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Malryx
DefaultGroupName=Malryx
DisableProgramGroupPage=yes
OutputBaseFilename=Malryx-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
; Pas de signature de code en v1 : SmartScreen affichera un avertissement,
; c'est documente dans la doc utilisateur.

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "Raccourci sur le Bureau"; GroupDescription: "Raccourcis :"
Name: "contextmenu"; Description: "« Analyser avec Malryx » dans le menu contextuel de l'Explorateur"; GroupDescription: "Integration :"

[Files]
Source: "staging\app\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
Source: "staging\clamav\*"; DestDir: "{app}\clamav"; Flags: recursesubdirs ignoreversion

[Dirs]
; Bases de signatures ClamAV (freshclam y ecrit) et journaux.
Name: "{commonappdata}\Malryx\clamav-db"; Permissions: users-modify
Name: "{commonappdata}\Malryx\logs"; Permissions: users-modify

[Icons]
Name: "{group}\Malryx"; Filename: "{app}\malryx.exe"
Name: "{autodesktop}\Malryx"; Filename: "{app}\malryx.exe"; Tasks: desktopicon

[Registry]
; Demarrage de l'interface avec la session (le backend tourne en tache
; SYSTEM, voir [Run] / planification dans la doc W6).
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
  ValueType: string; ValueName: "Malryx"; ValueData: """{app}\malryx.exe"""; \
  Flags: uninsdeletevalue
; Menu contextuel Explorateur (si la tache est cochee).
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
; Exclusions Defender : sans elles, le chargement des signatures ClamAV
; est perturbe (constate en CI le 2026-10-23, connexions TCP coupees).
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -Command ""Add-MpPreference -ExclusionPath '{app}\clamav','{commonappdata}\Malryx\clamav-db'"""; \
  Flags: runhidden waituntilterminated
; Premier telechargement des bases de signatures.
Filename: "{app}\clamav\freshclam.exe"; \
  Parameters: "--config-file=""{app}\clamav\freshclam.conf"""; \
  Flags: runhidden waituntilterminated; \
  StatusMsg: "Telechargement des definitions antivirus (peut prendre plusieurs minutes)..."
; Lancement propose en fin d'installation.
Filename: "{app}\malryx.exe"; Description: "Lancer Malryx"; \
  Flags: nowait postinstall skipifsilent
