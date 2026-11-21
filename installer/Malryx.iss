; Installateur Malryx (Inno Setup 6) – compilé par build.ps1 :  ISCC.exe /DAppVersion=x.y.z installer\Malryx.iss
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6B1F3C2A-8E4D-4C1B-9F2E-4D6A7B8C9E10}
AppName=Malryx
AppVersion={#AppVersion}
AppVerName=Malryx {#AppVersion}
AppPublisher=Malryx
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\Malryx
DefaultGroupName=Malryx
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=Malryx-Setup
SetupIconFile=..\assets\malryx.ico
UninstallDisplayIcon={app}\Malryx.exe
Compression=lzma2/ultra64
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
WizardStyle=modern
CloseApplications=yes

[Languages]
Name: "fr"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "Créer une icône sur le Bureau"; Flags: unchecked
Name: "autostart"; Description: "Lancer Malryx au démarrage de Windows (recommandé)"
Name: "contextmenu"; Description: "Ajouter « Analyser avec Malryx » au clic droit"

[Files]
Source: "..\dist\Malryx\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Malryx"; Filename: "{app}\Malryx.exe"
Name: "{group}\Désinstaller Malryx"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Malryx"; Filename: "{app}\Malryx.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Malryx"; \
  ValueData: """{app}\Malryx.exe"" --minimized"; Tasks: autostart; Flags: uninsdeletevalue
Root: HKCU; Subkey: "Software\Classes\*\shell\Malryx"; ValueType: string; ValueName: "MUIVerb"; ValueData: "Analyser avec Malryx"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\*\shell\Malryx"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\Malryx.exe"; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\*\shell\Malryx\command"; ValueType: string; ValueData: """{app}\Malryx.exe"" --scan ""%1"""; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\Malryx"; ValueType: string; ValueName: "MUIVerb"; ValueData: "Analyser avec Malryx"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\Directory\shell\Malryx\command"; ValueType: string; ValueData: """{app}\Malryx.exe"" --scan ""%1"""; Tasks: contextmenu

[Run]
Filename: "{app}\Malryx.exe"; Description: "Lancer Malryx"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/IM Malryx.exe /F"; Flags: runhidden; RunOnceId: "StopMalryx"
Filename: "{sys}\taskkill.exe"; Parameters: "/IM clamd.exe /F"; Flags: runhidden; RunOnceId: "StopClamd"
