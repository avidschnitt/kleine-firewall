; Installationsprogramm fuer die Kleine Firewall (Inno Setup)
#define V GetEnv("KF_VERSION")
[Setup]
AppId={{8C1B6F2E-5D0A-4E7B-9A53-2F1D7C4B9E10}
AppName=Kleine Firewall
AppVersion={#V}
AppVerName=Kleine Firewall {#V}
DefaultDirName={autopf}\Kleine Firewall
DefaultGroupName=Kleine Firewall
DisableProgramGroupPage=yes
DisableDirPage=yes
OutputDir=.
OutputBaseFilename=KleineFirewall-Setup-{#V}
SetupIconFile=kleinefirewall.ico
UninstallDisplayIcon={app}\KleineFirewall.exe
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
WizardStyle=modern

[Languages]
Name: "german"; MessagesFile: "compiler:Languages\German.isl"

[Tasks]
Name: "desktopicon"; Description: "Symbol auf dem Desktop anlegen"

[Files]
Source: "dist\KleineFirewall\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\Kleine Firewall"; Filename: "{app}\KleineFirewall.exe"
Name: "{autodesktop}\Kleine Firewall"; Filename: "{app}\KleineFirewall.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\KleineFirewall.exe"; Description: "Kleine Firewall jetzt starten"; Flags: postinstall nowait skipifsilent runascurrentuser

[UninstallRun]
Filename: "{app}\KleineFirewall.exe"; Parameters: "--zuruecksetzen"; Flags: waituntilterminated; RunOnceId: "zuruecksetzen"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\KleineFirewall"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  { laufendes Programm sauber beenden, damit die Dateien ersetzt werden koennen }
  if FileExists(ExpandConstant('{app}\KleineFirewall.exe')) then
    Exec(ExpandConstant('{app}\KleineFirewall.exe'), '--beenden', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/im KleineFirewall.exe /f', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := '';
end;
