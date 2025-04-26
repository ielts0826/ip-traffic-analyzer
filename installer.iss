#define MyAppName "IP流量分析器"
#define MyAppVersion "1.0"
#define MyAppPublisher "Your Company"
#define MyAppExeName "IP流量分析器.exe"

[Setup]
; 注意: AppId的值为唯一标识此应用程序。
; 不要在其他安装程序中使用相同的AppId值。
AppId={{8C8A5F2E-6C9F-4F6C-8E2B-7B7F9D54A2D2}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
; 删除以下行以在管理安装模式下运行（需要管理员权限）
PrivilegesRequired=lowest
OutputDir=.
OutputBaseFilename=IP流量分析器_Setup
SetupIconFile=ip.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; 注意：不要在"Source"中使用"Flags: ignoreversion"，否则将无法替换文件。
Source: "build\exe.win-amd64-3.12\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "ip.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent