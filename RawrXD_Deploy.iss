; =====================================================================================
; INSTALLATION MANIFEST SPECIFICATION: RawrXD Enterprise Installation Package Wizard
; Compiler Target: Inno Setup 6+ Engine Toolchain
; =====================================================================================

[Setup]
AppId={{5A4F5244-5844-4E41-5449-5645434F5245}
AppName=RawrXD Inference Platform Node
AppVersion=1.0.0.0
AppPublisher=Sovereign AI Systems International Inc.
AppPublisherURL=https://sovereignaisystems.com
DefaultDirName={autopf}\RawrXD
DefaultGroupName=RawrXD
AllowNoIcons=yes
LicenseFile=LICENSE.txt
PrivilegesRequired=admin
OutputDir=release
OutputBaseFilename=RawrXD_Setup_x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "release\RawrXD.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "src\config\panels.json"; DestDir: "{app}\src\config"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\RawrXD Node Manager"; Filename: "{app}\RawrXD.exe"
Name: "{autodesktop}\RawrXD Node Manager"; Filename: "{app}\RawrXD.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\RawrXD.exe"; Description: "{cm:LaunchProgram,RawrXD Inference Node Manager}"; Flags: nowait postinstall skipifsilent
