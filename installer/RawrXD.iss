; ============================================================================
; RawrXD.iss - Inno Setup Installer Script
; ============================================================================
; Creates professional Windows installer for RawrXD Sovereign IDE
; ============================================================================

#define MyAppName "RawrXD Sovereign IDE"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "RawrXD Technologies"
#define MyAppURL "https://rawrxd.dev"
#define MyAppExeName "RawrXD.exe"
#define MyAppAssocName MyAppName + " File"
#define MyAppAssocExt ".rxd"
#define MyAppAssocKey StringChange(MyAppAssocName, " ", "") + MyAppAssocExt

[Setup]
; NOTE: The value of AppId uniquely identifies this application. Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{B4A5C6D7-E8F9-4A0B-B1C2-D3E4F5G6H7I8}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\RawrXD
ChangesAssociations=yes
DisableProgramGroupPage=yes
; Remove the following line to run in administrative install mode (install for all users.)
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\dist
OutputBaseFilename=RawrXD-v{#MyAppVersion}-setup
SetupIconFile=..\resources\icons\rawrxd.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
; Sign the installer (requires code signing certificate)
; SignTool=signtool
; SignedUninstaller=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; OnlyBelowVersion: 6.1; Check: not IsAdminInstallMode
Name: "associatefiles"; Description: "Associate .rxd files with RawrXD"; GroupDescription: "File associations:"

[Files]
; Main executable
Source: "..\build\Release\RawrXD.exe"; DestDir: "{app}"; Flags: ignoreversion

; Core DLLs
Source: "..\build\Release\SovereignRuntime.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\build\Release\LSPClient.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\build\Release\GitIntegration.dll"; DestDir: "{app}"; Flags: ignoreversion

; Scintilla
Source: "..\build\Release\SciLexer.dll"; DestDir: "{app}"; Flags: ignoreversion

; Vulkan runtime (if not present on system)
Source: "..\redist\vulkan-1.dll"; DestDir: "{app}"; Flags: ignoreversion; Check: NeedsVulkan

; HIP runtime (AMD GPU support)
Source: "..\redist\amdhip64.dll"; DestDir: "{app}"; Flags: ignoreversion; Check: NeedsHIP

; Default models (optional)
Source: "..\models\tinyllama-1.1b-chat.gguf"; DestDir: "{app}\models"; Flags: ignoreversion; Components: models

; Sample projects
Source: "..\samples\*"; DestDir: "{app}\samples"; Flags: ignoreversion recursesubdirs createallsubdirs

; Documentation
Source: "..\docs\README.pdf"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\docs\API_Reference.pdf"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

; Icons
Source: "..\resources\icons\*.ico"; DestDir: "{app}\resources\icons"; Flags: ignoreversion

; Configuration templates
Source: "..\config\default_settings.json"; DestDir: "{app}\config"; Flags: ignoreversion

[Components]
Name: "main"; Description: "RawrXD IDE"; Types: full compact custom; Flags: fixed
Name: "models"; Description: "Default AI Models (TinyLlama 1.1B)"; Types: full
Name: "samples"; Description: "Sample Projects"; Types: full
Name: "docs"; Description: "Documentation"; Types: full compact

[Dirs]
Name: "{app}\models"; Permissions: everyone-full
Name: "{app}\temp"; Permissions: everyone-full
Name: "{app}\logs"; Permissions: everyone-full
Name: "{localappdata}\RawrXD"; Permissions: everyone-full

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: quicklaunchicon

[Registry]
; File association
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocExt}\OpenWithProgids"; ValueType: string; ValueName: "{#MyAppAssocKey}"; ValueData: ""; Flags: uninsdeletevalue; Tasks: associatefiles
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocKey}"; ValueType: string; ValueName: ""; ValueData: "{#MyAppAssocName}"; Flags: uninsdeletekey; Tasks: associatefiles
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocKey}\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\resources\icons\rawrxd_file.ico"; Tasks: associatefiles
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocKey}\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Tasks: associatefiles

; Add to PATH (optional)
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddToPath

[Run]
; Post-install: Run first-time setup wizard
Filename: "{app}\{#MyAppExeName}"; Parameters: "--first-run"; Description: "Launch RawrXD First-Run Wizard"; Flags: postinstall skipifsilent

; Optional: Open README
Filename: "{app}\docs\README.pdf"; Description: "View README"; Flags: postinstall skipifsilent unchecked

[UninstallRun]
; Cleanup before uninstall
Filename: "{app}\{#MyAppExeName}"; Parameters: "--cleanup"; RunOnceId: "CleanupRawrXD"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\temp"
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{localappdata}\RawrXD\cache"

[Code]
function NeedsVulkan(): Boolean;
begin
  // Check if Vulkan runtime is already installed
  Result := not RegKeyExists(HKLM, 'SOFTWARE\Khronos\Vulkan\Runtime');
end;

function NeedsHIP(): Boolean;
begin
  // Check if AMD HIP is installed
  Result := not RegKeyExists(HKLM, 'SOFTWARE\AMD\HIP');
end;

function NeedsAddToPath(): Boolean;
begin
  // Only add to PATH in admin mode
  Result := IsAdminInstallMode;
end;

procedure InitializeWizard();
begin
  // Custom welcome page
  WizardForm.WelcomeLabel1.Caption := 'Welcome to RawrXD Setup';
  WizardForm.WelcomeLabel2.Caption := 'This will install RawrXD Sovereign IDE v' + '{#MyAppVersion}' + ' on your computer.' + #13#10 + #13#10 +
    'RawrXD is a native Win32 AI development environment with local model inference.' + #13#10 + #13#10 +
    'Click Next to continue, or Cancel to exit Setup.';
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := true;
  
  // Check system requirements on select components page
  if CurPageID = wpSelectComponents then
  begin
    if not IsDotNetInstalled(net48, 0) then
    begin
      MsgBox('RawrXD requires .NET Framework 4.8 or higher.' + #13#10 +
             'Please install it and run setup again.', mbError, MB_OK);
      Result := false;
    end;
  end;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  Result := MemoUserInfoInfo + NewLine + NewLine +
            MemoDirInfo + NewLine + NewLine +
            MemoTypeInfo + NewLine + NewLine +
            MemoComponentsInfo + NewLine + NewLine +
            MemoGroupInfo + NewLine + NewLine +
            MemoTasksInfo;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Create default config if it doesn't exist
    if not FileExists(ExpandConstant('{localappdata}\RawrXD\settings.json')) then
    begin
      CreateDir(ExpandConstant('{localappdata}\RawrXD'));
      FileCopy(ExpandConstant('{app}\config\default_settings.json'), 
               ExpandConstant('{localappdata}\RawrXD\settings.json'), 
               False);
    end;
  end;
end;

[CustomMessages]
; Custom messages for better UX
CreateDesktopIcon=Create a &desktop icon
CreateQuickLaunchIcon=Create a &Quick Launch icon
