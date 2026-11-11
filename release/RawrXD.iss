; ============================================================================
; RawrXD.iss - Inno Setup Installer Script v1.0.0
; ============================================================================
; Produces: RawrXD-v1.0.0-setup.exe
; Features: Silent install, file associations, desktop shortcut, auto-updater
; ============================================================================

#define MyAppName "RawrXD"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "RawrXD Labs"
#define MyAppURL "https://rawrxd.dev"
#define MyAppExeName "RawrXD.exe"
#define MyAppId "{{B4E6A1F2-3C8D-4E5B-9A7C-2F1E8D6B5A3C}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/support
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=..\LICENSE.txt
OutputDir=..\dist
OutputBaseFilename=RawrXD-v{#MyAppVersion}-setup
SetupIconFile=..\assets\icon.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequiredOverridesAllowed=dialog
MinVersion=10.0.17763
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "fileassoc"; Description: "Associate with C++ and Python files"; GroupDescription: "File associations:"
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; OnlyBelowVersion: 6.1; Check: not IsAdminInstallMode
Name: "vulkanruntime"; Description: "Install Vulkan Runtime (if not present)"; GroupDescription: "Dependencies:"

[Files]
; Main executable
Source: "..\bin\Release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\bin\Release\SovereignRuntime.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\bin\Release\GGUFEngine.dll"; DestDir: "{app}"; Flags: ignoreversion

; Vulkan dependencies
Source: "..\bin\Release\vulkan-1.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\bin\Release\VkLayer_khronos_validation.dll"; DestDir: "{app}"; Flags: ignoreversion; Check: WizardIsTaskSelected('vulkanruntime')

; Scintilla editor component
Source: "..\bin\Release\SciLexer.dll"; DestDir: "{app}"; Flags: ignoreversion

; Default configuration
Source: "..\config\default.json"; DestDir: "{app}\config"; Flags: ignoreversion
Source: "..\config\themes\*.json"; DestDir: "{app}\config\themes"; Flags: ignoreversion

; Sample models (TinyLlama for first-run)
Source: "..\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"; DestDir: "{app}\models"; Flags: ignoreversion; Check: not FileExists(ExpandConstant('{app}\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'))

; Documentation
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\docs\*.pdf"; DestDir: "{app}\docs"; Flags: ignoreversion

; License
Source: "..\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: quicklaunchicon

[Registry]
; File associations for C++
Root: HKA; Subkey: "Software\Classes\.cpp"; ValueType: string; ValueName: ""; ValueData: "RawrXD.cpp"; Flags: uninsdeletevalue; Tasks: fileassoc
Root: HKA; Subkey: "Software\Classes\RawrXD.cpp"; ValueType: string; ValueName: ""; ValueData: "C++ Source File"; Flags: uninsdeletekey; Tasks: fileassoc
Root: HKA; Subkey: "Software\Classes\RawrXD.cpp\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName},0"; Tasks: fileassoc
Root: HKA; Subkey: "Software\Classes\RawrXD.cpp\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Tasks: fileassoc

; File associations for headers
Root: HKA; Subkey: "Software\Classes\.h"; ValueType: string; ValueName: ""; ValueData: "RawrXD.h"; Flags: uninsdeletevalue; Tasks: fileassoc
Root: HKA; Subkey: "Software\Classes\RawrXD.h"; ValueType: string; ValueName: ""; ValueData: "C++ Header File"; Flags: uninsdeletekey; Tasks: fileassoc
Root: HKA; Subkey: "Software\Classes\RawrXD.h\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Tasks: fileassoc

; File associations for Python
Root: HKA; Subkey: "Software\Classes\.py"; ValueType: string; ValueName: ""; ValueData: "RawrXD.py"; Flags: uninsdeletevalue; Tasks: fileassoc
Root: HKA; Subkey: "Software\Classes\RawrXD.py"; ValueType: string; ValueName: ""; ValueData: "Python Source File"; Flags: uninsdeletekey; Tasks: fileassoc
Root: HKA; Subkey: "Software\Classes\RawrXD.py\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Tasks: fileassoc

; Environment variables
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "RAWRXD_HOME"; ValueData: "{app}"; Flags: uninsdeletevalue

; Protocol handler for rawrxd:// links
Root: HKA; Subkey: "Software\Classes\rawrxd"; ValueType: string; ValueName: ""; ValueData: "RawrXD Protocol"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\rawrxd"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Classes\rawrxd\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\cache"
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\temp"

[Code]
// Check for Vulkan runtime
function VulkanRuntimeExists(): Boolean;
var
  VulkanDll: String;
begin
  VulkanDll := ExpandConstant('{sys}\vulkan-1.dll');
  Result := FileExists(VulkanDll);
end;

// Initialize setup
function InitializeSetup(): Boolean;
begin
  // Check Windows version (Windows 10 1809 or later)
  if not IsWindowsVersion(10, 0, 17763) then begin
    MsgBox('RawrXD requires Windows 10 version 1809 or later.', mbError, MB_OK);
    Result := false;
    Exit;
  end;
  
  // Check for 64-bit Windows
  if not Is64BitInstallMode then begin
    MsgBox('RawrXD requires 64-bit Windows.', mbError, MB_OK);
    Result := false;
    Exit;
  end;
  
  Result := true;
end;

// Post-install: Create config if not exists
procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfigPath: String;
begin
  if CurStep = ssPostInstall then begin
    ConfigPath := ExpandConstant('{app}\config\user.json');
    if not FileExists(ConfigPath) then begin
      // Create default user config
      SaveStringToFile(ConfigPath, 
        '{' + #13#10 +
        '  "version": "1.0.0",' + #13#10 +
        '  "firstRun": true,' + #13#10 +
        '  "modelPath": "{app}\\models",' + #13#10 +
        '  "theme": "dark",' + #13#10 +
        '  "fontSize": 14,' + #13#10 +
        '  "enableGhostText": true,' + #13#10 +
        '  "enableLSP": true,' + #13#10 +
        '  "autoUpdateCheck": true' + #13#10 +
        '}', False);
    end;
  end;
end;

// Uninstall: Clean up user data (optional)
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DeleteUserData: Integer;
begin
  if CurUninstallStep = usPostUninstall then begin
    DeleteUserData := MsgBox('Do you want to delete all user data (settings, cached models, logs)?' + #13#10 + 
                             'This cannot be undone.', mbConfirmation, MB_YESNO);
    if DeleteUserData = IDYES then begin
      DelTree(ExpandConstant('{localappdata}\RawrXD'), True, True, True);
    end;
  end;
end;
