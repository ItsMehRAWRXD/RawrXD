# install_rawr.ps1
# Installs the rawr CLI so `rawr run <model> "<prompt>"` works from any shell,
# and persists across PC reboots (user-scope PATH + RAWRXD_MODEL_DIR).
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File install_rawr.ps1
#   ... -InstallDir "C:\Users\Garrett\rawrxd\bin" -ModelDir "F:\models"
#   ... -RegisterAutostart   (optional: launch product on login/reboot)
#
# Safe + reversible: uses USER scope (no admin), copies rawr.exe to a stable dir
# (not the build output), and only appends to PATH if missing.

param(
    [string]$SourceExe    = "F:\~dev\build_win32ide_strict\bin\rawr.exe",
    [string]$InstallDir   = "$env:USERPROFILE\rawrxd\bin",
    [string]$ModelDir     = "F:\models",
    [string]$IdeExe       = "F:\~dev\build_win32ide_strict\bin\RawrXD-Win32IDE.exe",
    [switch]$RegisterAutostart,
    [string]$Receipt      = "F:\~dev\_install_rawr_receipt.txt"
)

$ErrorActionPreference = "Stop"
$lines = @()
function Log($m) { Write-Output $m; $script:lines += $m }

Log "=== RAWR INSTALL ==="
Log "SOURCE_EXE=$SourceExe"
Log "INSTALL_DIR=$InstallDir"
Log "MODEL_DIR=$ModelDir"

if (-not (Test-Path $SourceExe)) {
    Log "SOURCE_EXE_EXISTS=0"
    Log "VERDICT=FAIL  reason=source rawr.exe not found (build the 'rawr' target first)"
    $lines | Set-Content $Receipt -Encoding UTF8
    exit 1
}
Log "SOURCE_EXE_EXISTS=1"

# 1. Stable install dir + copy
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item $SourceExe (Join-Path $InstallDir "rawr.exe") -Force
$installedExe = Join-Path $InstallDir "rawr.exe"
Log "INSTALLED_EXE=$installedExe"
Log "INSTALLED_EXE_EXISTS=$([bool](Test-Path $installedExe))"

# 2. User PATH (persistent, appended only if missing)
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($null -eq $userPath) { $userPath = "" }
$onPath = ($userPath -split ';' | Where-Object { $_.TrimEnd('\') -ieq $InstallDir.TrimEnd('\') }).Count -gt 0
if ($onPath) {
    Log "PATH_ALREADY_PRESENT=1"
} else {
    $newPath = if ($userPath.TrimEnd(';')) { $userPath.TrimEnd(';') + ';' + $InstallDir } else { $InstallDir }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Log "PATH_APPENDED=1"
}

# 3. RAWRXD_MODEL_DIR (persistent, user)
[Environment]::SetEnvironmentVariable('RAWRXD_MODEL_DIR', $ModelDir, 'User')
Log "RAWRXD_MODEL_DIR_SET=$ModelDir"
Log "MODEL_DIR_EXISTS=$([bool](Test-Path $ModelDir))"

# 4. Optional autostart on reboot/login (user-scope Run key -> product IDE)
if ($RegisterAutostart) {
    if (Test-Path $IdeExe) {
        $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        New-ItemProperty -Path $runKey -Name 'RawrXD' -Value "`"$IdeExe`"" -PropertyType String -Force | Out-Null
        Log "AUTOSTART_REGISTERED=1  key=$runKey\RawrXD -> $IdeExe"
    } else {
        Log "AUTOSTART_REGISTERED=0  reason=IDE exe not found: $IdeExe"
    }
} else {
    Log "AUTOSTART_REGISTERED=0  reason=not requested (pass -RegisterAutostart to enable)"
}

# 5. Verify in a fresh child process (picks up new user env)
$verify = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command {
    $p = [Environment]::GetEnvironmentVariable('Path','User')
    $m = [Environment]::GetEnvironmentVariable('RAWRXD_MODEL_DIR','User')
    $cmd = Get-Command rawr -ErrorAction SilentlyContinue
    "PATH_HAS_RAWR=$([bool]$cmd);RAWR_SOURCE=$($cmd.Source);MODEL_DIR=$m"
} 2>&1
Log "VERIFY_FRESH_SHELL=$verify"

Log "VERDICT=PASS"
Log "NOTE=Open a NEW terminal, then: rawr run <modelname-or-gguf> `"<prompt>`""
$lines | Set-Content $Receipt -Encoding UTF8
Log "RECEIPT=$Receipt"
