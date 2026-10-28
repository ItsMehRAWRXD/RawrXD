$ErrorActionPreference = "Stop"
$Root = "G:\~dev\rawrxd"
$Ev = Join-Path $Root "evidence\RAWRXD_GPU_CODE31_RESET_001"
$Out = Join-Path $Ev "smoke_code31_reset.exe"
$Log = Join-Path $Ev "smoke_run.log"
$Receipt = Join-Path $Ev "RECEIPT.txt"
$Manifest = Join-Path $Ev "smoke_code31.manifest"
$PnpScript = Join-Path $Root "scripts\Reset-GpuDevicePnp.ps1"

# Auto elevated PnP cycle when 7800 XT is Code 10/31 (UAC RunAs if needed).
if (Test-Path $PnpScript) {
  Write-Host "GPU_ELEV_PNP_PREFLIGHT=$PnpScript"
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PnpScript
  Write-Host "GPU_ELEV_PNP_PREFLIGHT_EXIT=$LASTEXITCODE"
  # Avoid a second UAC from the C++ helper in the same smoke run.
  $env:RAWRXD_PNP_ELEV_DONE = "1"
}

$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
  -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
  -property installationPath 2>$null
if (-not $vs) { $vs = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools" }
$vcvars = Join-Path $vs "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) {
  @"
ASOF=$(Get-Date -Format o)
SOURCE_WIRED=1
RUNTIME_REACHED=0
DISPOSITION=NOT_RUN
REASON=vcvars64_missing
PROMOTE=0
"@ | Set-Content $Receipt
  exit 2
}

$manFlag = ""
if (Test-Path $Manifest) {
  $manFlag = "/MANIFESTUAC:level='requireAdministrator' /MANIFESTFILE:`"$Manifest`""
}

$cmd = @"
call `"$vcvars`" >nul
cl /nologo /EHsc /std:c++17 /O2 /DWIN32 /D_WINDOWS /I`"src\deep2`" /I`"include`" /Fe:`"$Out`" `"$Ev\src\smoke_code31_reset.cpp`" `"src\deep2\GpuPreflight.cpp`" `"src\deep2\GpuPreflightReset.cpp`" `"src\deep2\GpuPreflightElevatedPnp.cpp`" setupapi.lib cfgmgr32.lib advapi32.lib shell32.lib $manFlag 2>&1
if errorlevel 1 exit /b 1
`"$Out`" 2>`"$Log`"
exit /b %ERRORLEVEL%
"@
$tmp = Join-Path $env:TEMP "build_code31_smoke.cmd"
Set-Content $tmp $cmd
Push-Location $Root
cmd /c $tmp
$rc = $LASTEXITCODE
Pop-Location

$logTxt = if (Test-Path $Log) { Get-Content $Log -Raw } else { "" }
$disp = if ($logTxt -match 'DISPOSITION=(\w+)') { $Matches[1] } elseif ($rc -eq 0) { "PASS" } else { "FAIL" }
$runtime = if (Test-Path $Out) { 1 } else { 0 }
$recog = if ($logTxt -match 'RECOG_CODE31=1') { 1 } else { 0 }
$live = if ($logTxt -match 'LIVE_CODE31=(\d+)') { [int]$Matches[1] } else { -1 }
$live10 = if ($logTxt -match 'LIVE_CODE10=(\d+)') { [int]$Matches[1] } else { -1 }
$resetResult = if ($logTxt -match 'GPU_RESET=(\S+)') { $Matches[1] } else { "N/A" }
@"
ASOF=$(Get-Date -Format o)
EVIDENCE=RAWRXD_GPU_CODE31_RESET_001
SOURCE_WIRED=1
RUNTIME_REACHED=$runtime
RECOG_CODE31=$recog
LIVE_CODE31=$live
LIVE_CODE10=$live10
RESET_ATTEMPTED=$(if ($logTxt -match 'RESET_ATTEMPT=[1-9]') { 1 } else { 0 })
RESET_RESULT=$resetResult
RESET_VERIFIED=$(if ($disp -eq 'PASS') { 1 } else { 0 })
EXIT_CODE=$rc
DISPOSITION=$disp
PROMOTE=0
TIP_CLIMB=HOLD
PRODUCT_PATH=GpuPreflight+GpuPreflightReset+GpuPreflightElevatedPnp+Reset-GpuDevicePnp.ps1
LOG=smoke_run.log
"@ | Set-Content $Receipt
Get-Content $Receipt
exit $rc
