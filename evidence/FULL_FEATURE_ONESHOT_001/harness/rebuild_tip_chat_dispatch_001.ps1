# Rebuild tip_chat_dispatch_001 with send_seq journal. Never overwrite A4F / tip_final_004 / tip_final_005.
# PROMOTE=0 CERTIFIED=0 PRODUCT_PASS=0
$ErrorActionPreference = "Stop"
$Root = "F:\rawrxd"
$BuildDir = Join-Path $Root "build_tip_chat_dispatch_001"
# Reuse chat ctrl-enter build tree if present (same Native-Ext flags); else fall back.
$SrcBuild = Join-Path $Root "build_tip_chat_ctrl_enter_002"
$PkgDir = Join-Path $Root "evidence\DAILY_DRIVER_CLOSE_001\package\tip_chat_dispatch_001"
$LaneArt = Join-Path $Root "evidence\FULL_FEATURE_ONESHOT_001\artifacts"
$Log = Join-Path $LaneArt ("TIP_CHAT_DISPATCH_001_BUILD_" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")
$Vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
$Ninja = "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ninja.exe"
if (-not (Test-Path $Ninja)) {
  $Ninja = "C:\Program Files\CMake\bin\ninja.exe"
}
New-Item -ItemType Directory -Force -Path $LaneArt,$PkgDir | Out-Null

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $Log -Value $line
  Write-Host $line
}

if (-not (Test-Path $Vcvars)) { throw "vcvars64 missing: $Vcvars" }
if (-not (Test-Path $SrcBuild)) { throw "source build dir missing: $SrcBuild" }

Log "SRC_BUILD=$SrcBuild"
Log "PKG_DIR=$PkgDir"
Log "LOG=$Log"

# Touch Win32IDE.cpp object rebuild via ninja in existing configured tree.
$cmd = @"
call "$Vcvars" >nul
cd /d "$SrcBuild"
ninja RawrXD-Win32IDE-Native-Ext
echo NINJA_RC=!ERRORLEVEL!
"@
cmd.exe /c "$cmd" 2>&1 | Tee-Object -FilePath $Log -Append
$exe = Join-Path $SrcBuild "bin\RawrXD-Win32IDE-Native-Ext.exe"
if (-not (Test-Path $exe)) {
  $exe = Get-ChildItem -Path $SrcBuild -Recurse -Filter "RawrXD-Win32IDE-Native-Ext.exe" |
    Select-Object -First 1 -ExpandProperty FullName
}
if (-not $exe -or -not (Test-Path $exe)) { throw "built exe not found under $SrcBuild" }

Copy-Item -Force $exe (Join-Path $PkgDir "RawrXD-Win32IDE-Native-Ext.exe")
$hash = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $PkgDir "RawrXD-Win32IDE-Native-Ext.exe")).Hash
Set-Content -Path (Join-Path $PkgDir "SHA256.txt") -Value $hash -Encoding ASCII
Log "TIP_EXE=$PkgDir\RawrXD-Win32IDE-Native-Ext.exe"
Log "TIP_SHA256=$hash"
Log "A4F_UNTOUCHED=1"
Log "TIP_FINAL_004_UNTOUCHED=1"
Log "TIP_FINAL_005_UNTOUCHED=1"
Log "PROMOTE=0"
Write-Output "TIP_SHA256=$hash"
