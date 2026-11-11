#Requires -Version 5.1
$ErrorActionPreference = 'Continue'
$Out = 'F:\rawrxd\evidence\PROGRESSION_FINISH25_001\CANCEL\logs'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Log = Join-Path $Out 'force_rebuild_tip.txt'
function W($m){ $l='[{0}] {1}' -f (Get-Date -Format o),$m; Add-Content -LiteralPath $Log $l; Write-Output $l }

Set-Location F:\rawrxd
W 'GIT_STATUS_PRE'
git status --short src/win32app/Win32IDE_lifecycle.cpp src/win32app/Win32IDE_FileOps.cpp src/win32app/Win32IDE.h src/win32app/Win32IDE.cpp 2>&1 | Tee-Object -FilePath (Join-Path $Out 'git_status_tip.txt')

# Restore lifecycle if polluted (view-state fields vs F DocumentBuffer).
$lc = 'src\win32app\Win32IDE_lifecycle.cpp'
$hasSel = Select-String -LiteralPath $lc -Pattern 'selStart' -Quiet
W "LIFECYCLE_HAS_SELSTART=$hasSel"
if ($hasSel) {
  W 'RESTORE_LIFECYCLE_FROM_HEAD'
  git checkout HEAD -- src/win32app/Win32IDE_lifecycle.cpp 2>&1 | ForEach-Object { W $_ }
}

# Ensure T10 fix present in FileOps
$fo = 'src\win32app\Win32IDE_FileOps.cpp'
$hasT10 = Select-String -LiteralPath $fo -Pattern 'Force a real load' -Quiet
W "FILEOPS_T10_FIX=$hasT10"
if (-not $hasT10) {
  W 'T10_FIX_MISSING_ABORT'
  exit 2
}

# Tip: drain queued WM_APP+106 on Request A fence (already-posted discovery).
$ide = 'src\win32app\Win32IDE.cpp'
$hasDrain = Select-String -LiteralPath $ide -Pattern 'PeekMessageA.*WM_APP \+ 106|drain queued model-discovery' -Quiet
W "SEND_DRAIN_106=$hasDrain"

# Force rebuild objects
$build = 'F:\rawrxd\build_repair_candidate'
$objs = @(
  'CMakeFiles\RawrXD-Win32IDE-Native.dir\src\win32app\Win32IDE_FileOps.cpp.obj',
  'CMakeFiles\RawrXD-Win32IDE-Native.dir\src\win32app\Win32IDE.cpp.obj',
  'CMakeFiles\RawrXD-Win32IDE-Native.dir\src\win32app\Win32IDE_lifecycle.cpp.obj'
)
foreach ($o in $objs) {
  $p = Join-Path $build $o
  if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force; W "DEL_OBJ=$o" }
}

$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat'
$cmd = @"
call "$vs" -arch=x64 >nul
cd /d "$build"
ninja RawrXD-Win32IDE-Native
echo NINJA_EXIT=%ERRORLEVEL%
"@
$tmp = Join-Path $env:TEMP 'pf25_force_ninja.cmd'
Set-Content -LiteralPath $tmp -Value $cmd -Encoding ASCII
cmd /c $tmp 2>&1 | Tee-Object -FilePath (Join-Path $Out 'force_ninja_stdout.txt')
W "NINJA_LASTEXIT=$LASTEXITCODE"

$built = Join-Path $build 'bin\RawrXD-Win32IDE-Native.exe'
$dest = 'F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe'
if (-not (Test-Path -LiteralPath $built)) { W 'BUILD_EXE_MISSING'; exit 3 }
Copy-Item -LiteralPath $built -Destination $dest -Force
$h = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
$sz = (Get-Item -LiteralPath $dest).Length
W "POST_SHA=$h SIZE=$sz"
@"
PROGRESSION_CANDIDATE_EXE=$dest
PROGRESSION_CANDIDATE_SHA=$h
SIZE=$sz
LINK_PROFILE=SLIM_WIN32IDE_DEEP2_LINKED_OPTREF
BASELINE_SHA_IMMUTABLE=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
PROMOTE=0
CERTIFIED=0
TIP=REQUEST_A_DRAIN_106+T10_FORCE_SWITCH
"@ | Set-Content -LiteralPath 'F:\rawrxd\evidence\PROGRESSION_FINISH25_001\BINARY_HASH.txt' -Encoding UTF8
W 'DONE'
