#Requires -Version 5.1
# Recovery: rebuild tip Win32IDE objs, link EXISTING deep2_engine_lib.lib (do NOT rebuild deep2 tip).
# Stages NEW candidate under build_repair_finish25. Never touches baseline 3B720981 tree.
$ErrorActionPreference = 'Stop'
$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat'
$srcRoot = 'F:\rawrxd'
$buildDir = 'F:\rawrxd\build_repair_candidate'
$stageDir = 'F:\rawrxd\build_repair_finish25'
$ev = 'F:\rawrxd\evidence\REPAIR_FINISH25_001'
New-Item -ItemType Directory -Force -Path "$stageDir\bin", "$ev\EDITOR" | Out-Null

if (-not (Test-Path "$buildDir\deep2_engine_lib.lib")) {
  throw "Missing $buildDir\deep2_engine_lib.lib - refuse link without prebuilt deep2"
}

$cmd = @"
call "$vs" -arch=x64 >nul
cd /d "$buildDir"
cmake -S F:/rawrxd -B "$buildDir" -G Ninja -DRAWRXD_BUILD_DEEP2_ENGINE=OFF -DRAWRXD_BUILD_WIN32IDE=ON -DRAWRXD_BUILD_WIN32IDE_QT=OFF
"@
$tmp = Join-Path $env:TEMP 'rf25_cmake_off.cmd'
Set-Content -LiteralPath $tmp -Value $cmd -Encoding ASCII
cmd /c $tmp
if ($LASTEXITCODE -ne 0) { throw "cmake reconfig failed" }

$ninjaPath = Join-Path $buildDir 'build.ninja'
$txt = Get-Content -LiteralPath $ninjaPath -Raw
$m = [regex]::Match($txt, 'build bin\\RawrXD-Win32IDE-Native\.exe:[\s\S]*?LINK_LIBRARIES = ([^\r\n]+)')
if (-not $m.Success) { throw 'Win32IDE LINK_LIBRARIES not found' }
$curr = $m.Groups[1].Value
if ($curr -notmatch 'deep2_engine_lib') {
  $newLink = $curr
  if ($newLink -notmatch 'dbghelp') {
    $newLink = $newLink -replace 'kernel32\.lib', 'dbghelp.lib  kernel32.lib'
  }
  $newLink = $newLink -replace 'kernel32\.lib', 'deep2_engine_lib.lib  rawrxd_gpu_compute.lib  kernel32.lib'
  # Patch only the first LINK_LIBRARIES after the Win32IDE exe rule
  $idx = $txt.IndexOf('build bin\RawrXD-Win32IDE-Native.exe:')
  $sub = $txt.Substring($idx)
  $needle = "LINK_LIBRARIES = $curr"
  $repl = "LINK_LIBRARIES = $newLink"
  $pos = $sub.IndexOf($needle)
  if ($pos -lt 0) { throw 'LINK_LIBRARIES needle not found under Win32IDE rule' }
  $sub2 = $sub.Substring(0, $pos) + $repl + $sub.Substring($pos + $needle.Length)
  $txt = $txt.Substring(0, $idx) + $sub2
  [IO.File]::WriteAllText($ninjaPath, $txt)
}

$buildCmd = @"
call "$vs" -arch=x64 >nul
cd /d "$buildDir"
ninja RawrXD-Win32IDE-Native
echo NINJA_EXIT=%ERRORLEVEL%
"@
$tmp2 = Join-Path $env:TEMP 'rf25_ninja.cmd'
Set-Content -LiteralPath $tmp2 -Value $buildCmd -Encoding ASCII
cmd /c $tmp2
if ($LASTEXITCODE -ne 0) { throw "ninja failed" }

$exe = Join-Path $buildDir 'bin\RawrXD-Win32IDE-Native.exe'
Copy-Item $exe (Join-Path $stageDir 'bin\RawrXD-Win32IDE-Native.exe') -Force
$h = Get-FileHash $exe -Algorithm SHA256
$sz = (Get-Item $exe).Length
@"
REPAIR_CANDIDATE_EXE=$stageDir\bin\RawrXD-Win32IDE-Native.exe
REPAIR_CANDIDATE_SHA=$($h.Hash)
SIZE=$sz
DEEP2_LINKED=1
PROMOTE=0
"@ | Set-Content (Join-Path $ev 'BINARY_HASH.txt') -Encoding UTF8
Write-Host "STAGED_SHA=$($h.Hash) SIZE=$sz"
