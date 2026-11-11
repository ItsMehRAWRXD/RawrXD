#Requires -Version 5.1
# Build tip Win32IDE into NEW progression staging dir. Never touches baseline 3B720981.
$ErrorActionPreference = 'Stop'
$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat'
$buildDir = 'F:\rawrxd\build_repair_candidate'
$stageDir = 'F:\rawrxd\build_progression_finish25'
$ev = 'F:\rawrxd\evidence\PROGRESSION_FINISH25_001'
New-Item -ItemType Directory -Force -Path "$stageDir\bin", "$ev\EDITOR" | Out-Null

if (-not (Test-Path "$buildDir\deep2_engine_lib.lib")) {
  throw "Missing $buildDir\deep2_engine_lib.lib - refuse link without prebuilt deep2"
}

$cmd = @"
call "$vs" -arch=x64 >nul
cd /d "$buildDir"
cmake -S F:/rawrxd -B "$buildDir" -G Ninja -DRAWRXD_BUILD_DEEP2_ENGINE=OFF -DRAWRXD_BUILD_WIN32IDE=ON -DRAWRXD_BUILD_WIN32IDE_QT=OFF
"@
$tmp = Join-Path $env:TEMP 'pf25_cmake.cmd'
Set-Content -LiteralPath $tmp -Value $cmd -Encoding ASCII
cmd /c $tmp
if ($LASTEXITCODE -ne 0) { throw "cmake reconfig failed" }

$ninjaPath = Join-Path $buildDir 'build.ninja'
$txt = Get-Content -LiteralPath $ninjaPath -Raw
$m = [regex]::Match($txt, 'build bin\\RawrXD-Win32IDE-Native\.exe:[\s\S]*?LINK_LIBRARIES = ([^\r\n]+)')
if (-not $m.Success) { throw 'Win32IDE LINK_LIBRARIES not found' }
$curr = $m.Groups[1].Value
$linkProfile = 'SLIM_WIN32IDE_DEEP2_OFF'
if ($curr -notmatch 'deep2_engine_lib') {
  $newLink = $curr
  if ($newLink -notmatch 'dbghelp') {
    $newLink = $newLink -replace 'kernel32\.lib', 'dbghelp.lib  kernel32.lib'
  }
  $newLink = $newLink -replace 'kernel32\.lib', 'deep2_engine_lib.lib  rawrxd_gpu_compute.lib  kernel32.lib'
  $idx = $txt.IndexOf('build bin\RawrXD-Win32IDE-Native.exe:')
  $sub = $txt.Substring($idx)
  $needle = "LINK_LIBRARIES = $curr"
  $repl = "LINK_LIBRARIES = $newLink"
  $pos = $sub.IndexOf($needle)
  if ($pos -lt 0) { throw 'LINK_LIBRARIES needle not found under Win32IDE rule' }
  $sub2 = $sub.Substring(0, $pos) + $repl + $sub.Substring($pos + $needle.Length)
  $txt = $txt.Substring(0, $idx) + $sub2
  [IO.File]::WriteAllText($ninjaPath, $txt)
  $linkProfile = 'SLIM_WIN32IDE_DEEP2_LINKED_OPTREF'
}

$buildCmd = @"
call "$vs" -arch=x64 >nul
cd /d "$buildDir"
ninja RawrXD-Win32IDE-Native
echo NINJA_EXIT=%ERRORLEVEL%
"@
$tmp2 = Join-Path $env:TEMP 'pf25_ninja.cmd'
Set-Content -LiteralPath $tmp2 -Value $buildCmd -Encoding ASCII
cmd /c $tmp2
if ($LASTEXITCODE -ne 0) { throw "ninja failed" }

$exe = Join-Path $buildDir 'bin\RawrXD-Win32IDE-Native.exe'
$dest = Join-Path $stageDir 'bin\RawrXD-Win32IDE-Native.exe'
Copy-Item $exe $dest -Force
$h = Get-FileHash $dest -Algorithm SHA256
$sz = (Get-Item $dest).Length
@"
PROGRESSION_CANDIDATE_EXE=$dest
PROGRESSION_CANDIDATE_SHA=$($h.Hash)
SIZE=$sz
LINK_PROFILE=$linkProfile
BASELINE_SHA_IMMUTABLE=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
PROMOTE=0
CERTIFIED=0
"@ | Set-Content (Join-Path $ev 'BINARY_HASH.txt') -Encoding UTF8
Write-Host "PROGRESSION_CANDIDATE_SHA=$($h.Hash) SIZE=$sz LINK_PROFILE=$linkProfile"
