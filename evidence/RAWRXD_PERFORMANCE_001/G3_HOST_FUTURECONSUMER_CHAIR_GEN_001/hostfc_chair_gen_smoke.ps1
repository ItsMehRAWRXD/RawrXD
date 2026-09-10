# hostfc_chair_gen_smoke.ps1 — chair+gen wake path; no Vulkan.
$ErrorActionPreference = "Stop"
$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
$cl = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe"
$src = "G:\~dev\rawrxd\src\deep2"
$ev = "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_HOST_FUTURECONSUMER_CHAIR_GEN_001"
$out = Join-Path $ev "hostfc_chair_gen_smoke.exe"
$files = @(
  "$src\lavapath\FreeTokenMicroZone.cpp",
  "$src\lavapath\FreeTokenMicroZone_Query.cpp",
  "$src\lavapath\FutureConsumer_Space.cpp",
  "$src\lavapath\FutureConsumer_Register.cpp",
  "$src\lavapath\FutureConsumer_Advance.cpp",
  "$src\lavapath\FutureConsumer_Chair.cpp",
  "$src\lavapath\FutureConsumer_Notes.cpp",
  "$src\lavapath\FutureConsumer_Emit.cpp",
  "$src\lavapath\FutureConsumer_EmitExec.cpp",
  "$src\lavapath\HostFutureConsumerPrefetch.cpp",
  "$src\lavapath\HostFutureConsumerPrefetch_Move.cpp",
  "$src\lavapath\HostFutureConsumerPrefetch_Worker.cpp",
  "$src\lavapath\HostFutureConsumerPrefetch_Seal.cpp",
  "$src\lavapath\HostFutureConsumerPrefetch_KnO3.cpp",
  "$ev\hostfc_chair_gen_smoke.cpp"
)
$inc = "/I$src /I$src\lavapath"
$ml = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\ml64.exe"
$knObj = Join-Path $ev "KN_O3KKEN.obj"
& $ml /nologo /c /Fo"$knObj" /I"$src\lavapath" "$src\lavapath\KN_O3KKEN.asm"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$flist = ($files | ForEach-Object { '"' + $_ + '"' }) -join ' '
cmd /c "`"$vcvars`" >nul && `"$cl`" /nologo /EHsc /std:c++17 /O2 /DWIN32 /D_WINDOWS $inc $flist `"$knObj`" /Fe:`"$out`" /link /SUBSYSTEM:CONSOLE"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $out | Tee-Object -FilePath (Join-Path $ev "SMOKE_OUT.txt")
$outText = Get-Content (Join-Path $ev "SMOKE_OUT.txt") -Raw
if ($outText -notmatch "KN_O3_REACHED=1") { Write-Error "KN_O3_REACHED missing"; exit 1 }
if ($outText -notmatch "KN_O3_STATUS=1") { Write-Error "KN_O3_STATUS!=1"; exit 1 }
exit 0
