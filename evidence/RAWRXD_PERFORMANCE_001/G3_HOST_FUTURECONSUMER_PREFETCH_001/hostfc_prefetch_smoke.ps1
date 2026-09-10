# hostfc_prefetch_smoke.ps1 — compile+run purified HOST_DECODE edge (no Vulkan).
$ErrorActionPreference = "Stop"
$cl = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe"
$src = "G:\~dev\rawrxd\src\deep2"
$ev = "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_HOST_FUTURECONSUMER_PREFETCH_001"
$out = Join-Path $ev "hostfc_prefetch_smoke.exe"
$files = @(
  "$src\lavapath\FreeTokenMicroZone.cpp",
  "$src\lavapath\FreeTokenMicroZone_Query.cpp",
  "$src\lavapath\FutureConsumer_Space.cpp",
  "$src\lavapath\FutureConsumer_Register.cpp",
  "$src\lavapath\FutureConsumer_Advance.cpp",
  "$src\lavapath\FutureConsumer_Notes.cpp",
  "$src\lavapath\FutureConsumer_Emit.cpp",
  "$src\lavapath\FutureConsumer_EmitExec.cpp",
  "$src\lavapath\HostFutureConsumerPrefetch.cpp",
  "$src\lavapath\HostFutureConsumerPrefetch_Move.cpp",
  "$src\lavapath\HostFutureConsumerPrefetch_Worker.cpp",
  "$ev\hostfc_prefetch_smoke.cpp"
)
$inc = @("/I$src", "/I$src\lavapath")
& $cl /nologo /EHsc /std:c++17 /O2 /DWIN32 /D_WINDOWS @inc @files /Fe:$out /link /SUBSYSTEM:CONSOLE
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $out | Tee-Object -FilePath (Join-Path $ev "SMOKE_OUT.txt")
exit $LASTEXITCODE
