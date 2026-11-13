$ErrorActionPreference = 'Continue'
$ev = 'G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\REAP_ALL_16GB_001\AL10_AL14'
$exe = 'G:\~dev\rawrxd\build_ninja\bin\rawr.exe'
$phys = 'F:\ollamamodels\MiniMax-M2.7-REAP16-CALIB-ROUTE27\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf'
if (-not (Test-Path $phys)) {
  $phys = 'G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\REAP_ALL_16GB_001\exports\MiniMax-M2.7-REAP16-CALIB-epoch1\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf'
}

Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'rawr.exe' } | ForEach-Object {
  Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

# GPU-required law: no HOST_DECODE for A/B. OOM => NOT_RUN_GPU_OOM.
$env:RAWRXD_AL10 = '1'
$env:RAWRXD_AL09 = '1'
$env:RAWRXD_GREEDY = '1'
$env:RAWRXD_RAW_PROMPT = '1'
$env:RAWRXD_NO_TP = '1'
$env:RAWRXD_ALLOW_GPU = '1'
$env:RAWR_FORCE_GPU = '1'
$env:RAWR_NO_CPU_FALLBACK = '1'
Remove-Item Env:RAWR_SKIP_AUTO_BACKEND -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_HOST_DECODE -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_FORCE_CPU_INFERENCE -ErrorAction SilentlyContinue
$env:RAWRXD_MOE_ROUTE_TRACE = '1'
$env:WEIGHT_BUDGET_MIB = '32768'
$env:DEEP2_WEIGHT_BUDGET_MIB = '32768'
$env:RAWRXD_REAP_RETAINED = '27'
$env:RAWRXD_AL10_MAX_TOK = '4'
Remove-Item Env:WEIGHT_BUDGET_BYTES -ErrorAction SilentlyContinue

$os = Get-CimInstance Win32_OperatingSystem
@"
PHASE=BEFORE_PHYS
UTC=$([DateTime]::UtcNow.ToString('o'))
FreePhysGB=$([math]::Round($os.FreePhysicalMemory/1MB,2))
CommittedBytes=$([int64]($os.TotalVirtualMemorySize-$os.FreeVirtualMemory)*1024)
CommitLimitBytes=$([int64]$os.TotalVirtualMemorySize*1024)
EXE_SHA256=$((Get-FileHash $exe -Algorithm SHA256).Hash)
GPU_LAW=ALLOW_GPU=1 FORCE_GPU=1 NO_CPU_FALLBACK=1 NO_HOST_DECODE
PROMOTE=0
"@ | Set-Content "$ev\AL10_HOST_BEFORE_PHYS.txt"

$out = "$ev\al10_phys.out.txt"
$err = "$ev\al10_phys.err.txt"
$meta = "$ev\al10_phys.meta.txt"
$sw = [Diagnostics.Stopwatch]::StartNew()
& $exe run $phys --vulkan -p 'Hello' --max-tokens 4 --receipt "$ev\al10_phys.receipt.json" 1>$out 2>$err
$code = $LASTEXITCODE
$sw.Stop()
$os2 = Get-CimInstance Win32_OperatingSystem
$oom = ''
if (Test-Path $err) {
  $hit = Select-String -Path $err -Pattern 'OOM|out of memory|VK_ERROR_OUT_OF_DEVICE_MEMORY|NO_FEASIBLE|INSUFFICIENT' -ErrorAction SilentlyContinue | Select-Object -Last 1
  if ($hit) { $oom = $hit.Line }
}
@"
EXIT=$code
ELAPSED_SEC=$([math]::Round($sw.Elapsed.TotalSeconds,1))
PHASE=AFTER_PHYS
UTC=$([DateTime]::UtcNow.ToString('o'))
FreePhysGB=$([math]::Round($os2.FreePhysicalMemory/1MB,2))
CommittedBytes=$([int64]($os2.TotalVirtualMemorySize-$os2.FreeVirtualMemory)*1024)
CommitLimitBytes=$([int64]$os2.TotalVirtualMemorySize*1024)
OOM_LINE=$oom
PROMOTE=0
"@ | Set-Content $meta
Get-Content $meta
