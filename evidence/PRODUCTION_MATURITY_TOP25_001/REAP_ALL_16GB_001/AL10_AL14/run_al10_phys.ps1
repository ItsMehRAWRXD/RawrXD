$ErrorActionPreference = 'Continue'
$ev = 'G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\REAP_ALL_16GB_001\AL10_AL14'
$exe = 'G:\~dev\rawrxd\build_ninja\bin\rawr.exe'
$phys = 'G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\REAP_ALL_16GB_001\exports\MiniMax-M2.7-REAP16-CALIB-epoch1\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf'

Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'rawr.exe' } | ForEach-Object {
  Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

$env:RAWRXD_AL10 = '1'
$env:RAWRXD_AL09 = '1'
$env:RAWRXD_GREEDY = '1'
$env:RAWRXD_RAW_PROMPT = '1'
$env:RAWRXD_NO_TP = '1'
$env:RAWR_SKIP_AUTO_BACKEND = '1'
$env:RAWRXD_HOST_DECODE = '1'
$env:RAWRXD_MOE_ROUTE_TRACE = '1'
$env:WEIGHT_BUDGET_MIB = '59568'
$env:DEEP2_WEIGHT_BUDGET_MIB = '59568'
$env:RAWRXD_REAP_RETAINED = '27'
Remove-Item Env:WEIGHT_BUDGET_BYTES -ErrorAction SilentlyContinue

$os = Get-CimInstance Win32_OperatingSystem
@"
PHASE=BEFORE_PHYS
UTC=$([DateTime]::UtcNow.ToString('o'))
FreePhysGB=$([math]::Round($os.FreePhysicalMemory/1MB,2))
CommittedBytes=$([int64]($os.TotalVirtualMemorySize-$os.FreeVirtualMemory)*1024)
CommitLimitBytes=$([int64]$os.TotalVirtualMemorySize*1024)
EXE_SHA256=$((Get-FileHash $exe -Algorithm SHA256).Hash)
"@ | Set-Content "$ev\AL10_HOST_BEFORE_PHYS.txt"

$out = "$ev\al10_phys.out.txt"
$err = "$ev\al10_phys.err.txt"
$meta = "$ev\al10_phys.meta.txt"
$sw = [Diagnostics.Stopwatch]::StartNew()
& $exe run $phys -p 'Hello' --max-tokens 8 --receipt "$ev\al10_phys.receipt.json" 1>$out 2>$err
$code = $LASTEXITCODE
$sw.Stop()
$os2 = Get-CimInstance Win32_OperatingSystem
@"
EXIT=$code
ELAPSED_SEC=$([math]::Round($sw.Elapsed.TotalSeconds,1))
PHASE=AFTER_PHYS
UTC=$([DateTime]::UtcNow.ToString('o'))
FreePhysGB=$([math]::Round($os2.FreePhysicalMemory/1MB,2))
CommittedBytes=$([int64]($os2.TotalVirtualMemorySize-$os2.FreeVirtualMemory)*1024)
CommitLimitBytes=$([int64]$os2.TotalVirtualMemorySize*1024)
"@ | Set-Content $meta
Get-Content $meta
