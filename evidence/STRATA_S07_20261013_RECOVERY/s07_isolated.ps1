param([string]$Tag,[int]$Budget=128,[switch]$Spec,[double]$Baseline=0)
$ErrorActionPreference='Stop'
$taskDir='F:\rawrxd\evidence\STRATA_S07_20261013_RECOVERY'
$env:PATH='F:\rawrxd\build_ggml_profiler\bin\Release;'+$env:PATH
$active=@(Get-CimInstance Win32_Process -Filter "Name = 'deep2_strata_bench.exe'")
foreach($run in $active){ Stop-Process -Id $run.ProcessId -ErrorAction Stop; "Stopped competing Strata process $($run.ProcessId)" }
$taskArgs=@('--model','F:/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf','--prefill','32','--generate',"$Budget",'--gpu','--int8kv','--no-calibrate','--tag',$Tag,'--outdir','F:/rawrxd/evidence/STRATA_S07_20261013_RECOVERY')
if($Spec){$taskArgs+=@('--spec',"$Budget",'--baseline-tps',"$Baseline")}
[pscustomobject]@{at=(Get-Date).ToString('o');processes=@(Get-CimInstance Win32_Process -Filter "Name = 'deep2_strata_bench.exe'" | Select-Object ProcessId,CommandLine)} | ConvertTo-Json -Depth 5 | Set-Content "$taskDir/$Tag.pre_processes.json"
$taskTimer=[System.Diagnostics.Stopwatch]::StartNew()
$binaryHash=(Get-FileHash F:\rawrxd\tools\deep2_strata_bench.exe -Algorithm SHA256).Hash
$taskProcess=Start-Process -FilePath F:\rawrxd\tools\deep2_strata_bench.exe -ArgumentList $taskArgs -WorkingDirectory F:\rawrxd -WindowStyle Hidden -PassThru -RedirectStandardOutput "$taskDir/$Tag.log" -RedirectStandardError "$taskDir/$Tag.stderr.log"
$overlap=@()
while(-not $taskProcess.HasExited){
 $others=@(Get-CimInstance Win32_Process -Filter "Name = 'deep2_strata_bench.exe'" | Where-Object ProcessId -ne $taskProcess.Id)
 foreach($other in $others){$overlap+=@{at=(Get-Date).ToString('o');pid=$other.ProcessId;command=$other.CommandLine}; Stop-Process -Id $other.ProcessId -ErrorAction SilentlyContinue}
 Start-Sleep -Milliseconds 1000
 $taskProcess.Refresh()
}
$taskProcess.WaitForExit()
$taskTimer.Stop()
[pscustomobject]@{at=(Get-Date).ToString('o');processes=@(Get-CimInstance Win32_Process -Filter "Name = 'deep2_strata_bench.exe'" | Select-Object ProcessId,CommandLine)} | ConvertTo-Json -Depth 5 | Set-Content "$taskDir/$Tag.post_processes.json"
$result=@{tag=$Tag;process_wall_ms=$taskTimer.Elapsed.TotalMilliseconds;exit_code=$taskProcess.ExitCode;binary_sha256=$binaryHash;interference=$overlap;valid_isolation=($overlap.Count -eq 0);arguments=$taskArgs}
$result | ConvertTo-Json -Depth 5 | Set-Content "$taskDir/$Tag.provenance.json"
$result | ConvertTo-Json -Depth 5

