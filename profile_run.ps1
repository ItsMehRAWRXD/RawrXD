$p=Start-Process 'F:\~dev\rawrxd\build\bin\Release\test_generate_313_tokens.exe' -ArgumentList 'D:\rawrxd\gemma3-1b-Q2_K.gguf' -PassThru -NoNewWindow -RedirectStandardOutput 'F:\~dev\gemma3_313_full.txt' -RedirectStandardError 'F:\~dev\gemma3_313_err.txt'
$s=@()
while(!$p.HasExited){
    $cpu=$p.CPU
    Start-Sleep -Milliseconds 500
    $dc=$p.CPU-$cpu
    $gpuSamples=(Get-Counter '\GPU Engine(*)\Utilization Percentage' -ErrorAction SilentlyContinue).CounterSamples | Where-Object {$_.InstanceName -match "pid_$($p.Id)_"}
    $gpu=($gpuSamples | Measure-Object CookedValue -Sum).Sum
    $s+=[pscustomobject]@{
        CPU_pct=[math]::Round(($dc/.5/[Environment]::ProcessorCount)*100,1)
        GPU_pct=[math]::Round($gpu,1)
    }
}
$p.Refresh()
$c=($s|Measure-Object CPU_pct -Average).Average
$g=($s|Measure-Object GPU_pct -Average).Average
$result = "AVG_CPU=$([math]::Round($c,1))% AVG_GPU=$([math]::Round($g,1))% CASE="
if ($g -gt 40) {
    $result += "GPU_ACTIVE_CHECK_FENCE_OR_KERNEL_EFFICIENCY"
} elseif ($c -gt 20) {
    $result += "CPU_OR_FALLBACK_DOMINATED"
} else {
    $result += "IDLE_SYNC_FENCE_OR_SERIALIZATION"
}
Write-Host $result
Write-Host '--- Sample ---'
$s | Format-Table -AutoSize
