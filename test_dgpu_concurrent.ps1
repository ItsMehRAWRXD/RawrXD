$ErrorActionPreference = "Stop"
$exe = "F:\rawrxd\build_msvc\bin\rawrxd_deep2_engine.exe"
$model = "F:\rawrxd\models\tinyllama.gguf"
$prompt = "Write a python function to sort a list"
$maxTokens = 15

Write-Host "============================================"
Write-Host "CONCURRENT DUAL-GPU INFERENCE TEST (DGPU-05)"
Write-Host "============================================"
Write-Host "Launching R9700 and RX 7800 XT simultaneously..."

# Set env for GPU0 process (inherited by child process)
$env:DEEP2_VULKAN_DEVICE_NEEDLE = "AMD Radeon AI PRO R9700"
$job0 = Start-Process -FilePath $exe -ArgumentList ($model, $prompt, $maxTokens) -NoNewWindow -RedirectStandardOutput "F:\rawrxd\dgpu_concurrent_gpu0_log.txt" -RedirectStandardError "F:\rawrxd\dgpu_concurrent_gpu0_log.txt" -PassThru

# Set env for GPU1 process (inherited by child process)
$env:DEEP2_VULKAN_DEVICE_NEEDLE = "AMD Radeon RX 7800 XT"
$job1 = Start-Process -FilePath $exe -ArgumentList ($model, $prompt, $maxTokens) -RedirectStandardOutput "F:\rawrxd\dgpu_concurrent_gpu1_log.txt" -RedirectStandardError "F:\rawrxd\dgpu_concurrent_gpu1_log.txt" -PassThru

Write-Host "GPU0 PID: $($job0.Id)  GPU1 PID: $($job1.Id)"

# Poll until both have exited
while ($true) {
    $done0 = $job0.HasExited
    $done1 = $job1.HasExited
    if ($done0 -and $done1) { break }
    Start-Sleep -Milliseconds 200
}

$exit0 = $job0.ExitCode
$exit1 = $job1.ExitCode

Write-Host "============================================"
Write-Host "RESULTS"
Write-Host "============================================"
Write-Host "GPU0 (R9700) exit: $exit0"
Write-Host "GPU1 (RX7800XT) exit: $exit1"

if ($exit0 -eq 0 -and $exit1 -eq 0) {
    Write-Host "DGPU_CONCURRENT=PASS"
    exit 0
} else {
    Write-Host "DGPU_CONCURRENT=FAIL"
    exit 1
}
