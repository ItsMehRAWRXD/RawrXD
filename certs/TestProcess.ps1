$env:DEEP2_K2_SHARD_DIR = ""
$env:DEEP2_REAL_K2_GENERATE = "0"
$env:RAWRXD_NO_TP = "1"
$env:RAWRXD_GREEDY = "1"
$env:TPS_LIMIT = "NONE"
$env:FULL_MODEL_RESIDENCY_REQUIRED = "0"
$env:DEEP2_TPS_DISPLAY_SCALE = "1"
$env:RAWRXD_FFN_TRACE = "1"

$processInfo = New-Object System.Diagnostics.ProcessStartInfo
$processInfo.FileName = "G:\~dev\rawrxd\build\bin\rawr.exe"
$processInfo.Arguments = 'run G:\~dev\rawrxd\models\phi3-mini-Q2_K.gguf --prompt "Write a short poem about token generation. Exactly 4 lines." --max-tokens 64'
$processInfo.RedirectStandardOutput = $true
$processInfo.RedirectStandardError = $true
$processInfo.UseShellExecute = $false
$processInfo.CreateNoWindow = $true

$process = [System.Diagnostics.Process]::Start($processInfo)

$stdoutTask = $process.StandardOutput.ReadToEndAsync()
$stderrTask = $process.StandardError.ReadToEndAsync()

$process.WaitForExit(600000)
if (-not $process.HasExited) {
    $process.Kill()
    throw "Process timed out after 10 minutes"
}

$stdout = $stdoutTask.Result
$stderr = $stderrTask.Result
$exitCode = $process.ExitCode

Write-Host "ExitCode: $exitCode"
Write-Host "Stdout: [$stdout]"
Write-Host "Stderr: [$stderr]"