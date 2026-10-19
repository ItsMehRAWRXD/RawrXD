$env:DEEP2_K2_SHARD_DIR = ''
$env:DEEP2_REAL_K2_GENERATE = '0'
$env:RAWRXD_NO_TP = '1'
$env:RAWRXD_GREEDY = '1'
$env:TPS_LIMIT = 'NONE'
$env:FULL_MODEL_RESIDENCY_REQUIRED = '0'
$env:DEEP2_TPS_DISPLAY_SCALE = '1'
$env:RAWRXD_FFN_TRACE = '1'

$processInfo = New-Object System.Diagnostics.ProcessStartInfo
$processInfo.FileName = 'C:\Users\Garrett\rawrxd\bin\rawr.exe'
$processInfo.Arguments = '--help'
$processInfo.RedirectStandardOutput = $true
$processInfo.RedirectStandardError = $true
$processInfo.UseShellExecute = $false
$processInfo.CreateNoWindow = $true
$processInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
$processInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8

$process = [System.Diagnostics.Process]::Start($processInfo)
$stdoutTask = $process.StandardOutput.ReadToEndAsync()
$stderrTask = $process.StandardError.ReadToEndAsync()
$null = $process.WaitForExit(60000)
$stdout = $stdoutTask.Result
$stderr = $stderrTask.Result
$exitCode = $process.ExitCode

Write-Host "ExitCode: $exitCode"
Write-Host "Stdout: $stdout"
Write-Host "Stderr: $stderr"