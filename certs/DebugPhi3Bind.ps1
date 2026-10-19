$env:DEEP2_K2_SHARD_DIR = ''
$env:DEEP2_REAL_K2_GENERATE = '0'
$env:RAWRXD_NO_TP = '1'
$env:RAWRXD_GREEDY = '1'
$env:TPS_LIMIT = 'NONE'
$env:FULL_MODEL_RESIDENCY_REQUIRED = '0'
$env:DEEP2_TPS_DISPLAY_SCALE = '1'
$env:RAWRXD_FFN_TRACE = '1'

$processInfo = New-Object System.Diagnostics.ProcessStartInfo
$processInfo.FileName = 'G:\~dev\rawrxd\build\bin\rawr.exe'
$processInfo.Arguments = 'run G:\~dev\rawrxd\models\phi3-mini-Q2_K.gguf --prompt "test" --max-tokens 1'
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

$lines = $stderr -split "`n"
$lines | Where-Object { $_ -match 'GEMMA4_SCHEMA_BIND|wGate|wUp|wDown|ffn_gate|ffn_up|ffn_down|blk\.' } | Select-Object -First 100