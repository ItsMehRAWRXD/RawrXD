# V6 L61t8 — EXIT=0 sealable via Diagnostics.Process WaitForExit+Refresh.
param(
  [string]$Binary = "G:\~dev\rawrxd\build-fd\bin\rawr.exe",
  [string]$Model = "F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf",
  [int]$Tokens = 8,
  [int]$Layers = 61,
  [string]$OutRoot = "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\DEEP2_70B_CONSTRAINED_EXTERNAL_001\runs"
)
$ErrorActionPreference = "Stop"
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$tag = "kimi_moe_DS_L${Layers}t${Tokens}_v6_$stamp"
$dir = Join-Path $OutRoot $tag
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$env:RAWRXD_ALLOW_GPU = "1"
$env:RAWRXD_HOST_DECODE = "0"
$env:DEEP2_DUALSTICK_ARM = "1"
$env:RAWRXD_K2_LAYERS = "$Layers"
$env:DEEP2_MOE_PLACE_BUDGET_MIB = "8192"
$env:DEEP2_MOE_PLACE_TRACE = "1"
$env:VK_DRIVER_FILES = "C:\Windows\System32\DriverStore\FileRepository\amdvlk.inf_amd64_914ba89eaaafdf60\amd-vulkan64.json"
$stdout = Join-Path $dir "stdout.txt"
$stderr = Join-Path $dir "stderr.txt"
@"
STAMP=$stamp
TAG=COST_PREDICTOR_CALIBRATION_V6_L${Layers}T${Tokens}
BINARY=$Binary
HARNESS=System.Diagnostics.Process+WaitForExit+Refresh+ExitCode
DEEP2_DUALSTICK_ARM=1
RAWRXD_K2_LAYERS=$Layers
TOKENS=$Tokens
PROMOTE=0
PARENT_HOLD=7f9f52daaa
"@ | Set-Content -LiteralPath (Join-Path $dir "CMD.txt") -Encoding UTF8
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $Binary
$psi.Arguments = "run `"$Model`" -p hello --max-tokens $Tokens"
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $psi
$sw = [Diagnostics.Stopwatch]::StartNew()
[void]$p.Start()
$stdoutTask = $p.StandardOutput.ReadToEndAsync()
$stderrTask = $p.StandardError.ReadToEndAsync()
$p.WaitForExit()
$p.Refresh()
$sw.Stop()
[IO.File]::WriteAllText($stdout, $stdoutTask.Result)
[IO.File]::WriteAllText($stderr, $stderrTask.Result)
$exit = $p.ExitCode
if ($null -eq $exit) { $exit = -999 }
"EXIT=$exit WALL_MS=$([int]$sw.Elapsed.TotalMilliseconds) HARNESS=WaitForExit+Refresh" |
  Set-Content -LiteralPath (Join-Path $dir "exit.txt") -Encoding UTF8
Write-Host "RUN_DIR=$dir EXIT=$exit WALL_MS=$([int]$sw.Elapsed.TotalMilliseconds)"
exit [int]$exit
