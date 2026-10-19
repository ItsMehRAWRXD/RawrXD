# V7_RELOAD_AB_ATTRIBUTION_001 — paired L61t8 A(observe=0) B(observe=1).
param(
  [ValidateSet("A","B")][string]$Arm = "A",
  [string]$Binary = "G:\~dev\rawrxd\build-fd\bin\rawr.exe",
  [string]$Model = "F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf",
  [int]$Tokens = 8,
  [int]$Layers = 61,
  [string]$OutRoot = "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\DEEP2_70B_CONSTRAINED_EXTERNAL_001\runs"
)
$ErrorActionPreference = "Stop"
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$tag = "kimi_moe_DS_L${Layers}t${Tokens}_ab${Arm}_$stamp"
$dir = Join-Path $OutRoot $tag
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$env:RAWRXD_ALLOW_GPU = "1"
$env:RAWRXD_HOST_DECODE = "0"
$env:DEEP2_DUALSTICK_ARM = "1"
$env:RAWRXD_K2_LAYERS = "$Layers"
$env:DEEP2_MOE_PLACE_BUDGET_MIB = "12288"
$env:DEEP2_MOE_PLACE_TRACE = "1"
$env:DEEP2_V7_BLEND_W = "0"
if ($Arm -eq "A") { $env:DEEP2_V7_MODE = "0" } else { $env:DEEP2_V7_MODE = "observe" }
$env:VK_DRIVER_FILES = "C:\Windows\System32\DriverStore\FileRepository\amdvlk.inf_amd64_914ba89eaaafdf60\amd-vulkan64.json"
$stdout = Join-Path $dir "stdout.txt"
$stderr = Join-Path $dir "stderr.txt"
@"
STAMP=$stamp
TAG=V7_RELOAD_AB_ATTRIBUTION_001_ARM_$Arm
BINARY=$Binary
DEEP2_V7_MODE=$($env:DEEP2_V7_MODE)
BLEND_W=0
ASSIGN=V6_FULLCOST
PROMOTE=0
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
"EXIT=$exit WALL_MS=$([int]$sw.Elapsed.TotalMilliseconds) ARM=$Arm V7_MODE=$($env:DEEP2_V7_MODE)" |
  Set-Content -LiteralPath (Join-Path $dir "exit.txt") -Encoding UTF8
Write-Host "RUN_DIR=$dir EXIT=$exit ARM=$Arm"
exit [int]$exit
