# Run-K2-TeardownWitness.ps1
# Cert-owned generation: WaitForExit on GEN_PID only. No orphan-reaper.

param(
  [int]$MaxTokens = 2048,
  [string]$Tag = "survive2048",
  [int]$HardTimeoutSec = 0
)

$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\K2_USEFUL_TPS_001"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$log = Join-Path $OutDir (${Tag} + "_" + $stamp + ".log")
$err = Join-Path $OutDir (${Tag} + "_" + $stamp + ".err.log")
$exitf = Join-Path $OutDir (${Tag} + "_" + $stamp + ".exit.txt")
$pidf = Join-Path $OutDir (${Tag} + "_PID.txt")
$latest = Join-Path $OutDir (${Tag} + "_LATEST.txt")
$exe = "G:\~dev\rawrxd\build-fd\bin\deep2_benchmark.exe"
$model = "F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf"
$json = Join-Path $OutDir (${Tag} + "_" + $stamp + ".json")

if (-not (Test-Path $exe)) { throw "missing $exe" }
if (-not (Test-Path $model)) { throw "missing $model" }

$env:DEEP2_K2_SHARD_DIR = "F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M"
$env:DEEP2_REAL_K2_GENERATE = "1"
$env:DEEP2_WEIGHT_MODE = "BOUNDED_STREAM"
$env:DEEP2_LIVE_POLICY = "PROMO"
$env:DEEP2_K2_GPU_MLA = "1"
$env:DEEP2_K2_GPU_STREAM_COPY = "1"
$env:DEEP2_WEIGHT_PIN = "1"
$env:RAWRXD_GPU_POLICY = "SOLO"
$env:RAWRXD_K2_LAYERS = "61"
$env:DEEP2_CERT_STEP_LOG = "1"
$env:RAWRXD_NO_TP = "1"
Remove-Item Env:RAWRXD_DEEP2_ALLOW_UNSAFE_MLA -ErrorAction SilentlyContinue

$argv = @(
  "--model", $model,
  "--phase", "single",
  "--max-tokens", "$MaxTokens",
  "--ctx-size", "4096",
  "--format", "telemetry",
  "--output", $json
)

@(
  "TAG=$Tag",
  "STAMP=$stamp",
  "LOG=$log",
  "ERR=$err",
  "EXITF=$exitf",
  "MAX_TOKENS=$MaxTokens",
  "HARNESS_ORPHAN_REAPER=0",
  "OWNERSHIP=GEN_PID_WaitForExit"
) | Set-Content -Path $latest -Encoding ascii

Write-Host "HARNESS_ORPHAN_REAPER=0"
$p = Start-Process -FilePath $exe -ArgumentList $argv `
  -RedirectStandardOutput $log -RedirectStandardError $err `
  -PassThru -NoNewWindow

$genPid = $p.Id
Set-Content -Path $pidf -Value $genPid -Encoding ascii
Add-Content -Path $latest -Value ("GEN_PID=" + $genPid)
Write-Host ("GEN_PID=" + $genPid)

$timedOut = $false
if ($HardTimeoutSec -gt 0) {
  if (-not $p.WaitForExit($HardTimeoutSec * 1000)) {
    $timedOut = $true
    Write-Host ("HARD_TIMEOUT_SEC=" + $HardTimeoutSec + " Stop-Process ONLY GEN_PID=" + $genPid)
    Stop-Process -Id $genPid -Force -ErrorAction SilentlyContinue
    [void]$p.WaitForExit(60000)
  }
} else {
  $p.WaitForExit()
}

$p.Refresh()
$code = $p.ExitCode
if ($null -eq $code) { $code = -1 }
$habort = 0
if ($timedOut) { $habort = 1 }

@(
  ("EXIT=" + $code),
  ("GEN_PID=" + $genPid),
  ("HARNESS_ABORT=" + $habort),
  "HARNESS_ORPHAN_REAPER=0"
) | Set-Content -Path $exitf -Encoding ascii

Write-Host ("GEN_EXIT=" + $code)
Write-Host ("HARNESS_ABORT=" + $habort)
exit $code
