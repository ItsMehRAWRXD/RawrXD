# Exclusive sequential MoE/dense recovery. Fail-closed gate: no steal of QC lock.
# NOT_RUN != PASS. PROMOTE=0.
$ErrorActionPreference = "Continue"
$ev = "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001"
$lock = "g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\REAP_ALL_16GB_001\COMPARISON_MATRIX_001\CONCURRENCY_LOCK.txt"
$minFreeMb = 20000
$runOne = Join-Path $ev "run_one.ps1"

function Get-FreeMb {
  [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1024)
}
function Test-QcLockLive {
  if (-not (Test-Path $lock)) { return $false }
  $t = Get-Content $lock -Raw
  if ($t -match 'LOCK_OWNER=QUALITY_CURVE_001' -and $t -match 'EXCLUSIVE=1') { return $true }
  return $false
}

$free = Get-FreeMb
$qc = Test-QcLockLive
$rawrLive = @(Get-Process rawr,llama-cli -ErrorAction SilentlyContinue)
Write-Host "GATE freeMB=$free qcLock=$qc peerCount=$($rawrLive.Count) minFree=$minFreeMb"

if ($qc) {
  Write-Host "EXCLUSIVE_SEQUENTIAL_RERUN=NOT_RUN WHY=QC_EXCLUSIVE_LOCK_LIVE"
  Write-Host "PROMOTE=0 NOT_RUN!=PASS"
  exit 2
}
if ($free -lt $minFreeMb) {
  Write-Host "EXCLUSIVE_SEQUENTIAL_RERUN=NOT_RUN WHY=LOW_FREE_RAM freeMB=$free"
  Write-Host "PROMOTE=0 NOT_RUN!=PASS"
  exit 3
}

# Kill peers (QC already cleared)
Get-Process rawr,rawr_clmax,llama-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
$free = Get-FreeMb
Write-Host "POST_KILL freeMB=$free — beginning one-arm sequential"

$arms = @(
  @{ Id="M_minimax_reap27_sidecar_host"; Model="F:\ollamamodels\MiniMax-M2.7-REAP27-16GB\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf"; Budget=59568; Extra=""; Retain=0 },
  @{ Id="M_minimax_full_reap16_host"; Model="F:\ollamamodels\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf"; Budget=59568; Extra="--reap 16GB/8"; Retain=27 },
  @{ Id="M_dsv2lite_host"; Model="G:\~dev\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"; Budget=16384; Extra=""; Retain=0 },
  @{ Id="M_qwen36_a3b_host"; Model="G:\~dev\rawrxd\models\_matrix_f\Qwen3.6-35B-A3B-GGUF\Qwen3.6-35B-A3B-Q4_K_M.gguf"; Budget=59568; Extra=""; Retain=0 },
  @{ Id="D_nemotron35_host"; Model="G:\~dev\rawrxd\models\_matrix_f\gguf\nemotron-3.5-lightning-30b-Q4_K_M.gguf"; Budget=59568; Extra=""; Retain=0 },
  @{ Id="D_glm47_flash_host"; Model="G:\~dev\rawrxd\models\_matrix_f\GLM-4.7-Flash-GGUF\GLM-4.7-Flash-Q4_K_M.gguf"; Budget=59568; Extra=""; Retain=0 }
)

foreach ($a in $arms) {
  if (Test-QcLockLive) {
    Write-Host "ABORT_RECOVERY WHY=QC_LOCK_REACQUIRED mid-sequence"
    Write-Host "PROMOTE=0"
    exit 4
  }
  Get-Process rawr,rawr_clmax,llama-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 2
  & $runOne -Id $a.Id -Model $a.Model -Backend HOST -ExtraArgs $a.Extra -BudgetMib $a.Budget -Retain $a.Retain -MaxTokens 8
  Start-Sleep -Seconds 2
}

Write-Host "RECOVERY_SEQUENCE_COMPLETE PROMOTE=0 (disposition from metas; do not invent PASS)"
exit 0
