# PRODUCTION_INFERENCE_CERT_001 — pinned-exe short smokes (max-tokens 8)
# Fail-closed: NOT_RUN != PASS. PROMOTE=0.
$ErrorActionPreference = "Continue"
$ev = "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001"
$bin = "g:\~dev\rawrxd\build_ninja\bin"
$exe = Join-Path $bin "rawr_cert_pin.exe"
$runs = Join-Path $ev "runs"
New-Item -ItemType Directory -Force -Path $runs | Out-Null
if (-not (Test-Path $exe)) { throw "Missing pin exe: $exe" }

Get-Process rawr_clmax,rawr -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
Set-Content (Join-Path $ev "EXE_SHA256.txt") $sha -Encoding ascii
Set-Content (Join-Path $ev "EXE_PIN_PATH.txt") $exe -Encoding ascii
Write-Host "EXE_PIN=$exe"
Write-Host "EXE_SHA=$sha"

function Clear-SmokeEnv {
  foreach ($k in @(
    "WEIGHT_BUDGET","E8B0M","RAWR_REAP_EXPORT_DIR","RAWR_REAP_EXPORT_EXPERIMENTAL",
    "RAWRXD_REAP_RETAINED","RAWRXD_DUALSTICK","RAWRXD_HOST_DECODE","R1_HOST_FLOOR",
    "RAWRXD_ALLOW_GPU","DEEP2_WEIGHT_BUDGET_MIB","WEIGHT_BUDGET_MIB"
  )) { Remove-Item "Env:$k" -ErrorAction SilentlyContinue }
}

function Invoke-Smoke {
  param(
    [string]$Id,
    [string]$Model,
    [ValidateSet("HOST","GPU")][string]$Backend,
    [string]$ExtraArgs = "",
    [hashtable]$ExtraEnv = @{},
    [int]$MaxTokens = 8
  )
  $out = Join-Path $runs "$Id.out.txt"
  $err = Join-Path $runs "$Id.err.txt"
  $exitf = Join-Path $runs "$Id.exit.txt"
  $meta = Join-Path $runs "$Id.meta.txt"
  $receipt = Join-Path $runs "$Id.receipt.json"

  Get-Process rawr,rawr_cert_pin,rawr_clmax -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1

  Clear-SmokeEnv
  if ($Backend -eq "HOST") {
    $env:RAWRXD_HOST_DECODE = "1"
    $env:R1_HOST_FLOOR = "1"
    $env:RAWRXD_ALLOW_GPU = "0"
    $env:DEEP2_WEIGHT_BUDGET_MIB = "2048"
    $env:WEIGHT_BUDGET_MIB = "2048"
  } else {
    $env:RAWRXD_HOST_DECODE = "0"
    $env:R1_HOST_FLOOR = "0"
    $env:RAWRXD_ALLOW_GPU = "1"
  }
  foreach ($k in $ExtraEnv.Keys) { Set-Item -Path "Env:$k" -Value ([string]$ExtraEnv[$k]) }

  @"
ID=$Id
BACKEND=$Backend
MODEL=$Model
EXE=$exe
EXE_SHA=$sha
EXTRA_ARGS=$ExtraArgs
STARTED=$(Get-Date -Format o)
"@ | Set-Content $meta -Encoding utf8

  Write-Host "=== SMOKE $Id ($Backend) ==="
  Push-Location $bin
  try {
    $argList = @("run", $Model, "-p", "Hello", "--max-tokens", "$MaxTokens", "--receipt", $receipt)
    if ($ExtraArgs -and $ExtraArgs.Trim().Length -gt 0) {
      $argList += ($ExtraArgs -split '\s+' | Where-Object { $_ })
    }
    & $exe @argList 1> $out 2> $err
    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) { $exitCode = -998 }
    "EXIT=$exitCode" | Set-Content $exitf -Encoding ascii
  } finally {
    Pop-Location
  }

  $exitLine = (Get-Content $exitf -Raw).Trim()
  $combined = ""
  if (Test-Path $out) { $combined += Get-Content $out -Raw -ErrorAction SilentlyContinue }
  $combined += "`n"
  if (Test-Path $err) { $combined += Get-Content $err -Raw -ErrorAction SilentlyContinue }

  $gt = "NOT_FOUND"
  if ($combined -match "GENERATED_TOKENS=(\d+)") { $gt = $Matches[1] }
  $ce = "0"
  if ($combined -match "CLEAN_EXIT=1" -or $combined -match "DISPOSITION=CLEAN_EXIT" -or $combined -match "TD=\d+ CLEAN_EXIT") { $ce = "1" }
  $arch = "UNKNOWN"
  if ($combined -match "GGUF architecture: '([^']+)'") { $arch = $Matches[1] }
  elseif ($combined -match "(?m)^ARCH=([A-Za-z0-9_]+)") { $arch = $Matches[1] }
  $hd = "?"
  if ($combined -match "HOST_DECODE=([01])") { $hd = $Matches[1] }
  $dsUsed = "?"
  if ($combined -match "DUALSTICK_RUNTIME_USED=([01])") { $dsUsed = $Matches[1] }
  $dsArm = "?"
  if ($combined -match "DUALSTICK_ARM=([01])") { $dsArm = $Matches[1] }
  $vk = "?"
  if ($combined -match "Vulkan open failed") { $vk = "OPEN_FAIL" }
  elseif ($combined -match "ENHANCEMENT STACK: HOST_DECODE") { $vk = "HOST_STACK" }
  elseif ($combined -match "vulkanInit=1") { $vk = "VK_INIT1" }
  elseif ($combined -match "Vulkan") { $vk = "VK_MENTION" }
  $blocker = ""
  if ($combined -match "SSM-CERT|SSM/hybrid|refuse SSM|SSM_CERT") { $blocker = "SSM_CERT_REFUSE" }
  elseif ($ce -ne "1") { $blocker = "NO_CLEAN_EXIT" }

  @"
ARCH=$arch
GENERATED_TOKENS=$gt
CLEAN_EXIT_MARKER=$ce
HOST_DECODE_SEEN=$hd
DUALSTICK_RUNTIME_USED=$dsUsed
DUALSTICK_ARM=$dsArm
VK=$vk
BLOCKER=$blocker
$exitLine
ENDED=$(Get-Date -Format o)
"@ | Add-Content $meta -Encoding utf8

  Write-Host "=== $Id $exitLine GT=$gt CE=$ce ARCH=$arch HD=$hd DS=$dsUsed VK=$vk BLOCKER=$blocker ==="
  [pscustomobject]@{
    Id=$Id; Exit=$exitLine; GT=$gt; CE=$ce; Arch=$arch; HD=$hd; DS=$dsUsed; VK=$vk; Backend=$Backend; Blocker=$blocker
  }
}

$results = @()
$results += Invoke-Smoke -Id "D_tinyllama_host" -Model "G:\~dev\rawrxd\models\tinyllama.gguf" -Backend HOST
$results += Invoke-Smoke -Id "D_tinyllama_gpu" -Model "G:\~dev\rawrxd\models\tinyllama.gguf" -Backend GPU
$results += Invoke-Smoke -Id "D_llama32_3b_host" -Model "G:\~dev\rawrxd\llama3.2-3b-Q2_K.gguf" -Backend HOST
$results += Invoke-Smoke -Id "D_phi3_mini_host" -Model "G:\~dev\rawrxd\models\phi3-mini-Q2_K.gguf" -Backend HOST
$results += Invoke-Smoke -Id "D_gemma4_e4b_host" -Model "G:\~dev\rawrxd\models\_matrix_f\gemma-4-E4B-it-GGUF\gemma-4-E4B-it-Q4_K_M.gguf" -Backend HOST
$results += Invoke-Smoke -Id "M_dsv2lite_host" -Model "G:\~dev\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf" -Backend HOST
$results += Invoke-Smoke -Id "M_qwen36_a3b_host" -Model "G:\~dev\rawrxd\models\_matrix_f\Qwen3.6-35B-A3B-GGUF\Qwen3.6-35B-A3B-Q4_K_M.gguf" -Backend HOST
$results += Invoke-Smoke -Id "D_glm47_flash_host" -Model "G:\~dev\rawrxd\models\_matrix_f\GLM-4.7-Flash-GGUF\GLM-4.7-Flash-Q4_K_M.gguf" -Backend HOST
$results += Invoke-Smoke -Id "D_nemotron35_host" -Model "G:\~dev\rawrxd\models\_matrix_f\gguf\nemotron-3.5-lightning-30b-Q4_K_M.gguf" -Backend HOST
$results += Invoke-Smoke -Id "D_qwen38_27b_host" -Model "G:\~dev\rawrxd\models\_matrix_f\Qwen3.8-27B-AD-Q4_K_M\Qwen3.8-27B-AD-Q4_K_M.gguf" -Backend HOST

$mmFull = "F:\ollamamodels\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf"
$results += Invoke-Smoke -Id "M_minimax_full_reap16_host" -Model $mmFull -Backend HOST `
  -ExtraArgs "--reap 16GB/8" `
  -ExtraEnv @{
    RAWRXD_REAP_RETAINED = "27"
    DEEP2_WEIGHT_BUDGET_MIB = "59568"
    WEIGHT_BUDGET_MIB = "59568"
  }

$mmReap27 = "F:\ollamamodels\MiniMax-M2.7-REAP27-16GB\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf"
if (Test-Path $mmReap27) {
  $results += Invoke-Smoke -Id "M_minimax_reap27_sidecar_host" -Model $mmReap27 -Backend HOST `
    -ExtraEnv @{
      DEEP2_WEIGHT_BUDGET_MIB = "59568"
      WEIGHT_BUDGET_MIB = "59568"
    }
}

$dsOk = $results | Where-Object { $_.Id -eq "M_dsv2lite_host" -and $_.Exit -match "EXIT=0" -and $_.CE -eq "1" }
if ($dsOk) {
  $results += Invoke-Smoke -Id "M_dsv2lite_gpu" -Model "G:\~dev\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf" -Backend GPU
}

$results | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $ev "smoke_results.json") -Encoding utf8
$results | Format-Table -AutoSize | Out-String | Set-Content (Join-Path $ev "smoke_results_table.txt") -Encoding utf8
Write-Host "DONE smokes=$($results.Count)"
$results | Format-Table -AutoSize
