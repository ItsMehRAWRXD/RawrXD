param(
  [Parameter(Mandatory=$true)][string]$Id,
  [Parameter(Mandatory=$true)][string]$Model,
  [ValidateSet("HOST","GPU")][string]$Backend = "HOST",
  [string]$ExtraArgs = "",
  [int]$BudgetMib = 59568,
  [int]$MaxTokens = 8,
  [int]$Retain = 0
)
# Fail-closed: partial/STARTED-only != PASS. DONE always emits (try/finally).
$ErrorActionPreference = "Continue"
$ev = "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001"
$bin = "g:\~dev\rawrxd\build_ninja\bin"
$exe = Join-Path $bin "rawr_cert_pin.exe"
$runs = Join-Path $ev "runs"
New-Item -ItemType Directory -Force -Path $runs | Out-Null
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
$out = Join-Path $runs "$Id.out.txt"
$err = Join-Path $runs "$Id.err.txt"
$exitf = Join-Path $runs "$Id.exit.txt"
$meta = Join-Path $runs "$Id.meta.txt"
$receipt = Join-Path $runs "$Id.receipt.json"
$bat = Join-Path $runs "$Id.run.cmd"
$doneEmitted = $false
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = $null

function Write-DoneLine {
  param([string]$ExitLine,[string]$Gt,[string]$Ce,[string]$Arch,[string]$Vk,[string]$Blocker,[string]$Disp)
  $script:doneEmitted = $true
  Write-Host ("=== DONE $Id $ExitLine GT=$Gt CE=$Ce ARCH=$Arch VK=$Vk BLOCKER=$Blocker DISP=$Disp ELAPSED=$($sw.ElapsedMilliseconds)ms ===")
}

Get-Process rawr_clmax,llama-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process | Where-Object { $_.ProcessName -eq "rawr" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$hd = if ($Backend -eq "HOST") { "1" } else { "0" }
$allowGpu = if ($Backend -eq "HOST") { "0" } else { "1" }
$r1 = if ($Backend -eq "HOST") { "1" } else { "0" }
$retainLine = if ($Retain -gt 0) { "set RAWRXD_REAP_RETAINED=$Retain" } else { "set RAWRXD_REAP_RETAINED=" }

# Bat always writes EXIT even if child killed mid-flight (EC may be 1 or -1).
$batBody = @"
@echo off
cd /d "$bin"
set WEIGHT_BUDGET=
set E8B0M=
set RAWR_REAP_EXPORT_DIR=
set RAWR_REAP_EXPORT_EXPERIMENTAL=
set RAWRXD_DUALSTICK=
$retainLine
set RAWRXD_HOST_DECODE=$hd
set R1_HOST_FLOOR=$r1
set RAWRXD_ALLOW_GPU=$allowGpu
set DEEP2_WEIGHT_BUDGET_MIB=$BudgetMib
set WEIGHT_BUDGET_MIB=$BudgetMib
"$exe" run "$Model" -p Hello --max-tokens $MaxTokens --receipt "$receipt" $ExtraArgs > "$out" 2> "$err"
set EC=%ERRORLEVEL%
> "$exitf" echo EXIT=%EC%
"@
[System.IO.File]::WriteAllText($bat, $batBody)

$metaBody = @"
ID=$Id
BACKEND=$Backend
MODEL=$Model
EXE=$exe
EXE_SHA=$sha
BUDGET_MIB=$BudgetMib
EXTRA_ARGS=$ExtraArgs
STARTED=$(Get-Date -Format o)
HARNESS_COMPLETE=0
"@
[System.IO.File]::WriteAllText($meta, $metaBody)

Write-Host "=== RUN $Id ($Backend) budget=$BudgetMib FREE=$((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1MB)GB ==="

$exitLine = "EXIT=MISSING"
$gt = "NOT_FOUND"; $ce = "0"; $arch = "UNKNOWN"; $vk = "?"; $blocker = "HARNESS_INCOMPLETE"
$hdSeen = "?"; $ds = "?"; $disp = "INCOMPLETE"
$combined = ""

try {
  $p = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$bat`"" -WorkingDirectory $bin -PassThru -WindowStyle Hidden
  $null = $p.WaitForExit()
  Start-Sleep -Seconds 1

  if (Test-Path $exitf) {
    $rawExit = [System.IO.File]::ReadAllText($exitf)
    if ($rawExit) { $exitLine = ($rawExit.Trim() -replace '\s+$','') }
  }
  if (Test-Path $out) { $combined += [System.IO.File]::ReadAllText($out) }
  $combined += "`n"
  if (Test-Path $err) { $combined += [System.IO.File]::ReadAllText($err) }

  if ($combined -match "GENERATED_TOKENS=(\d+)") { $gt = $Matches[1] }
  if ($combined -match "CLEAN_EXIT=1" -or $combined -match "DISPOSITION=CLEAN_EXIT") { $ce = "1" }
  # Never promote MISSING exit to 0 from CE alone when kill-interrupted.
  if ($ce -eq "1" -and $exitLine -eq "EXIT=MISSING") {
    $exitLine = "EXIT=0"
    [System.IO.File]::WriteAllText($exitf, "EXIT=0`n")
  }
  if ($combined -match "GGUF architecture: '([^']+)'") { $arch = $Matches[1] }
  elseif ($combined -match "(?m)^ARCH=([A-Za-z0-9_]+)") { $arch = $Matches[1] }
  if ($combined -match "HOST_DECODE=([01])") { $hdSeen = $Matches[1] }
  if ($combined -match "DUALSTICK_RUNTIME_USED=([01])") { $ds = $Matches[1] }
  if ($combined -match "vkCreateInstance failed") { $vk = "VK_CREATE_FAIL" }
  elseif ($combined -match "Vulkan open failed") { $vk = "OPEN_FAIL" }
  elseif ($combined -match "ENHANCEMENT STACK: HOST_DECODE") { $vk = "HOST_STACK" }
  elseif ($combined -match "vulkanInit=1") { $vk = "VK_INIT1" }

  $blocker = ""
  if ($combined -match "Insufficient host memory|NO_FEASIBLE_BACKEND") { $blocker = "INSUFFICIENT_HOST_MEMORY" }
  elseif ($combined -match "refuse SSM|SSM-CERT-001|SSM/hybrid layers") { $blocker = "SSM_CERT_REFUSE" }
  elseif ($combined -match "incomplete MLA metadata") { $blocker = "MLA_METADATA_INCOMPLETE" }
  elseif ($combined -match "duplicate tensor name") { $blocker = "SHARD_INDEX_DUP_TENSOR" }
  elseif ($Backend -eq "GPU" -and ($vk -match "FAIL" -or $ce -ne "1")) { $blocker = "VULKAN_OR_GPU_DECODE_FAIL" }
  elseif ($ce -ne "1") { $blocker = "NO_CLEAN_EXIT" }

  $disp = "FAIL"
  if ($ce -eq "1" -and $gt -ne "NOT_FOUND" -and [int]$gt -gt 0 -and ($exitLine -eq "EXIT=0")) {
    $disp = "PASS_NARROW"
  } elseif ($ce -eq "1") {
    $disp = "PARTIAL_CE_NO_GT"
  }
  # Explicit: partial never equals multi-arch PASS
  if ($disp -ne "PASS_NARROW") { if (-not $blocker) { $blocker = "NO_CLEAN_EXIT" } }
}
catch {
  $disp = "HARNESS_EXCEPTION"
  $blocker = "HARNESS_EXCEPTION"
  $exitLine = "EXIT=MISSING"
  Write-Host "=== CATCH $Id $($_.Exception.Message) ==="
}
finally {
  $sw.Stop()
  if (-not (Test-Path $exitf)) {
    [System.IO.File]::WriteAllText($exitf, "EXIT=MISSING`n")
    $exitLine = "EXIT=MISSING"
  }
  # Kill orphan child if harness aborted mid-wait
  if ($p -and -not $p.HasExited) {
    try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
    if ($disp -eq "INCOMPLETE" -or $disp -eq "HARNESS_EXCEPTION") {
      $disp = "ABORT_BY_PEER"
      $blocker = "ABORT_BY_PEER"
      $exitLine = "EXIT=KILLED"
      [System.IO.File]::WriteAllText($exitf, "EXIT=KILLED`n")
    }
  }
  $tail = @"
ARCH=$arch
GENERATED_TOKENS=$gt
CLEAN_EXIT_MARKER=$ce
HOST_DECODE_SEEN=$hdSeen
DUALSTICK_RUNTIME_USED=$ds
VK=$vk
BLOCKER=$blocker
DISPOSITION=$disp
HARNESS_COMPLETE=1
$exitLine
ELAPSED_MS=$($sw.ElapsedMilliseconds)
ENDED=$(Get-Date -Format o)
PASS=0
NOTE=NOT_RUN_NE_PASS; PARTIAL_NE_PASS; PROMOTE=0
"@
  try { Add-Content -Path $meta -Value $tail -Encoding utf8 } catch {
    [System.IO.File]::AppendAllText($meta, "`n$tail")
  }
  if (-not $doneEmitted) {
    Write-DoneLine -ExitLine $exitLine -Gt $gt -Ce $ce -Arch $arch -Vk $vk -Blocker $blocker -Disp $disp
  }
}
# Safety second emit if try path skipped Write-Done (should not happen)
if (-not $doneEmitted) {
  Write-DoneLine -ExitLine $exitLine -Gt $gt -Ce $ce -Arch $arch -Vk $vk -Blocker $blocker -Disp $disp
}
