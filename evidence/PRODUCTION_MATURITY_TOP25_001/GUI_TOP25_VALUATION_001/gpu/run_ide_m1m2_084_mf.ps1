# Private cand m1m2_084 remasure. Tip RO. PROMOTE=0 TIP_CLIMB=HOLD
param(
  [Parameter(Mandatory = $true)][string]$Family,
  [Parameter(Mandatory = $true)][string]$ModelRel,
  [int]$MaxTok = 8
)
$ErrorActionPreference = "Continue"
$root = "G:\~dev\rawrxd"
$ev = Join-Path $root "evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\gpu"
$exe = Join-Path $root "evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_tip_land_m1m2_084.exe"
$tip = Join-Path $root "bin\RawrXD-Win32IDE.exe"
$tipExpect = "6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431"
$model = Join-Path $root $ModelRel
if (-not (Test-Path $model)) { throw "MODEL_MISSING=$model" }
if (-not (Test-Path $exe)) { throw "EXE_MISSING=$exe" }
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
$tipSha = (Get-FileHash $tip -Algorithm SHA256).Hash
if ($tipSha -ne $tipExpect) { throw "TIP_SHA_MISMATCH=$tipSha" }
$sha16 = $sha.Substring(0, 16)

@(
  "RAWRXD_ALLOW_GPU", "RAWR_FORCE_GPU", "RAWR_NO_CPU_FALLBACK", "RAWRXD_GPU_POLICY",
  "RAWRXD_HOST_DECODE", "RAWR_HOST_DECODE", "DEEP2_LIVE_POLICY", "DEEP2_LIVE_PATH",
  "DEEP2_DUALSTICK_ARM", "WEIGHT_BUDGET_MIB", "DEEP2_WEIGHT_BUDGET_MIB",
  "RAWRXD_PRODUCT_STREAMER_ARM", "RAWRXD_PRODUCT_STREAMER_PREP", "RAWRXD_UNREVERSE_HOTPATCH",
  "RAWRXD_KV_FP16_ROUNDTRIP"
) | ForEach-Object { Remove-Item "Env:$_" -ErrorAction SilentlyContinue }

$env:RAWRXD_ALLOW_GPU = "1"
$env:RAWR_FORCE_GPU = "1"
$env:RAWR_NO_CPU_FALLBACK = "1"
$env:RAWRXD_GPU_POLICY = "SOLO"
$env:RAWRXD_HOST_DECODE = "0"
$env:RAWR_HOST_DECODE = "0"
$env:DEEP2_LIVE_POLICY = "OFF"
$env:DEEP2_LIVE_PATH = "0"
$env:DEEP2_DUALSTICK_ARM = "0"
$env:WEIGHT_BUDGET_MIB = "8192"
$env:DEEP2_WEIGHT_BUDGET_MIB = "2048"
$env:RAWRXD_PRODUCT_STREAMER_ARM = "1"
$env:RAWRXD_PRODUCT_STREAMER_PREP = "1"

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$tag = "ide_mf_m1m2_084_$($Family)_$($sha16)_$stamp"
$gout = Join-Path $ev "$tag.out.txt"
$gerr = Join-Path $ev "$tag.err.txt"
$gex = Join-Path $ev "$tag.exit.txt"
$gmeta = Join-Path $ev "$tag.meta.txt"
$arg = "--headless --no-server --model `"$model`" --prompt `"What is 2+2? Answer with one digit only.`" --max-tokens $MaxTok --vulkan"
"FAMILY=$Family PRE_SHA16=$sha16" | Write-Output
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath $exe -ArgumentList $arg -WorkingDirectory $root `
  -RedirectStandardOutput $gout -RedirectStandardError $gerr -PassThru -NoNewWindow
"PID=$($p.Id)" | Write-Output
$ok = $p.WaitForExit(600000)
$sw.Stop()
if (-not $ok) {
  try { $p.Kill() } catch {}
  Start-Sleep 2
  $c = "TIMEOUT"
}
else {
  $p.Refresh()
  if ($null -eq $p.ExitCode) { Start-Sleep -Milliseconds 250; $p.Refresh() }
  $c = if ($null -eq $p.ExitCode) { "NULL" } else { [string]$p.ExitCode }
}
"EXIT=$c WALL_MS=$($sw.ElapsedMilliseconds)" | Write-Output
"EXIT=$c" | Set-Content $gex

$o = ""; $e = ""
if (Test-Path $gout) { $o = Get-Content $gout -Raw -ErrorAction SilentlyContinue }
if (Test-Path $gerr) { $e = Get-Content $gerr -Raw -ErrorAction SilentlyContinue }
$both = "$e`n$o"
$tok = 0
if ($both -match "GENERATED_TOKENS[=:\s]+(\d+)") { $tok = [int]$Matches[1] }
elseif ($both -match "(?m)^LAYER_COUNT=\d+\s+TOKENS=(\d+)") { $tok = [int]$Matches[1] }
elseif ($both -match "(?m)^TOKENS=(\d+)") { $tok = [int]$Matches[1] }
$hd = -1
if ($both -match "HOST_DECODE[=:\s]+(\d+)") { $hd = [int]$Matches[1] }
$seh = 0
if ($both -match "PRODUCT_DEEP2_OPEN_SEH[=:\s]*1") { $seh = 1 }
$streamSeh = 0
if ($both -match "PRODUCT_DEEP2_INFER_STREAM_SEH[=:\s]*1") { $streamSeh = 1 }
$streamSehCode = ""
if ($both -match "PRODUCT_DEEP2_INFER_STREAM_SEH=1 CODE=(\S+)") { $streamSehCode = $Matches[1] }
$sessionExit = 0
if ($both -match "PRODUCT_OPEN SESSION_EXIT ok=1|SESSION_EXIT[^\n]*ok[=:\s]*1") { $sessionExit = 1 }
$gpuRes = 0
if ($both -match "HOTPATH_FFN=GPU_RESIDENT|DEEP2_GPU_RESIDENT_FORWARD=1|HOTPATH_GPU_FWD_ENABLED=1|(?m)GPU_RESIDENT=1") { $gpuRes = 1 }
$crit = ""
if ($both -match "PRODUCT_OPEN_CRITICAL_TENSORS=(\S+)") { $crit = $Matches[1] }
$tokenSurvived = 0
if ($tok -gt 0 -and $seh -eq 0 -and $streamSeh -eq 0) { $tokenSurvived = 1 }
$av = 0
if ($c -match '^-?\d+$' -and [int64]$c -eq [int64]0xC0000005) { $av = 1 }
if ($both -match "INFER_STREAM_SEH=1") { if ($streamSehCode -match "C0000005") { $av = 1 } }
$tipPost = (Get-FileHash $tip -Algorithm SHA256).Hash

@(
  "ASOF_LOCAL=$((Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz'))",
  "ID=$tag",
  "LANE=M1M2_084_HOTSEH_FP16GATE",
  "FAMILY=$Family",
  "MODEL=$ModelRel",
  "EXE=$exe",
  "EXE_SHA256=$sha",
  "SHA16=$sha16",
  "TIP_SHA256=$tipPost",
  "TIP_STILL_6754=$([int]($tipPost -eq $tipExpect))",
  "FIX=qDim=wq.rows+FP16_GATE+HotPatcher_VirtualQuery+ElasticIdemp",
  "FORCE=0",
  "HOST_DECODE=$hd",
  "PRODUCT_DEEP2_OPEN_SEH=$seh",
  "INFER_STREAM_SEH=$streamSeh",
  "STREAM_SEH_CODE=$streamSehCode",
  "PRODUCT_OPEN_CRITICAL_TENSORS=$crit",
  "SESSION_EXIT_OK=$sessionExit",
  "GENERATED_TOKENS=$tok",
  "TOKEN_SURVIVED=$tokenSurvived",
  "GPU_RESIDENT_SEEN=$gpuRes",
  "AV_SEEN=$av",
  "PROCESS_EXIT=$c",
  "WALL_MS=$($sw.ElapsedMilliseconds)",
  "PROMOTE=0",
  "TIP_CLIMB=HOLD",
  "INVENT_PASS=0",
  "OUT=$gout",
  "ERR=$gerr"
) | Set-Content $gmeta
Copy-Item $gmeta (Join-Path $ev "ide_mf_m1m2_084_$($Family)_LATEST.meta.txt") -Force
"FAMILY=$Family TOK=$tok STREAM_SEH=$streamSeh AV=$av SURV=$tokenSurvived EXIT=$c WALL=$($sw.ElapsedMilliseconds) META=$gmeta" | Write-Output
