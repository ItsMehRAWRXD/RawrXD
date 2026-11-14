# TIP6754_MF_BIND: TOKEN_SURVIVED on tip GUI bind SHA 6754616E (not qdim077 absorb).
# PROMOTE=0 TIP_CLIMB=HOLD REJECT_FORCE_ABSORB=1 TIP_ABSORB=0 — never overwrite tip.
param(
  [Parameter(Mandatory=$true)][string]$Family,
  [Parameter(Mandatory=$true)][string]$ModelRel,
  [int]$MaxTok = 8
)
$ErrorActionPreference = "Continue"
$ev = "G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\gpu"
$exe = "G:\~dev\rawrxd\bin\RawrXD-Win32IDE.exe"
$tipExpect = "6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431"
$model = Join-Path "G:\~dev\rawrxd" $ModelRel
if (-not (Test-Path $model)) { throw "MODEL_MISSING=$model" }
if (-not (Test-Path $exe)) { throw "EXE_MISSING=$exe" }
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
if ($sha -ne $tipExpect) { throw "TIP_SHA_MISMATCH=$sha" }

@(
  "RAWRXD_ALLOW_GPU","RAWR_FORCE_GPU","RAWR_NO_CPU_FALLBACK","RAWRXD_GPU_POLICY",
  "RAWRXD_HOST_DECODE","RAWR_HOST_DECODE","DEEP2_LIVE_POLICY","DEEP2_LIVE_PATH",
  "DEEP2_DUALSTICK_ARM","WEIGHT_BUDGET_MIB","DEEP2_WEIGHT_BUDGET_MIB",
  "RAWRXD_PRODUCT_STREAMER_ARM","RAWRXD_PRODUCT_STREAMER_PREP","RAWRXD_UNREVERSE_HOTPATCH"
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
$env:RAWRXD_PRODUCT_STREAMER_ARM = "1"
$env:RAWRXD_PRODUCT_STREAMER_PREP = "1"

$sha16 = $sha.Substring(0, 16)
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$tag = "ide_tip6754_mf_bind_$($Family)_$($sha16)_$stamp"
$gout = Join-Path $ev "$tag.out.txt"
$gerr = Join-Path $ev "$tag.err.txt"
$gex = Join-Path $ev "$tag.exit.txt"
$gmeta = Join-Path $ev "$tag.meta.txt"
$arg = "--headless --no-server --model `"$model`" --prompt `"What is 2+2? Answer with one digit only.`" --max-tokens $MaxTok --vulkan"
"FAMILY=$Family PRE_SHA16=$sha16 MODEL=$ModelRel TIP_OK=1" | Write-Output
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath $exe -ArgumentList $arg -WorkingDirectory "G:\~dev\rawrxd" `
  -RedirectStandardOutput $gout -RedirectStandardError $gerr -PassThru -NoNewWindow
"PID=$($p.Id)" | Write-Output
$ok = $p.WaitForExit(600000)
$sw.Stop()
if (-not $ok) { try { $p.Kill() } catch {}; Start-Sleep 2; $c = "TIMEOUT" }
else {
  $p.Refresh()
  if ($null -eq $p.ExitCode) { Start-Sleep -Milliseconds 250; $p.Refresh() }
  $c = if ($null -eq $p.ExitCode) { "NULL" } else { [string]$p.ExitCode }
}
$o = ""; $e = ""
if (Test-Path $gout) { $o = Get-Content $gout -Raw -ErrorAction SilentlyContinue }
if (Test-Path $gerr) { $e = Get-Content $gerr -Raw -ErrorAction SilentlyContinue }
if ($c -eq "" -or $null -eq $c -or $c -eq "NULL") {
  if ($e -match "(?m)^EXIT_CODE=(-?\d+)") { $c = $Matches[1] }
  elseif ($e -match "CLEAN_EXIT=1") { $c = "0" }
  else { $c = "NULL" }
}
"EXIT=$c WALL_MS=$($sw.ElapsedMilliseconds)" | Write-Output
"EXIT=$c" | Set-Content $gex
$both = "$e`n$o"
$tok = 0
if ($both -match "GENERATED_TOKENS[=:\s]+(\d+)") { $tok = [int]$Matches[1] }
elseif ($both -match "(?m)^LAYER_COUNT=\d+\s+TOKENS=(\d+)") { $tok = [int]$Matches[1] }
elseif ($both -match "(?m)^TOKENS=(\d+)") { $tok = [int]$Matches[1] }
$hd = -1; if ($both -match "HOST_DECODE[=:\s]+(\d+)") { $hd = [int]$Matches[1] }
$seh = 0
if ($both -match "PRODUCT_DEEP2_OPEN_SEH[=:\s]*1") { $seh = 1 }
$sehCode = ""
if ($both -match "PRODUCT_DEEP2_OPEN_SEH=1 CODE=(\S+)") { $sehCode = $Matches[1] }
$streamSeh = 0
if ($both -match "PRODUCT_DEEP2_INFER_STREAM_SEH[=:\s]*1") { $streamSeh = 1 }
$sessionExit = 0
if ($both -match "PRODUCT_OPEN SESSION_EXIT ok=1|SESSION_EXIT[^\n]*ok[=:\s]*1") { $sessionExit = 1 }
$gpuRes = 0
if ($both -match "HOTPATH_FFN=GPU_RESIDENT|DEEP2_GPU_RESIDENT_FORWARD=1|HOTPATH_GPU_FWD_ENABLED=1|(?m)GPU_RESIDENT=1") { $gpuRes = 1 }
$crit = ""
if ($both -match "PRODUCT_OPEN_CRITICAL_TENSORS=(\S+)") { $crit = $Matches[1] }
$arch = ""
if ($both -match "ARCH=(\S+)") { $arch = $Matches[1] }
elseif ($both -match "GGUF architecture:\s*'([^']+)'") { $arch = $Matches[1] }
$tokenSurvived = 0
if ($tok -gt 0 -and $seh -eq 0 -and $streamSeh -eq 0) { $tokenSurvived = 1 }
$tipPost = (Get-FileHash $exe -Algorithm SHA256).Hash

$meta = @(
"ASOF_LOCAL=$((Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz'))",
"ID=$tag",
"LANE=TIP6754_MF_BIND",
"FAMILY=$Family",
"MODEL=$ModelRel",
"ARCH=$arch",
"EXE=$exe",
"EXE_SHA256=$sha",
"SHA16=$sha16",
"TIP_SHA256=$tipPost",
"TIP_STILL_6754=$([int]($tipPost -eq $tipExpect))",
"FORCE=0",
"HOST_DECODE=$hd",
"PRODUCT_DEEP2_OPEN_SEH=$seh",
"OPEN_SEH_CODE=$sehCode",
"INFER_STREAM_SEH=$streamSeh",
"PRODUCT_OPEN_CRITICAL_TENSORS=$crit",
"SESSION_EXIT_OK=$sessionExit",
"GENERATED_TOKENS=$tok",
"TOKEN_SURVIVED=$tokenSurvived",
"GPU_RESIDENT_SEEN=$gpuRes",
"PROCESS_EXIT=$c",
"WALL_MS=$($sw.ElapsedMilliseconds)",
"PROMOTE=0",
"TIP_CLIMB=HOLD",
"INVENT_PASS=0",
"REJECT_FORCE_ABSORB=1",
"TIP_ABSORB=0",
"REJECT_QDIM077_ABSORB_CREDIT=1",
"OUT=$gout",
"ERR=$gerr"
)
$meta | Set-Content $gmeta
Copy-Item $gmeta (Join-Path $ev "ide_tip6754_mf_bind_$($Family)_LATEST.meta.txt") -Force
Get-Content $gmeta
Write-Output "META=$gmeta"
exit $(if ($tokenSurvived -eq 1) { 0 } else { 2 })
