# AA4F remasure after HotPatcher addrOk on tip_land avfix079 lineage. PROMOTE=0 TIP_ABSORB=0.
param([int]$MaxTok = 8, [string]$ModelPath = "")
$ErrorActionPreference = "Continue"
$ev = "G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\gpu"
$exe = "G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\RawrXD-Win32IDE_tip_land_avfix_aa4frem.exe"
$tip = "G:\~dev\rawrxd\bin\RawrXD-Win32IDE.exe"
if (-not $ModelPath) { $ModelPath = "G:\~dev\rawrxd\models\gemma3-1b-Q2_K.gguf" }
$expect = "C9FB0B4846680E4B4B00A365E697DFC00492CF31B73328D706A99CB16DA668AE"
$tipExpect = "6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431"
$family = if ($ModelPath -match "tinyllama") { "tinyllama" } elseif ($ModelPath -match "gemma") { "gemma3" } else { "other" }
if (-not (Test-Path $exe)) { throw "EXE_MISSING" }
if (-not (Test-Path $ModelPath)) { throw "MODEL_MISSING=$ModelPath" }
Get-Process | Where-Object { $_.ProcessName -like "RawrXD*" } | ForEach-Object {
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep 3
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
if ($sha -ne $expect) { throw "EXE_SHA_MISMATCH=$sha" }
$tipSha = (Get-FileHash $tip -Algorithm SHA256).Hash
if ($tipSha -ne $tipExpect) { throw "TIP_SHA_MISMATCH=$tipSha" }
@(
  "RAWRXD_ALLOW_GPU","RAWR_FORCE_GPU","RAWR_NO_CPU_FALLBACK","RAWRXD_GPU_POLICY",
  "RAWRXD_HOST_DECODE","RAWR_HOST_DECODE","DEEP2_LIVE_POLICY","DEEP2_LIVE_PATH",
  "DEEP2_DUALSTICK_ARM","WEIGHT_BUDGET_MIB","DEEP2_WEIGHT_BUDGET_MIB",
  "RAWRXD_PRODUCT_STREAMER_ARM","RAWRXD_PRODUCT_STREAMER_PREP","RAWRXD_UNREVERSE_HOTPATCH",
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
$env:RAWRXD_PRODUCT_STREAMER_ARM = "1"
$env:RAWRXD_PRODUCT_STREAMER_PREP = "1"
$sha16 = $sha.Substring(0, 16)
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$tag = "ide_mf_aa4frem_$($family)_$($sha16)_$stamp"
$gout = Join-Path $ev "$tag.out.txt"
$gerr = Join-Path $ev "$tag.err.txt"
$gex = Join-Path $ev "$tag.exit.txt"
$gmeta = Join-Path $ev "$tag.meta.txt"
$arg = "--headless --no-server --model `"$ModelPath`" --prompt `"What is 2+2? Answer with one digit only.`" --max-tokens $MaxTok --vulkan"
Write-Output "PRE_SOLO_CLEAR=1 TAG=$tag SHA16=$sha16 TIP_STILL_6754=1 FAMILY=$family"
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath $exe -ArgumentList $arg -WorkingDirectory "G:\~dev\rawrxd" `
  -RedirectStandardOutput $gout -RedirectStandardError $gerr -PassThru -NoNewWindow
Write-Output "PID=$($p.Id)"
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
"EXIT=$c" | Set-Content $gex
$both = "$e`n$o"
$tok = 0
if ($both -match "GENERATED_TOKENS[=:\s]+(\d+)") { $tok = [int]$Matches[1] }
$seh = 0; if ($both -match "PRODUCT_DEEP2_OPEN_SEH[=:\s]*1") { $seh = 1 }
$streamSeh = 0; if ($both -match "PRODUCT_DEEP2_INFER_STREAM_SEH[=:\s]*1") { $streamSeh = 1 }
$streamSehCode = ""; if ($both -match "PRODUCT_DEEP2_INFER_STREAM_SEH=1 CODE=(\S+)") { $streamSehCode = $Matches[1] }
$streamEnter = 0; if ($both -match "GENERATE_STREAM_ENTER=1") { $streamEnter = 1 }
$sessionExit = 0
if ($both -match "PRODUCT_OPEN SESSION_EXIT ok=1|SESSION_EXIT[^\n]*ok[=:\s]*1") { $sessionExit = 1 }
$crit = ""; if ($both -match "PRODUCT_OPEN_CRITICAL_TENSORS=(\S+)") { $crit = $Matches[1] }
$tensors = ""; if ($both -match "PRODUCT_OPEN_SESSION=OK tensors=(\d+)") { $tensors = $Matches[1] }
$gpuRes = 0
if ($both -match "HOTPATH_FFN=GPU_RESIDENT|DEEP2_GPU_RESIDENT_FORWARD=1|HOTPATH_GPU_FWD_ENABLED=1") { $gpuRes = 1 }
$avHint = 0
if ($c -match "C0000005" -or $both -match "0xC0000005|ACCESS_VIOLATION|emergencyRollback") { $avHint = 1 }
$tokenSurvived = 0
if ($tok -gt 0 -and $seh -eq 0 -and $streamSeh -eq 0) { $tokenSurvived = 1 }
$avClosed = 0
if ($avHint -eq 0 -and $c -ne "NULL" -and $c -notmatch "C0000005") { $avClosed = 1 }
if ($tokenSurvived -eq 1) { $avClosed = 1 }
$tipPost = (Get-FileHash $tip -Algorithm SHA256).Hash
@(
"ASOF_LOCAL=$((Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz'))",
"ID=$tag",
"LANE=AA4FREM_ADDROK_TIPLAND_AVFIX079",
"FAMILY=$family",
"MODEL=$ModelPath",
"EXE=$exe",
"EXE_SHA256=$sha",
"SHA16=$sha16",
"SHA8=$($sha.Substring(0,8))",
"LINEAGE=tip_land_avfix079_rsp+HotPatcher_addrOk+Deep2Engine_hotseh_current",
"PRIOR_AA4F=AA4F853099E1F022",
"TIP_SHA256=$tipPost",
"TIP_STILL_6754=$(([int]($tipPost -eq $tipExpect)))",
"FORCE=0",
"HOST_DECODE=0",
"PRODUCT_DEEP2_OPEN_SEH=$seh",
"INFER_STREAM_SEH=$streamSeh",
"STREAM_SEH_CODE=$streamSehCode",
"GENERATE_STREAM_ENTER=$streamEnter",
"PRODUCT_OPEN_CRITICAL_TENSORS=$crit",
"OPEN_TENSORS=$tensors",
"SESSION_EXIT_OK=$sessionExit",
"GENERATED_TOKENS=$tok",
"TOKEN_SURVIVED=$tokenSurvived",
"GPU_RESIDENT_SEEN=$gpuRes",
"AV_HINT=$avHint",
"AV_CLOSED=$avClosed",
"PROCESS_EXIT=$c",
"WALL_MS=$($sw.ElapsedMilliseconds)",
"PROMOTE=0",
"TIP_CLIMB=HOLD",
"INVENT_PASS=0",
"REJECT_FORCE_ABSORB=1",
"TIP_ABSORB=0",
"OUT=$gout",
"ERR=$gerr"
) | Set-Content $gmeta
Copy-Item $gmeta (Join-Path $ev "ide_mf_aa4frem_$($family)_LATEST.meta.txt") -Force
Get-Content $gmeta
Write-Output "RESULT TOK=$tok SEH=$seh STREAM_SEH=$streamSeh EXIT=$c AV_CLOSED=$avClosed WALL=$($sw.ElapsedMilliseconds)"
exit $(if ($tokenSurvived -eq 1) { 0 } else { 2 })
