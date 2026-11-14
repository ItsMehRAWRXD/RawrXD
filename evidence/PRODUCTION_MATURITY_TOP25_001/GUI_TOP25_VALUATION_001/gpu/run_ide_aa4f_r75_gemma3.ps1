# AA4F R75 EXIT=NULL / TOK residual — E8B0M neutralize + once budget emit.
# PROMOTE=0 TIP_ABSORB=0 TIP_CLIMB=HOLD CROSS_SHA_CREDIT=0
param([int]$MaxTok = 8)
$ErrorActionPreference = "Continue"
$ev = "G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\gpu"
$exe = "G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\RawrXD-Win32IDE_tip_land_aa4f_r75.exe"
$model = "G:\~dev\rawrxd\models\gemma3-1b-Q2_K.gguf"
$tip = "G:\~dev\rawrxd\bin\RawrXD-Win32IDE.exe"
$tipExpect = "6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431"
if (-not (Test-Path $exe)) { throw "EXE_MISSING" }
if (-not (Test-Path $model)) { throw "MODEL_MISSING" }
Get-Process | Where-Object { $_.ProcessName -like "RawrXD*" } | ForEach-Object {
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep 3
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
$tipSha = (Get-FileHash $tip -Algorithm SHA256).Hash
if ($tipSha -ne $tipExpect) { throw "TIP_SHA_MISMATCH=$tipSha" }
@(
  "RAWRXD_ALLOW_GPU","RAWR_FORCE_GPU","RAWR_NO_CPU_FALLBACK","RAWRXD_GPU_POLICY",
  "RAWRXD_HOST_DECODE","RAWR_HOST_DECODE","DEEP2_LIVE_POLICY","DEEP2_LIVE_PATH",
  "DEEP2_DUALSTICK_ARM","WEIGHT_BUDGET_MIB","DEEP2_WEIGHT_BUDGET_MIB",
  "RAWRXD_PRODUCT_STREAMER_ARM","RAWRXD_PRODUCT_STREAMER_PREP","RAWRXD_UNREVERSE_HOTPATCH",
  "RAWRXD_KV_FP16_ROUNDTRIP","RAWRXD_HOTPATCHER_CRASH_RECOVERY","DEEP2_GEN_QUALITY_TRACE"
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
$env:DEEP2_WEIGHT_BUDGET_MIB = "8192"
$env:RAWRXD_PRODUCT_STREAMER_ARM = "1"
$env:RAWRXD_PRODUCT_STREAMER_PREP = "1"
$sha16 = $sha.Substring(0, 16)
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$tag = "ide_mf_aa4f_r75_gemma3_$($sha16)_$stamp"
$gout = Join-Path $ev "$tag.out.txt"
$gerr = Join-Path $ev "$tag.err.txt"
$gex = Join-Path $ev "$tag.exit.txt"
$gmeta = Join-Path $ev "$tag.meta.txt"
$arg = "--headless --no-server --model `"$model`" --prompt `"What is 2+2? Answer with one digit only.`" --max-tokens $MaxTok --vulkan"
Write-Output "PRE_SOLO_CLEAR=1 TAG=$tag SHA16=$sha16 TIP_STILL_6754=1"
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
Write-Output "EXIT=$c WALL_MS=$($sw.ElapsedMilliseconds)"
"EXIT=$c" | Set-Content $gex
$both = "$e`n$o"
$tok = 0
if ($both -match "GENERATED_TOKENS[=:\s]+(\d+)") { $tok = [int]$Matches[1] }
$seh = 0; if ($both -match "PRODUCT_DEEP2_OPEN_SEH[=:\s]*1") { $seh = 1 }
$streamSeh = 0; if ($both -match "PRODUCT_DEEP2_INFER_STREAM_SEH[=:\s]*1") { $streamSeh = 1 }
$streamSehCode = ""; if ($both -match "PRODUCT_DEEP2_INFER_STREAM_SEH=1 CODE=(\S+)") { $streamSehCode = $Matches[1] }
$streamSehVa = ""; if ($both -match "PRODUCT_DEEP2_INFER_STREAM_SEH_ACCESS=\S+ VA=(\S+)") { $streamSehVa = $Matches[1] }
$streamEnter = 0; if ($both -match "GENERATE_STREAM_ENTER=1") { $streamEnter = 1 }
$crit = ""; if ($both -match "PRODUCT_OPEN_CRITICAL_TENSORS=(\S+)") { $crit = $Matches[1] }
$openPass = 0; if ($both -match "(?m)^PRODUCT_OPEN_PASS=1") { $openPass = 1 }
$midVramHard = 0
if ($c -eq "NULL" -and $streamEnter -eq 0 -and $both -match "blk\.2[0-9]") { $midVramHard = 1 }
$avClosed = 0
if ($midVramHard -eq 0 -and $streamSeh -eq 0 -and $seh -eq 0 -and $c -ne "NULL") { $avClosed = 1 }
elseif ($midVramHard -eq 0 -and $streamSeh -eq 0 -and $seh -eq 0 -and $both -match "CLEAN_EXIT|alreadyClosed fast-exit") { $avClosed = 1 }
$tokenSurvived = 0; if ($tok -gt 0 -and $seh -eq 0 -and $streamSeh -eq 0) { $tokenSurvived = 1 }
$tipPost = (Get-FileHash $tip -Algorithm SHA256).Hash
$prefillDone = 0; if ($both -match "PREFILL_DONE") { $prefillDone = 1 }
$logitsBefore = 0; if ($both -match "HEAP_OK_LOGITS_BEFORE=1|LOGITS_BEFORE") { $logitsBefore = 1 }
$e8b0 = 0; if ($both -match "WEIGHT_BUDGET_INPUT=E8B0M") { $e8b0 = 1 }
@(
"ASOF_LOCAL=$((Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz'))",
"ID=$tag",
"LANE=AA4F_R75_EXIT_NULL_TOK",
"FAMILY=gemma3",
"MODEL=models\gemma3-1b-Q2_K.gguf",
"EXE=$exe",
"EXE_SHA256=$sha",
"SHA16=$sha16",
"ROOT_FIX=ArmSpeed E8B0M→8192 neutralize in ProductStreamerPrep; GpuForward prefer WEIGHT_BUDGET_MIB + once emit + clamp>16GiB; prior D2GenQualitySlotFor ABI",
"TIP_SHA256=$tipPost",
"TIP_STILL_6754=$(([int]($tipPost -eq $tipExpect)))",
"FORCE=0",
"HOST_DECODE=0",
"PRODUCT_OPEN_PASS=$openPass",
"PRODUCT_OPEN_CRITICAL_TENSORS=$crit",
"PRODUCT_DEEP2_OPEN_SEH=$seh",
"INFER_STREAM_SEH=$streamSeh",
"STREAM_SEH_CODE=$streamSehCode",
"STREAM_SEH_VA=$streamSehVa",
"GENERATE_STREAM_ENTER=$streamEnter",
"MID_VRAM_HARD=$midVramHard",
"PREFILL_DONE=$prefillDone",
"LOGITS_REACHED=$logitsBefore",
"E8B0M_SPAM=$e8b0",
"GENERATED_TOKENS=$tok",
"TOKEN_SURVIVED=$tokenSurvived",
"SEH=$(([int]($seh -or $streamSeh)))",
"AV_CLOSED=$avClosed",
"PROCESS_EXIT=$c",
"WALL_MS=$($sw.ElapsedMilliseconds)",
"PROMOTE=0",
"TIP_CLIMB=HOLD",
"INVENT_PASS=0",
"CROSS_SHA_CREDIT=0",
"REJECT_FORCE_ABSORB=1",
"TIP_ABSORB=0",
"OUT=$gout",
"ERR=$gerr"
) | Set-Content $gmeta
Copy-Item $gmeta (Join-Path $ev "ide_mf_aa4f_r75_gemma3_LATEST.meta.txt") -Force
Write-Output "META=$gmeta OPEN=$openPass STREAM_ENTER=$streamEnter STREAM_SEH=$streamSeh TOK=$tok AV_CLOSED=$avClosed SEH=$seh/$streamSeh EXIT=$c E8B0=$e8b0 PREFILL=$prefillDone"
