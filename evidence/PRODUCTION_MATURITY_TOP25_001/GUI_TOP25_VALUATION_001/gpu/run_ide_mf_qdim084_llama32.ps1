# Private qdim084 MARS-dedup+keepGPU llama32 remasure. PROMOTE=0 TIP_ABSORB=0.
param([int]$MaxTok = 8)
$ErrorActionPreference = "Continue"
$ev = "G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\gpu"
$exe = "G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084.exe"
$model = "G:\~dev\rawrxd\models\llama3.2-3b-Q2_K.gguf"
$tip = "G:\~dev\rawrxd\bin\RawrXD-Win32IDE.exe"
$expect = "A01AC1C1E958A5D0500E2B457008DB0A87CC6D598EEFD7CFB352811B3901AF3C"
$tipExpect = "6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431"
if (-not (Test-Path $exe)) { throw "EXE_MISSING" }
if (-not (Test-Path $model)) { throw "MODEL_MISSING" }
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
if ($sha -ne $expect) { throw "EXE_SHA_MISMATCH=$sha" }
$tipSha = (Get-FileHash $tip -Algorithm SHA256).Hash
if ($tipSha -ne $tipExpect) { throw "TIP_SHA_MISMATCH=$tipSha" }
@(
  "RAWRXD_ALLOW_GPU","RAWR_FORCE_GPU","RAWR_NO_CPU_FALLBACK","RAWRXD_GPU_POLICY",
  "RAWRXD_HOST_DECODE","RAWR_HOST_DECODE","DEEP2_LIVE_POLICY","DEEP2_LIVE_PATH",
  "DEEP2_DUALSTICK_ARM","WEIGHT_BUDGET_MIB","DEEP2_WEIGHT_BUDGET_MIB","WEIGHT_BUDGET_INPUT",
  "RAWRXD_PRODUCT_STREAMER_ARM","RAWRXD_PRODUCT_STREAMER_PREP","RAWRXD_UNREVERSE_HOTPATCH",
  "GPU_POLICY","RAWRXD_GPU_DEVICE","RAWRXD_DEEP2_ALLOW_ELASTIC","DEEP2_MARS","RAWRXD_ENHANCE_SKIP"
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
$env:RAWRXD_DEEP2_ALLOW_ELASTIC = "0"
$env:DEEP2_MARS = "1"
$env:DEEP2_KV_WORKING_SEQ = "2048"
$env:RAWRXD_ENHANCE_SKIP = "torus,plasma,chamber,sov,medusa,nu,warmup,ckv,nvme"
$env:WEIGHT_BUDGET_MIB = "8192"
$env:WEIGHT_BUDGET_INPUT = "8192"
$env:RAWRXD_PRODUCT_STREAMER_ARM = "1"
$env:RAWRXD_PRODUCT_STREAMER_PREP = "1"
$sha16 = $sha.Substring(0, 16)
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$tag = "ide_mf_qdim084_llama32_$($sha16)_$stamp"
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
$dupWarn = 0; if ($both -match "already registered") { $dupWarn = 1 }
$streamEnter = 0; if ($both -match "GENERATE_STREAM_ENTER=1") { $streamEnter = 1 }
$crit = ""; if ($both -match "PRODUCT_OPEN_CRITICAL_TENSORS=(\S+)") { $crit = $Matches[1] }
$keepGpu = 0; if ($both -match "MARS keep-GPU pin") { $keepGpu = 1 }
$tokenSurvived = 0; if ($tok -gt 0 -and $seh -eq 0 -and $streamSeh -eq 0) { $tokenSurvived = 1 }
$tipPost = (Get-FileHash $tip -Algorithm SHA256).Hash
@(
"ASOF_LOCAL=$((Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz'))",
"ID=$tag",
"LANE=MULTI_FAMILY_QDIM084_MARS_DEDUP_KEEPGPU_PRIVATE",
"FAMILY=llama32",
"MODEL=models\llama3.2-3b-Q2_K.gguf",
"EXE=$exe",
"EXE_SHA256=$sha",
"SHA16=$sha16",
"TIP_SHA256=$tipPost",
"TIP_STILL_6754=$(([int]($tipPost -eq $tipExpect)))",
"FORCE=0",
"HOST_DECODE=0",
"PRODUCT_DEEP2_OPEN_SEH=$seh",
"INFER_STREAM_SEH=$streamSeh",
"STREAM_SEH_CODE=$streamSehCode",
"DUP_TOKEN_EMBD_WARN=$dupWarn",
"MARS_KEEP_GPU_PIN=$keepGpu",
"GENERATE_STREAM_ENTER=$streamEnter",
"PRODUCT_OPEN_CRITICAL_TENSORS=$crit",
"GENERATED_TOKENS=$tok",
"TOKEN_SURVIVED=$tokenSurvived",
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
Copy-Item $gmeta (Join-Path $ev "ide_mf_qdim084_llama32_LATEST.meta.txt") -Force
Write-Output "META=$gmeta DUP=$dupWarn STREAM_ENTER=$streamEnter STREAM_SEH=$streamSeh TOK=$tok KEEP_GPU=$keepGpu TOKEN_SURVIVED=$tokenSurvived"
