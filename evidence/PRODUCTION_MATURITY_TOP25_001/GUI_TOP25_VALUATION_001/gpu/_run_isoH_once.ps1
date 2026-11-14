# Private isoH remasure. PROMOTE=0 TIP_ABSORB=0.
param(
  [Parameter(Mandatory = $true)][string]$ModelPath,
  [Parameter(Mandatory = $true)][string]$Family
)
$ErrorActionPreference = "Continue"
$ev = "G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\gpu"
$exe = "G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\RawrXD-Win32IDE_tip_land_avfix_aa4frem_isoH.exe"
$tip = "G:\~dev\rawrxd\bin\RawrXD-Win32IDE.exe"
$tipExpect = "6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431"
Get-Process | Where-Object { $_.ProcessName -like "RawrXD*" } | ForEach-Object {
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep 2
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
$tipSha = (Get-FileHash $tip -Algorithm SHA256).Hash
if ($tipSha -ne $tipExpect) { throw "TIP_SHA_MISMATCH" }
@(
  "RAWRXD_ALLOW_GPU","RAWR_FORCE_GPU","RAWR_NO_CPU_FALLBACK","RAWRXD_GPU_POLICY",
  "RAWRXD_HOST_DECODE","RAWR_HOST_DECODE","DEEP2_LIVE_POLICY","DEEP2_LIVE_PATH",
  "DEEP2_DUALSTICK_ARM","WEIGHT_BUDGET_MIB","RAWRXD_PRODUCT_STREAMER_ARM",
  "RAWRXD_PRODUCT_STREAMER_PREP","RAWRXD_NVME_REVERSE_BUNNYHOP","RAWRXD_KV_FP16_ROUNDTRIP"
) | ForEach-Object { Remove-Item "Env:$_" -ErrorAction SilentlyContinue }
$env:RAWRXD_ALLOW_GPU = "1"
$env:RAWR_FORCE_GPU = "1"
$env:RAWR_NO_CPU_FALLBACK = "1"
$env:RAWRXD_GPU_POLICY = "SOLO"
$env:RAWRXD_HOST_DECODE = "0"
$env:RAWR_HOST_DECODE = "0"
$env:DEEP2_LIVE_POLICY = "OFF"
$env:DEEP2_LIVE_PATH = "0"
$env:WEIGHT_BUDGET_MIB = "8192"
$env:RAWRXD_PRODUCT_STREAMER_ARM = "1"
$env:RAWRXD_PRODUCT_STREAMER_PREP = "1"
$env:RAWRXD_NVME_REVERSE_BUNNYHOP = "0"
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$tag = "ide_mf_aa4frem_isoH_$($Family)_$($sha.Substring(0,16))_$stamp"
$gout = Join-Path $ev "$tag.out.txt"
$gerr = Join-Path $ev "$tag.err.txt"
$gmeta = Join-Path $ev "$tag.meta.txt"
$arg = "--headless --no-server --model `"$ModelPath`" --prompt `"What is 2+2? Answer with one digit only.`" --max-tokens 8 --vulkan"
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath $exe -ArgumentList $arg -WorkingDirectory "G:\~dev\rawrxd" `
  -RedirectStandardOutput $gout -RedirectStandardError $gerr -PassThru -NoNewWindow
$ok = $p.WaitForExit(600000)
$sw.Stop()
if (-not $ok) { try { $p.Kill() } catch {}; $c = "TIMEOUT" }
else {
  $p.Refresh()
  $c = if ($null -eq $p.ExitCode) { "NULL" } else { [string]$p.ExitCode }
}
$o = ""; $e = ""
if (Test-Path $gout) { $o = Get-Content $gout -Raw -ErrorAction SilentlyContinue }
if (Test-Path $gerr) { $e = Get-Content $gerr -Raw -ErrorAction SilentlyContinue }
$both = "$e`n$o"
$tok = 0
if ($both -match "GENERATED_TOKENS[=:\s]+(\d+)") { $tok = [int]$Matches[1] }
$seh = 0
if ($both -match "PRODUCT_DEEP2_INFER_STREAM_SEH[=:\s]*1") { $seh = 1 }
$enter = 0
if ($both -match "GENERATE_STREAM_ENTER=1") { $enter = 1 }
$code = ""
if ($both -match "PRODUCT_DEEP2_INFER_STREAM_SEH=1 CODE=(\S+)") { $code = $Matches[1] }
$av = if (($tok -gt 0) -and ($seh -eq 0)) { 1 } else { 0 }
@(
  "ID=$tag",
  "LANE=AA4FREM_ISOH_BAK_ADDROK_IE_QDIM077",
  "FAMILY=$Family",
  "EXE_SHA256=$sha",
  "GENERATED_TOKENS=$tok",
  "INFER_STREAM_SEH=$seh",
  "STREAM_SEH_CODE=$code",
  "GENERATE_STREAM_ENTER=$enter",
  "PROCESS_EXIT=$c",
  "AV_CLOSED=$av",
  "WALL_MS=$([int]$sw.Elapsed.TotalMilliseconds)",
  "TIP_STILL_6754=1",
  "PROMOTE=0",
  "OUT=$gout",
  "ERR=$gerr"
) | Set-Content $gmeta
Write-Output "SHA8=$($sha.Substring(0,8)) TOK=$tok SEH=$seh ENTER=$enter EXIT=$c AV=$av META=$gmeta"
