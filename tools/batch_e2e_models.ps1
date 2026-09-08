# Batch E2E: load + generate for local GGUFs (non-fiction receipts).
# Usage: pwsh -File tools/batch_e2e_models.ps1 [-Tier small|medium|all]
param(
  [ValidateSet('small','medium','all')]
  [string]$Tier = 'small',
  [int]$MaxTokens = 4,
  [int]$Ctx = 128,
  [string]$OutDir = 'G:\~dev\rawrxd\evidence\LOCAL_MODEL_E2E'
)

$ErrorActionPreference = 'Continue'
$bench = 'G:\~dev\rawrxd\build-fd\bin\deep2_benchmark.exe'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Remove-Item Env:DEEP2_K2_SHARD_DIR -EA SilentlyContinue
$env:RAWRXD_HOST_DECODE = '1'
$env:RAWRXD_GPU_FWD = '0'
$env:RAWRXD_KEEP_ENHANCE_SKIP = '1'
$env:RAWRXD_ENHANCE_SKIP = 'elastic,cyclone,ckv,mars,medusa,nvme,vulkan,warmup,nu,chamber,plasma,sov,prefetch,telemetry,slide'
$env:RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM = '1'
# Allow byte tokenizer so load proceeds when SPM/BPE table is incomplete
# (gemma4 / exotic GGUFs). Decode quality may be reduced; tokens still prove path.
$env:RAWRXD_DEEP2_ALLOW_BYTE_TOKENIZER = '1'

# Unique loadable entrypoints (skip mmproj, dummy, non-first shards).
$candidates = @()
Get-ChildItem 'F:\OllamaModels' -Recurse -Filter '*.gguf' -EA SilentlyContinue | ForEach-Object {
  $n = $_.Name.ToLowerInvariant()
  if ($n -like 'mmproj*') { return }
  if ($n -eq 'dummy.gguf') { return }
  if ($n -match '-0000[2-9]-of-' -or $n -match '-0001[0-9]-of-') { return }
  $candidates += $_.FullName
}

function Get-SizeGB([string]$p) {
  try { [math]::Round((Get-Item $p).Length / 1GB, 2) } catch { 0 }
}

$selected = switch ($Tier) {
  'small'  { $candidates | Where-Object { (Get-SizeGB $_) -gt 0 -and (Get-SizeGB $_) -le 8 } }
  'medium' { $candidates | Where-Object { (Get-SizeGB $_) -gt 8 -and (Get-SizeGB $_) -le 25 } }
  'all'    { $candidates }
}

$report = Join-Path $OutDir "REPORT_$Tier.csv"
"model,gb,exit,generated_tokens,stream_status,fail_reason,notes" | Set-Content $report -Encoding UTF8

foreach ($m in ($selected | Sort-Object { Get-SizeGB $_ })) {
  $gb = Get-SizeGB $m
  $safe = ($m -replace '[\\/:\*\?"<>\|]', '_').Substring([Math]::Max(0, ($m.Length - 80)))
  $log = Join-Path $OutDir ("run_" + $safe + ".txt")
  Write-Host "=== E2E $gb GB :: $m ==="
  $sw = [Diagnostics.Stopwatch]::StartNew()
  & $bench --model $m --phase single --prompt "hi" --max-tokens $MaxTokens --ctx-size $Ctx 2>&1 |
    Tee-Object -FilePath $log | Out-Null
  $code = $LASTEXITCODE
  $sw.Stop()
  $txt = Get-Content $log -Raw -EA SilentlyContinue
  $gen = if ($txt -match 'GENERATED_TOKENS=(\d+)') { $Matches[1] } else { '0' }
  $st  = if ($txt -match 'STREAM_STATUS=(\w+)') { $Matches[1] } else { 'NA' }
  $fr  = if ($txt -match 'FAIL_REASON=([^\r\n]+)') { $Matches[1] } else { 'NA' }
  $note = "elapsed_s=$([math]::Round($sw.Elapsed.TotalSeconds,1))"
  if ($code -eq -1073741819 -or $code -eq 3221225477) { $note += ';ACCESS_VIOLATION' }
  $line = "`"$m`",$gb,$code,$gen,$st,`"$fr`",$note"
  Add-Content $report $line -Encoding UTF8
  Write-Host "  exit=$code gen=$gen status=$st fail=$fr $note"
}

Write-Host "REPORT=$report"
Get-Content $report
