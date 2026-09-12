param(
  [string]$Rawr = "G:\~dev\rawrxd\build-fd\bin\rawr.exe",
  [string]$QualityExe = ".\d2_gen_quality.exe",
  [string]$Evidence = "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\DEEP2_GEN_QUALITY_LLAMA32_Q2K_001",
  [string[]]$Models = @("llama3.2-3b-Q2_K","tinyllama"),
  [string]$Prompt = "introduce yourself in under 99 words",
  [int]$Tokens = 48
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Evidence | Out-Null
$rows = @()
foreach ($m in $Models) {
  $safe = ($m -replace '[^A-Za-z0-9_.-]','_')
  $out = Join-Path $Evidence "$safe.stdout.txt"
  $err = Join-Path $Evidence "$safe.stderr.txt"
  $trace = Join-Path $Evidence "$safe.trace.txt"
  $env:DEEP2_GEN_QUALITY_TRACE = $trace
  & $Rawr run $m $Prompt -n $Tokens 1>$out 2>$err
  $exit = $LASTEXITCODE
  $stdout = if (Test-Path $out) { Get-Content $out -Raw } else { "" }
  $stderr = if (Test-Path $err) { Get-Content $err -Raw } else { "" }
  $mock = if ($stderr -match 'MOCK_BACKEND=1') {1} else {0}
  $gen = if ($stderr -match 'GENERATED_TOKENS=(\d+)') {[int]$Matches[1]} elseif ($stderr -match 'TOKENS_COMMITTED=(\d+)') {[int]$Matches[1]} else {0}
  $qlog = Join-Path $Evidence "$safe.quality.txt"
  if (Test-Path $trace) { & $QualityExe $out $trace > $qlog } else { & $QualityExe $out > $qlog }
  $qexit = $LASTEXITCODE
  $q = if (Test-Path $qlog) { Get-Content $qlog -Raw } else { "" }
  $quality = if ($q -match 'GEN_QUALITY=PASS') {1} else {0}
  $rows += [pscustomobject]@{
    MODEL=$m; EXIT=$exit; GENERATED_TOKENS=$gen; MOCK_BACKEND=$mock;
    STDOUT_BYTES=[Text.Encoding]::UTF8.GetByteCount($stdout);
    QUALITY_PASS=$quality; QUALITY_EXIT=$qexit;
    PASS=$(if($exit -eq 0 -and $gen -gt 0 -and $mock -eq 0 -and $quality -eq 1){1}else{0})
  }
}
$matrix = Join-Path $Evidence "MODEL_MATRIX.tsv"
$rows | Export-Csv -Delimiter "`t" -NoTypeInformation -Path $matrix
$all = ($rows | Where-Object {$_.PASS -ne 1}).Count -eq 0
"MODEL_MATRIX_REQUIRED_ROWS_PASS=$(if($all){1}else{0})" | Set-Content (Join-Path $Evidence "RECEIPT_MATRIX.txt")
$rows | Format-Table -AutoSize
if (-not $all) { exit 20 }
exit 0
