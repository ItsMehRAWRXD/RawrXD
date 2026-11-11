$ErrorActionPreference = 'Continue'
$ev = 'F:\rawrxd-native-agent-001\evidence'
$errCandidates = @(
  (Join-Path $ev 'oracle_n300.err'),
  (Join-Path $ev 'oracle_256.err')
)
$err = $null
foreach ($c in $errCandidates) {
  if (Test-Path -LiteralPath $c) { $err = $c; break }
}
$copy = Join-Path $ev 'oracle_window_err.copy'
$idsPath = Join-Path $ev 'oracle_256_token_ids.txt'
$receipt = Join-Path $ev 'independent_reference_receipt.json'
$backup = Join-Path $ev 'independent_reference_receipt.255prev.json'
$exe = 'F:\rawrxd\build_ide\bin-msvc\reap-reference-receipt.exe'
$log = New-Object 'System.Collections.Generic.List[string]'
function L([string]$s) { [void]$log.Add($s); Write-Output $s }

L('=== seal_oracle_256 ' + (Get-Date -Format o))
L('DISPOSITION=OPTION_C_NATURAL_256_NO_PAD')
L('OPTION_A=REJECTED_NO_SCHEMA_DOWNGRADE')
L('OPTION_B=REJECTED_NO_SYNTHETIC_PADDING')
L('ERR_SOURCE=' + $err)

if (-not $err) { L('MISSING_ERR'); exit 2 }
[IO.File]::Copy($err, $copy, $true)

$ids = New-Object 'System.Collections.Generic.List[string]'
foreach ($line in [IO.File]::ReadLines($copy)) {
  if ($line -match 'slot decode token, id=(\d+)') {
    [void]$ids.Add($Matches[1])
  }
}
L('TOKEN_ID_COUNT_RAW=' + $ids.Count)

if ($ids.Count -lt 256) {
  L('STILL_SHORT count=' + $ids.Count)
  $ids | Set-Content -LiteralPath $idsPath -Encoding ASCII
  $log | Set-Content (Join-Path $ev 'seal_oracle_256_log.txt') -Encoding UTF8
  exit 3
}

$take = New-Object 'System.Collections.Generic.List[string]'
for ($i = 0; $i -lt 256; $i++) { [void]$take.Add($ids[$i]) }
$take | Set-Content -LiteralPath $idsPath -Encoding ASCII
$csv = ($take -join ',')
L('TOKEN_ID_COUNT_SEAL=' + $take.Count)
L('FIRST20=' + (($take | Select-Object -First 20) -join ','))
L('LAST10=' + (($take | Select-Object -Last 10) -join ','))

if (Test-Path -LiteralPath $receipt) {
  Copy-Item -LiteralPath $receipt -Destination $backup -Force
  L('BACKUP_PREV=' + $backup)
}

& $exe 'llama-cli' 'F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf' `
  'F:\rawrxd-native-agent-001\corpus.jsonl' '100' $csv 'b1-961c376+ignore-eos-n300' $receipt
L('RECEIPT_EXIT=' + $LASTEXITCODE)
if (Test-Path -LiteralPath $receipt) {
  L('RECEIPT_BYTES=' + (Get-Item -LiteralPath $receipt).Length)
}
L('REQUIRED_WINDOWS=256')
L('GATE2_REPLAY=NOT_RUN')
L('PROMOTE=0')
$log | Set-Content (Join-Path $ev 'seal_oracle_256_log.txt') -Encoding UTF8
