$ErrorActionPreference = 'Continue'
$ev = 'F:\rawrxd-native-agent-001\evidence'
$err = Join-Path $ev 'oracle_single_turn.err'
$copy = Join-Path $ev 'oracle_single_turn.err.copy'
$idsPath = Join-Path $ev 'oracle_single_turn_token_ids.txt'
$csvPath = Join-Path $ev 'oracle_single_turn_token_ids.csv'
$receipt = Join-Path $ev 'independent_reference_receipt.json'
$exe = 'F:\rawrxd\build_ide\bin-msvc\reap-reference-receipt.exe'
$log = New-Object 'System.Collections.Generic.List[string]'
function L([string]$s) { [void]$log.Add($s); Write-Output $s }

L('=== extract_and_seal ' + (Get-Date -Format o))

# Copy even if source is locked for exclusive write (share-read may work via .NET).
try {
  [IO.File]::Copy($err, $copy, $true)
  L('COPY_OK')
} catch {
  L('COPY_FAIL=' + $_.Exception.Message)
  # Fallback: cmd copy
  cmd /c "copy /y `"$err`" `"$copy`"" | Out-Null
  L('CMD_COPY_EXIT=' + $LASTEXITCODE)
}

$ids = New-Object 'System.Collections.Generic.List[string]'
if (Test-Path -LiteralPath $copy) {
  foreach ($line in [IO.File]::ReadLines($copy)) {
    if ($line -match 'slot decode token, id=(\d+)') {
      [void]$ids.Add($Matches[1])
    }
  }
}
$ids | Set-Content -LiteralPath $idsPath -Encoding ASCII
$csv = ($ids -join ',')
[IO.File]::WriteAllText($csvPath, $csv)
L('TOKEN_ID_COUNT=' + $ids.Count)
L('FIRST20=' + (($ids | Select-Object -First 20) -join ','))
L('LAST10=' + (($ids | Select-Object -Last 10) -join ','))

if ($ids.Count -eq 0) {
  L('NO_TOKENS_ABORT')
  $log | Set-Content (Join-Path $ev 'extract_and_seal_log.txt') -Encoding UTF8
  exit 2
}

# prompt_tokens from err: task.n_tokens = 100
$promptTokens = 100
& $exe `
  'llama-cli' `
  'F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf' `
  'F:\rawrxd-native-agent-001\corpus.jsonl' `
  "$promptTokens" `
  $csv `
  'b1-961c376' `
  $receipt
L('RECEIPT_EXIT=' + $LASTEXITCODE)
if (Test-Path -LiteralPath $receipt) {
  L('RECEIPT_BYTES=' + (Get-Item -LiteralPath $receipt).Length)
  L('RECEIPT_HEAD=' + ((Get-Content -LiteralPath $receipt -TotalCount 1).Substring(0, [Math]::Min(240, (Get-Item $receipt).Length))))
}
L('OUT_STILL_HAS_REPL_BANNER=1')
L('GATE2=RECEIPT_FILE_ONLY_NOT_PARITY_PASS')
L('PROMOTE=0')
$log | Set-Content (Join-Path $ev 'extract_and_seal_log.txt') -Encoding UTF8
