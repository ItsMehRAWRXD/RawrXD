$ErrorActionPreference = 'Continue'
$ev = 'F:\rawrxd-native-agent-001\evidence'
$err = Join-Path $ev 'k2_oracle_single_turn.err'
$copy = Join-Path $ev 'k2_oracle_single_turn.err.copy'
$idsPath = Join-Path $ev 'k2_oracle_token_ids.txt'
$csvPath = Join-Path $ev 'k2_oracle_token_ids.csv'
$receipt = Join-Path $ev 'independent_reference_receipt.k2.json'
$exe = 'F:\rawrxd\build_ide\bin-msvc\reap-reference-receipt.exe'
$model = 'F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf'
$corpus = 'F:\rawrxd-native-agent-001\corpus.jsonl'
$required = 256
$log = New-Object 'System.Collections.Generic.List[string]'
function L([string]$s) { [void]$log.Add($s); Write-Output $s }

L('=== extract_and_seal_k2 ' + (Get-Date -Format o))
L('PROMOTE=0 TIP_CLIMB=HOLD FABRICATE=0')

try {
  [IO.File]::Copy($err, $copy, $true)
  L('COPY_OK')
} catch {
  L('COPY_FAIL=' + $_.Exception.Message)
  cmd /c "copy /y `"$err`" `"$copy`"" | Out-Null
  L('CMD_COPY_EXIT=' + $LASTEXITCODE)
}

$ids = New-Object 'System.Collections.Generic.List[string]'
$promptTokens = 0
if (Test-Path -LiteralPath $copy) {
  foreach ($line in [IO.File]::ReadLines($copy)) {
    if ($line -match 'slot decode token, id=(\d+)') {
      [void]$ids.Add($Matches[1])
    }
    if ($promptTokens -eq 0 -and $line -match 'task\.n_tokens = (\d+)') {
      $promptTokens = [int]$Matches[1]
    }
  }
}
if ($promptTokens -eq 0) { $promptTokens = 87 }

$ids | Set-Content -LiteralPath $idsPath -Encoding ASCII
[IO.File]::WriteAllText($csvPath, ($ids -join ','))
L('TOKEN_ID_COUNT=' + $ids.Count)
L('PROMPT_TOKENS=' + $promptTokens)
L('FIRST20=' + (($ids | Select-Object -First 20) -join ','))
L('LAST10=' + (($ids | Select-Object -Last 10) -join ','))

if ($ids.Count -lt $required) {
  L('INCOMPLETE_WINDOW count=' + $ids.Count + ' required=' + $required)
  L('RECEIPT_SEAL=NOT_SEALED')
  $log | Set-Content (Join-Path $ev 'extract_and_seal_k2_log.txt') -Encoding UTF8
  exit 3
}

& $exe 'llama-cli' $model $corpus "$promptTokens" ($ids -join ',') 'b1-961c376' $receipt
L('RECEIPT_EXIT=' + $LASTEXITCODE)
if (Test-Path -LiteralPath $receipt) {
  L('RECEIPT_BYTES=' + (Get-Item -LiteralPath $receipt).Length)
  L('RECEIPT_PATH=' + $receipt)
  L('RECEIPT_SEAL=FILE_WRITTEN_PENDING_SCHEMA_VALIDATE')
} else {
  L('RECEIPT_SEAL=NOT_SEALED_MISSING_FILE')
}
L('GATE2=K2_RECEIPT_FILE_ONLY_NOT_PARITY_PASS')
$log | Set-Content (Join-Path $ev 'extract_and_seal_k2_log.txt') -Encoding UTF8
