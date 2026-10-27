$ErrorActionPreference = 'Continue'
$err = 'F:\rawrxd-native-agent-001\evidence\oracle_single_turn.err'
$out = 'F:\rawrxd-native-agent-001\evidence\oracle_single_turn_token_ids.txt'
$meta = 'F:\rawrxd-native-agent-001\evidence\oracle_single_turn_token_extract.txt'
$ids = New-Object 'System.Collections.Generic.List[string]'
foreach ($line in [IO.File]::ReadLines($err)) {
  if ($line -match 'slot decode token, id=(\d+)') {
    [void]$ids.Add($Matches[1])
  }
}
$ids | Set-Content -LiteralPath $out -Encoding ASCII
$lines = @(
  'TOKEN_ID_COUNT=' + $ids.Count
  'FIRST20=' + (($ids | Select-Object -First 20) -join ',')
  'LAST10=' + (($ids | Select-Object -Last 10) -join ',')
  'SOURCE=' + $err
  'NOTE=generated_decode_token_ids_from_verbose_slot_log'
  'OUT_STILL_HAS_REPL_BANNER=1'
  'GATE2=BLOCKED_UNTIL_RECEIPT_TOOL_CONSUMES'
)
$lines | Set-Content -LiteralPath $meta -Encoding UTF8
$lines
Get-ChildItem -LiteralPath 'F:\rawrxd\build_ide\bin-msvc' -Filter '*receipt*' -ErrorAction SilentlyContinue |
  ForEach-Object { 'BIN=' + $_.FullName }
Get-ChildItem -LiteralPath 'F:\rawrxd\build_ide' -Recurse -Filter 'reap-reference-receipt.exe' -ErrorAction SilentlyContinue |
  Select-Object -First 5 |
  ForEach-Object { 'FOUND=' + $_.FullName }
