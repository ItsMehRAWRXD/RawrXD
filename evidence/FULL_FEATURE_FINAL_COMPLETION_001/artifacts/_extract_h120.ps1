$p = 'C:\Users\Garrett\.cursor\projects\g-dev\agent-transcripts\4aa15404-044f-497e-b610-6cef7366d9ff\4aa15404-044f-497e-b610-6cef7366d9ff.jsonl'
$lines = Get-Content -LiteralPath $p
foreach ($line in $lines) {
  if ($line -notmatch 'hidden-blocker categories') { continue }
  $j = $line | ConvertFrom-Json
  $t = $j.message.content[0].text
  $out = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\_parent_h120_extract.txt'
  Set-Content -LiteralPath $out -Value $t -Encoding utf8
  Write-Output ("WROTE_LEN=" + $t.Length)
  break
}
