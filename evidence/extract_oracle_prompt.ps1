$ErrorActionPreference = 'Stop'
$line = Get-Content -LiteralPath 'F:\rawrxd-native-agent-001\corpus.jsonl' -TotalCount 1
$obj = $line | ConvertFrom-Json
Set-Content -LiteralPath 'F:\rawrxd-native-agent-001\evidence\oracle_prompt_001.txt' -Value $obj.text -NoNewline
Write-Output ("PROMPT_ID=" + $obj.id)
Write-Output ("PROMPT_CHARS=" + $obj.text.Length)
