$ErrorActionPreference = 'Stop'
$line = Get-Content -LiteralPath 'F:\rawrxd-native-agent-001\corpus.jsonl' -TotalCount 1
$obj = $line | ConvertFrom-Json
$out = 'F:\rawrxd-native-agent-001\evidence\first_corpus_prompt.txt'
Set-Content -LiteralPath $out -Value $obj.text -NoNewline
Write-Output ("PROMPT_ID=" + $obj.id)
Write-Output ("PROMPT_CHARS=" + $obj.text.Length)
Write-Output ("PROMPT_FILE=" + $out)
