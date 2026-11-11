$p = 'F:\rawrxd\tmp_remeasure_016_div\stdout.txt'
$lines = Get-Content -LiteralPath $p -Encoding UTF8
# 1-based lines 198-203 are indices 197-202
$out = New-Object System.Collections.Generic.List[string]
for ($i = 197; $i -le 202; $i++) {
  [void]$out.Add($lines[$i])
}
# Tip prints <bos> as literal text; llama-cli with --special or raw may treat BOS separately.
# Build gemma2 formatted prompt WITHOUT the literal "<bos>" marker if tokenizer adds BOS,
# but tip contract says pass full gemma2 formatted string including bos as text that tip used.
# Tip stdout shows literal "<bos><start_of_turn>user" as the formatted prompt string.
$text = ($out -join "`n") + "`n"
# Normalize: tip may have shown <bos> as a printable marker; keep as tip printed.
[IO.File]::WriteAllText('F:\rawrxd\tmp_trusted_ref\tip_prompt_raw.txt', $text, [Text.UTF8Encoding]::new($false))
Write-Output ("BYTES=" + ([IO.File]::ReadAllBytes('F:\rawrxd\tmp_trusted_ref\tip_prompt_raw.txt').Length))
Write-Output '---TEXT---'
Write-Output $text
Write-Output '---HEX---'
$bytes = [IO.File]::ReadAllBytes('F:\rawrxd\tmp_trusted_ref\tip_prompt_raw.txt')
($bytes | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
