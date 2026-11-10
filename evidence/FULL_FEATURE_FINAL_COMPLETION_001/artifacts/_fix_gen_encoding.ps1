$ErrorActionPreference = 'Stop'
$p = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\_gen_master_register.ps1'
$bytes = [System.IO.File]::ReadAllBytes($p)
$text = [System.Text.Encoding]::UTF8.GetString($bytes)
# Replace common unicode operators with ASCII
$text = $text.Replace([string][char]0x2192, '->')  # right arrow
$text = $text.Replace([string][char]0x2260, '!=')  # not equal
$text = $text.Replace([string][char]0x2014, '-')   # em dash
$text = $text.Replace([string][char]0x2013, '-')   # en dash
$text = $text.Replace([string][char]0x2026, '...') # ellipsis
# Fix UTF-8 mojibake sequences if present as literal
$text = $text.Replace([char]0xFFFD + '+', '->')
# Drop any remaining replacement chars in string literals by replacing lone U+FFFD
$text = $text.Replace([string][char]0xFFFD, '?')
[System.IO.File]::WriteAllText($p, $text, (New-Object System.Text.UTF8Encoding $false))
# Syntax check
$null = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$errs)
if ($errs -and $errs.Count -gt 0) {
  $errs | Select-Object -First 10 | ForEach-Object { $_.ToString() }
  exit 1
}
Write-Output 'SYNTAX_OK'
