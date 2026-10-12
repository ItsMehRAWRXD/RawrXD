$Script:path = Resolve-Path 'RawrXD.ps1'
$Script:lines = Get-Content -LiteralPath $path.Path
$Script:balance = 0
for ($i=0; $i -lt $lines.Count; $i++) {
$Script:line = $lines[$i]
$Script:opens = ([regex]::Matches($line, '{')).Count
$Script:closes = ([regex]::Matches($line, '}')).Count
    $balance += $opens - $closes
    if ($balance -lt 0) {
        Write-Output "NEGATIVE balance at line $($i+1): $balance -> $line"
    }
}
Write-Output "FINAL BALANCE: $balance"
if ($balance -ne 0) { exit 1 } else { exit 0 }
