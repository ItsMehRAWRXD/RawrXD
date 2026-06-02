# PROC Definition Audit Script
$lines = Get-Content 'd:\rawrxd\src\agentic\RawrXD_Absolutely_Complete.asm'
$firstEnd = 943
$procPattern = '^\s*(\w+)\s+PROC\s+'
$results = @()

for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match $procPattern) {
        $procName = $matches[1]
        $lineNum = $i + 1
        $status = if ($lineNum -le $firstEnd) { 'ASSEMBLED' } else { 'IGNORED' }
        $results += [PSCustomObject]@{
            Line = $lineNum
            Name = $procName
            Status = $status
        }
    }
}

Write-Host '========================================' -ForegroundColor Cyan
Write-Host 'PROC DEFINITION AUDIT REPORT' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''

$assembled = $results | Where-Object { $_.Status -eq 'ASSEMBLED' }
$ignored = $results | Where-Object { $_.Status -eq 'IGNORED' }

Write-Host "Assembled (first module): $($assembled.Count) PROCs" -ForegroundColor Green
Write-Host "Ignored (after first END): $($ignored.Count) PROCs" -ForegroundColor Yellow
Write-Host ''

if ($assembled.Count -gt 0) {
    Write-Host 'ASSEMBLED PROCs (Line <= 943):' -ForegroundColor Green
    $assembled | Format-Table -AutoSize | Out-String | Write-Host
}

Write-Host ''
Write-Host 'SAMPLE OF IGNORED PROCs (first 30):' -ForegroundColor Yellow
$ignored | Select-Object -First 30 | Format-Table -AutoSize | Out-String | Write-Host

Write-Host ''
Write-Host "Total: $($results.Count) PROC definitions found" -ForegroundColor White

# Save full report to file
$results | Export-Csv 'd:\rawrxd\src\agentic\proc_audit_report.csv' -NoTypeInformation
Write-Host ''
Write-Host 'Full report saved to: d:\rawrxd\src\agentic\proc_audit_report.csv' -ForegroundColor Cyan