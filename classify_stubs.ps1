# Build stub classification report
$csv = Import-Csv F:\~dev\rawrxd_inventory.csv
$stubs = $csv | Where-Object { [int]$_.Lines -eq 1 -and $_.FirstLine -match '^// \[RAWRXD_BUILD_AUTHORITY_BASELINE_001\] stub' }

Write-Host "Total stubs: $($stubs.Count)"

# Build a hash of basename+ext -> all paths
$pathMap = @{}
foreach ($row in $csv) {
    $key = ([System.IO.Path]::GetFileNameWithoutExtension($row.FullName) + [System.IO.Path]::GetExtension($row.FullName)).ToLower()
    if (-not $pathMap[$key]) { $pathMap[$key] = @() }
    $pathMap[$key] += $row.FullName
}

$report = @()
foreach ($stub in $stubs) {
    $key = ([System.IO.Path]::GetFileNameWithoutExtension($stub.FullName) + [System.IO.Path]::GetExtension($stub.FullName)).ToLower()
    $rel = $stub.FullName -replace '^F:\\~dev\\',''
    $dir = [System.IO.Path]::GetDirectoryName($rel)
    
    $classification = 'UNKNOWN'
    $notes = ''
    
    if ($dir -match '^rawrxd[/\\]certs' -or $dir -match '^rawrxd[/\\]tests') {
        $classification = 'A'
        $notes = 'pure_stub'
    } else {
        $others = $pathMap[$key] | Where-Object { $_ -ne $stub.FullName }
        if ($others) {
            $classification = 'C'
            $realPaths = ($others | ForEach-Object { $_ -replace '^F:\\~dev\\','' }) -join ';'
            $notes = "dual:$realPaths"
        } else {
            $classification = 'UNKNOWN'
            $notes = 'no_counterpart'
        }
    }
    
    $report += [PSCustomObject]@{
        FullName = $stub.FullName
        Classification = $classification
        Notes = $notes
    }
}

# Summary
$report | Group-Object Classification | ForEach-Object { Write-Host "$($_.Name): $($_.Count)" }

# Save report
$report | Export-Csv -Path F:\~dev\stub_classification.csv -NoTypeInformation
Write-Host ""
Write-Host "Report saved to stub_classification.csv"
Write-Host ""
Write-Host "First 10 C (dual) stubs:"
$report | Where-Object { $_.Classification -eq 'C' } | Select-Object -First 10 | ForEach-Object { Write-Host "$($_.FullName) | $($_.Notes)" }
