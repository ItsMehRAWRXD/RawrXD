#!/usr/bin/env powershell
$content = Get-Content 'CMakeLists.txt'
$inAddExec = $null
$sources = @()
$missing = @()
foreach ($line in $content) {
    if ($line -match '^add_executable\((\S+)\s+(.+)') {
        $inAddExec = $Matches[1]
        $sources = @($Matches[2])
    } elseif ($inAddExec -ne $null) {
        $sources += $line
        if ($line -match '\)') {
            $full = ($sources -join ' ')
            $srcs = $full -replace '^\S+\s+','' -replace '\)','' -split '\s+' | Where-Object { $_ -match '\.(cpp|c|hpp|h|asm)$' }
            $first = $srcs | Select-Object -First 1
            if ($first -and -not (Test-Path $first)) {
                $missing += $first
            }
            $inAddExec = $null
            $sources = @()
        }
    }
}
$unique = $missing | Select-Object -Unique
$unique | Out-File -Encoding utf8 'missing_sources3.txt'
Write-Host "Found $($unique.Count) missing files"
