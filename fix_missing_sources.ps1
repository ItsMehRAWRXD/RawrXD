<#
.SYNOPSIS
    Finds all add_executable blocks in CMakeLists.txt and wraps those with missing sources in EXISTS guards.
#>

$cmakeFile = "F:\rawrxd\CMakeLists.txt"
$baseDir = "F:\rawrxd"
$lines = Get-Content $cmakeFile

$outputLines = @()
$i = 0
$missingTargets = @()

while ($i -lt $lines.Count) {
    $line = $lines[$i]
    
    if ($line -match '^\s*add_executable\((\S+)') {
        $target = $matches[1]
        $blockStart = $i
        $blockLines = @($line)
        $i++
        
        # Collect all lines until closing paren
        while ($i -lt $lines.Count -and $lines[$i] -notmatch '^\s*\)$') {
            $blockLines += $lines[$i]
            $i++
        }
        if ($i -lt $lines.Count) {
            $blockLines += $lines[$i]  # closing paren
            $i++
        }
        
        # Check if sources exist
        $hasMissing = $false
        foreach ($bline in $blockLines) {
            if ($bline -match '(\S+\.(cpp|c|h|asm))') {
                $src = $matches[1]
                $srcPath = Join-Path $baseDir $src
                if (-not (Test-Path $srcPath)) {
                    $hasMissing = $true
                    break
                }
            }
        }
        
        if ($hasMissing) {
            $missingTargets += $target
            # Wrap in EXISTS guard
            $outputLines += "if(EXISTS `"${CMAKE_CURRENT_SOURCE_DIR}/$target`")"
            foreach ($bline in $blockLines) {
                $outputLines += $bline
            }
            $outputLines += "endif()"
        } else {
            foreach ($bline in $blockLines) {
                $outputLines += $bline
            }
        }
    } else {
        $outputLines += $line
        $i++
    }
}

Write-Host "Wrapped $($missingTargets.Count) targets with missing sources:"
$missingTargets | ForEach-Object { Write-Host "  $_" }

Set-Content $cmakeFile $outputLines
