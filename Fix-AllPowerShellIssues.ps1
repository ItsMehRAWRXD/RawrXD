# Fix-AllPowerShellIssues.ps1
# Fixes common PowerShell script analyzer issues across all PS1 files

param([string]$RootPath = "D:\rawrxd")

$fixedCount = 0
$files = Get-ChildItem -Path $RootPath -Recurse -Filter "*.ps1" -ErrorAction SilentlyContinue

foreach ($file in $files) {
    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $content) { continue }
    
    $original = $content
    $changes = @()
    
    # Fix 1: switch parameters with default $true
    if ($content -match '\[switch\]\s*\$\w+\s*=\s*\$true') {
        $content = $content -replace '(\[switch\]\s*\$\w+)\s*=\s*\$true', '$1'
        $changes += "Removed switch default value"
    }
    
    # Fix 2: Subexpression in hashtable values
    if ($content -match '=\s*if\s*\(') {
        $content = $content -replace '=\s*if\s*\(', '= $(if ('
        $changes += "Fixed subexpression in hashtable"
    }
    
    # Fix 3: Use ${} for variable names with special chars
    if ($content -match '\$\w+:\w+') {
        $content = $content -replace '\$(\w+:\w+)', '${$1}'
        $changes += "Fixed variable name delimiters"
    }
    
    # Fix 4: Replace bare if statements with proper assignment
    if ($content -match 'Write-Log.*if\s*\(') {
        $content = $content -replace '(Write-Log\s+"[^"]*?)\$\((if\s*\([^)]+\)\s*\{[^}]+\}\s*else\s*\{[^}]+\})\)([^"]*")', '$1" + $(if ($2) { "true" } else { "false" }) + "$3'
        $changes += "Fixed inline if in Write-Log"
    }
    
    # Fix 5: Use Script: scope for script-level variables
    if ($content -match '^\$\w+\s*=' -and $content -notmatch '\$Script:') {
        # Don't modify if already has Script: scope
        $lines = $content -split "`n"
        $newLines = @()
        foreach ($line in $lines) {
            if ($line -match '^\s*\$(\w+)\s*=' -and $line -notmatch '\$Script:' -and $line -notmatch '\$env:' -and $line -notmatch '\$global:') {
                $line = $line -replace '^\s*\$(\w+)\s*=', '$Script:$1 ='
            }
            $newLines += $line
        }
        $content = $newLines -join "`n"
        $changes += "Added Script: scope to script variables"
    }
    
    if ($content -ne $original) {
        Set-Content -Path $file.FullName -Value $content -NoNewline
        Write-Host "Fixed $($file.Name): $($changes -join ', ')" -ForegroundColor Green
        $fixedCount++
    }
}

Write-Host "`nFixed $fixedCount files" -ForegroundColor Cyan
