# Fix ALL markdown files with git merge conflicts in d:\rawrxd
$ErrorActionPreference = 'Continue'

function Resolve-ConflictFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    
    try {
        $content = Get-Content -Raw -Path $Path -ErrorAction SilentlyContinue
        if ($content -and ($content -match '<<<<<<< HEAD')) {
            Write-Host "Fixing: $Path"
            # Keep HEAD version (between <<<<<<< HEAD and =======)
            $cleaned = $content -replace '(?s)<<<<<<< HEAD\r?\n(.*?)=======\r?\n.*?>>>>>>> [^\r\n]*\r?\n?', '$1'
            # Handle case where there's no newline after >>>>>>> branch
            $cleaned = $cleaned -replace '(?s)<<<<<<< HEAD\r?\n(.*?)=======\r?\n.*?>>>>>>> [^\r\n]*$', '$1'
            Set-Content -Path $Path -Value $cleaned -NoNewline
            return $true
        }
    } catch {
        Write-Host "  Error: $_" -ForegroundColor Red
    }
    return $false
}

Write-Host "Scanning for markdown files with conflicts..." -ForegroundColor Cyan

# Get all .md files in rawrxd (excluding archive and git directories)
$mdFiles = Get-ChildItem -Path 'd:\rawrxd' -Recurse -Filter '*.md' -ErrorAction SilentlyContinue | 
    Where-Object { 
        $_.FullName -notlike '*\.archive\*' -and 
        $_.FullName -notlike '*\.git\*' -and
        $_.FullName -notlike '*\.worktrees\*'
    }

$fixed = 0
$scanned = 0

foreach ($file in $mdFiles) {
    $scanned++
    if (Resolve-ConflictFile -Path $file.FullName) {
        $fixed++
    }
    if ($scanned % 50 -eq 0) {
        Write-Host "Scanned $scanned files..." -ForegroundColor Gray
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Scan complete!" -ForegroundColor Green
Write-Host "Total markdown files scanned: $scanned" -ForegroundColor White
Write-Host "Files with conflicts fixed: $fixed" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
