# Resolve git merge conflicts in documentation files by accepting HEAD version
$ErrorActionPreference = 'Continue'

function Resolve-ConflictFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    
    try {
        $content = Get-Content -Raw -Path $Path -ErrorAction SilentlyContinue
        if ($content -and ($content -match '<<<<<<< HEAD')) {
            Write-Host "Resolving: $Path"
            # Keep HEAD version (between <<<<<<< HEAD and =======)
            $cleaned = $content -replace '(?s)<<<<<<< HEAD\r?\n(.*?)=======\r?\n.*?>>>>>>> [^\r\n]*\r?\n?', '$1'
            # Handle case where there's no newline after >>>>>>> branch
            $cleaned = $cleaned -replace '(?s)<<<<<<< HEAD\r?\n(.*?)=======\r?\n.*?>>>>>>> [^\r\n]*$', '$1'
            Set-Content -Path $Path -Value $cleaned -NoNewline
            Write-Host "  -> Fixed" -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "  -> Error: $_" -ForegroundColor Red
    }
    return $false
}

# List of documentation files with known conflicts
$docFiles = @(
    'WEEK4_MASTER_INDEX.md',
    'WEEK4_FINAL_HANDOFF.md', 
    'WEEK4_DELIVERABLE_GUIDE.md',
    'WEEK2_MEMORY_MANAGEMENT_PLAN.md',
    'WEEK1_STATUS_REPORT.md',
    'WEEK1_QUICK_REFERENCE.md',
    'WEEK1_PHASE2_INTEGRATION.md',
    'WEEK1_MASTER_INDEX.md',
    'WEEK1_FINAL_HANDOFF.md',
    'WEEK1_DELIVERABLE_GUIDE.md',
    'WEEK1_DELIVERABLE_COMPLETE.md',
    'VISUAL_PROJECT_SUMMARY.md',
    'WEEK5_FINAL_INTEGRATION_GUIDE.md',
    'WEEK4_STATUS_REPORT.md',
    'WEEK4_QUICK_REFERENCE.md',
    '47_CRITICAL_ISSUES_INTEGRATION_SUMMARY.md',
    'AGENTIC_IDE_BUILD_SUCCESS.md',
    'AGENTIC_FRAMEWORK_IMPLEMENTATION_COMPLETE.md'
)

$fixed = 0
foreach ($file in $docFiles) {
    $fullPath = Join-Path 'd:\rawrxd' $file
    if (Resolve-ConflictFile -Path $fullPath) {
        $fixed++
    }
}

Write-Host "`nFixed $fixed documentation files." -ForegroundColor Cyan

# Also scan for any other .md files with conflicts
Write-Host "`nScanning for additional markdown files with conflicts..." -ForegroundColor Gray
$mdFiles = Get-ChildItem -Path 'd:\rawrxd' -Recurse -Filter '*.md' -ErrorAction SilentlyContinue | 
    Where-Object { $_.FullName -notlike '*\.archive\*' -and $_.FullName -notlike '*\.git\*' }

$additionalFixed = 0
foreach ($file in $mdFiles) {
    if (Resolve-ConflictFile -Path $file.FullName) {
        $additionalFixed++
    }
}

Write-Host "`nTotal files fixed: $($fixed + $additionalFixed)" -ForegroundColor Green
