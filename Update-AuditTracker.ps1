# RawrXD IDE Audit Tracker Update Script
# Usage: .\Update-AuditTracker.ps1 [command] [args...]
# Example: .\Update-AuditTracker.ps1 complete "CodeLens"

param(
    [Parameter(Position=0)]
    [string]$Action = "status",
    
    [Parameter(Position=1)]
    [string]$Component = "",
    
    [Parameter(Position=2)]
    [string]$NewStatus = ""
)

$TrackerJson = "d:\rawrxd\AUDIT_TRACKER.json"
$TrackerMd = "d:\rawrxd\AUDIT_TRACKER.md"

function Show-Status {
    $json = Get-Content $TrackerJson | ConvertFrom-Json
    $rate = [math]::Round($json.summary.completionRate * 100, 1)
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD IDE Production Audit Status" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Overall Completion: $rate%" -ForegroundColor Green
    Write-Host ""
    Write-Host "Category Breakdown:" -ForegroundColor Yellow
    foreach ($cat in $json.categories) {
        Write-Host "  $($cat.name): $($cat.complete)/$($cat.total) complete"
    }
    Write-Host ""
    Write-Host "Priority 1 Skeletons:" -ForegroundColor Red
    foreach ($cat in $json.categories) {
        foreach ($comp in $cat.components) {
            if ($comp.status -eq "skeleton" -and $comp.priority -eq "P1") {
                Write-Host "  - $($comp.name) ($($comp.file))" -ForegroundColor Red
            }
        }
    }
}

function Update-Component {
    param([string]$Name, [string]$Status)
    
    if ([string]::IsNullOrEmpty($Name)) {
        Write-Error "Component name required"
        return
    }
    if ([string]::IsNullOrEmpty($Status)) {
        Write-Error "New status required"
        return
    }
    
    $json = Get-Content $TrackerJson | ConvertFrom-Json
    $found = $false
    
    foreach ($cat in $json.categories) {
        foreach ($comp in $cat.components) {
            if ($comp.name -eq $Name) {
                $oldStatus = $comp.status
                $comp.status = $Status
                $found = $true
                
                # Update counts
                if ($oldStatus -eq "complete") { $cat.complete-- }
                elseif ($oldStatus -eq "partial") { $cat.partial-- }
                elseif ($oldStatus -eq "skeleton") { $cat.skeleton-- }
                
                if ($Status -eq "complete") { $cat.complete++ }
                elseif ($Status -eq "partial") { $cat.partial++ }
                elseif ($Status -eq "skeleton") { $cat.skeleton++ }
                
                Write-Host "Updated: $Name -> $Status" -ForegroundColor Green
                break
            }
        }
        if ($found) { break }
    }
    
    if (-not $found) {
        Write-Error "Component not found: $Name"
        return
    }
    
    # Recalculate summary
    $json.summary.complete = ($json.categories | Measure-Object -Property complete -Sum).Sum
    $json.summary.partial = ($json.categories | Measure-Object -Property partial -Sum).Sum
    $json.summary.skeleton = ($json.categories | Measure-Object -Property skeleton -Sum).Sum
    $json.summary.completionRate = $json.summary.complete / $json.summary.totalComponents
    
    $json | ConvertTo-Json -Depth 10 | Set-Content $TrackerJson
    Write-Host "Tracker saved. New completion rate: $([math]::Round($json.summary.completionRate * 100, 1))%" -ForegroundColor Cyan
}

function Generate-Report {
    $json = Get-Content $TrackerJson | ConvertFrom-Json
    $md = @"
# RawrXD Win32IDE Production Audit Tracker
**Auto-generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

## Summary

| Metric | Value |
|--------|-------|
| Total Components | $($json.summary.totalComponents) |
| Complete | $($json.summary.complete) |
| Partial | $($json.summary.partial) |
| Skeleton | $($json.summary.skeleton) |
| Completion Rate | $([math]::Round($json.summary.completionRate * 100, 1))% |

## Categories

"@
    
    foreach ($cat in $json.categories) {
        $md += "### $($cat.name) ($($cat.complete)/$($cat.total))`n`n"
        $md += "| Component | Status | Priority | Notes |`n"
        $md += "|-----------|--------|----------|-------|`n"
        foreach ($comp in $cat.components) {
            $icon = switch ($comp.status) {
                "complete" { "✅" }
                "partial" { "⚠️" }
                "skeleton" { "❌" }
                default { "❓" }
            }
            $md += "| $($comp.name) | $icon $($comp.status) | $($comp.priority) | $($comp.notes) |`n"
        }
        $md += "`n"
    }
    
    $md += "## MASM Kernels`n`n"
    $md += "| Name | File | Size | Features |`n"
    $md += "|------|------|------|----------|`n"
    foreach ($k in $json.masmKernels) {
        $md += "| $($k.name) | $($k.file) | $($k.size) | $($k.features) |`n"
    }
    
    $md += "`n## Roadmap`n`n"
    foreach ($phase in $json.roadmap.PSObject.Properties) {
        $p = $phase.Value
        $md += "### $($p.name) (Target: $($p.targetDate))`n`n"
        foreach ($item in $p.items) {
            $check = $(if ($item.status -eq "complete") { "x" } else { " " }
            $md += "- [$check] $($item.task)`n"
        }
        $md += "`n"
    }
    
    $md | Set-Content $TrackerMd
    Write-Host "Report generated: $TrackerMd" -ForegroundColor Green
}

function List-Stubs {
    $json = Get-Content $TrackerJson | ConvertFrom-Json
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "Stub Files to Remove/Consolidate" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    foreach ($stub in $json.stubFiles) {
        Write-Host "  - $stub" -ForegroundColor Red
    }
}

function List-Elegant {
    $json = Get-Content $TrackerJson | ConvertFrom-Json
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Most Elegant Implementations" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    foreach ($piece in $json.elegantPieces) {
        Write-Host "  $($piece.name) ($($piece.file)) - $($piece.quality)" -ForegroundColor Cyan
    }
}

# Main dispatch
switch ($Action.ToLower()) {
    "status" { Show-Status }
    "update" { Update-Component -Name $Component -Status $NewStatus }
    "complete" { Update-Component -Name $Component -Status "complete" }
    "skeleton" { Update-Component -Name $Component -Status "skeleton" }
    "partial" { Update-Component -Name $Component -Status "partial" }
    "report" { Generate-Report }
    "stubs" { List-Stubs }
    "elegant" { List-Elegant }
    default {
        Write-Host @"
RawrXD IDE Audit Tracker Update Script
======================================

Usage: .\Update-AuditTracker.ps1 [command] [args...]

Commands:
  status              Show current completion status
  update [comp] [st]  Update component status
  complete [comp]     Mark component as complete
  skeleton [comp]     Mark component as skeleton
  partial [comp]      Mark component as partial
  report              Regenerate AUDIT_TRACKER.md
  stubs               List all stub files
  elegant             List elegant implementations

Examples:
  .\Update-AuditTracker.ps1 status
  .\Update-AuditTracker.ps1 complete "CodeLens"
  .\Update-AuditTracker.ps1 update "AnnotationOverlay" partial
  .\Update-AuditTracker.ps1 report
"@ -ForegroundColor Cyan
    }
}
