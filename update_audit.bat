@echo off
REM RawrXD IDE Audit Tracker Auto-Update Script
REM Usage: update_audit.bat [status] [component]
REM Example: update_audit.bat complete "AnnotationOverlay"

setlocal enabledelayedexpansion

set "TRACKER_JSON=d:\rawrxd\AUDIT_TRACKER.json"
set "TRACKER_MD=d:\rawrxd\AUDIT_TRACKER.md"
set "ACTION=%~1"
set "COMPONENT=%~2"
set "NEW_STATUS=%~3"

if "%ACTION%"=="" goto :usage
if "%ACTION%"=="help" goto :usage
if "%ACTION%"=="/?" goto :usage

if "%ACTION%"=="status" goto :show_status
if "%ACTION%"=="update" goto :update_component
if "%ACTION%"=="complete" goto :mark_complete
if "%ACTION%"=="skeleton" goto :mark_skeleton
if "%ACTION%"=="partial" goto :mark_partial
if "%ACTION%"=="report" goto :generate_report
if "%ACTION%"=="stubs" goto :list_stubs
if "%ACTION%"=="elegant" goto :list_elegant

goto :usage

:show_status
    echo ========================================
    echo RawrXD IDE Production Audit Status
    echo ========================================
    echo.
    for /f "tokens=*" %%a in ('powershell -Command "(Get-Content '%TRACKER_JSON%' | ConvertFrom-Json).summary.completionRate * 100"') do set "RATE=%%a"
    echo Overall Completion: %RATE%%%%
    echo.
    echo Category Breakdown:
    powershell -Command "(Get-Content '%TRACKER_JSON%' | ConvertFrom-Json).categories | ForEach-Object { Write-Host ('  {0}: {1}/{2} complete' -f $_.name, $_.complete, $_.total) }"
    echo.
    echo Priority 1 Skeletons:
    powershell -Command "(Get-Content '%TRACKER_JSON%' | ConvertFrom-Json).categories | ForEach-Object { $_.components | Where-Object { $_.status -eq 'skeleton' -and $_.priority -eq 'P1' } | ForEach-Object { Write-Host ('  - {0} ({1})' -f $_.name, $_.file) } }"
    goto :eof

:update_component
    if "%COMPONENT%"=="" echo ERROR: Component name required & goto :eof
    if "%NEW_STATUS%"=="" echo ERROR: New status required & goto :eof
    
    powershell -Command "
        $json = Get-Content '%TRACKER_JSON%' | ConvertFrom-Json
        $found = $false
        foreach ($cat in $json.categories) {
            foreach ($comp in $cat.components) {
                if ($comp.name -eq '%COMPONENT%') {
                    $oldStatus = $comp.status
                    $comp.status = '%NEW_STATUS%'
                    $found = $true
                    
                    # Update counts
                    if ($oldStatus -eq 'complete') { $cat.complete-- }
                    elseif ($oldStatus -eq 'partial') { $cat.partial-- }
                    elseif ($oldStatus -eq 'skeleton') { $cat.skeleton-- }
                    
                    if ('%NEW_STATUS%' -eq 'complete') { $cat.complete++ }
                    elseif ('%NEW_STATUS%' -eq 'partial') { $cat.partial++ }
                    elseif ('%NEW_STATUS%' -eq 'skeleton') { $cat.skeleton++ }
                    
                    Write-Host ('Updated: %COMPONENT% -> %NEW_STATUS%')
                    break
                }
            }
            if ($found) { break }
        }
        if (-not $found) { Write-Host 'ERROR: Component not found' }
        $json.summary.complete = ($json.categories | Measure-Object -Property complete -Sum).Sum
        $json.summary.partial = ($json.categories | Measure-Object -Property partial -Sum).Sum
        $json.summary.skeleton = ($json.categories | Measure-Object -Property skeleton -Sum).Sum
        $json.summary.completionRate = $json.summary.complete / $json.summary.totalComponents
        $json | ConvertTo-Json -Depth 10 | Set-Content '%TRACKER_JSON%'
    "
    goto :eof

:mark_complete
    set "NEW_STATUS=complete"
    call :update_component "%COMPONENT%"
    goto :eof

:mark_skeleton
    set "NEW_STATUS=skeleton"
    call :update_component "%COMPONENT%"
    goto :eof

:mark_partial
    set "NEW_STATUS=partial"
    call :update_component "%COMPONENT%"
    goto :eof

:generate_report
    echo Generating markdown report...
    powershell -Command "
        $json = Get-Content '%TRACKER_JSON%' | ConvertFrom-Json
        $md = '# RawrXD Win32IDE Production Audit Tracker'+\"`n\"+'**Auto-generated:** '+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+\"`n`n\"
        $md += '## Summary'+\"`n`n\"+'| Metric | Value |'+\"`n\"+'|--------|-------|'+\"`n\"
        $md += '| Total Components | ' + $json.summary.totalComponents + ' |'+\"`n\"+
               '| Complete | ' + $json.summary.complete + ' |'+\"`n\"+
               '| Partial | ' + $json.summary.partial + ' |'+\"`n\"+
               '| Skeleton | ' + $json.summary.skeleton + ' |'+\"`n\"+
               '| Completion Rate | ' + [math]::Round($json.summary.completionRate * 100, 1) + '% |'+\"`n`n\"
        
        $md += '## Categories'+\"`n`n\"
        foreach ($cat in $json.categories) {
            $md += '### ' + $cat.name + ' (' + $cat.complete + '/' + $cat.total + ')' + \"`n`n\"
            $md += '| Component | Status | Priority | Notes |'+\"`n\"+'|-----------|--------|----------|-------|'+\"`n\"
            foreach ($comp in $cat.components) {
                $statusIcon = if ($comp.status -eq 'complete') { '✅' } elseif ($comp.status -eq 'partial') { '⚠️' } else { '❌' }
                $md += '| ' + $comp.name + ' | ' + $statusIcon + ' ' + $comp.status + ' | ' + $comp.priority + ' | ' + $comp.notes + ' |'+\"`n\"
            }
            $md += \"`n\"
        }
        
        $md += '## MASM Kernels'+\"`n`n\"
        $md += '| Name | File | Size | Features |'+\"`n\"+'|------|------|------|----------|'+\"`n\"
        foreach ($k in $json.masmKernels) {
            $md += '| ' + $k.name + ' | ' + $k.file + ' | ' + $k.size + ' | ' + $k.features + ' |'+\"`n\"
        }
        
        $md += \"`n## Roadmap`n`n\"
        foreach ($phase in $json.roadmap.PSObject.Properties) {
            $p = $phase.Value
            $md += '### ' + $p.name + ' (Target: ' + $p.targetDate + ')' + \"`n`n\"
            foreach ($item in $p.items) {
                $md += '- [' + (if ($item.status -eq 'complete') { 'x' } else { ' ' }) + '] ' + $item.task + \"`n\"
            }
            $md += \"`n\"
        }
        
        $md | Set-Content '%TRACKER_MD%'
        Write-Host 'Report generated: %TRACKER_MD%'
    "
    goto :eof

:list_stubs
    echo ========================================
    echo Stub Files to Remove/Consolidate
    echo ========================================
    powershell -Command "(Get-Content '%TRACKER_JSON%' | ConvertFrom-Json).stubFiles | ForEach-Object { Write-Host '  - $_' }"
    goto :eof

:list_elegant
    echo ========================================
    echo Most Elegant Implementations
    echo ========================================
    powershell -Command "(Get-Content '%TRACKER_JSON%' | ConvertFrom-Json).elegantPieces | ForEach-Object { Write-Host ('  {0} ({1}) - {2}' -f $_.name, $_.file, $_.quality) }"
    goto :eof

:usage
    echo RawrXD IDE Audit Tracker Update Script
    echo ======================================
    echo.
    echo Usage: update_audit.bat [command] [args...]
    echo.
    echo Commands:
    echo   status              Show current completion status
    echo   update [comp] [st]  Update component status
    echo   complete [comp]     Mark component as complete
    echo   skeleton [comp]     Mark component as skeleton
    echo   partial [comp]      Mark component as partial
    echo   report              Regenerate AUDIT_TRACKER.md
    echo   stubs               List all stub files
    echo   elegant             List elegant implementations
    echo.
    echo Examples:
    echo   update_audit.bat status
    echo   update_audit.bat complete "CodeLens"
    echo   update_audit.bat update "AnnotationOverlay" partial
    echo   update_audit.bat report
    goto :eof
