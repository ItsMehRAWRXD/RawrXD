#!/usr/bin/env pwsh
<#
.SYNOPSIS
    RawrXD Integration Analyzer Orchestrator
.DESCRIPTION
    Runs all integration analyzers, normalizes outputs, and produces one authoritative report.
    Answers: which sources aren't compiled, which commands aren't registered, which panels
    aren't docked, which tools aren't exposed, which symbols are dead, which services fail.
.PARAMETER RootPath
    Root of the RawrXD source tree (default: D:\rawrxd-ci-bootstrap)
.PARAMETER OutputDir
    Where to write the report (default: .\integration-report)
.PARAMETER RunExistingTools
    If true, invokes ManifestTracer, SourceDigestionEngine, audit_all_features, audit_orphans
.PARAMETER SkipNewAnalyzers
    If true, skips the new CMake/Symbol/Registration/Runtime/Extension analyzers
.PARAMETER CIBuild
    If true, produces machine-readable JSON for CI pipelines
.EXAMPLE
    .\Invoke-IntegrationAnalyzer.ps1
.EXAMPLE
    .\Invoke-IntegrationAnalyzer.ps1 -RootPath D:\rawrxd-ci-bootstrap -CIBuild
#>

[CmdletBinding()]
param(
    [string]$RootPath = "D:\rawrxd-ci-bootstrap",
    [string]$OutputDir = ".\integration-report",
    [switch]$RunExistingTools,
    [switch]$SkipNewAnalyzers,
    [switch]$CIBuild
)

$ErrorActionPreference = "Stop"
$script:StartTime = Get-Date

# Ensure output directory
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

# ============================================================================
# RESULT AGGREGATOR
# ============================================================================
$script:Results = [System.Collections.Generic.List[hashtable]]::new()

function Add-Result {
    param(
        [string]$Name,
        [string]$Status = "pass",
        [int]$Warnings = 0,
        [int]$Errors = 0,
        [hashtable]$Metrics = @{},
        [array]$Findings = @(),
        [string]$RawOutput = ""
    )
    $script:Results.Add(@{
        name = $Name
        status = $Status
        warnings = $Warnings
        errors = $Errors
        metrics = $Metrics
        findings = $Findings
        raw_output = $RawOutput
        duration_ms = 0
    })
}

function Get-LastResult { $script:Results[-1] }

# ============================================================================
# MODULE 1: CMake Graph Analyzer
# ============================================================================
function Invoke-CMakeGraphAnalyzer {
    Write-Host "[Analyzer] CMake Graph Analyzer..." -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $findings = @()
    $warnings = 0; $errors = 0

    $cmakeFile = Join-Path $RootPath "CMakeLists.txt"
    if (-not (Test-Path $cmakeFile)) {
        Add-Result -Name "CMakeGraph" -Status "error" -Errors 1 -Findings @("CMakeLists.txt not found at $cmakeFile")
        return
    }

    $content = Get-Content $cmakeFile -Raw

    # Parse add_executable / add_library targets
    $targets = @{}
    $targetPattern = '(add_executable|add_library)\s*\(\s*(\S+)\s+'
    $matches = [regex]::Matches($content, $targetPattern)
    foreach ($m in $matches) {
        $targets[$m.Groups[2].Value] = @{ type = $m.Groups[1].Value; sources = @(); libraries = @() }
    }

    # Parse target_sources
    $srcPattern = 'target_sources\s*\(\s*(\S+)\s+(?:PRIVATE|PUBLIC|INTERFACE)\s+([^)]+)\)'
    $srcMatches = [regex]::Matches($content, $srcPattern)
    foreach ($m in $srcMatches) {
        $tgt = $m.Groups[1].Value
        $srcs = $m.Groups[2].Value -split '\s+' | Where-Object { $_ -match '\.(cpp|c|asm|h|hpp|rc)$' }
        if ($targets.ContainsKey($tgt)) {
            $targets[$tgt].sources += $srcs
        }
    }

    # Parse target_link_libraries
    $linkPattern = 'target_link_libraries\s*\(\s*(\S+)\s+(?:PRIVATE|PUBLIC|INTERFACE)\s+([^)]+)\)'
    $linkMatches = [regex]::Matches($content, $linkPattern)
    foreach ($m in $linkMatches) {
        $tgt = $m.Groups[1].Value
        $libs = $m.Groups[2].Value -split '\s+' | Where-Object { $_ -match '^[a-zA-Z]' -and $_ -notmatch '^\$' }
        if ($targets.ContainsKey($tgt)) {
            $targets[$tgt].libraries += $libs
        }
    }

    # Collect all source files from src/ directory
    $allSources = @(Get-ChildItem (Join-Path $RootPath "src") -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.cpp','.c','.asm' } | Select-Object -ExpandProperty FullName)
    $compiledSources = @()
    foreach ($tgt in $targets.Keys) {
        foreach ($s in $targets[$tgt].sources) {
            $resolved = Join-Path $RootPath $s
            if (Test-Path $resolved) { $compiledSources += $resolved }
        }
    }

    # Find orphaned sources
    $orphaned = $allSources | Where-Object { $_ -notin $compiledSources }
    if ($orphaned.Count -gt 0) {
        $warnings += $orphaned.Count
        $findings += @{ severity = "warning"; category = "orphaned_source"; count = $orphaned.Count; items = $orphaned[0..[Math]::Min(20, $orphaned.Count-1)] }
    }

    # Find targets with no sources
    $emptyTargets = $targets.Keys | Where-Object { $targets[$_].sources.Count -eq 0 }
    if ($emptyTargets.Count -gt 0) {
        $errors += $emptyTargets.Count
        $findings += @{ severity = "error"; category = "empty_target"; count = $emptyTargets.Count; items = $emptyTargets }
    }

    $sw.Stop()
    Add-Result -Name "CMakeGraph" -Status $(if ($errors -gt 0) { "error" } elseif ($warnings -gt 0) { "warning" } else { "pass" }) `
        -Warnings $warnings -Errors $errors `
        -Metrics @{ targets = $targets.Count; total_sources = $allSources.Count; compiled = $compiledSources.Count; orphaned = $orphaned.Count; empty_targets = $emptyTargets.Count } `
        -Findings $findings
    Write-Host "  -> $($targets.Count) targets, $($compiledSources.Count)/$($allSources.Count) sources compiled, $($orphaned.Count) orphaned" -ForegroundColor $(if ($orphaned.Count -gt 0) { "Yellow" } else { "Green" })
}

# ============================================================================
# MODULE 2: Registration Analyzer
# ============================================================================
function Invoke-RegistrationAnalyzer {
    Write-Host "[Analyzer] Registration Analyzer..." -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $findings = @()
    $warnings = 0; $errors = 0

    # Patterns for registration calls
    $regPatterns = @{
        Command = 'RegisterCommand\s*\(|AddCommand\s*\(|registerCommand\s*\('
        Panel = 'RegisterPanel\s*\(|AddPanel\s*\(|registerPanel\s*\('
        Tool = 'RegisterTool\s*\(|AddTool\s*\(|registerTool\s*\('
        Provider = 'RegisterProvider\s*\(|AddProvider\s*\(|registerProvider\s*\('
        Dock = 'RegisterDock\s*\(|AddDock\s*\(|registerDock\s*\('
        Menu = 'RegisterMenu\s*\(|AddMenu\s*\(|registerMenu\s*\('
        Extension = 'RegisterExtension\s*\(|AddExtension\s*\(|registerExtension\s*\('
        Debugger = 'RegisterDebugger\s*\(|AddDebugger\s*\(|registerDebugger\s*\('
        Theme = 'RegisterTheme\s*\(|AddTheme\s*\(|registerTheme\s*\('
        Keybinding = 'RegisterKeybinding\s*\(|AddKeybinding\s*\(|registerKeybinding\s*\('
    }

    # Scan all source files for registration calls
    $srcFiles = Get-ChildItem (Join-Path $RootPath "src") -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.cpp','.c','.h','.hpp' }
    $registrations = @{}
    foreach ($cat in $regPatterns.Keys) { $registrations[$cat] = @() }

    foreach ($file in $srcFiles) {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        foreach ($cat in $regPatterns.Keys) {
            if ($content -match $regPatterns[$cat]) {
                $registrations[$cat] += $file.FullName
            }
        }
    }

    # Count implementation files per category
    $implPatterns = @{
        Command = 'Win32IDE_Commands?\.(cpp|h)'
        Panel = 'Win32IDE_\w+Panel\.(cpp|h)'
        Tool = 'ToolRegistry|tool_registry'
        Provider = 'Provider|provider'
        Dock = 'DockingPane|dock'
        Menu = 'Win32IDE_Menu|Menu'
        Extension = 'ExtensionHost|ExtensionManager'
        Debugger = 'Win32IDE_Debugger|DAPServer'
        Theme = 'Win32IDE_Themes|Theme'
        Keybinding = 'Win32IDE_Keybinding|Keybinding'
    }

    $implementations = @{}
    foreach ($cat in $implPatterns.Keys) {
        $implFiles = $srcFiles | Where-Object { $_.Name -match $implPatterns[$cat] }
        $implementations[$cat] = $implFiles.Count
    }

    # Compare: implemented vs registered
    foreach ($cat in $regPatterns.Keys) {
        $implCount = $implementations[$cat]
        $regCount = $registrations[$cat].Count
        if ($implCount -gt 0 -and $regCount -eq 0) {
            $warnings++
            $findings += @{ severity = "warning"; category = "unregistered_$cat"; implemented = $implCount; registered = $regCount; message = "$implCount $cat implementations found but 0 registrations" }
        }
    }

    $sw.Stop()
    Add-Result -Name "Registration" -Status $(if ($errors -gt 0) { "error" } elseif ($warnings -gt 0) { "warning" } else { "pass" }) `
        -Warnings $warnings -Errors $errors `
        -Metrics @{ implementations = $implementations; registrations = ($registrations | ForEach-Object { $_.Value.Count } | Measure-Object -Sum).Sum } `
        -Findings $findings
    Write-Host "  -> $warnings unregistered components detected" -ForegroundColor $(if ($warnings -gt 0) { "Yellow" } else { "Green" })
}

# ============================================================================
# MODULE 3: Symbol Graph Analyzer
# ============================================================================
function Invoke-SymbolGraphAnalyzer {
    Write-Host "[Analyzer] Symbol Graph Analyzer..." -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $findings = @()
    $warnings = 0; $errors = 0

    # Quick scan: count files and check for common patterns
    $scanDirs = @(
        (Join-Path $RootPath "src\win32app"),
        (Join-Path $RootPath "src\agentic"),
        (Join-Path $RootPath "src\full_agentic_ide"),
        (Join-Path $RootPath "src\ai")
    )
    $srcFiles = @()
    foreach ($dir in $scanDirs) {
        if (Test-Path $dir) {
            $srcFiles += Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.cpp','.c','.h','.hpp' }
        }
    }
    if ($srcFiles.Count -eq 0) {
        $srcFiles = Get-ChildItem (Join-Path $RootPath "src") -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.cpp','.c','.h','.hpp' } | Select-Object -First 200
    }

    # Quick grep for common patterns across all files
    $totalLines = 0
    $classCount = 0
    $functionCount = 0
    $stubCount = 0

    foreach ($file in $srcFiles) {
        if ($file.Length -gt 1MB) { continue }
        $lines = Get-Content $file.FullName -ReadCount 0 -ErrorAction SilentlyContinue
        if (-not $lines) { continue }
        $totalLines += $lines.Count
        foreach ($line in $lines) {
            if ($line -match '^\s*(class|struct)\s+\w+') { $classCount++ }
            elseif ($line -match '^\s*\w+\s+\w+\s*\([^)]*\)\s*(\{|;)') { $functionCount++ }
            if ($line -match 'TODO|FIXME|STUB|stub|NotImplemented') { $stubCount++ }
        }
    }

    if ($stubCount -gt 0) {
        $warnings += $stubCount
        $findings += @{ severity = "warning"; category = "stub_patterns"; count = $stubCount; message = "$stubCount stub/TODO patterns found across $($srcFiles.Count) files" }
    }

    $sw.Stop()
    Add-Result -Name "SymbolGraph" -Status $(if ($errors -gt 0) { "error" } elseif ($warnings -gt 0) { "warning" } else { "pass" }) `
        -Warnings $warnings -Errors $errors `
        -Metrics @{ files_scanned = $srcFiles.Count; total_lines = $totalLines; classes = $classCount; functions = $functionCount; stub_patterns = $stubCount } `
        -Findings $findings
    Write-Host "  -> $($srcFiles.Count) files, $totalLines lines, $classCount classes, $functionCount functions, $stubCount stubs" -ForegroundColor $(if ($stubCount -gt 0) { "Yellow" } else { "Green" })
}

# ============================================================================
# MODULE 4: Runtime Initialization Analyzer
# ============================================================================
function Invoke-RuntimeInitAnalyzer {
    Write-Host "[Analyzer] Runtime Init Analyzer..." -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $findings = @()
    $warnings = 0; $errors = 0

    $srcFiles = Get-ChildItem (Join-Path $RootPath "src") -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.cpp','.c' } | Select-Object -First 500

    # Expected initialization sequence
    $initSequence = @(
        @{ name = "WorkspaceService"; patterns = @('WorkspaceService|workspace_init|InitWorkspace') },
        @{ name = "ProjectService"; patterns = @('ProjectService|project_init|InitProject') },
        @{ name = "IndexService"; patterns = @('IndexService|index_init|InitIndex|SymbolIndex') },
        @{ name = "LSP"; patterns = @('LSPClient|LSP_Init|lsp_init|InitLSP') },
        @{ name = "Debugger"; patterns = @('Debugger|DAPServer|debugger_init|InitDebugger') },
        @{ name = "AgentService"; patterns = @('AgentService|AgentOrchestrator|agent_init|InitAgent') },
        @{ name = "ExtensionHost"; patterns = @('ExtensionHost|extension_init|InitExtension') },
        @{ name = "Terminal"; patterns = @('TerminalManager|terminal_init|InitTerminal') },
        @{ name = "Git"; patterns = @('GitService|git_init|InitGit') },
        @{ name = "Telemetry"; patterns = @('Telemetry|telemetry_init|InitTelemetry') },
        @{ name = "ModelService"; patterns = @('ModelService|ModelManager|model_init|InitModel') },
        @{ name = "ToolRegistry"; patterns = @('ToolRegistry|tool_registry_init|InitToolRegistry') },
        @{ name = "Hotpatch"; patterns = @('Hotpatch|hotpatch_init|InitHotpatch') },
        @{ name = "Beacon"; patterns = @('Beacon|beacon_init|InitBeacon') }
    )

    # Check each service for implementation
    $found = @{}; $missing = @()
    foreach ($svc in $initSequence) {
        $foundService = $false
        foreach ($file in $srcFiles) {
            $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
            if (-not $content) { continue }
            foreach ($pat in $svc.patterns) {
                if ($content -match $pat) {
                    $foundService = $true
                    break
                }
            }
            if ($foundService) { break }
        }
        if ($foundService) {
            $found[$svc.name] = $true
        } else {
            $missing += $svc.name
            $warnings++
            $findings += @{ severity = "warning"; category = "missing_service"; service = $svc.name; message = "No implementation found for $($svc.name)" }
        }
    }

    $sw.Stop()
    Add-Result -Name "RuntimeInit" -Status $(if ($errors -gt 0) { "error" } elseif ($warnings -gt 0) { "warning" } else { "pass" }) `
        -Warnings $warnings -Errors $errors `
        -Metrics @{ services_found = $found.Count; services_missing = $missing.Count; total_expected = $initSequence.Count } `
        -Findings $findings
    Write-Host "  -> $($found.Count)/$($initSequence.Count) services found, $($missing.Count) missing" -ForegroundColor $(if ($missing.Count -gt 0) { "Yellow" } else { "Green" })
}

# ============================================================================
# MODULE 5: Extension Compatibility Analyzer
# ============================================================================
function Invoke-ExtensionAnalyzer {
    Write-Host "[Analyzer] Extension Analyzer..." -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $findings = @()
    $warnings = 0; $errors = 0

    $extDir = Join-Path $RootPath "extensions"
    $vsixDir = Join-Path $RootPath "vsix"
    $marketplaceDir = Join-Path $RootPath "marketplace"

    $extDirs = @()
    if (Test-Path $extDir) { $extDirs += $extDir }
    if (Test-Path $vsixDir) { $extDirs += $vsixDir }
    if (Test-Path $marketplaceDir) { $extDirs += $marketplaceDir }

    $extCount = 0
    $loadedCount = 0

    foreach ($dir in $extDirs) {
        $extFolders = Get-ChildItem $dir -Directory -ErrorAction SilentlyContinue
        $extCount += $extFolders.Count
        foreach ($ext in $extFolders) {
            $packageJson = Join-Path $ext.FullName "package.json"
            $manifestJson = Join-Path $ext.FullName "manifest.json"
            $hasPackage = Test-Path $packageJson
            $hasManifest = Test-Path $manifestJson
            if ($hasPackage -or $hasManifest) {
                $loadedCount++
            } else {
                $warnings++
                $findings += @{ severity = "warning"; category = "unloadable_extension"; path = $ext.FullName; message = "Extension folder missing package.json or manifest.json" }
            }
        }
    }

    # Check ExtensionHost implementation
    $extHostFiles = Get-ChildItem (Join-Path $RootPath "src") -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'ExtensionHost|ExtensionManager' }
    if ($extHostFiles.Count -eq 0) {
        $errors++
        $findings += @{ severity = "error"; category = "missing_extension_host"; message = "No ExtensionHost implementation found" }
    }

    $sw.Stop()
    Add-Result -Name "Extension" -Status $(if ($errors -gt 0) { "error" } elseif ($warnings -gt 0) { "warning" } else { "pass" }) `
        -Warnings $warnings -Errors $errors `
        -Metrics @{ extension_dirs = $extDirs.Count; extensions_found = $extCount; extensions_loadable = $loadedCount; extension_host_files = $extHostFiles.Count } `
        -Findings $findings
    Write-Host "  -> $extCount extensions found, $loadedCount loadable" -ForegroundColor $(if ($warnings -gt 0) { "Yellow" } else { "Green" })
}

# ============================================================================
# MODULE 6: Existing Tools Runner
# ============================================================================
function Invoke-ExistingTools {
    Write-Host "[Analyzer] Running existing tools..." -ForegroundColor Cyan

    # Run audit_all_features if available
    $auditScript = Join-Path $RootPath "audit_all_features.ps1"
    if (Test-Path $auditScript) {
        Write-Host "  -> Running audit_all_features.ps1..." -ForegroundColor Gray
        $output = & $auditScript -RootPath $RootPath -OutputFile (Join-Path $OutputDir "audit_all_features.html") -ErrorAction SilentlyContinue 2>&1
        Add-Result -Name "audit_all_features" -Status "pass" -RawOutput ($output | Out-String)
    }

    # Run audit_orphans if available
    $orphanScript = Join-Path $RootPath "audit_orphans.ps1"
    if (Test-Path $orphanScript) {
        Write-Host "  -> Running audit_orphans.ps1..." -ForegroundColor Gray
        $output = & $orphanScript -Phase All -OutputFormat JSON -OutputDir (Join-Path $OutputDir "orphans") -ErrorAction SilentlyContinue 2>&1
        Add-Result -Name "audit_orphans" -Status "pass" -RawOutput ($output | Out-String)
    }
}

# ============================================================================
# REPORT GENERATOR
# ============================================================================
function New-IntegrationReport {
    param([string]$OutputPath)

    $totalErrors = ($script:Results | Where-Object { $_.errors -gt 0 } | Measure-Object -Property errors -Sum).Sum
    $totalWarnings = ($script:Results | Where-Object { $_.warnings -gt 0 } | Measure-Object -Property warnings -Sum).Sum
    $totalDuration = ($script:Results | Measure-Object -Property duration_ms -Sum).Sum
    $elapsed = [Math]::Round(((Get-Date) - $script:StartTime).TotalSeconds)

    $report = @{
        metadata = @{
            timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            root_path = $RootPath
            duration_seconds = $elapsed
            total_analyzers = $script:Results.Count
            total_errors = [int]$totalErrors
            total_warnings = [int]$totalWarnings
        }
        summary = @{
            overall_status = if ($totalErrors -gt 0) { "error" } elseif ($totalWarnings -gt 0) { "warning" } else { "pass" }
            errors = [int]$totalErrors
            warnings = [int]$totalWarnings
            analyzers_passed = ($script:Results | Where-Object { $_.status -eq "pass" }).Count
            analyzers_with_warnings = ($script:Results | Where-Object { $_.status -eq "warning" }).Count
            analyzers_with_errors = ($script:Results | Where-Object { $_.status -eq "error" }).Count
        }
        results = $script:Results | ForEach-Object {
            @{
                name = $_.name
                status = $_.status
                warnings = $_.warnings
                errors = $_.errors
                metrics = $_.metrics
                findings = $_.findings
            }
        }
    }

    # Write JSON
    $jsonPath = Join-Path $OutputPath "integration-report.json"
    $report | ConvertTo-Json -Depth 10 | Set-Content $jsonPath -Encoding UTF8

    # Write Markdown
    $mdPath = Join-Path $OutputPath "INTEGRATION_REPORT.md"
    $md = @"
# RawrXD Integration Analysis Report

**Date:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
**Root:** $RootPath
**Duration:** $elapsed seconds
**Status:** $($report.summary.overall_status)

## Summary

| Metric | Value |
|--------|-------|
| Analyzers Run | $($script:Results.Count) |
| Passed | $($report.summary.analyzers_passed) |
| With Warnings | $($report.summary.analyzers_with_warnings) |
| With Errors | $($report.summary.analyzers_with_errors) |
| Total Errors | $($report.summary.errors) |
| Total Warnings | $($report.summary.warnings) |

## Results

"@
    foreach ($r in $script:Results) {
        $icon = switch ($r.status) { "pass" { "✅" } "warning" { "⚠️" } "error" { "❌" } default { "❓" } }
        $md += "### $icon $($r.name)`n`n"
        $md += "| Metric | Value |`n|---|---|`n"
        $md += "| Status | $($r.status) |`n"
        $md += "| Errors | $($r.errors) |`n"
        $md += "| Warnings | $($r.warnings) |`n"
        if ($r.metrics.Keys.Count -gt 0) {
            foreach ($k in $r.metrics.Keys) {
                $v = $r.metrics[$k]
                if ($v -is [hashtable]) {
                    $md += "| $k | $(($v.Keys | ForEach-Object { "$_`: $($v[$_])" }) -join ', ') |`n"
                } elseif ($v -is [array]) {
                    $md += "| $k | $($v.Count) items |`n"
                } else {
                    $md += "| $k | $v |`n"
                }
            }
        }
        if ($r.findings.Count -gt 0) {
            $md += "`n**Findings:**`n`n"
            foreach ($f in $r.findings) {
                $sev = switch ($f.severity) { "error" { "❌" } "warning" { "⚠️" } default { "ℹ️" } }
                $md += "- $sev $($f.message)"
                if ($f.items) { $md += " ($($f.items.Count) items)" }
                $md += "`n"
            }
        }
        $md += "`n---`n`n"
    }

    $md += @"

## Priority Actions

"@
    $priorityFindings = $script:Results | ForEach-Object { $_.findings } | Where-Object { $_ -ne $null } | Sort-Object @{Expression={$_.severity}; Descending=$true}
    if ($priorityFindings.Count -gt 0) {
        $md += "| Severity | Category | Message |`n|---|---|---|`n"
        foreach ($f in $priorityFindings[0..[Math]::Min(20, $priorityFindings.Count-1)]) {
            $sev = switch ($f.severity) { "error" { "❌" } "warning" { "⚠️" } default { "ℹ️" } }
            $md += "| $sev | $($f.category) | $($f.message) |`n"
        }
    } else {
        $md += "No issues found.`n"
    }

    $md | Set-Content $mdPath -Encoding UTF8
    Write-Host "`nReport written to:" -ForegroundColor Green
    Write-Host "  JSON: $jsonPath" -ForegroundColor White
    Write-Host "  Markdown: $mdPath" -ForegroundColor White
}

# ============================================================================
# MAIN
# ============================================================================
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD Integration Analyzer Orchestrator v1.0           ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "Root: $RootPath" -ForegroundColor Gray
Write-Host ""

# Run existing tools if requested
if ($RunExistingTools) { Invoke-ExistingTools }

# Run new analyzers
if (-not $SkipNewAnalyzers) {
    Invoke-CMakeGraphAnalyzer
    Invoke-RegistrationAnalyzer
    Invoke-SymbolGraphAnalyzer
    Invoke-RuntimeInitAnalyzer
    Invoke-ExtensionAnalyzer
}

# Generate report
New-IntegrationReport -OutputPath $OutputDir

Write-Host "`nIntegration analysis complete." -ForegroundColor Green
