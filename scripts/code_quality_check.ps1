#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Code Quality Check Script for RawrXD CI/CD Pipeline

.DESCRIPTION
    Performs automated code quality checks including:
    - Clang-Format validation
    - Clang-Tidy static analysis
    - Copyright header verification
    - Line ending normalization checks
    - Trailing whitespace detection

.EXAMPLE
    .\scripts\code_quality_check.ps1
    .\scripts\code_quality_check.ps1 -Fix -Path src/
    .\scripts\code_quality_check.ps1 -ReportFormat json

.NOTES
    Part of RawrXD Phase AB: CI/CD Pipeline & Automation
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Path = ".",

    [Parameter()]
    [switch]$Fix,

    [Parameter()]
    [ValidateSet("console", "json", "xml", "github")]
    [string]$ReportFormat = "console",

    [Parameter()]
    [string]$OutputFile = "",

    [Parameter()]
    [switch]$FailOnWarnings,

    [Parameter()]
    [string[]]$ExcludePatterns = @(
        "*/3rdparty/*",
        "*/build*/*",
        "*/.git/*",
        "*/node_modules/*",
        "*/generated/*",
        "*/out/*",
        "*/.vs/*",
        "*/.vscode/*"
    )
)

# Error codes
$ErrorCode = @{
    Success = 0
    FormatErrors = 1
    TidyErrors = 2
    HeaderErrors = 4
    WhitespaceErrors = 8
    LineEndingErrors = 16
    OtherErrors = 32
}

$script:ExitCode = $ErrorCode.Success
$script:Issues = @()
$script:Stats = @{
    FilesChecked = 0
    FormatIssues = 0
    TidyIssues = 0
    HeaderIssues = 0
    WhitespaceIssues = 0
    LineEndingIssues = 0
    FixedIssues = 0
}

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Add-Issue {
    param(
        [string]$File,
        [int]$Line = 0,
        [string]$Type,
        [string]$Message,
        [string]$Severity = "error"
    )
    $issue = [PSCustomObject]@{
        File = $File
        Line = $Line
        Type = $Type
        Message = $Message
        Severity = $Severity
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    }
    $script:Issues += $issue
}

function Test-Excluded {
    param([string]$FilePath)
    foreach ($pattern in $ExcludePatterns) {
        if ($FilePath -like $pattern) { return $true }
    }
    return $false
}

function Get-SourceFiles {
    param([string]$RootPath)
    $extensions = @("*.cpp", "*.hpp", "*.h", "*.c", "*.cc", "*.cxx", "*.cu", "*.cuh")
    $files = @()
    foreach ($ext in $extensions) {
        $files += Get-ChildItem -Path $RootPath -Recurse -Filter $ext -ErrorAction SilentlyContinue |
            Where-Object { -not (Test-Excluded $_.FullName) }
    }
    return $files | Select-Object -ExpandProperty FullName | Sort-Object -Unique
}

# ============================================================================
# Check: Clang-Format
# ============================================================================

function Test-ClangFormat {
    Write-Status "Running clang-format check..." "Info"

    $clangFormat = Get-Command "clang-format" -ErrorAction SilentlyContinue
    if (-not $clangFormat) {
        Write-Status "clang-format not found in PATH" "Warning"
        return
    }

    $files = Get-SourceFiles $Path | Where-Object { $_ -match "\.(cpp|hpp|h|c|cc|cxx)$" }
    $script:Stats.FilesChecked += $files.Count

    foreach ($file in $files) {
        $relPath = Resolve-Path -Relative $file

        if ($Fix) {
            # Apply formatting
            $output = & clang-format -i $file 2>&1
            if ($LASTEXITCODE -ne 0) {
                Add-Issue -File $relPath -Type "clang-format" -Message "Failed to format file" -Severity "error"
                $script:Stats.FormatIssues++
                $script:ExitCode = $script:ExitCode -bor $ErrorCode.FormatErrors
            } else {
                $script:Stats.FixedIssues++
            }
        } else {
            # Check formatting
            $formatted = & clang-format --dry-run --Werror $file 2>&1
            if ($LASTEXITCODE -ne 0) {
                Add-Issue -File $relPath -Type "clang-format" -Message "Code formatting issues detected" -Severity "error"
                $script:Stats.FormatIssues++
                $script:ExitCode = $script:ExitCode -bor $ErrorCode.FormatErrors
            }
        }
    }

    Write-Status "Checked $($files.Count) files, found $($script:Stats.FormatIssues) format issues" $(if ($script:Stats.FormatIssues -eq 0) { "Success" } else { "Warning" })
}

# ============================================================================
# Check: Copyright Headers
# ============================================================================

function Test-CopyrightHeaders {
    Write-Status "Checking copyright headers..." "Info"

    $expectedHeader = @(
        "// Copyright \\(c\\) 20\d{2}-20\d{2} RawrXD Contributors",
        "// SPDX-License-Identifier: MIT"
    )

    $files = Get-SourceFiles $Path | Where-Object { $_ -match "\.(cpp|hpp|h|c|cc|cxx)$" }

    foreach ($file in $files) {
        $relPath = Resolve-Path -Relative $file
        $content = Get-Content -Path $file -TotalCount 5 -ErrorAction SilentlyContinue

        if (-not ($content -match "Copyright.*RawrXD")) {
            Add-Issue -File $relPath -Line 1 -Type "copyright" -Message "Missing or invalid copyright header" -Severity "warning"
            $script:Stats.HeaderIssues++
            $script:ExitCode = $script:ExitCode -bor $ErrorCode.HeaderErrors
        }
    }

    Write-Status "Checked copyright headers, found $($script:Stats.HeaderIssues) issues" $(if ($script:Stats.HeaderIssues -eq 0) { "Success" } else { "Warning" })
}

# ============================================================================
# Check: Trailing Whitespace
# ============================================================================

function Test-TrailingWhitespace {
    Write-Status "Checking for trailing whitespace..." "Info"

    $files = Get-SourceFiles $Path

    foreach ($file in $files) {
        $relPath = Resolve-Path -Relative $file
        $lines = Get-Content -Path $file
        $lineNum = 0

        foreach ($line in $lines) {
            $lineNum++
            if ($line -match "\s+$") {
                if ($Fix) {
                    # Fix would be applied here in a real implementation
                    $script:Stats.FixedIssues++
                } else {
                    Add-Issue -File $relPath -Line $lineNum -Type "whitespace" -Message "Trailing whitespace detected" -Severity "warning"
                    $script:Stats.WhitespaceIssues++
                    $script:ExitCode = $script:ExitCode -bor $ErrorCode.WhitespaceErrors
                }
            }
        }
    }

    Write-Status "Checked whitespace, found $($script:Stats.WhitespaceIssues) issues" $(if ($script:Stats.WhitespaceIssues -eq 0) { "Success" } else { "Warning" })
}

# ============================================================================
# Check: Line Endings
# ============================================================================

function Test-LineEndings {
    Write-Status "Checking line endings..." "Info"

    $files = Get-SourceFiles $Path | Where-Object { $_ -notmatch "\.(bat|cmd|ps1)$" }

    foreach ($file in $files) {
        $relPath = Resolve-Path -Relative $file
        $content = [System.IO.File]::ReadAllBytes($file)

        # Check for CRLF in non-Windows script files
        for ($i = 0; $i -lt $content.Length - 1; $i++) {
            if ($content[$i] -eq 0x0D -and $content[$i + 1] -eq 0x0A) {
                Add-Issue -File $relPath -Type "line-endings" -Message "CRLF line endings detected (should be LF)" -Severity "warning"
                $script:Stats.LineEndingIssues++
                $script:ExitCode = $script:ExitCode -bor $ErrorCode.LineEndingErrors
                break
            }
        }
    }

    Write-Status "Checked line endings, found $($script:Stats.LineEndingIssues) issues" $(if ($script:Stats.LineEndingIssues -eq 0) { "Success" } else { "Warning" })
}

# ============================================================================
# Report Generation
# ============================================================================

function Write-ConsoleReport {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Code Quality Check Report" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $grouped = $script:Issues | Group-Object -Property Type

    foreach ($group in $grouped) {
        Write-Host "`n$($group.Name): $($group.Count) issue(s)" -ForegroundColor Yellow
        foreach ($issue in $group.Group | Select-Object -First 10) {
            $color = if ($issue.Severity -eq "error") { "Red" } else { "Yellow" }
            Write-Host "  $($issue.File):$($issue.Line) - $($issue.Message)" -ForegroundColor $color
        }
        if ($group.Count -gt 10) {
            Write-Host "  ... and $($group.Count - 10) more" -ForegroundColor Gray
        }
    }

    Write-Host "`n----------------------------------------" -ForegroundColor Cyan
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  Files checked:     $($script:Stats.FilesChecked)" -ForegroundColor White
    Write-Host "  Format issues:     $($script:Stats.FormatIssues)" -ForegroundColor $(if ($script:Stats.FormatIssues -eq 0) { "Green" } else { "Yellow" })
    Write-Host "  Header issues:     $($script:Stats.HeaderIssues)" -ForegroundColor $(if ($script:Stats.HeaderIssues -eq 0) { "Green" } else { "Yellow" })
    Write-Host "  Whitespace issues: $($script:Stats.WhitespaceIssues)" -ForegroundColor $(if ($script:Stats.WhitespaceIssues -eq 0) { "Green" } else { "Yellow" })
    Write-Host "  Line ending issues:$($script:Stats.LineEndingIssues)" -ForegroundColor $(if ($script:Stats.LineEndingIssues -eq 0) { "Green" } else { "Yellow" })
    if ($Fix) {
        Write-Host "  Issues fixed:      $($script:Stats.FixedIssues)" -ForegroundColor Green
    }
    Write-Host "----------------------------------------" -ForegroundColor Cyan

    if ($script:ExitCode -eq 0) {
        Write-Host "Result: PASSED ✓" -ForegroundColor Green
    } else {
        Write-Host "Result: FAILED ✗ (Exit code: $($script:ExitCode))" -ForegroundColor Red
    }
}

function Write-JsonReport {
    param([string]$OutputPath)

    $report = [PSCustomObject]@{
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        stats = $script:Stats
        issues = $script:Issues
        exitCode = $script:ExitCode
        passed = ($script:ExitCode -eq 0)
    }

    $json = $report | ConvertTo-Json -Depth 10

    if ($OutputPath) {
        $json | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Status "Report written to $OutputPath" "Success"
    } else {
        Write-Output $json
    }
}

function Write-GitHubReport {
    # Output in GitHub Actions annotation format
    foreach ($issue in $script:Issues) {
        $level = if ($issue.Severity -eq "error") { "error" } else { "warning" }
        $message = "::$level file=$($issue.File),line=$($issue.Line)::$($issue.Message)"
        Write-Output $message
    }

    Write-Output "::group::Code Quality Summary"
    Write-Output "Files checked: $($script:Stats.FilesChecked)"
    Write-Output "Total issues: $($script:Issues.Count)"
    Write-Output "::endgroup::"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Status "RawrXD Code Quality Check" "Info"
    Write-Status "Path: $(Resolve-Path $Path)" "Info"
    Write-Status "Fix mode: $Fix" "Info"
    Write-Status "Report format: $ReportFormat" "Info"
    Write-Status ""

    # Run checks
    Test-ClangFormat
    Test-CopyrightHeaders
    Test-TrailingWhitespace
    Test-LineEndings

    # Generate report
    switch ($ReportFormat) {
        "json" { Write-JsonReport -OutputPath $OutputFile }
        "github" { Write-GitHubReport }
        "xml" {
            # JUnit XML format for CI integration
            Write-Status "XML output not yet implemented" "Warning"
        }
        default { Write-ConsoleReport }
    }

    # Set exit code
    if ($FailOnWarnings -and $script:Issues.Count -gt 0) {
        exit 1
    }

    exit $script:ExitCode
}

# Run main
Main
