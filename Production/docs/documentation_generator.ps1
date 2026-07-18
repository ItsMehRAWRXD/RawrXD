# RawrXD Documentation Generator
# Phase H Batch 3/5: Automated Documentation Generation
# Generates comprehensive API and user documentation

param(
    [Parameter()]
    [ValidateSet("Generate", "Validate", "Export", "ShowStatus")]
    [string]$Action = "Generate",
    
    [Parameter()]
    [string]$OutputPath = "$PSScriptRoot\..\..\docs\generated",
    
    [Parameter()]
    [string]$SourcePath = "$PSScriptRoot\..\..",
    
    [Parameter()]
    [ValidateSet("Markdown", "HTML", "JSON")]
    [string]$Format = "Markdown",
    
    [Parameter()]
    [switch]$IncludeAPI,
    
    [Parameter()]
    [switch]$IncludeUserGuide,
    
    [Parameter()]
    [switch]$IncludeArchitecture
)

# Documentation templates
$Templates = @{
    API = @"
# API Documentation

Generated: {{Timestamp}}

## Overview

This document describes the RawrXD API endpoints and their usage.

## Endpoints

{{Endpoints}}

## Authentication

{{Authentication}}

## Error Handling

{{ErrorHandling}}
"@

    UserGuide = @"
# RawrXD User Guide

Generated: {{Timestamp}}
Version: {{Version}}

## Table of Contents

{{TOC}}

## Getting Started

{{GettingStarted}}

## Configuration

{{Configuration}}

## Usage Examples

{{Examples}}

## Troubleshooting

{{Troubleshooting}}
"@

    Architecture = @"
# RawrXD Architecture Documentation

Generated: {{Timestamp}}

## System Overview

{{Overview}}

## Component Diagram

{{ComponentDiagram}}

## Data Flow

{{DataFlow}}

## Security Architecture

{{SecurityArchitecture}}

## Deployment Architecture

{{DeploymentArchitecture}}
"@
}

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

function Write-DocLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $(
        switch ($Level) {
            "ERROR" { "Red" }
            "WARN"  { "Yellow" }
            "GENERATE" { "Green" }
            default { "White" }
        }
    )
}

function Get-SourceFiles {
    param([string]$Path, [string[]]$Extensions)
    
    $files = @()
    foreach ($ext in $Extensions) {
        $files += Get-ChildItem -Path $Path -Recurse -Filter "*$ext" -ErrorAction SilentlyContinue
    }
    return $files
}

function Extract-Documentation {
    param([System.IO.FileInfo]$File)
    
    $content = Get-Content $File.FullName -Raw
    $docs = @{
        File = $File.Name
        Path = $File.FullName
        Description = ""
        Functions = @()
        Parameters = @()
        Examples = @()
    }
    
    # Extract file description (first comment block)
    if ($content -match '(?s)#\s*(.+?)(?=\n[^#]|\Z)') {
        $docs.Description = $matches[1].Trim()
    }
    
    # Extract functions (PowerShell)
    if ($File.Extension -eq '.ps1') {
        $functionMatches = [regex]::Matches($content, 'function\s+(\w+)\s*\{')
        foreach ($match in $functionMatches) {
            $funcName = $match.Groups[1].Value
            
            # Look for function documentation
            $funcPattern = "(?s)#\s*$funcName\s*.*?function\s+$funcName"
            if ($content -match $funcPattern) {
                $funcDoc = $matches[0] -replace "function\s+$funcName", ""
                $docs.Functions += @{
                    Name = $funcName
                    Documentation = $funcDoc.Trim()
                }
            }
            else {
                $docs.Functions += @{
                    Name = $funcName
                    Documentation = "No documentation available"
                }
            }
        }
    }
    
    return $docs
}

function Generate-APIDocumentation {
    $endpoints = @()
    
    # Scan for API endpoints in governance dashboard
    $dashboardPath = Join-Path $SourcePath "governance\dashboard\dashboard_server.ps1"
    if (Test-Path $dashboardPath) {
        $content = Get-Content $dashboardPath -Raw
        
        # Extract route definitions
        $routeMatches = [regex]::Matches($content, '"(GET|POST|PUT|DELETE)\s+(/[^"]+)"')
        foreach ($match in $routeMatches) {
            $endpoints += @{
                Method = $match.Groups[1].Value
                Path = $match.Groups[2].Value
                Description = "Dashboard API endpoint"
            }
        }
    }
    
    # Scan for REST API endpoints
    $apiFiles = Get-SourceFiles -Path $SourcePath -Extensions @('.ps1')
    foreach ($file in $apiFiles) {
        $content = Get-Content $file.FullName -Raw
        
        # Look for HTTP listener patterns
        if ($content -match 'HttpListener') {
            $endpoints += @{
                Method = "GET"
                Path = "/api/$($file.BaseName)"
                Description = "Auto-generated from $($file.Name)"
                Source = $file.FullName
            }
        }
    }
    
    return $endpoints
}

function Generate-UserGuide {
    $guide = @{
        TOC = @()
        GettingStarted = @()
        Configuration = @()
        Examples = @()
        Troubleshooting = @()
    }
    
    # Extract getting started info from README files
    $readmeFiles = Get-ChildItem -Path $SourcePath -Filter "README*" -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $readmeFiles) {
        $content = Get-Content $file.FullName -Raw
        $guide.GettingStarted += $content
    }
    
    # Extract configuration info
    $configFiles = Get-ChildItem -Path $SourcePath -Filter "*.json" -Recurse -ErrorAction SilentlyContinue | 
                   Where-Object { $_.Name -like "*config*" }
    foreach ($file in $configFiles) {
        $guide.Configuration += @{
            File = $file.Name
            Path = $file.FullName
            Description = "Configuration file"
        }
    }
    
    # Extract examples from script files
    $scriptFiles = Get-SourceFiles -Path $SourcePath -Extensions @('.ps1')
    foreach ($file in $scriptFiles) {
        $content = Get-Content $file.FullName -Raw
        
        # Look for usage examples in comments
        $exampleMatches = [regex]::Matches($content, '(?s)#\s*Example[s]?:\s*(.+?)(?=\n[^#]|\Z)')
        foreach ($match in $exampleMatches) {
            $guide.Examples += @{
                Source = $file.Name
                Example = $match.Groups[1].Value.Trim()
            }
        }
    }
    
    return $guide
}

function Generate-ArchitectureDoc {
    $arch = @{
        Overview = "RawrXD is a sovereign AI inference runtime with autonomous operations capabilities."
        Components = @()
        DataFlow = @()
    }
    
    # Scan directory structure
    $directories = Get-ChildItem -Path $SourcePath -Directory -ErrorAction SilentlyContinue | 
                   Where-Object { $_.Name -notin @('.git', 'node_modules', 'bin', 'obj') }
    
    foreach ($dir in $directories) {
        $component = @{
            Name = $dir.Name
            Path = $dir.FullName
            Description = ""
            Files = (Get-ChildItem $dir.FullName -Recurse -File).Count
        }
        
        # Look for description in any README
        $readme = Join-Path $dir.FullName "README.md"
        if (Test-Path $readme) {
            $content = Get-Content $readme -Raw
            if ($content -match '#\s*(.+?)(?=\n)') {
                $component.Description = $matches[1].Trim()
            }
        }
        
        $arch.Components += $component
    }
    
    return $arch
}

function Export-ToMarkdown {
    param([hashtable]$Documentation)
    
    $output = @()
    
    # API Documentation
    if ($Documentation.API -and $Documentation.API.Count -gt 0) {
        $output += "# API Documentation`n`n"
        $output += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n`n"
        $output += "## Endpoints`n`n"
        
        foreach ($endpoint in $Documentation.API) {
            $output += "### $($endpoint.Method) $($endpoint.Path)`n`n"
            $output += "$($endpoint.Description)`n`n"
        }
    }
    
    # User Guide
    if ($Documentation.UserGuide) {
        $output += "`n---`n`n# User Guide`n`n"
        
        if ($Documentation.UserGuide.GettingStarted.Count -gt 0) {
            $output += "## Getting Started`n`n"
            foreach ($section in $Documentation.UserGuide.GettingStarted) {
                $output += "$section`n`n"
            }
        }
        
        if ($Documentation.UserGuide.Examples.Count -gt 0) {
            $output += "## Examples`n`n"
            foreach ($example in $Documentation.UserGuide.Examples) {
                $output += "### From $($example.Source)`n`n"
                $output += "````powershell`n$($example.Example)`n```` `n`n"
            }
        }
    }
    
    # Architecture
    if ($Documentation.Architecture) {
        $output += "`n---`n`n# Architecture`n`n"
        $output += "$($Documentation.Architecture.Overview)`n`n"
        
        if ($Documentation.Architecture.Components.Count -gt 0) {
            $output += "## Components`n`n"
            foreach ($comp in $Documentation.Architecture.Components) {
                $output += "### $($comp.Name)`n`n"
                if ($comp.Description) {
                    $output += "$($comp.Description)`n`n"
                }
                $output += "- Files: $($comp.Files)`n"
                $output += "- Path: ``$($comp.Path)`` `n`n"
            }
        }
    }
    
    return $output -join ""
}

function Export-ToHTML {
    param([hashtable]$Documentation)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Documentation</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        h2 { color: #666; border-bottom: 1px solid #ddd; }
        h3 { color: #999; }
        code { background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
    </style>
</head>
<body>
    <h1>RawrXD Documentation</h1>
    <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
"@
    
    # Add API documentation
    if ($Documentation.API) {
        $html += "<h2>API Reference</h2>"
        foreach ($endpoint in $Documentation.API) {
            $html += "<h3>$($endpoint.Method) $($endpoint.Path)</h3>"
            $html += "<p>$($endpoint.Description)</p>"
        }
    }
    
    # Add User Guide
    if ($Documentation.UserGuide) {
        $html += "<h2>User Guide</h2>"
        if ($Documentation.UserGuide.Examples.Count -gt 0) {
            $html += "<h3>Examples</h3>"
            foreach ($example in $Documentation.UserGuide.Examples) {
                $html += "<h4>From $($example.Source)</h4>"
                $html += "<pre><code>$([System.Web.HttpUtility]::HtmlEncode($example.Example))</code></pre>"
            }
        }
    }
    
    $html += "</body></html>"
    
    return $html
}

function Export-ToJSON {
    param([hashtable]$Documentation)
    
    return $Documentation | ConvertTo-Json -Depth 10
}

function Show-DocumentationStatus {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║         RawrXD Documentation Generator Status                   ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    # Count source files
    $psFiles = (Get-ChildItem -Path $SourcePath -Recurse -Filter "*.ps1" -ErrorAction SilentlyContinue).Count
    $jsonFiles = (Get-ChildItem -Path $SourcePath -Recurse -Filter "*.json" -ErrorAction SilentlyContinue).Count
    $mdFiles = (Get-ChildItem -Path $SourcePath -Recurse -Filter "*.md" -ErrorAction SilentlyContinue).Count
    
    Write-Host "║ Source Files:" -ForegroundColor Cyan
    Write-Host "║   PowerShell: $psFiles" -ForegroundColor Gray
    Write-Host "║   JSON: $jsonFiles" -ForegroundColor Gray
    Write-Host "║   Markdown: $mdFiles" -ForegroundColor Gray
    
    # Check generated docs
    if (Test-Path $OutputPath) {
        $generatedFiles = (Get-ChildItem -Path $OutputPath -Recurse -File).Count
        Write-Host "║ Generated Documents: $generatedFiles" -ForegroundColor Green
    }
    else {
        Write-Host "║ Generated Documents: 0 (not yet generated)" -ForegroundColor Yellow
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Generate" {
        Write-DocLog "Generating documentation..." "GENERATE"
        
        $documentation = @{}
        
        if ($IncludeAPI -or (-not $IncludeUserGuide -and -not $IncludeArchitecture)) {
            Write-DocLog "Generating API documentation..." "GENERATE"
            $documentation.API = Generate-APIDocumentation
        }
        
        if ($IncludeUserGuide -or (-not $IncludeAPI -and -not $IncludeArchitecture)) {
            Write-DocLog "Generating user guide..." "GENERATE"
            $documentation.UserGuide = Generate-UserGuide
        }
        
        if ($IncludeArchitecture -or (-not $IncludeAPI -and -not $IncludeUserGuide)) {
            Write-DocLog "Generating architecture documentation..." "GENERATE"
            $documentation.Architecture = Generate-ArchitectureDoc
        }
        
        # Export based on format
        $outputFile = Join-Path $OutputPath "documentation"
        
        switch ($Format) {
            "Markdown" {
                $outputFile += ".md"
                $content = Export-ToMarkdown -Documentation $documentation
                $content | Out-File $outputFile -Encoding UTF8
            }
            "HTML" {
                $outputFile += ".html"
                $content = Export-ToHTML -Documentation $documentation
                $content | Out-File $outputFile -Encoding UTF8
            }
            "JSON" {
                $outputFile += ".json"
                $content = Export-ToJSON -Documentation $documentation
                $content | Out-File $outputFile -Encoding UTF8
            }
        }
        
        Write-DocLog "Documentation generated: $outputFile" "GENERATE"
    }
    
    "Validate" {
        Write-DocLog "Validating documentation..." "INFO"
        
        $issues = @()
        
        # Check for missing README files
        $directories = Get-ChildItem -Path $SourcePath -Directory -ErrorAction SilentlyContinue
        foreach ($dir in $directories) {
            $readme = Join-Path $dir.FullName "README.md"
            if (-not (Test-Path $readme)) {
                $issues += "Missing README.md in $($dir.Name)"
            }
        }
        
        # Check for undocumented functions
        $psFiles = Get-SourceFiles -Path $SourcePath -Extensions @('.ps1')
        foreach ($file in $psFiles) {
            $docs = Extract-Documentation -File $file
            foreach ($func in $docs.Functions) {
                if ($func.Documentation -eq "No documentation available") {
                    $issues += "Undocumented function: $($func.Name) in $($file.Name)"
                }
            }
        }
        
        if ($issues.Count -eq 0) {
            Write-DocLog "Documentation validation passed" "INFO"
        }
        else {
            Write-DocLog "Documentation issues found:" "WARN"
            foreach ($issue in $issues) {
                Write-Host "  - $issue" -ForegroundColor Yellow
            }
        }
    }
    
    "Export" {
        Write-DocLog "Exporting documentation..." "GENERATE"
        # Implementation would export to various formats
    }
    
    "ShowStatus" {
        Show-DocumentationStatus
    }
}
