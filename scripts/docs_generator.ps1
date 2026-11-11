#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Documentation Generator for RawrXD

.DESCRIPTION
    Automated documentation generation:
    - API documentation from source code
    - Architecture diagrams
    - Changelog aggregation
    - README updates
    - Wiki generation

.EXAMPLE
    .\scripts\docs_generator.ps1
    .\scripts\docs_generator.ps1 -GenerateAPI
    .\scripts\docs_generator.ps1 -Output docs/

.NOTES
    Part of RawrXD Phase AB: CI/CD Pipeline & Automation
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = "docs/generated",

    [Parameter()]
    [switch]$GenerateAPI,

    [Parameter()]
    [switch]$GenerateDiagrams,

    [Parameter()]
    [switch]$UpdateReadme,

    [Parameter()]
    [switch]$GenerateWiki,

    [Parameter()]
    [switch]$All,

    [Parameter()]
    [string]$DoxygenConfig = "Doxyfile",

    [Parameter()]
    [switch]$Serve
)

# ============================================================================
# Configuration
# ============================================================================

$Config = @{
    SourcePaths = @("src", "include", "cmake")
    ExcludePatterns = @("*/3rdparty/*", "*/build*/*", "*/test*/*")
    TemplateDir = "docs/templates"
}

$script:GeneratedFiles = @()
$script:Errors = @()

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n========================================" -ForegroundColor Blue
    Write-Host $Title -ForegroundColor Blue
    Write-Host "========================================" -ForegroundColor Blue
}

function Test-Command {
    param([string]$Command)
    return [bool](Get-Command $Command -ErrorAction SilentlyContinue)
}

function New-Directory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Status "Created directory: $Path" "Success"
    }
}

# ============================================================================
# API Documentation Generation
# ============================================================================

function New-APIDocumentation {
    Write-Section "API Documentation Generation"

    New-Directory "$OutputPath/api"

    # Check for Doxygen
    if (Test-Command "doxygen") {
        Write-Status "Generating API docs with Doxygen..." "Info"

        if (Test-Path $DoxygenConfig) {
            doxygen $DoxygenConfig 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Status "Doxygen documentation generated" "Success"
                $script:GeneratedFiles += "$OutputPath/api/html"
            } else {
                Write-Status "Doxygen generation failed" "Error"
                $script:Errors += "Doxygen failed"
            }
        } else {
            Write-Status "Doxyfile not found, using default configuration" "Warning"
            # Create minimal Doxyfile
            @"
PROJECT_NAME = "RawrXD"
OUTPUT_DIRECTORY = $OutputPath/api
INPUT = src include
RECURSIVE = YES
GENERATE_HTML = YES
GENERATE_LATEX = NO
EXTRACT_ALL = YES
"@ | Out-File -FilePath "Doxyfile.tmp" -Encoding UTF8

            doxygen "Doxyfile.tmp" 2>&1
            Remove-Item "Doxyfile.tmp"
        }
    } else {
        Write-Status "Doxygen not found, using fallback generation" "Warning"
        New-FallbackAPIDocs
    }

    # Generate Markdown API summary
    New-APIMarkdownSummary
}

function New-FallbackAPIDocs {
    Write-Status "Generating fallback API documentation..." "Info"

    $apiDoc = @"
# RawrXD API Reference

Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

## Modules

"@

    # Scan source files for documentation
    $sourceFiles = Get-ChildItem -Path $Config.SourcePaths -Recurse -Filter "*.hpp" -ErrorAction SilentlyContinue |
        Where-Object { $path = $_.FullName; -not ($Config.ExcludePatterns | Where-Object { $path -like $_ }) }

    foreach ($file in $sourceFiles) {
        $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
        $relPath = Resolve-Path -Relative $file.FullName

        # Extract class definitions
        $classes = [regex]::Matches($content, 'class\s+(\w+)')
        foreach ($match in $classes) {
            $className = $match.Groups[1].Value
            $apiDoc += "### $className`n`n"
            $apiDoc += "*Defined in: $relPath*`n`n"
        }

        # Extract function definitions
        $functions = [regex]::Matches($content, '(\w+[\s\*]+)+(\w+)\s*\([^)]*\)\s*;')
        foreach ($match in $functions) {
            $funcName = $match.Groups[2].Value
            $apiDoc += "- ``$funcName()`` - Function`n"
        }
    }

    $apiDoc | Out-File -FilePath "$OutputPath/api/api_reference.md" -Encoding UTF8
    $script:GeneratedFiles += "$OutputPath/api/api_reference.md"
    Write-Status "Fallback API docs generated" "Success"
}

function New-APIMarkdownSummary {
    $summary = @"
# API Documentation Summary

## Quick Links

- [Full API Reference](./api/html/index.html) (HTML)
- [Module Index](./api/modules.md)
- [Class Index](./api/classes.md)

## Core Components

| Component | Description |
|-----------|-------------|
| Core | Initialization and system management |
| Config | Configuration management |
| Inference | Model inference engine |
| Hardware | Hardware abstraction layer |

## Getting Started

See [Getting Started Guide](./getting_started.md) for API usage examples.

---
*Auto-generated by docs_generator.ps1*
"@

    $summary | Out-File -FilePath "$OutputPath/api_summary.md" -Encoding UTF8
    $script:GeneratedFiles += "$OutputPath/api_summary.md"
}

# ============================================================================
# Architecture Diagrams
# ============================================================================

function New-ArchitectureDiagrams {
    Write-Section "Architecture Diagram Generation"

    New-Directory "$OutputPath/diagrams"

    # Generate Mermaid diagrams
    $componentDiagram = @"
# RawrXD Architecture

## Component Diagram

```mermaid
graph TB
    subgraph "Application Layer"
        CLI[CLI Interface]
        GUI[GUI Interface]
        API[REST API]
    end

    subgraph "Core Layer"
        CORE[Core Engine]
        CFG[Config Manager]
        LOG[Logger]
    end

    subgraph "Inference Layer"
        INF[Inference Engine]
        MODEL[Model Loader]
        TOKEN[Tokenizer]
    end

    subgraph "Hardware Layer"
        CPU[CPU Backend]
        GPU[GPU Backend]
        VULKAN[Vulkan]
        CUDA[CUDA]
    end

    CLI --> CORE
    GUI --> CORE
    API --> CORE
    CORE --> INF
    INF --> MODEL
    INF --> TOKEN
    INF --> CPU
    INF --> GPU
    GPU --> VULKAN
    GPU --> CUDA
```

## Data Flow

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Core
    participant Inference
    participant Model

    User->>CLI: Submit prompt
    CLI->>Core: Process request
    Core->>Inference: Run inference
    Inference->>Model: Load weights
    Model-->>Inference: Return tensors
    Inference-->>Core: Return tokens
    Core-->>CLI: Format output
    CLI-->>User: Display result
```

---
*Auto-generated by docs_generator.ps1*
"@

    $componentDiagram | Out-File -FilePath "$OutputPath/diagrams/architecture.md" -Encoding UTF8
    $script:GeneratedFiles += "$OutputPath/diagrams/architecture.md"
    Write-Status "Architecture diagrams generated" "Success"

    # Generate build system diagram
    $buildDiagram = @"
# Build System Architecture

```mermaid
flowchart LR
    subgraph "Configuration"
        CMAKE[CMakeLists.txt]
        PRESET[CMakePresets.json]
    end

    subgraph "Generation"
        CONFIG[cmake configure]
        NINJA[ninja]
    end

    subgraph "Output"
        EXE[RawrXD.exe]
        DLL[*.dll]
        LIB[*.lib]
    end

    CMAKE --> CONFIG
    PRESET --> CONFIG
    CONFIG --> NINJA
    NINJA --> EXE
    NINJA --> DLL
    NINJA --> LIB
```

---
*Auto-generated by docs_generator.ps1*
"@

    $buildDiagram | Out-File -FilePath "$OutputPath/diagrams/build_system.md" -Encoding UTF8
    $script:GeneratedFiles += "$OutputPath/diagrams/build_system.md"
}

# ============================================================================
# README Update
# ============================================================================

function Update-Readme {
    Write-Section "README Update"

    if (-not (Test-Path "README.md")) {
        Write-Status "README.md not found" "Error"
        return
    }

    $readme = Get-Content -Path "README.md" -Raw

    # Update version badge
    $version = git describe --tags --abbrev=0 2>$null
    if ($version) {
        $readme = $readme -replace '(?\u003c=Version:\s)[\w.]+', $version.TrimStart('v')
        Write-Status "Updated version badge to $version" "Success"
    }

    # Update build status
    $buildStatus = @"
[![Build Status](https://github.com/ItsMehRAWRXD/RawrXD/workflows/CI/badge.svg)](https://github.com/ItsMehRAWRXD/RawrXD/actions)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](./tests)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
"@

    # Save updated README
    $readme | Out-File -Path "README.md" -Encoding UTF8
    Write-Status "README.md updated" "Success"
}

# ============================================================================
# Wiki Generation
# ============================================================================

function New-WikiContent {
    Write-Section "Wiki Content Generation"

    New-Directory "$OutputPath/wiki"

    # Home page
    $home = @"
# RawrXD Wiki

Welcome to the RawrXD documentation wiki!

## Quick Links

- [Getting Started](./Getting-Started)
- [Installation Guide](./Installation)
- [Configuration](./Configuration)
- [API Reference](./API-Reference)
- [Troubleshooting](./Troubleshooting)

## Contributing

See [Contributing Guide](./Contributing) for information on how to contribute to the project.

---
*Last updated: $(Get-Date -Format "yyyy-MM-dd")*
"@

    $home | Out-File -FilePath "$OutputPath/wiki/Home.md" -Encoding UTF8
    $script:GeneratedFiles += "$OutputPath/wiki/Home.md"

    # Getting Started
    $gettingStarted = @"
# Getting Started with RawrXD

## Installation

### Windows

```powershell
# Download the latest release
Invoke-WebRequest -Uri "https://github.com/ItsMehRAWRXD/RawrXD/releases/latest/download/RawrXD-win64.zip" -OutFile "rawrxd.zip"

# Extract
Expand-Archive -Path "rawrxd.zip" -DestinationPath "C:\Program Files\RawrXD"

# Add to PATH
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\RawrXD", "User")
```

### Linux

```bash
# Download
wget https://github.com/ItsMehRAWRXD/RawrXD/releases/latest/download/RawrXD-linux-x64.tar.gz

# Extract and install
tar -xzf RawrXD-linux-x64.tar.gz
sudo cp -r RawrXD /opt/
sudo ln -s /opt/RawrXD/bin/rawrxd /usr/local/bin/rawrxd
```

## First Run

```bash
# Check version
rawrxd --version

# Run inference
rawrxd -m model.gguf -p "Hello, world!"
```

---
*Auto-generated by docs_generator.ps1*
"@

    $gettingStarted | Out-File -FilePath "$OutputPath/wiki/Getting-Started.md" -Encoding UTF8
    $script:GeneratedFiles += "$OutputPath/wiki/Getting-Started.md"

    # Configuration
    $config = @"
# Configuration Guide

## Configuration File

RawrXD uses JSON configuration files. Default location: `~/.rawrxd/config.json`

## Example Configuration

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 8080
  },
  "inference": {
    "threads": 4,
    "batch_size": 512,
    "context_length": 4096
  },
  "hardware": {
    "gpu": true,
    "vulkan": true
  }
}
```

## Environment Variables

- `RAWRXD_CONFIG_PATH` - Path to config file
- `RAWRXD_LOG_LEVEL` - Logging level (debug, info, warn, error)
- `RAWRXD_THREADS` - Number of inference threads

---
*Auto-generated by docs_generator.ps1*
"@

    $config | Out-File -FilePath "$OutputPath/wiki/Configuration.md" -Encoding UTF8
    $script:GeneratedFiles += "$OutputPath/wiki/Configuration.md"

    Write-Status "Wiki content generated" "Success"
}

# ============================================================================
# Summary Report
# ============================================================================

function Write-Summary {
    Write-Section "Documentation Generation Summary"

    Write-Host "Generated Files:" -ForegroundColor Cyan
    foreach ($file in $script:GeneratedFiles) {
        Write-Host "  - $file" -ForegroundColor White
    }

    Write-Host "`nTotal files generated: $($script:GeneratedFiles.Count)" -ForegroundColor Green

    if ($script:Errors.Count -gt 0) {
        Write-Host "`nErrors:" -ForegroundColor Red
        foreach ($error in $script:Errors) {
            Write-Host "  - $error" -ForegroundColor Red
        }
    }

    if ($Serve -and (Test-Command "python")) {
        Write-Status "Starting documentation server..." "Info"
        Write-Status "Navigate to http://localhost:8000" "Info"
        Start-Process python -ArgumentList "-m", "http.server", "8000", "--directory", "$OutputPath/api/html" -NoNewWindow
    }
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Documentation Generator" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    New-Directory $OutputPath

    if ($All) {
        $GenerateAPI = $true
        $GenerateDiagrams = $true
        $UpdateReadme = $true
        $GenerateWiki = $true
    }

    if ($GenerateAPI) { New-APIDocumentation }
    if ($GenerateDiagrams) { New-ArchitectureDiagrams }
    if ($UpdateReadme) { Update-Readme }
    if ($GenerateWiki) { New-WikiContent }

    Write-Summary
}

# Run main
Main
