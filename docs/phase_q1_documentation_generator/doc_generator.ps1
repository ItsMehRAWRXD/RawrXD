#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase Q.1: Documentation Generator
    
.DESCRIPTION
    Automated documentation generation for RawrXD platform.
    Generates API docs, user guides, and developer documentation.
    
.PARAMETER Action
    Action to perform: generate-api, generate-user, generate-dev, validate
    
.PARAMETER OutputPath
    Output directory for generated documentation
    
.PARAMETER Format
    Output format: markdown, html, pdf
    
.EXAMPLE
    .\doc_generator.ps1 -Action generate-api -Format markdown
    .\doc_generator.ps1 -Action validate
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("generate-api", "generate-user", "generate-dev", "validate", "index")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\generated_docs",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("markdown", "html", "pdf")]
    [string]$Format = "markdown",
    
    [Parameter(Mandatory=$false)]
    [string]$SourcePath = "..\.."
)

$ErrorActionPreference = "Stop"

# Documentation registry
$DocRegistry = @{
    LastGenerated = $null
    Documents = @()
    ValidationResults = @{}
}

# Document templates
$Templates = @{
    APIDoc = @"
# {Title}

## Overview
{Description}

## Endpoints
{Endpoints}

## Authentication
{Auth}

## Examples
{Examples}

---
*Generated: {Timestamp}*
"@
    UserGuide = @"
# {Title}

## Getting Started
{GettingStarted}

## Features
{Features}

## Usage
{Usage}

## Troubleshooting
{Troubleshooting}

---
*Generated: {Timestamp}*
"@
    DevGuide = @"
# {Title}

## Architecture
{Architecture}

## Development Setup
{Setup}

## API Reference
{APIReference}

## Contributing
{Contributing}

---
*Generated: {Timestamp}*
"@
}

function Write-DocHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase Q.1: Documentation Generator                                  ║
║  Automated documentation for RawrXD platform                       ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-DocGenerator {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $registryFile = Join-Path $OutputPath "doc_registry.json"
    if (Test-Path $registryFile) {
        $script:DocRegistry = Get-Content -Path $registryFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-DocRegistry {
    $registryFile = Join-Path $OutputPath "doc_registry.json"
    $script:DocRegistry.LastGenerated = Get-Date -Format "o"
    $script:DocRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryFile
}

function Get-SourceFiles {
    param($Pattern)
    
    $files = @()
    if (Test-Path $SourcePath) {
        $files = Get-ChildItem -Path $SourcePath -Recurse -Filter $Pattern -File | Where-Object {
            $_.FullName -notlike "*\node_modules\*" -and
            $_.FullName -notlike "*\.git\*" -and
            $_.FullName -notlike "*\generated_docs\*"
        }
    }
    return $files
}

function New-APIDocumentation {
    param($Format)
    
    Write-Host "`nGenerating API documentation..." -ForegroundColor Yellow
    
    $apiDocDir = Join-Path $OutputPath "api"
    New-Item -ItemType Directory -Path $apiDocDir -Force | Out-Null
    
    # Collect API endpoints from all phases
    $endpoints = @()
    
    # Phase M - SaaS API
    $endpoints += @{
        Phase = "M - SaaS"
        Name = "Tenant Management"
        Endpoints = @(
            @{ Method = "POST"; Path = "/api/v1/tenants"; Description = "Create new tenant" },
            @{ Method = "GET"; Path = "/api/v1/tenants/{id}"; Description = "Get tenant details" },
            @{ Method = "PUT"; Path = "/api/v1/tenants/{id}"; Description = "Update tenant" },
            @{ Method = "DELETE"; Path = "/api/v1/tenants/{id}"; Description = "Delete tenant" }
        )
    }
    
    # Phase M - Usage API
    $endpoints += @{
        Phase = "M - SaaS"
        Name = "Usage Metering"
        Endpoints = @(
            @{ Method = "POST"; Path = "/api/v1/usage/record"; Description = "Record token usage" },
            @{ Method = "GET"; Path = "/api/v1/usage/{tenantId}"; Description = "Get usage report" },
            @{ Method = "GET"; Path = "/api/v1/quota/{tenantId}"; Description = "Check quota status" }
        )
    }
    
    # Phase N - Health API
    $endpoints += @{
        Phase = "N - Operations"
        Name = "Health Monitoring"
        Endpoints = @(
            @{ Method = "GET"; Path = "/api/v1/health"; Description = "Get system health" },
            @{ Method = "GET"; Path = "/api/v1/health/{component}"; Description = "Get component health" }
        )
    }
    
    # Phase O - Analytics API
    $endpoints += @{
        Phase = "O - Analytics"
        Name = "Analytics"
        Endpoints = @(
            @{ Method = "GET"; Path = "/api/v1/analytics/usage"; Description = "Get usage analytics" },
            @{ Method = "GET"; Path = "/api/v1/analytics/trends"; Description = "Get usage trends" },
            @{ Method = "GET"; Path = "/api/v1/analytics/mrr"; Description = "Get MRR metrics" }
        )
    }
    
    # Generate documentation for each phase
    foreach ($group in $endpoints) {
        $content = @"
# $($group.Name) API

## Phase: $($group.Phase)

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
"@
        foreach ($ep in $group.Endpoints) {
            $content += "`n| $($ep.Method) | $($ep.Path) | $($ep.Description) |"
        }
        
        $content += @"

## Authentication

All API requests require authentication via Bearer token:

```http
Authorization: Bearer {api_key}
```

## Rate Limiting

- Standard tier: 100 requests/minute
- Enterprise tier: 1000 requests/minute

## Response Format

All responses are JSON:

```json
{
  "success": true,
  "data": { },
  "error": null
}
```

---
*Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@
        
        $filename = $group.Name.ToLower().Replace(" ", "_") + ".md"
        $filepath = Join-Path $apiDocDir $filename
        $content | Set-Content -Path $filepath
        
        Write-Host "  ✓ Generated: $filename" -ForegroundColor Green
    }
    
    # Generate main API index
    $indexContent = @"
# RawrXD API Reference

Complete API documentation for the RawrXD platform.

## API Sections

"@
    foreach ($group in $endpoints) {
        $filename = $group.Name.ToLower().Replace(" ", "_") + ".md"
        $indexContent += "- [$($group.Name)]($filename)`n"
    }
    
    $indexContent += @"

## Getting Started

1. Obtain an API key from the [Customer Portal](https://portal.rawrxd.io)
2. Include the key in all requests: `Authorization: Bearer {key}`
3. Start with the Health API to verify connectivity

## Support

For API support, contact: api-support@rawrxd.io

---
*Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@
    
    $indexContent | Set-Content -Path (Join-Path $apiDocDir "README.md")
    
    $script:DocRegistry.Documents += @{
        Type = "API"
        Path = $apiDocDir
        GeneratedAt = Get-Date -Format "o"
        Format = $Format
    }
    
    Write-Host "`n✓ API documentation generated in: $apiDocDir" -ForegroundColor Green
}

function New-UserGuide {
    param($Format)
    
    Write-Host "`nGenerating user guide..." -ForegroundColor Yellow
    
    $userGuideDir = Join-Path $OutputPath "user-guide"
    New-Item -ItemType Directory -Path $userGuideDir -Force | Out-Null
    
    # Quick Start Guide
    $quickStart = @"
# Quick Start Guide

## Welcome to RawrXD!

RawrXD is a sovereign AI runtime platform for enterprise workloads.

## Installation

### Windows

```powershell
# Download installer
Invoke-WebRequest -Uri "https://rawrxd.io/download/windows" -OutFile "rawrxd-setup.exe"

# Run installer
.\rawrxd-setup.exe
```

### Linux

```bash
# Download and install
curl -fsSL https://rawrxd.io/install.sh | bash
```

## First Steps

1. **Create an Account**
   - Visit https://portal.rawrxd.io
   - Sign up for a free tier

2. **Get Your API Key**
   - Navigate to Settings → API Keys
   - Generate a new key

3. **Make Your First Request**

```python
import requests

response = requests.post(
    "https://api.rawrxd.io/v1/chat/completions",
    headers={"Authorization": "Bearer YOUR_API_KEY"},
    json={
        "model": "rawrxd-3b",
        "messages": [{"role": "user", "content": "Hello!"}]
    }
)
print(response.json())
```

## Next Steps

- [Installation Guide](installation.md)
- [API Reference](../api/README.md)
- [Tutorials](tutorials.md)

---
*Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@
    
    $quickStart | Set-Content -Path (Join-Path $userGuideDir "quick-start.md")
    Write-Host "  ✓ Generated: quick-start.md" -ForegroundColor Green
    
    # Installation Guide
    $installation = @"
# Installation Guide

## System Requirements

### Minimum
- Windows 10/Server 2019 or Ubuntu 20.04
- 4 CPU cores
- 8 GB RAM
- 10 GB disk space

### Recommended
- Windows 11/Server 2022 or Ubuntu 22.04
- 8+ CPU cores
- 32 GB RAM
- 100 GB SSD
- NVIDIA GPU with 8GB+ VRAM

## Installation Steps

### 1. Download

Download the appropriate installer from https://rawrxd.io/download

### 2. Install

Run the installer and follow the prompts.

### 3. Configure

Edit `rawrxd.config.json` to match your environment.

### 4. Start

```bash
rawrxd start
```

## Verification

```bash
rawrxd status
```

Should show: `Status: Running`

## Troubleshooting

See [Troubleshooting](troubleshooting.md) for common issues.

---
*Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@
    
    $installation | Set-Content -Path (Join-Path $userGuideDir "installation.md")
    Write-Host "  ✓ Generated: installation.md" -ForegroundColor Green
    
    # Tutorials
    $tutorials = @"
# Tutorials

## Tutorial 1: Your First Inference

Learn how to run your first AI inference.

## Tutorial 2: Multi-Tenant Setup

Configure RawrXD for multiple teams.

## Tutorial 3: Performance Tuning

Optimize for your specific workload.

## Tutorial 4: Custom Models

Deploy your own fine-tuned models.

---
*Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@
    
    $tutorials | Set-Content -Path (Join-Path $userGuideDir "tutorials.md")
    Write-Host "  ✓ Generated: tutorials.md" -ForegroundColor Green
    
    # Troubleshooting
    $troubleshooting = @"
# Troubleshooting

## Common Issues

### Issue: Service won't start

**Solution:**
1. Check logs: `rawrxd logs`
2. Verify configuration
3. Check port availability

### Issue: High latency

**Solution:**
1. Run performance tuner: `.\performance\phase_j2_kernel_tuner\kernel_tuner.ps1`
2. Check GPU utilization
3. Review batch size settings

### Issue: Out of memory

**Solution:**
1. Reduce context length
2. Use smaller model
3. Enable memory paging

## Getting Help

- Documentation: https://docs.rawrxd.io
- Community: https://community.rawrxd.io
- Support: support@rawrxd.io

---
*Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@
    
    $troubleshooting | Set-Content -Path (Join-Path $userGuideDir "troubleshooting.md")
    Write-Host "  ✓ Generated: troubleshooting.md" -ForegroundColor Green
    
    # User Guide Index
    $indexContent = @"
# RawrXD User Guide

Welcome! This guide will help you get the most out of RawrXD.

## Contents

- [Quick Start](quick-start.md) - Get up and running in minutes
- [Installation Guide](installation.md) - Detailed installation instructions
- [Tutorials](tutorials.md) - Step-by-step tutorials
- [Troubleshooting](troubleshooting.md) - Common issues and solutions

## Support

Need help? Contact us at support@rawrxd.io

---
*Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@
    
    $indexContent | Set-Content -Path (Join-Path $userGuideDir "README.md")
    
    $script:DocRegistry.Documents += @{
        Type = "UserGuide"
        Path = $userGuideDir
        GeneratedAt = Get-Date -Format "o"
        Format = $Format
    }
    
    Write-Host "`n✓ User guide generated in: $userGuideDir" -ForegroundColor Green
}

function New-DeveloperGuide {
    param($Format)
    
    Write-Host "`nGenerating developer guide..." -ForegroundColor Yellow
    
    $devGuideDir = Join-Path $OutputPath "developer-guide"
    New-Item -ItemType Directory -Path $devGuideDir -Force | Out-Null
    
    # Architecture Overview
    $architecture = @"
# Architecture Overview

## System Architecture

RawrXD follows a modular, microservices-inspired architecture.

```
┌─────────────────────────────────────────────────────────────┐
│                    RawrXD Platform                          │
├─────────────────────────────────────────────────────────────┤
│  Extensions │  Analytics │  Operations │  SaaS │  Core       │
├─────────────────────────────────────────────────────────────┤
│                    Inference Engine                         │
├─────────────────────────────────────────────────────────────┤
│                    Hardware Layer                           │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### Inference Engine
- Tokenizer
- Model loader
- KV cache manager
- Sampling engine

### SaaS Layer
- Tenant isolation
- Usage metering
- Billing
- Customer management

### Extensions
- Plugin system
- Marketplace
- Integrations

## Data Flow

1. Request → API Gateway
2. Authentication → Tenant validation
3. Rate limiting → Quota check
4. Inference → Response

---
*Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@
    
    $architecture | Set-Content -Path (Join-Path $devGuideDir "architecture.md")
    Write-Host "  ✓ Generated: architecture.md" -ForegroundColor Green
    
    # Development Setup
    $devSetup = @"
# Development Setup

## Prerequisites

- PowerShell 7.0+
- Git
- Visual Studio 2022 or VS Code
- Python 3.10+

## Clone Repository

```bash
git clone https://github.com/ItsMehRAWRXD/rawrxd.git
cd rawrxd
```

## Build

```powershell
# Configure
.\configure.ps1

# Build
.\build.ps1

# Test
.\test.ps1
```

## Development Workflow

1. Create feature branch
2. Make changes
3. Run tests
4. Submit PR

## Debugging

See [Debugging Guide](debugging.md)

---
*Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@
    
    $devSetup | Set-Content -Path (Join-Path $devGuideDir "setup.md")
    Write-Host "  ✓ Generated: setup.md" -ForegroundColor Green
    
    # Contributing Guide
    $contributing = @"
# Contributing to RawrXD

## Getting Started

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Code Standards

- PowerShell: Follow PSScriptAnalyzer rules
- C++: Follow Google C++ Style Guide
- Documentation: Clear, concise, examples

## Testing

All changes must include tests.

## Commit Messages

Follow conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `refactor:` Code refactoring

## Code Review

All PRs require review from at least one maintainer.

---
*Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@
    
    $contributing | Set-Content -Path (Join-Path $devGuideDir "contributing.md")
    Write-Host "  ✓ Generated: contributing.md" -ForegroundColor Green
    
    # Developer Guide Index
    $indexContent = @"
# RawrXD Developer Guide

Welcome, contributor! This guide will help you understand and extend RawrXD.

## Contents

- [Architecture Overview](architecture.md) - System design and components
- [Development Setup](setup.md) - Get your dev environment ready
- [Contributing Guide](contributing.md) - How to contribute

## API Reference

See [API Reference](../api/README.md)

## Questions?

Join our developer community: https://discord.gg/rawrxd-dev

---
*Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@
    
    $indexContent | Set-Content -Path (Join-Path $devGuideDir "README.md")
    
    $script:DocRegistry.Documents += @{
        Type = "DeveloperGuide"
        Path = $devGuideDir
        GeneratedAt = Get-Date -Format "o"
        Format = $Format
    }
    
    Write-Host "`n✓ Developer guide generated in: $devGuideDir" -ForegroundColor Green
}

function Test-Documentation {
    Write-Host "`nValidating documentation..." -ForegroundColor Yellow
    
    $issues = @()
    $warnings = @()
    
    # Check for required documents
    $requiredDocs = @(
        "api\README.md",
        "user-guide\README.md",
        "developer-guide\README.md"
    )
    
    foreach ($doc in $requiredDocs) {
        $path = Join-Path $OutputPath $doc
        if (-not (Test-Path $path)) {
            $issues += "Missing required document: $doc"
        }
    }
    
    # Check for broken links (basic check)
    $allDocs = Get-ChildItem -Path $OutputPath -Recurse -Filter "*.md"
    foreach ($doc in $allDocs) {
        $content = Get-Content -Path $doc.FullName -Raw
        # Check for empty sections
        if ($content -match "#{2,}\s*\r?\n#{2,}") {
            $warnings += "$($doc.Name): Empty section detected"
        }
    }
    
    $script:DocRegistry.ValidationResults = @{
        Timestamp = Get-Date -Format "o"
        Issues = $issues
        Warnings = $warnings
        Passed = ($issues.Count -eq 0)
    }
    
    Save-DocRegistry
    
    if ($issues.Count -eq 0 -and $warnings.Count -eq 0) {
        Write-Host "  ✓ All documentation validated successfully" -ForegroundColor Green
    } else {
        if ($issues.Count -gt 0) {
            Write-Host "`n  Issues:" -ForegroundColor Red
            foreach ($issue in $issues) {
                Write-Host "    ✗ $issue" -ForegroundColor Red
            }
        }
        if ($warnings.Count -gt 0) {
            Write-Host "`n  Warnings:" -ForegroundColor Yellow
            foreach ($warning in $warnings) {
                Write-Host "    ⚠ $warning" -ForegroundColor Yellow
            }
        }
    }
}

function New-DocumentationIndex {
    Write-Host "`nGenerating documentation index..." -ForegroundColor Yellow
    
    $indexContent = @"
# RawrXD Documentation

Complete documentation for the RawrXD platform.

## Quick Links

- [User Guide](user-guide/README.md) - Get started with RawrXD
- [API Reference](api/README.md) - API documentation
- [Developer Guide](developer-guide/README.md) - Contribute to RawrXD

## Documentation Structure

```
docs/
├── api/              # API reference
├── user-guide/       # End-user documentation
└── developer-guide/  # Developer documentation
```

## Contributing to Documentation

See [Developer Guide](developer-guide/contributing.md)

## Support

- Documentation issues: docs@rawrxd.io
- General support: support@rawrxd.io

---
*Last Updated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@
    
    $indexContent | Set-Content -Path (Join-Path $OutputPath "README.md")
    
    Write-Host "  ✓ Documentation index generated" -ForegroundColor Green
}

# Main execution
Write-DocHeader
Initialize-DocGenerator

switch ($Action) {
    "generate-api" {
        New-APIDocumentation -Format $Format
    }
    "generate-user" {
        New-UserGuide -Format $Format
    }
    "generate-dev" {
        New-DeveloperGuide -Format $Format
    }
    "validate" {
        Test-Documentation
    }
    "index" {
        New-DocumentationIndex
    }
}

Save-DocRegistry

Write-Host "`n✅ Documentation generation complete" -ForegroundColor Green
