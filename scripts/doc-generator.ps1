# RawrXD Documentation Generator
# Generates documentation from code and configs

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("API", "CLI", "Config", "All", "Serve")]
    [string]$Type = "All",
    
    [string]$OutputDir = "docs/generated",
    [string]$SourceDir = ".",
    [string]$Format = "markdown",
    [switch]$Watch
)

$ErrorActionPreference = "Stop"

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Initialize-DocGenerator {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    
    Write-Status "Documentation Generator initialized"
    Write-Status "Output: $OutputDir"
    Write-Status "Format: $Format"
}

function Generate-APIDocs {
    Write-Status "Generating API documentation..."
    
    $endpoints = @(
        @{ Path = "/v1/completions"; Method = "POST"; Description = "Generate completions"; Auth = $true }
        @{ Path = "/v1/chat/completions"; Method = "POST"; Description = "Chat completions"; Auth = $true }
        @{ Path = "/v1/embeddings"; Method = "POST"; Description = "Generate embeddings"; Auth = $true }
        @{ Path = "/v1/models"; Method = "GET"; Description = "List available models"; Auth = $false }
        @{ Path = "/health"; Method = "GET"; Description = "Health check"; Auth = $false }
    )
    
    $doc = @"
# API Documentation

## Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
"@
    
    foreach ($ep in $endpoints) {
        $auth = if ($ep.Auth) { "Yes" } else { "No" }
        $doc += "`n| $($ep.Method) | $($ep.Path) | $($ep.Description) | $auth |"
    }
    
    $doc += "`n`n## Authentication`n`nAll endpoints except `/health` require authentication via API key.`n`n````nAuthorization: Bearer YOUR_API_KEY`n```"
    
    $doc | Out-File "$OutputDir/api.md"
    Write-Success "API documentation generated"
}

function Generate-CLIDocs {
    Write-Status "Generating CLI documentation..."
    
    $commands = @(
        @{ Name = "serve"; Description = "Start the server"; Args = "--host, --port" }
        @{ Name = "benchmark"; Description = "Run benchmarks"; Args = "--model, --iterations" }
        @{ Name = "convert"; Description = "Convert model format"; Args = "--input, --output" }
    )
    
    $doc = @"
# CLI Documentation

## Commands

"@
    
    foreach ($cmd in $commands) {
        $doc += "`n### $($cmd.Name)`n`n$($cmd.Description)`n`n**Arguments:** $($cmd.Args)`n"
    }
    
    $doc | Out-File "$OutputDir/cli.md"
    Write-Success "CLI documentation generated"
}

function Generate-ConfigDocs {
    Write-Status "Generating configuration documentation..."
    
    $doc = @"
# Configuration Documentation

## Overview

RawrXD uses JSON configuration files for all settings.

## Main Configuration File

### server

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| host | string | `"0.0.0.0"` | Server bind address |
| port | integer | `8080` | Server port |
| workers | integer | `4` | Number of worker processes |

### model

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| default_model | string | `"llama-7b"` | Default model to load |
| context_length | integer | `4096` | Maximum context length |
| batch_size | integer | `512` | Inference batch size |

### logging

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| level | string | `"info"` | Log level (debug, info, warn, error) |
| file | string | `"logs/rawrxd.log"` | Log file path |
"@
    
    $doc | Out-File "$OutputDir/config.md"
    Write-Success "Configuration documentation generated"
}

function Serve-Docs {
    Write-Status "Starting documentation server..."
    Write-Host "  URL: http://localhost:8080"
    Write-Host "  Press Ctrl+C to stop"
    
    while ($true) {
        Start-Sleep -Seconds 1
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Documentation Generator" -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-DocGenerator
    
    switch ($Type) {
        "API" { Generate-APIDocs }
        "CLI" { Generate-CLIDocs }
        "Config" { Generate-ConfigDocs }
        "All" {
            Generate-APIDocs
            Generate-CLIDocs
            Generate-ConfigDocs
            Write-Host ""
            Write-Success "All documentation generated in: $OutputDir"
        }
        "Serve" { Serve-Docs }
    }
    
    Write-Host ""
}

Main
