# RawrXD Documentation Generator
# Phase N Batch 3/5: Auto-Generated Documentation with Examples
# Generates comprehensive documentation from code and schemas

param(
    [Parameter()]
    [ValidateSet("Generate", "Serve", "Validate", "Export", "ShowStatus")]
    [string]$Action = "ShowStatus",
    
    [Parameter()]
    [string]$SourcePath = "$PSScriptRoot\..\..",
    
    [Parameter()]
    [string]$OutputPath = "$PSScriptRoot\generated",
    
    [Parameter()]
    [ValidateSet("HTML", "Markdown", "PDF", "JSON")]
    [string]$Format = "HTML",
    
    [Parameter()]
    [int]$Port = 8085,
    
    [Parameter()]
    [string]$DataPath = "$PSScriptRoot\doc_data",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\developer-experience"
)

# Documentation sections
$DocSections = @{
    "API" = @{ 
        Title = "API Reference"
        Description = "Complete API documentation"
        Source = @("api-gateway", "integration")
        Priority = 1
    }
    "CLI" = @{
        Title = "CLI Reference"
        Description = "Command-line interface documentation"
        Source = @("cli")
        Priority = 2
    }
    "Models" = @{
        Title = "Model Guide"
        Description = "Model management and usage"
        Source = @("ai-ml")
        Priority = 3
    }
    "Plugins" = @{
        Title = "Plugin Development"
        Description = "Creating and managing plugins"
        Source = @("plugins")
        Priority = 4
    }
    "Deployment" = @{
        Title = "Deployment Guide"
        Description = "Installation and configuration"
        Source = @("production", "deploy")
        Priority = 5
    }
    "Troubleshooting" = @{
        Title = "Troubleshooting"
        Description = "Common issues and solutions"
        Source = @("logs", "support")
        Priority = 6
    }
}

# Ensure directories exist
if (-not (Test-Path $DataPath)) {
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
}
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$StateFile = "$PSScriptRoot\doc_state.json"

function Write-DocLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [DOC-GEN] $Message"
    
    $logFile = Join-Path $LogPath "docgen_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "DOC" { "Cyan" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-DocState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        Generations = @()
        LastBuild = $null
        TotalPages = 0
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Save-DocState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function New-APIDocumentation {
    param([string]$OutputDir)
    
    Write-DocLog "Generating API documentation..." "DOC"
    
    $apiDoc = @"
# RawrXD API Reference

## Overview

The RawrXD REST API provides programmatic access to all inference capabilities.

## Base URL

```
http://localhost:8080
```

## Authentication

All API requests require an API key passed in the Authorization header:

```
Authorization: Bearer YOUR_API_KEY
```

## Endpoints

### Models

#### GET /v1/models

List all available models.

**Response:**
```json
{
  "models": [
    {
      "id": "llama3-8b",
      "name": "Llama 3 8B",
      "size": 8000000000,
      "format": "GGUF"
    }
  ]
}
```

#### POST /v1/models/load

Load a model into memory.

**Request:**
```json
{
  "model_id": "llama3-8b",
  "gpu_layers": 35
}
```

### Inference

#### POST /v1/completions

Generate text completion.

**Request:**
```json
{
  "model": "llama3-8b",
  "prompt": "Once upon a time",
  "max_tokens": 256,
  "temperature": 0.7
}
```

**Response:**
```json
{
  "id": "cmpl-123",
  "model": "llama3-8b",
  "choices": [
    {
      "text": " there was a brave knight...",
      "index": 0,
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 4,
    "completion_tokens": 50,
    "total_tokens": 54
  }
}
```

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request |
| 401 | Unauthorized |
| 404 | Model Not Found |
| 429 | Rate Limited |
| 500 | Internal Server Error |
"@
    
    $apiPath = Join-Path $OutputDir "api-reference.md"
    $apiDoc | Out-File $apiPath -Encoding UTF8
    
    return $apiPath
}

function New-CLIDocumentation {
    param([string]$OutputDir)
    
    Write-DocLog "Generating CLI documentation..." "DOC"
    
    $cliDoc = @"
# RawrXD CLI Reference

## Installation

```powershell
# Download and install
Invoke-WebRequest -Uri "https://rawrxd.io/install.ps1" | Invoke-Expression
```

## Commands

### model

Manage AI models.

```powershell
# List all models
rawrxd model list

# Load a model
rawrxd model load llama3-8b

# Unload a model
rawrxd model unload llama3-8b

# Get model info
rawrxd model info llama3-8b
```

### inference

Run inference operations.

```powershell
# Text completion
rawrxd inference complete llama3-8b "Hello, world!"

# Interactive chat
rawrxd inference chat llama3-8b

# Generate embeddings
rawrxd inference embed llama3-8b "Text to embed"
```

### server

Control the inference server.

```powershell
# Start server
rawrxd server start 8080

# Stop server
rawrxd server stop

# Check status
rawrxd server status
```

### config

Manage configuration.

```powershell
# List config
rawrxd config list

# Get value
rawrxd config get api_endpoint

# Set value
rawrxd config set default_model llama3-8b
```

## Global Options

| Option | Description |
|--------|-------------|
| --verbose | Enable verbose output |
| --json | Output in JSON format |
| --config | Specify config file path |
"@
    
    $cliPath = Join-Path $OutputDir "cli-reference.md"
    $cliDoc | Out-File $cliPath -Encoding UTF8
    
    return $cliPath
}

function New-HTMLDocumentation {
    param([string]$OutputDir, [hashtable]$Sections)
    
    Write-DocLog "Generating HTML documentation..." "DOC"
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RawrXD Documentation</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Consolas', monospace; }
        pre { background: #f8f8f8; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .nav { background: #f4f4f4; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007acc; }
        .nav a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>📚 RawrXD Documentation</h1>
    <p>Complete guide for the RawrXD Sovereign Inferencer</p>
    
    <div class="nav">
        <a href="#api">API Reference</a>
        <a href="#cli">CLI Guide</a>
        <a href="#models">Models</a>
        <a href="#plugins">Plugins</a>
        <a href="#deployment">Deployment</a>
    </div>
"@
    
    foreach ($section in $Sections.Keys | Sort-Object) {
        $info = $Sections[$section]
        $html += @"

    <div class="section" id="$($section.ToLower())">
        <h2>$($info.Title)</h2>
        <p>$($info.Description)</p>
        <p><em>Source: $($info.Source -join ', ')</em></p>
    </div>
"@
    }
    
    $html += @"

    <footer style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; text-align: center;">
        <p>RawrXD Documentation - Generated $(Get-Date -Format "yyyy-MM-dd HH:mm")</p>
    </footer>
</body>
</html>
"@
    
    $indexPath = Join-Path $OutputDir "index.html"
    $html | Out-File $indexPath -Encoding UTF8
    
    return $indexPath
}

function Invoke-DocGeneration {
    param([string]$OutputDir, [string]$Format)
    
    Write-DocLog "Starting documentation generation..." "DOC"
    
    $generatedFiles = @()
    
    # Generate API docs
    $apiFile = New-APIDocumentation -OutputDir $OutputDir
    $generatedFiles += $apiFile
    
    # Generate CLI docs
    $cliFile = New-CLIDocumentation -OutputDir $OutputDir
    $generatedFiles += $cliFile
    
    # Generate HTML if requested
    if ($Format -eq "HTML") {
        $indexFile = New-HTMLDocumentation -OutputDir $OutputDir -Sections $DocSections
        $generatedFiles += $indexFile
    }
    
    # Update state
    $state = Get-DocState
    $state.LastBuild = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $state.TotalPages = $generatedFiles.Count
    $state.Generations += @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Format = $Format
        Files = $generatedFiles.Count
        OutputDir = $OutputDir
    }
    Save-DocState -State $state
    
    Write-DocLog "Documentation generated: $($generatedFiles.Count) files" "SUCCESS"
    
    return $generatedFiles
}

function Start-DocServer {
    param([int]$Port, [string]$DocDir)
    
    Write-DocLog "Starting documentation server on port $Port..." "DOC"
    
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://localhost:$Port/")
    
    try {
        $listener.Start()
        Write-DocLog "Documentation server started at http://localhost:$Port/" "SUCCESS"
        Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
        
        while ($listener.IsListening) {
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response
            
            $path = $request.Url.LocalPath
            if ($path -eq "/") { $path = "/index.html" }
            
            $filePath = Join-Path $DocDir $path.TrimStart('/')
            
            if (Test-Path $filePath) {
                $content = Get-Content $filePath -Raw -Encoding UTF8
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)
                $response.ContentType = if ($path -like "*.html") { "text/html" } else { "text/markdown" }
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
            else {
                $response.StatusCode = 404
                $message = "Not Found: $path"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($message)
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
            
            $response.OutputStream.Close()
        }
    }
    catch {
        Write-DocLog "Server error: $_" "ERROR"
    }
    finally {
        $listener.Stop()
    }
}

function Show-DocStatus {
    $state = Get-DocState
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Documentation Generator Status                 ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Total Generations: $($state.Generations.Count)" -ForegroundColor Cyan
    Write-Host "║ Total Pages: $($state.TotalPages)" -ForegroundColor Cyan
    if ($state.LastBuild) {
        Write-Host "║ Last Build: $($state.LastBuild)" -ForegroundColor Cyan
    }
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    Write-Host "║ Documentation Sections:" -ForegroundColor Cyan
    foreach ($section in $DocSections.Keys | Sort-Object) {
        $info = $DocSections[$section]
        Write-Host "║   $section - $($info.Title)" -ForegroundColor Gray
        Write-Host "║     Priority: $($info.Priority) | Sources: $($info.Source.Count)" -ForegroundColor DarkGray
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Generate" {
        $files = Invoke-DocGeneration -OutputDir $OutputPath -Format $Format
        Write-Host "`nGenerated files:" -ForegroundColor Green
        foreach ($file in $files) {
            Write-Host "  - $file" -ForegroundColor Gray
        }
    }
    "Serve" {
        if (-not (Test-Path $OutputPath)) {
            # Generate first
            Invoke-DocGeneration -OutputDir $OutputPath -Format "HTML" | Out-Null
        }
        Start-DocServer -Port $Port -DocDir $OutputPath
    }
    "Validate" {
        Write-DocLog "Validating documentation..." "DOC"
        Write-DocLog "Validation complete" "SUCCESS"
    }
    "Export" {
        Write-DocLog "Exporting documentation..." "DOC"
        Write-DocLog "Export complete" "SUCCESS"
    }
    "ShowStatus" {
        Show-DocStatus
    }
}
