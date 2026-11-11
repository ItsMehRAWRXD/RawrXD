#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase Q.3: API Reference Generator
    
.DESCRIPTION
    Generates comprehensive API reference documentation from
    source code and OpenAPI specifications.
    
.PARAMETER Action
    Action to perform: generate, validate, export
    
.PARAMETER Format
    Output format: openapi, markdown, html
    
.PARAMETER OutputPath
    Output directory for generated reference
    
.EXAMPLE
    .\api_reference.ps1 -Action generate -Format openapi
    .\api_reference.ps1 -Action export -Format markdown
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("generate", "validate", "export", "serve")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("openapi", "markdown", "html", "json")]
    [string]$Format = "openapi",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\api_reference",
    
    [Parameter(Mandatory=$false)]
    [int]$Port = 8080
)

$ErrorActionPreference = "Stop"

# API Reference registry
$APIRegistry = @{
    Version = "1.0.0"
    LastGenerated = $null
    Endpoints = @()
    Schemas = @{}
}

# OpenAPI template
$OpenAPITemplate = @"
{
  "openapi": "3.0.0",
  "info": {
    "title": "RawrXD API",
    "description": "Complete API reference for the RawrXD platform",
    "version": "1.0.0",
    "contact": {
      "name": "RawrXD Support",
      "email": "api@rawrxd.io"
    }
  },
  "servers": [
    {
      "url": "https://api.rawrxd.io/v1",
      "description": "Production server"
    },
    {
      "url": "https://staging-api.rawrxd.io/v1",
      "description": "Staging server"
    }
  ],
  "paths": {PATHS},
  "components": {
    "schemas": {SCHEMAS},
    "securitySchemes": {
      "bearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT"
      }
    }
  }
}
"@

function Write-APIRefHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase Q.3: API Reference Generator                                ║
║  OpenAPI and documentation generation for RawrXD API               ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-APIReference {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $registryFile = Join-Path $OutputPath "api_registry.json"
    if (Test-Path $registryFile) {
        $script:APIRegistry = Get-Content -Path $registryFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-APIRegistry {
    $registryFile = Join-Path $OutputPath "api_registry.json"
    $script:APIRegistry.LastGenerated = Get-Date -Format "o"
    $script:APIRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryFile
}

function Get-APIEndpoints {
    # Define all API endpoints
    $endpoints = @()
    
    # Authentication
    $endpoints += @{
        Path = "/auth/token"
        Method = "POST"
        Summary = "Generate API token"
        Description = "Exchange credentials for an API access token"
        Tags = @("Authentication")
        RequestBody = @{
            required = $true
            content = @{
                "application/json" = @{
                    schema = @{
                        type = "object"
                        properties = @{
                            api_key = @{ type = "string" }
                        }
                        required = @("api_key")
                    }
                }
            }
        }
        Responses = @{
            "200" = @{
                description = "Token generated successfully"
                content = @{
                    "application/json" = @{
                        schema = @{ '$ref' = "#/components/schemas/TokenResponse" }
                    }
                }
            }
            "401" = @{ description = "Invalid credentials" }
        }
    }
    
    # Chat Completions
    $endpoints += @{
        Path = "/chat/completions"
        Method = "POST"
        Summary = "Create chat completion"
        Description = "Generate a completion for a chat conversation"
        Tags = @("Chat")
        Security = @(@{ bearerAuth = @() })
        RequestBody = @{
            required = $true
            content = @{
                "application/json" = @{
                    schema = @{ '$ref' = "#/components/schemas/ChatCompletionRequest" }
                }
            }
        }
        Responses = @{
            "200" = @{
                description = "Completion generated"
                content = @{
                    "application/json" = @{
                        schema = @{ '$ref' = "#/components/schemas/ChatCompletionResponse" }
                    }
                }
            }
            "400" = @{ description = "Invalid request" }
            "429" = @{ description = "Rate limit exceeded" }
        }
    }
    
    # Embeddings
    $endpoints += @{
        Path = "/embeddings"
        Method = "POST"
        Summary = "Create embeddings"
        Description = "Generate embeddings for input text"
        Tags = @("Embeddings")
        Security = @(@{ bearerAuth = @() })
        RequestBody = @{
            required = $true
            content = @{
                "application/json" = @{
                    schema = @{ '$ref' = "#/components/schemas/EmbeddingRequest" }
                }
            }
        }
        Responses = @{
            "200" = @{
                description = "Embeddings generated"
                content = @{
                    "application/json" = @{
                        schema = @{ '$ref' = "#/components/schemas/EmbeddingResponse" }
                    }
                }
            }
        }
    }
    
    # Models
    $endpoints += @{
        Path = "/models"
        Method = "GET"
        Summary = "List models"
        Description = "Get a list of available models"
        Tags = @("Models")
        Security = @(@{ bearerAuth = @() })
        Responses = @{
            "200" = @{
                description = "List of models"
                content = @{
                    "application/json" = @{
                        schema = @{ '$ref' = "#/components/schemas/ModelList" }
                    }
                }
            }
        }
    }
    
    # Tenant Management
    $endpoints += @{
        Path = "/tenants"
        Method = "POST"
        Summary = "Create tenant"
        Description = "Create a new tenant (admin only)"
        Tags = @("Tenants")
        Security = @(@{ bearerAuth = @() })
        RequestBody = @{
            required = $true
            content = @{
                "application/json" = @{
                    schema = @{ '$ref' = "#/components/schemas/CreateTenantRequest" }
                }
            }
        }
        Responses = @{
            "201" = @{
                description = "Tenant created"
                content = @{
                    "application/json" = @{
                        schema = @{ '$ref' = "#/components/schemas/Tenant" }
                    }
                }
            }
        }
    }
    
    $endpoints += @{
        Path = "/tenants/{tenantId}"
        Method = "GET"
        Summary = "Get tenant"
        Description = "Get tenant details"
        Tags = @("Tenants")
        Security = @(@{ bearerAuth = @() })
        Parameters = @(
            @{
                name = "tenantId"
                in = "path"
                required = $true
                schema = @{ type = "string" }
            }
        )
        Responses = @{
            "200" = @{
                description = "Tenant details"
                content = @{
                    "application/json" = @{
                        schema = @{ '$ref' = "#/components/schemas/Tenant" }
                    }
                }
            }
        }
    }
    
    # Usage
    $endpoints += @{
        Path = "/usage"
        Method = "GET"
        Summary = "Get usage"
        Description = "Get token usage for the current tenant"
        Tags = @("Usage")
        Security = @(@{ bearerAuth = @() })
        Parameters = @(
            @{
                name = "start_date"
                in = "query"
                schema = @{ type = "string"; format = "date" }
            },
            @{
                name = "end_date"
                in = "query"
                schema = @{ type = "string"; format = "date" }
            }
        )
        Responses = @{
            "200" = @{
                description = "Usage data"
                content = @{
                    "application/json" = @{
                        schema = @{ '$ref' = "#/components/schemas/UsageResponse" }
                    }
                }
            }
        }
    }
    
    # Health
    $endpoints += @{
        Path = "/health"
        Method = "GET"
        Summary = "Health check"
        Description = "Check API health status"
        Tags = @("Health")
        Responses = @{
            "200" = @{
                description = "API is healthy"
                content = @{
                    "application/json" = @{
                        schema = @{ '$ref' = "#/components/schemas/HealthResponse" }
                    }
                }
            }
        }
    }
    
    return $endpoints
}

function Get-APISchemas {
    return @{
        TokenResponse = @{
            type = "object"
            properties = @{
                access_token = @{ type = "string" }
                token_type = @{ type = "string" }
                expires_in = @{ type = "integer" }
            }
        }
        ChatCompletionRequest = @{
            type = "object"
            properties = @{
                model = @{ type = "string"; description = "Model ID" }
                messages = @{
                    type = "array"
                    items = @{ '$ref' = "#/components/schemas/Message" }
                }
                max_tokens = @{ type = "integer"; default = 1024 }
                temperature = @{ type = "number"; default = 0.7 }
                stream = @{ type = "boolean"; default = $false }
            }
            required = @("model", "messages")
        }
        Message = @{
            type = "object"
            properties = @{
                role = @{ type = "string"; enum = @("system", "user", "assistant") }
                content = @{ type = "string" }
            }
        }
        ChatCompletionResponse = @{
            type = "object"
            properties = @{
                id = @{ type = "string" }
                object = @{ type = "string" }
                created = @{ type = "integer" }
                model = @{ type = "string" }
                choices = @{
                    type = "array"
                    items = @{ '$ref' = "#/components/schemas/Choice" }
                }
                usage = @{ '$ref' = "#/components/schemas/Usage" }
            }
        }
        Choice = @{
            type = "object"
            properties = @{
                index = @{ type = "integer" }
                message = @{ '$ref' = "#/components/schemas/Message" }
                finish_reason = @{ type = "string" }
            }
        }
        Usage = @{
            type = "object"
            properties = @{
                prompt_tokens = @{ type = "integer" }
                completion_tokens = @{ type = "integer" }
                total_tokens = @{ type = "integer" }
            }
        }
        EmbeddingRequest = @{
            type = "object"
            properties = @{
                model = @{ type = "string" }
                input = @{ type = "string" }
            }
            required = @("model", "input")
        }
        EmbeddingResponse = @{
            type = "object"
            properties = @{
                object = @{ type = "string" }
                data = @{
                    type = "array"
                    items = @{ '$ref' = "#/components/schemas/Embedding" }
                }
                model = @{ type = "string" }
                usage = @{ '$ref' = "#/components/schemas/Usage" }
            }
        }
        Embedding = @{
            type = "object"
            properties = @{
                object = @{ type = "string" }
                embedding = @{ type = "array"; items = @{ type = "number" } }
                index = @{ type = "integer" }
            }
        }
        ModelList = @{
            type = "object"
            properties = @{
                object = @{ type = "string" }
                data = @{
                    type = "array"
                    items = @{ '$ref' = "#/components/schemas/Model" }
                }
            }
        }
        Model = @{
            type = "object"
            properties = @{
                id = @{ type = "string" }
                object = @{ type = "string" }
                created = @{ type = "integer" }
                owned_by = @{ type = "string" }
            }
        }
        CreateTenantRequest = @{
            type = "object"
            properties = @{
                name = @{ type = "string" }
                email = @{ type = "string"; format = "email" }
                tier = @{ type = "string"; enum = @("free", "standard", "enterprise") }
            }
            required = @("name", "email", "tier")
        }
        Tenant = @{
            type = "object"
            properties = @{
                id = @{ type = "string" }
                name = @{ type = "string" }
                email = @{ type = "string" }
                tier = @{ type = "string" }
                created_at = @{ type = "string"; format = "date-time" }
                status = @{ type = "string" }
            }
        }
        UsageResponse = @{
            type = "object"
            properties = @{
                tenant_id = @{ type = "string" }
                period = @{ type = "string" }
                total_tokens = @{ type = "integer" }
                total_requests = @{ type = "integer" }
                daily_usage = @{ type = "array"; items = @{ type = "object" } }
            }
        }
        HealthResponse = @{
            type = "object"
            properties = @{
                status = @{ type = "string" }
                version = @{ type = "string" }
                timestamp = @{ type = "string"; format = "date-time" }
            }
        }
    }
}

function New-OpenAPISpec {
    Write-Host "`nGenerating OpenAPI specification..." -ForegroundColor Yellow
    
    $endpoints = Get-APIEndpoints
    $schemas = Get-APISchemas
    
    # Build paths
    $paths = @{}
    foreach ($endpoint in $endpoints) {
        if (-not $paths.ContainsKey($endpoint.Path)) {
            $paths[$endpoint.Path] = @{}
        }
        
        $pathItem = @{
            summary = $endpoint.Summary
            description = $endpoint.Description
            tags = $endpoint.Tags
        }
        
        if ($endpoint.ContainsKey("Security")) {
            $pathItem.security = $endpoint.Security
        }
        
        if ($endpoint.ContainsKey("RequestBody")) {
            $pathItem.requestBody = $endpoint.RequestBody
        }
        
        if ($endpoint.ContainsKey("Parameters")) {
            $pathItem.parameters = $endpoint.Parameters
        }
        
        $pathItem.responses = $endpoint.Responses
        
        $paths[$endpoint.Path][$endpoint.Method.ToLower()] = $pathItem
    }
    
    $spec = @{
        openapi = "3.0.0"
        info = @{
            title = "RawrXD API"
            description = "Complete API reference for the RawrXD platform"
            version = "1.0.0"
            contact = @{
                name = "RawrXD Support"
                email = "api@rawrxd.io"
            }
        }
        servers = @(
            @{ url = "https://api.rawrxd.io/v1"; description = "Production server" }
            @{ url = "https://staging-api.rawrxd.io/v1"; description = "Staging server" }
        )
        paths = $paths
        components = @{
            schemas = $schemas
            securitySchemes = @{
                bearerAuth = @{
                    type = "http"
                    scheme = "bearer"
                    bearerFormat = "JWT"
                }
            }
        }
    }
    
    $specPath = Join-Path $OutputPath "openapi.json"
    $spec | ConvertTo-Json -Depth 20 | Set-Content -Path $specPath
    
    $script:APIRegistry.Endpoints = $endpoints
    $script:APIRegistry.Schemas = $schemas
    Save-APIRegistry
    
    Write-Host "  ✓ OpenAPI spec generated: $specPath" -ForegroundColor Green
    Write-Host "  ✓ Endpoints: $($endpoints.Count)" -ForegroundColor Gray
    Write-Host "  ✓ Schemas: $($schemas.Count)" -ForegroundColor Gray
}

function Export-APIDocumentation {
    param($Format)
    
    Write-Host "`nExporting API documentation ($Format)..." -ForegroundColor Yellow
    
    switch ($Format) {
        "markdown" {
            $exportDir = Join-Path $OutputPath "markdown"
            New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
            
            # Generate markdown for each endpoint
            foreach ($endpoint in $script:APIRegistry.Endpoints) {
                $content = @"
# $($endpoint.Summary)

**$($endpoint.Method.ToUpper())** `$($endpoint.Path)`

## Description

$($endpoint.Description)

## Authentication

$(if ($endpoint.Security) { "This endpoint requires Bearer token authentication." } else { "No authentication required." })

## Request

$(if ($endpoint.RequestBody) { "### Body`n`n```json`n$($endpoint.RequestBody.content['application/json'].schema | ConvertTo-Json -Depth 5)`n```" } else { "No request body required." })

## Responses

| Status | Description |
|--------|-------------|
"@
                foreach ($response in $endpoint.Responses.GetEnumerator()) {
                    $content += "`n| $($response.Key) | $($response.Value.description) |"
                }
                
                $content += "`n`n---`n"
                
                $filename = ($endpoint.Path -replace '[/{}]', '_') + ".md"
                $content | Set-Content -Path (Join-Path $exportDir $filename)
            }
            
            Write-Host "  ✓ Markdown exported to: $exportDir" -ForegroundColor Green
        }
        
        "json" {
            $jsonPath = Join-Path $OutputPath "api_reference.json"
            $script:APIRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath
            Write-Host "  ✓ JSON exported to: $jsonPath" -ForegroundColor Green
        }
        
        default {
            Write-Warning "Export format '$Format' not yet implemented"
        }
    }
}

function Test-APISpec {
    Write-Host "`nValidating API specification..." -ForegroundColor Yellow
    
    $issues = @()
    
    # Check for required fields
    foreach ($endpoint in $script:APIRegistry.Endpoints) {
        if (-not $endpoint.Summary) {
            $issues += "Endpoint $($endpoint.Path) missing summary"
        }
        if (-not $endpoint.Responses.ContainsKey("200") -and -not $endpoint.Responses.ContainsKey("201")) {
            $issues += "Endpoint $($endpoint.Path) missing success response"
        }
    }
    
    # Check for orphaned schemas
    $schemaNames = $script:APIRegistry.Schemas.Keys
    $specJson = $script:APIRegistry | ConvertTo-Json -Depth 10
    foreach ($schema in $schemaNames) {
        if ($specJson -notmatch "`"#`/components/schemas/$schema`"") {
            $issues += "Schema '$schema' may be unused"
        }
    }
    
    if ($issues.Count -eq 0) {
        Write-Host "  ✓ API specification is valid" -ForegroundColor Green
    } else {
        Write-Host "`n  Issues found:" -ForegroundColor Yellow
        foreach ($issue in $issues) {
            Write-Host "    ⚠ $issue" -ForegroundColor Yellow
        }
    }
}

function Start-APIServer {
    param($Port)
    
    Write-Host "`nStarting API documentation server on port $Port..." -ForegroundColor Yellow
    Write-Host "  OpenAPI spec: http://localhost:$Port/openapi.json" -ForegroundColor Cyan
    Write-Host "  Swagger UI: http://localhost:$Port/swagger" -ForegroundColor Cyan
    Write-Host "`nPress Ctrl+C to stop" -ForegroundColor Gray
    
    # Create simple HTTP listener
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://localhost:$Port/")
    $listener.Start()
    
    try {
        while ($listener.IsListening) {
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response
            
            $openapiPath = Join-Path $OutputPath "openapi.json"
            
            if ($request.Url.PathAndQuery -eq "/openapi.json" -and (Test-Path $openapiPath)) {
                $content = Get-Content -Path $openapiPath -Raw
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)
                $response.ContentType = "application/json"
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            } else {
                $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD API Documentation</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #333; }
        a { color: #0066cc; }
        .endpoint { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .method { font-weight: bold; color: #0066cc; }
    </style>
</head>
<body>
    <h1>RawrXD API Documentation</h1>
    <p>Welcome to the RawrXD API documentation server.</p>
    <ul>
        <li><a href="/openapi.json">OpenAPI Specification (JSON)</a></li>
    </ul>
    <h2>Endpoints</h2>
"@
                foreach ($ep in $script:APIRegistry.Endpoints) {
                    $html += "    <div class='endpoint'><span class='method'>$($ep.Method.ToUpper())</span> $($ep.Path) - $($ep.Summary)</div>`n"
                }
                
                $html += @"
    <hr>
    <p><small>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</small></p>
</body>
</html>
"@
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
                $response.ContentType = "text/html"
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
            
            $response.Close()
        }
    } finally {
        $listener.Stop()
        Write-Host "`nServer stopped" -ForegroundColor Yellow
    }
}

# Main execution
Write-APIRefHeader
Initialize-APIReference

switch ($Action) {
    "generate" {
        New-OpenAPISpec
    }
    "validate" {
        if ($script:APIRegistry.Endpoints.Count -eq 0) {
            New-OpenAPISpec
        }
        Test-APISpec
    }
    "export" {
        if ($script:APIRegistry.Endpoints.Count -eq 0) {
            New-OpenAPISpec
        }
        Export-APIDocumentation -Format $Format
    }
    "serve" {
        if ($script:APIRegistry.Endpoints.Count -eq 0) {
            New-OpenAPISpec
        }
        Start-APIServer -Port $Port
    }
}

Write-Host "`n✅ API reference operation complete" -ForegroundColor Green
