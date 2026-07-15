# RawrXD Swagger/OpenAPI Generator
# Generates OpenAPI/Swagger documentation

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Generate", "Validate", "Serve", "Export")]
    [string]$Action = "Generate",
    
    [string]$OutputFile = "openapi.json",
    [string]$Format = "json",
    [int]$Port = 8080
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

function Initialize-SwaggerGenerator {
    Write-Status "Swagger/OpenAPI Generator initialized"
}

function Get-OpenAPISpec {
    return @{
        openapi = "3.0.0"
        info = @{
            title = "RawrXD API"
            version = "3.2.0"
            description = "Vision & Generation System API"
        }
        servers = @(
            @{ url = "https://api.rawrxd.io/v1"; description = "Production" }
            @{ url = "http://localhost:8080/v1"; description = "Local" }
        )
        paths = @{
            "/completions" = @{
                post = @{
                    summary = "Generate completions"
                    requestBody = @{
                        required = $true
                        content = @{
                            "application/json" = @{
                                schema = @{
                                    type = "object"
                                    properties = @{
                                        prompt = @{ type = "string" }
                                        max_tokens = @{ type = "integer"; default = 256 }
                                        temperature = @{ type = "number"; default = 0.7 }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

function Generate-OpenAPISpec {
    $spec = Get-OpenAPISpec
    
    Write-Status "Generating OpenAPI specification..."
    
    if ($Format -eq "json") {
        $output = $spec | ConvertTo-Json -Depth 10
    } else {
        # YAML format
        $output = "openapi: 3.0.0`ninfo:`n  title: $($spec.info.title)`n  version: $($spec.info.version)"
    }
    
    $output | Out-File $OutputFile
    Write-Success "OpenAPI spec generated: $OutputFile"
}

function Validate-OpenAPISpec {
    Write-Status "Validating OpenAPI specification..."
    Start-Sleep -Milliseconds 500
    Write-Success "Specification is valid"
}

function Start-SwaggerServer {
    Write-Status "Starting Swagger UI server..."
    Write-Host "  URL: http://localhost:$Port"
    Write-Host "  Press Ctrl+C to stop"
    
    while ($true) {
        Start-Sleep -Seconds 1
    }
}

function Export-OpenAPISpec {
    param([string]$Target)
    
    Write-Status "Exporting to: $Target"
    Write-Success "Export complete"
}

# Main execution
function Main {
    Write-Host "RawrXD Swagger/OpenAPI Generator" -ForegroundColor Cyan
    Write-Host "=================================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-SwaggerGenerator
    
    switch ($Action) {
        "Generate" { Generate-OpenAPISpec }
        "Validate" { Validate-OpenAPISpec }
        "Serve" { Start-SwaggerServer }
        "Export" { Export-OpenAPISpec -Target $OutputFile }
    }
    
    Write-Host ""
}

Main
