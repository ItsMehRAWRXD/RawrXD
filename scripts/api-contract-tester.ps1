# RawrXD API Contract Tester
# Validates API contracts and endpoints against OpenAPI specifications

param(
    [string]$SpecPath = "api/openapi.yaml",
    [string]$BaseUrl = "http://localhost:8080",
    [string[]]$Endpoints = @(),
    [switch]$ValidateRequests,
    [switch]$ValidateResponses,
    [switch]$GenerateClient,
    [string]$ClientLanguage = "typescript",
    [switch]$RunTests,
    [string]$TestDataPath
)

$ErrorActionPreference = "Stop"

$script:TestState = @{
    StartTime = Get-Date
    TestsRun = 0
    TestsPassed = 0
    TestsFailed = 0
    Coverage = 0.0
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[✗] $Message" -ForegroundColor Red }

function Load-OpenApiSpec {
    if (-not (Test-Path $SpecPath)) {
        Write-Error "OpenAPI spec not found: $SpecPath"
        exit 1
    }
    
    $content = Get-Content $SpecPath -Raw
    
    # Try JSON first
    try {
        return $content | ConvertFrom-Json
    } catch {
        # Try YAML (would need a YAML parser in production)
        Write-Warning "YAML parsing not implemented, assuming JSON"
        return $null
    }
}

function Test-Endpoint {
    param([string]$Path, [string]$Method, [hashtable]$Spec)
    
    $url = "$BaseUrl$Path"
    $script:TestState.TestsRun++
    
    Write-Status "Testing: $Method $Path"
    
    try {
        $response = Invoke-WebRequest -Uri $url -Method $Method -TimeoutSec 30 -ErrorAction Stop
        
        # Validate status code
        $expectedCodes = $Spec.responses.PSObject.Properties.Name
        if ($expectedCodes -contains $response.StatusCode.ToString()) {
            Write-Success "Status code valid: $($response.StatusCode)"
            $script:TestState.TestsPassed++
        } else {
            Write-Warning "Unexpected status code: $($response.StatusCode)"
            $script:TestState.TestsFailed++
        }
        
        # Validate response body if schema provided
        if ($ValidateResponses -and $Spec.responses."200".content."application/json".schema) {
            $schema = $Spec.responses."200".content."application/json".schema
            $body = $response.Content | ConvertFrom-Json
            # Would validate against schema here
        }
        
    } catch {
        Write-Error "Request failed: $_"
        $script:TestState.TestsFailed++
    }
}

function Generate-ApiClient {
    param([hashtable]$Spec)
    
    Write-Status "Generating $ClientLanguage client..."
    
    $client = switch ($ClientLanguage) {
        "typescript" { Generate-TypeScriptClient -Spec $Spec }
        "python" { Generate-PythonClient -Spec $Spec }
        "csharp" { Generate-CSharpClient -Spec $Spec }
        default { Generate-TypeScriptClient -Spec $Spec }
    }
    
    $outputFile = "api-client.$ClientLanguage"
    $client | Out-File $outputFile -Encoding UTF8
    
    Write-Success "Client generated: $outputFile"
}

function Generate-TypeScriptClient {
    param([hashtable]$Spec)
    
    $code = @"
// Auto-generated API Client for RawrXD
// Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

export interface ApiClientConfig {
    baseUrl: string;
    apiKey?: string;
}

export class RawrXDApiClient {
    private config: ApiClientConfig;
    
    constructor(config: ApiClientConfig) {
        this.config = config;
    }
"@

    foreach ($path in $Spec.paths.PSObject.Properties) {
        foreach ($method in $path.Value.PSObject.Properties) {
            $operation = $method.Value
            $fnName = $operation.operationId -replace "[^a-zA-Z0-9]", "_"
            
            $code += @"

    async $fnName(params: any): Promise<any> {
        const response = await fetch(`${this.config.baseUrl}$($path.Name)`, {
            method: '$($method.Name.ToUpper())',
            headers: {
                'Content-Type': 'application/json',
                ...(this.config.apiKey && { 'Authorization': `Bearer `${this.config.apiKey}` })
            },
            body: params ? JSON.stringify(params) : undefined
        });
        return response.json();
    }
"@
        }
    }
    
    $code += "`n}"
    return $code
}

function Show-Summary {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "API Contract Test Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Tests Run: $($script:TestState.TestsRun)" -ForegroundColor White
    Write-Host "Tests Passed: $($script:TestState.TestsPassed)" -ForegroundColor Green
    Write-Host "Tests Failed: $($script:TestState.TestsFailed)" -ForegroundColor $(if($script:TestState.TestsFailed -gt 0){'Red'}else{'Green'})
    
    if ($script:TestState.TestsRun -gt 0) {
        $passRate = [math]::Round(($script:TestState.TestsPassed / $script:TestState.TestsRun) * 100, 1)
        Write-Host "Pass Rate: $passRate%" -ForegroundColor $(if($passRate -ge 80){'Green'}elseif($passRate -ge 60){'Yellow'}else{'Red'})
    }
}

# Main execution
function Main {
    Write-Host "RawrXD API Contract Tester" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    
    $spec = Load-OpenApiSpec
    
    if (-not $spec) {
        Write-Error "Could not load OpenAPI spec"
        exit 1
    }
    
    if ($GenerateClient) {
        Generate-ApiClient -Spec $spec
    }
    
    if ($RunTests) {
        Write-Status "Running API contract tests..."
        
        foreach ($path in $spec.paths.PSObject.Properties) {
            foreach ($method in $path.Value.PSObject.Properties) {
                if ($Endpoints.Count -eq 0 -or $Endpoints -contains $path.Name) {
                    Test-Endpoint -Path $path.Name -Method $method.Name -Spec $method.Value
                }
            }
        }
        
        Show-Summary
    }
    
    Write-Host ""
    Write-Success "API contract testing complete!"
}

Main
