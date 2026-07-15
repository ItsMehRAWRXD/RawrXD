# RawrXD Configuration Validator
# Validates configuration files and schemas

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Validate", "Schema", "Check", "Fix", "Diff")]
    [string]$Action = "Validate",
    
    [string]$ConfigFile = "",
    [string]$SchemaFile = "",
    [string]$CompareFile = "",
    [switch]$FixIssues
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

function Initialize-ConfigValidator {
    Write-Status "Configuration Validator initialized"
}

function Get-ConfigSchema {
    return @{
        type = "object"
        required = @("name", "version", "server")
        properties = @{
            name = @{ type = "string" }
            version = @{ type = "string"; pattern = "^\d+\.\d+\.\d+$" }
            server = @{
                type = "object"
                required = @("host", "port")
                properties = @{
                    host = @{ type = "string" }
                    port = @{ type = "integer"; minimum = 1; maximum = 65535 }
                    workers = @{ type = "integer"; minimum = 1 }
                }
            }
            model = @{
                type = "object"
                properties = @{
                    default_model = @{ type = "string" }
                    context_length = @{ type = "integer"; minimum = 1 }
                    batch_size = @{ type = "integer"; minimum = 1 }
                }
            }
            logging = @{
                type = "object"
                properties = @{
                    level = @{ type = "string"; enum = @("debug", "info", "warn", "error") }
                    file = @{ type = "string" }
                }
            }
        }
    }
}

function Test-ConfigFile {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        Write-Error "Config file not found: $Path"
        return $false
    }
    
    Write-Status "Validating: $Path"
    
    $issues = @()
    $warnings = @()
    
    try {
        $content = Get-Content $Path -Raw
        $config = $content | ConvertFrom-Json
        
        # Check required fields
        $required = @("name", "version", "server")
        foreach ($field in $required) {
            if (-not $config.$field) {
                $issues += "Missing required field: $field"
            }
        }
        
        # Validate version format
        if ($config.version -and $config.version -notmatch "^\d+\.\d+\.\d+$") {
            $issues += "Invalid version format (expected: x.x.x)"
        }
        
        # Validate server settings
        if ($config.server) {
            if ($config.server.port -lt 1 -or $config.server.port -gt 65535) {
                $issues += "Invalid port number"
            }
        }
        
        # Check for unknown fields
        $knownFields = @("name", "version", "server", "model", "logging", "security", "cache")
        $configFields = $config.PSObject.Properties.Name
        foreach ($field in $configFields) {
            if ($field -notin $knownFields) {
                $warnings += "Unknown field: $field"
            }
        }
        
        # Display results
        if ($issues.Count -eq 0 -and $warnings.Count -eq 0) {
            Write-Success "Configuration is valid"
            return $true
        } else {
            if ($issues.Count -gt 0) {
                Write-Error "Validation failed with $($issues.Count) issue(s)"
                foreach ($issue in $issues) {
                    Write-Host "  ✗ $issue" -ForegroundColor Red
                }
            }
            if ($warnings.Count -gt 0) {
                Write-Warning "$($warnings.Count) warning(s)"
                foreach ($warning in $warnings) {
                    Write-Host "  ⚠ $warning" -ForegroundColor Yellow
                }
            }
            return $false
        }
    }
    catch {
        Write-Error "Invalid JSON: $_"
        return $false
    }
}

function Show-ConfigSchema {
    Write-Host ""
    Write-Host "Configuration Schema" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    
    $schema = Get-ConfigSchema
    
    Write-Host "Required Fields:" -ForegroundColor Yellow
    foreach ($field in $schema.required) {
        Write-Host "  • $field"
    }
    
    Write-Host ""
    Write-Host "Properties:" -ForegroundColor Yellow
    foreach ($prop in $schema.properties.GetEnumerator()) {
        $type = $prop.Value.type
        Write-Host "  $($prop.Key) ($type)"
        
        if ($prop.Value.required) {
            Write-Host "    Required sub-fields: $($prop.Value.required -join ', ')"
        }
    }
}

function Compare-Configs {
    param([string]$File1, [string]$File2)
    
    if (-not (Test-Path $File1) -or -not (Test-Path $File2)) {
        Write-Error "One or both files not found"
        return
    }
    
    Write-Status "Comparing configurations..."
    
    $config1 = Get-Content $File1 | ConvertFrom-Json
    $config2 = Get-Content $File2 | ConvertFrom-Json
    
    $diffs = @()
    
    # Compare top-level fields
    $fields1 = $config1.PSObject.Properties.Name
    $fields2 = $config2.PSObject.Properties.Name
    
    $allFields = $fields1 + $fields2 | Select-Object -Unique
    
    foreach ($field in $allFields) {
        $val1 = $config1.$field | ConvertTo-Json -Compress
        $val2 = $config2.$field | ConvertTo-Json -Compress
        
        if ($val1 -ne $val2) {
            $diffs += [PSCustomObject]@{
                Field = $field
                File1 = $val1
                File2 = $val2
            }
        }
    }
    
    Write-Host ""
    Write-Host "Configuration Differences" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host "  File 1: $File1"
    Write-Host "  File 2: $File2"
    Write-Host ""
    
    if ($diffs.Count -eq 0) {
        Write-Success "Configurations are identical"
    } else {
        Write-Host "  Found $($diffs.Count) difference(s):" -ForegroundColor Yellow
        foreach ($diff in $diffs) {
            Write-Host "  Field: $($diff.Field)" -ForegroundColor Cyan
            Write-Host "    File1: $($diff.File1)"
            Write-Host "    File2: $($diff.File2)"
        }
    }
}

function Repair-ConfigFile {
    param([string]$Path)
    
    Write-Status "Attempting to repair: $Path"
    
    try {
        $content = Get-Content $Path -Raw
        $config = $content | ConvertFrom-Json
        
        $fixed = $false
        
        # Fix missing required fields with defaults
        if (-not $config.name) {
            $config.name = "rawrxd"
            $fixed = $true
            Write-Warning "Added default name"
        }
        
        if (-not $config.version) {
            $config.version = "1.0.0"
            $fixed = $true
            Write-Warning "Added default version"
        }
        
        if (-not $config.server) {
            $config.server = @{ host = "0.0.0.0"; port = 8080 }
            $fixed = $true
            Write-Warning "Added default server config"
        }
        
        if ($fixed) {
            $config | ConvertTo-Json -Depth 5 | Out-File $Path
            Write-Success "Configuration repaired"
        } else {
            Write-Success "No repairs needed"
        }
    }
    catch {
        Write-Error "Could not repair: $_"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Configuration Validator" -ForegroundColor Cyan
    Write-Host "=============================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-ConfigValidator
    
    switch ($Action) {
        "Validate" {
            if (-not $ConfigFile) {
                Write-Error "Specify -ConfigFile"
                return
            }
            $valid = Test-ConfigFile -Path $ConfigFile
            if (-not $valid -and $FixIssues) {
                Repair-ConfigFile -Path $ConfigFile
            }
        }
        "Schema" { Show-ConfigSchema }
        "Check" {
            if ($ConfigFile) {
                Test-ConfigFile -Path $ConfigFile
            } else {
                Write-Error "Specify -ConfigFile"
            }
        }
        "Fix" {
            if (-not $ConfigFile) {
                Write-Error "Specify -ConfigFile"
                return
            }
            Repair-ConfigFile -Path $ConfigFile
        }
        "Diff" {
            if (-not $ConfigFile -or -not $CompareFile) {
                Write-Error "Specify both -ConfigFile and -CompareFile"
                return
            }
            Compare-Configs -File1 $ConfigFile -File2 $CompareFile
        }
    }
    
    Write-Host ""
}

Main
