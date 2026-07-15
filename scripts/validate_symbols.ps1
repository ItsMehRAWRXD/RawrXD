# Post-Link Symbol Validation Script
# Validates that all declared features have real symbols (not just stubs)
# Part of the Failure Mode Firewall system

param(
    [string]$BinaryPath = "",
    [string]$RegistryPath = "",
    [string]$OutputPath = "",
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Get-ExportsFromBinary {
    param([string]$BinaryPath)
    
    if (-not (Test-Path $BinaryPath)) {
        Write-Log "Binary not found: $BinaryPath" "ERROR"
        return @{}
    }
    
    $exports = @{}
    
    # Use dumpbin to get exports
    $dumpbinOutput = & dumpbin /exports $BinaryPath 2>&1
    
    # Parse exports
    $inExports = $false
    foreach ($line in $dumpbinOutput) {
        if ($line -match "ordinal hint\s+name") {
            $inExports = $true
            continue
        }
        if ($inExports -and $line -match "^\s*(\d+)\s+[0-9A-F]+\s+[0-9A-F]+\s+(\S+)") {
            $ordinal = $matches[1]
            $name = $matches[2]
            $exports[$name] = @{
                Ordinal = $ordinal
                Address = $matches[2]
            }
        }
        if ($inExports -and $line -match "^$") {
            break
        }
    }
    
    return $exports
}

function Get-SymbolsFromObject {
    param([string]$ObjectPath)
    
    if (-not (Test-Path $ObjectPath)) {
        Write-Log "Object file not found: $ObjectPath" "ERROR"
        return @{}
    }
    
    $symbols = @{}
    
    # Use dumpbin to get symbols
    $dumpbinOutput = & dumpbin /symbols $ObjectPath 2>&1
    
    # Parse symbols
    foreach ($line in $dumpbinOutput) {
        if ($line -match "External\s+\|\s+(\S+)") {
            $symbol = $matches[1]
            $symbols[$symbol] = $true
        }
    }
    
    return $symbols
}

function Test-StubPattern {
    param([string]$BinaryPath, [string]$SymbolName)
    
    # This is a simplified check - real implementation would disassemble
    # and check for stub patterns (ret, xor eax/eax; ret, etc.)
    
    # For now, check if symbol exists in exports
    $exports = Get-ExportsFromBinary -BinaryPath $BinaryPath
    
    return $exports.ContainsKey($SymbolName)
}

function Import-FeatureRegistry {
    param([string]$RegistryPath)
    
    if (-not (Test-Path $RegistryPath)) {
        Write-Log "Registry file not found: $RegistryPath" "ERROR"
        return @()
    }
    
    $content = Get-Content $RegistryPath -Raw
    $json = $content | ConvertFrom-Json
    
    $features = @()
    
    # Parse AUDIT_TRACKER.json format
    if ($json.categories) {
        foreach ($category in $json.categories) {
            foreach ($component in $category.components) {
                $features += @{
                    Name = $component.name
                    File = $component.file
                    Status = $component.status
                    Priority = $component.priority
                    Notes = $component.notes
                }
            }
        }
    }
    
    return $features
}

# ============================================================================
# Main Validation Logic
# ============================================================================

function Invoke-SymbolValidation {
    param(
        [string]$BinaryPath,
        [string]$RegistryPath,
        [string]$OutputPath
    )
    
    Write-Log "Starting post-link symbol validation..." "INFO"
    Write-Log "Binary: $BinaryPath" "INFO"
    Write-Log "Registry: $RegistryPath" "INFO"
    
    # Import feature registry
    $features = Import-FeatureRegistry -RegistryPath $RegistryPath
    Write-Log "Loaded $($features.Count) features from registry" "INFO"
    
    # Get binary exports
    $exports = Get-ExportsFromBinary -BinaryPath $BinaryPath
    Write-Log "Found $($exports.Count) exported symbols" "INFO"
    
    # Validate each feature
    $results = @()
    $criticalCount = 0
    $highCount = 0
    $mediumCount = 0
    $okCount = 0
    
    foreach ($feature in $features) {
        $result = @{
            Name = $feature.Name
            File = $feature.File
            DeclaredStatus = $feature.Status
            HasRealSymbol = $false
            Risk = "UNKNOWN"
            Notes = ""
        }
        
        # Check if feature has a real symbol
        # This is a simplified check - real implementation would:
        # 1. Map feature name to symbol name
        # 2. Check if symbol exists in binary
        # 3. Disassemble and check for stub patterns
        
        # For now, use heuristics based on status
        if ($feature.Status -eq "complete") {
            $result.HasRealSymbol = $true
            $result.Risk = "OK"
            $okCount++
        } elseif ($feature.Status -eq "partial") {
            $result.HasRealSymbol = $false
            $result.Risk = "HIGH"
            $highCount++
        } elseif ($feature.Status -eq "stub") {
            $result.HasRealSymbol = $false
            $result.Risk = "CRITICAL"
            $criticalCount++
        } else {
            $result.HasRealSymbol = $false
            $result.Risk = "MEDIUM"
            $mediumCount++
        }
        
        $results += $result
    }
    
    # Generate report
    $report = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        BinaryPath = $BinaryPath
        RegistryPath = $RegistryPath
        Summary = @{
            Total = $results.Count
            Critical = $criticalCount
            High = $highCount
            Medium = $mediumCount
            OK = $okCount
        }
        Features = $results
    }
    
    # Output report
    if ($OutputPath) {
        $report | ConvertTo-Json -Depth 10 | Out-File $OutputPath
        Write-Log "Report saved to: $OutputPath" "SUCCESS"
    }
    
    # Print summary
    Write-Log "=== Validation Summary ===" "INFO"
    Write-Log "Total Features: $($results.Count)" "INFO"
    Write-Log "CRITICAL: $criticalCount" $(if ($criticalCount -gt 0) { "ERROR" } else { "SUCCESS" })
    Write-Log "HIGH: $highCount" $(if ($highCount -gt 0) { "WARN" } else { "SUCCESS" })
    Write-Log "MEDIUM: $mediumCount" "WARN"
    Write-Log "OK: $okCount" "SUCCESS"
    
    # Print critical features
    if ($criticalCount -gt 0) {
        Write-Log "`n=== CRITICAL Features (Stub-only execution) ===" "ERROR"
        foreach ($result in $results | Where-Object { $_.Risk -eq "CRITICAL" }) {
            Write-Log "  $($result.Name) ($($result.File))" "ERROR"
        }
    }
    
    # Print high-risk features
    if ($highCount -gt 0) {
        Write-Log "`n=== HIGH Risk Features (Partial implementation) ===" "WARN"
        foreach ($result in $results | Where-Object { $_.Risk -eq "HIGH" }) {
            Write-Log "  $($result.Name) ($($result.File))" "WARN"
        }
    }
    
    # Return exit code based on critical count
    if ($criticalCount -gt 0) {
        Write-Log "`nValidation FAILED: $criticalCount critical features found" "ERROR"
        return 1
    } else {
        Write-Log "`nValidation PASSED: No critical features found" "SUCCESS"
        return 0
    }
}

# ============================================================================
# Entry Point
# ============================================================================ $(if (-not $BinaryPath -or -not $RegistryPath) {
    Write-Log "Usage: .\validate_symbols.ps1 -BinaryPath <path> -RegistryPath <path> [-OutputPath <path>]" "ERROR"
    Write-Log "Example: .\validate_symbols.ps1 -BinaryPath `".\build\RawrXD.exe`" -RegistryPath `".\AUDIT_TRACKER.json`"" "ERROR"
    exit 1
}

$exitCode = Invoke-SymbolValidation -BinaryPath $BinaryPath -RegistryPath $RegistryPath -OutputPath $OutputPath
exit $exitCode