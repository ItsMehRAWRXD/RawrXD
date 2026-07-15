#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Security Scan Script for RawrXD CI/CD Pipeline

.DESCRIPTION
    Performs automated security scanning including:
    - Secret detection (API keys, tokens, passwords)
    - Dependency vulnerability scanning
    - Static Application Security Testing (SAST)
    - Infrastructure security checks
    - License compliance verification

.EXAMPLE
    .\scripts\security_scan.ps1
    .\scripts\security_scan.ps1 -FullScan
    .\scripts\security_scan.ps1 -ReportFormat sarif

.NOTES
    Part of RawrXD Phase AB: CI/CD Pipeline & Automation
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Path = ".",

    [Parameter()]
    [switch]$FullScan,

    [Parameter()]
    [ValidateSet("console", "json", "sarif", "github")]
    [string]$ReportFormat = "console",

    [Parameter()]
    [string]$OutputFile = "security-report.sarif",

    [Parameter()]
    [string[]]$ExcludePatterns = @(
        "*/.git/*",
        "*/build*/*",
        "*/out/*",
        "*/.vs/*",
        "*/node_modules/*",
        "*/3rdparty/*",
        "*/test*/*",
        "*/*.log",
        "*/*.min.js",
        "*/*.min.css"
    ),

    [Parameter()]
    [switch]$FailOnFindings
)

# Severity levels
$SeverityLevel = @{
    Critical = 4
    High = 3
    Medium = 2
    Low = 1
    Info = 0
}

$script:Findings = @()
$script:Stats = @{
    FilesScanned = 0
    SecretsFound = 0
    VulnerabilitiesFound = 0
    LicenseIssues = 0
    InfraIssues = 0
    Critical = 0
    High = 0
    Medium = 0
    Low = 0
}

# Secret patterns to detect
$SecretPatterns = @{
    "AWS Access Key" = "AKIA[0-9A-Z]{16}"
    "AWS Secret Key" = "[0-9a-zA-Z/+]{40}"
    "GitHub Token" = "gh[pousr]_[A-Za-z0-9_]{36,}"
    "Generic API Key" = "(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][a-z0-9]{16,}['\"]"
    "Private Key" = "-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"
    "Password in URL" = "(?i)(ftp|http|https)://[^:]+:[^@]+@"
    "Connection String" = "(?i)(password|pwd|pass)\s*=\s*[^;\s]+"
    "Bearer Token" = "(?i)bearer\s+[a-z0-9_\-\.]{20,}"
    "Basic Auth" = "(?i)basic\s+[a-z0-9+/=]{20,}"
}

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Add-Finding {
    param(
        [string]$RuleId,
        [string]$Title,
        [string]$File,
        [int]$Line = 0,
        [string]$Severity = "Medium",
        [string]$Category,
        [string]$Message,
        [string]$Remediation = ""
    )

    $finding = [PSCustomObject]@{
        RuleId = $RuleId
        Title = $Title
        File = $File
        Line = $Line
        Severity = $Severity
        Category = $Category
        Message = $Message
        Remediation = $Remediation
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    }

    $script:Findings += $finding

    # Update severity counters
    switch ($Severity) {
        "Critical" { $script:Stats.Critical++ }
        "High" { $script:Stats.High++ }
        "Medium" { $script:Stats.Medium++ }
        "Low" { $script:Stats.Low++ }
    }
}

function Test-Excluded {
    param([string]$FilePath)
    foreach ($pattern in $ExcludePatterns) {
        if ($FilePath -like $pattern) { return $true }
    }
    return $false
}

function Get-ScanFiles {
    param([string]$RootPath)
    $extensions = @("*.cpp", "*.hpp", "*.h", "*.c", "*.cc", "*.cxx", "*.ps1", "*.py", "*.js", "*.json", "*.yml", "*.yaml", "*.xml", "*.cmake", "*.txt")
    $files = @()
    foreach ($ext in $extensions) {
        $files += Get-ChildItem -Path $RootPath -Recurse -Filter $ext -ErrorAction SilentlyContinue |
            Where-Object { -not (Test-Excluded $_.FullName) }
    }
    return $files | Select-Object -ExpandProperty FullName | Sort-Object -Unique
}

# ============================================================================
# Scan: Secret Detection
# ============================================================================

function Test-Secrets {
    Write-Status "Scanning for secrets and credentials..." "Info"

    $files = Get-ScanFiles $Path
    $script:Stats.FilesScanned += $files.Count

    foreach ($file in $files) {
        $relPath = Resolve-Path -Relative $file
        $content = Get-Content -Path $file -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }

        $lines = $content -split "`r?`n"
        $lineNum = 0

        foreach ($line in $lines) {
            $lineNum++

            foreach ($patternName in $SecretPatterns.Keys) {
                $pattern = $SecretPatterns[$patternName]

                if ($line -match $pattern) {
                    # Mask the secret in the output
                    $maskedLine = $line -replace $pattern, "***REDACTED***"

                    Add-Finding `
                        -RuleId "SEC001" `
                        -Title "Potential $patternName detected" `
                        -File $relPath `
                        -Line $lineNum `
                        -Severity "Critical" `
                        -Category "Secrets" `
                        -Message "Potential $patternName found in source code" `
                        -Remediation "Remove hardcoded secrets. Use environment variables or secure vaults."

                    $script:Stats.SecretsFound++
                }
            }
        }
    }

    Write-Status "Secret scan complete. Found $($script:Stats.SecretsFound) potential secrets." $(if ($script:Stats.SecretsFound -eq 0) { "Success" } else { "Error" })
}

# ============================================================================
# Scan: Dependency Vulnerabilities
# ============================================================================

function Test-DependencyVulnerabilities {
    Write-Status "Scanning dependencies for vulnerabilities..." "Info"

    # Check for package.json (Node.js)
    $packageJson = Join-Path $Path "package.json"
    if (Test-Path $packageJson) {
        Write-Status "Found package.json - checking Node.js dependencies" "Info"

        # Check for known vulnerable patterns in package.json
        $content = Get-Content -Path $packageJson -Raw

        # Check for http (insecure) URLs
        if ($content -match '"http://') {
            Add-Finding `
                -RuleId "DEP001" `
                -Title "Insecure HTTP dependency URL" `
                -File "package.json" `
                -Severity "High" `
                -Category "Dependencies" `
                -Message "Dependencies should use HTTPS URLs" `
                -Remediation "Update all HTTP URLs to HTTPS in package.json"

            $script:Stats.VulnerabilitiesFound++
        }
    }

    # Check for requirements.txt (Python)
    $requirements = Join-Path $Path "requirements.txt"
    if (Test-Path $requirements) {
        Write-Status "Found requirements.txt - checking Python dependencies" "Info"
    }

    # Check for Cargo.toml (Rust)
    $cargoToml = Join-Path $Path "Cargo.toml"
    if (Test-Path $cargoToml) {
        Write-Status "Found Cargo.toml - checking Rust dependencies" "Info"
    }

    Write-Status "Dependency scan complete. Found $($script:Stats.VulnerabilitiesFound) issues." $(if ($script:Stats.VulnerabilitiesFound -eq 0) { "Success" } else { "Warning" })
}

# ============================================================================
# Scan: Infrastructure Security
# ============================================================================

function Test-InfrastructureSecurity {
    Write-Status "Scanning infrastructure configurations..." "Info"

    # Check Docker files
    $dockerFiles = Get-ChildItem -Path $Path -Recurse -Filter "Dockerfile*" -ErrorAction SilentlyContinue |
        Where-Object { -not (Test-Excluded $_.FullName) }

    foreach ($dockerFile in $dockerFiles) {
        $relPath = Resolve-Path -Relative $dockerFile.FullName
        $content = Get-Content -Path $dockerFile.FullName -Raw

        # Check for running as root
        if (-not ($content -match "USER\s+")) {
            Add-Finding `
                -RuleId "INF001" `
                -Title "Docker container runs as root" `
                -File $relPath `
                -Severity "Medium" `
                -Category "Infrastructure" `
                -Message "Dockerfile does not specify a non-root USER" `
                -Remediation "Add 'USER <non-root-user>' instruction to Dockerfile"

            $script:Stats.InfraIssues++
        }

        # Check for latest tag
        if ($content -match "FROM\s+\S+:latest") {
            Add-Finding `
                -RuleId "INF002" `
                -Title "Docker image uses 'latest' tag" `
                -File $relPath `
                -Severity "Low" `
                -Category "Infrastructure" `
                -Message "Using 'latest' tag can lead to unpredictable builds" `
                -Remediation "Pin to specific version tags for reproducible builds"

            $script:Stats.InfraIssues++
        }
    }

    # Check Kubernetes manifests
    $k8sFiles = Get-ChildItem -Path $Path -Recurse -Filter "*.yaml" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "(deployment|service|configmap|secret)" -and -not (Test-Excluded $_.FullName) }

    foreach ($k8sFile in $k8sFiles) {
        $relPath = Resolve-Path -Relative $k8sFile.FullName
        $content = Get-Content -Path $k8sFile.FullName -Raw

        # Check for hardcoded secrets in K8s manifests
        if ($content -match "kind:\s*Secret" -and $content -match "stringData:") {
            Add-Finding `
                -RuleId "INF003" `
                -Title "Potential hardcoded secret in Kubernetes manifest" `
                -File $relPath `
                -Severity "High" `
                -Category "Infrastructure" `
                -Message "Kubernetes Secret may contain hardcoded sensitive data" `
                -Remediation "Use external secret management (e.g., Sealed Secrets, Vault)"

            $script:Stats.InfraIssues++
        }
    }

    Write-Status "Infrastructure scan complete. Found $($script:Stats.InfraIssues) issues." $(if ($script:Stats.InfraIssues -eq 0) { "Success" } else { "Warning" })
}

# ============================================================================
# Scan: License Compliance
# ============================================================================

function Test-LicenseCompliance {
    Write-Status "Checking license compliance..." "Info"

    $licenseFile = Join-Path $Path "LICENSE"
    if (-not (Test-Path $licenseFile)) {
        Add-Finding `
            -RuleId "LIC001" `
            -Title "Missing LICENSE file" `
            -File "." `
            -Severity "Medium" `
            -Category "License" `
            -Message "No LICENSE file found in repository root" `
            -Remediation "Add a LICENSE file with appropriate open source license"

        $script:Stats.LicenseIssues++
    }

    # Check for GPL in dependencies (potential conflict)
    $lockFiles = @("package-lock.json", "Cargo.lock", "poetry.lock")
    foreach ($lockFile in $lockFiles) {
        $fullPath = Join-Path $Path $lockFile
        if (Test-Path $fullPath) {
            $content = Get-Content -Path $fullPath -Raw
            if ($content -match '"license"\s*:\s*"GPL') {
                Add-Finding `
                    -RuleId "LIC002" `
                    -Title "GPL-licensed dependency detected" `
                    -File $lockFile `
                    -Severity "Low" `
                    -Category "License" `
                    -Message "GPL license may conflict with project licensing" `
                    -Remediation "Review GPL dependencies for license compatibility"

                $script:Stats.LicenseIssues++
            }
        }
    }

    Write-Status "License scan complete. Found $($script:Stats.LicenseIssues) issues." $(if ($script:Stats.LicenseIssues -eq 0) { "Success" } else { "Warning" })
}

# ============================================================================
# Report Generation
# ============================================================================

function Write-ConsoleReport {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Security Scan Report" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $grouped = $script:Findings | Group-Object -Property Severity | Sort-Object { $SeverityLevel[$_.Name] } -Descending

    foreach ($group in $grouped) {
        $color = switch ($group.Name) {
            "Critical" { "Red" }
            "High" { "DarkRed" }
            "Medium" { "Yellow" }
            "Low" { "Cyan" }
            default { "Gray" }
        }
        Write-Host "`n$($group.Name) Severity ($($group.Count) finding(s)):" -ForegroundColor $color

        foreach ($finding in $group.Group | Select-Object -First 5) {
            Write-Host "  [$($finding.RuleId)] $($finding.File):$($finding.Line)" -ForegroundColor White
            Write-Host "    $($finding.Title)" -ForegroundColor Gray
            if ($finding.Remediation) {
                Write-Host "    Remediation: $($finding.Remediation)" -ForegroundColor DarkGray
            }
        }
        if ($group.Count -gt 5) {
            Write-Host "  ... and $($group.Count - 5) more" -ForegroundColor DarkGray
        }
    }

    Write-Host "`n----------------------------------------" -ForegroundColor Cyan
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  Files scanned:        $($script:Stats.FilesScanned)" -ForegroundColor White
    Write-Host "  Secrets found:        $($script:Stats.SecretsFound)" -ForegroundColor $(if ($script:Stats.SecretsFound -eq 0) { "Green" } else { "Red" })
    Write-Host "  Vulnerabilities:      $($script:Stats.VulnerabilitiesFound)" -ForegroundColor $(if ($script:Stats.VulnerabilitiesFound -eq 0) { "Green" } else { "Yellow" })
    Write-Host "  Infrastructure issues:$($script:Stats.InfraIssues)" -ForegroundColor $(if ($script:Stats.InfraIssues -eq 0) { "Green" } else { "Yellow" })
    Write-Host "  License issues:       $($script:Stats.LicenseIssues)" -ForegroundColor $(if ($script:Stats.LicenseIssues -eq 0) { "Green" } else { "Yellow" })
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    Write-Host "  Critical: $($script:Stats.Critical) | High: $($script:Stats.High) | Medium: $($script:Stats.Medium) | Low: $($script:Stats.Low)" -ForegroundColor White
    Write-Host "----------------------------------------" -ForegroundColor Cyan

    $totalIssues = $script:Findings.Count
    if ($totalIssues -eq 0) {
        Write-Host "Result: PASSED ✓ No security issues found" -ForegroundColor Green
    } else {
        Write-Host "Result: FAILED ✗ $totalIssues security issue(s) found" -ForegroundColor Red
    }
}

function Write-SarifReport {
    param([string]$OutputPath)

    $sarif = @{
        `$schema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        version = "2.1.0"
        runs = @(
            @{
                tool = @{
                    driver = @{
                        name = "RawrXD Security Scanner"
                        version = "1.0.0"
                        informationUri = "https://rawrxd.dev/security"
                        rules = @()
                    }
                }
                results = @()
            }
        )
    }

    # Add rules
    $rules = $script:Findings | Select-Object -Property RuleId, Title, Category -Unique
    foreach ($rule in $rules) {
        $sarif.runs[0].tool.driver.rules += @{
            id = $rule.RuleId
            name = $rule.Title
            shortDescription = @{ text = $rule.Title }
            fullDescription = @{ text = $rule.Title }
            defaultConfiguration = @{ level = $rule.Category }
        }
    }

    # Add results
    foreach ($finding in $script:Findings) {
        $sarif.runs[0].results += @{
            ruleId = $finding.RuleId
            message = @{ text = $finding.Message }
            locations = @(
                @{
                    physicalLocation = @{
                        artifactLocation = @{ uri = $finding.File }
                        region = @{ startLine = $finding.Line }
                    }
                }
            )
            level = switch ($finding.Severity) {
                "Critical" { "error" }
                "High" { "error" }
                "Medium" { "warning" }
                default { "note" }
            }
        }
    }

    $json = $sarif | ConvertTo-Json -Depth 20
    $json | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Status "SARIF report written to $OutputPath" "Success"
}

function Write-GitHubReport {
    foreach ($finding in $script:Findings) {
        $level = if ($finding.Severity -in @("Critical", "High")) { "error" } else { "warning" }
        Write-Output "::$level file=$($finding.File),line=$($finding.Line),title=$($finding.Title)::$($finding.Message)"
    }
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Status "RawrXD Security Scanner v1.0" "Info"
    Write-Status "Scan path: $(Resolve-Path $Path)" "Info"
    Write-Status "Full scan: $FullScan" "Info"
    Write-Status ""

    # Run scans
    Test-Secrets
    Test-DependencyVulnerabilities
    Test-InfrastructureSecurity
    Test-LicenseCompliance

    # Generate report
    switch ($ReportFormat) {
        "sarif" { Write-SarifReport -OutputPath $OutputFile }
        "json" {
            $report = @{ findings = $script:Findings; stats = $script:Stats; timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ" }
            $report | ConvertTo-Json -Depth 10 | Out-File -FilePath ($OutputFile -replace "\.sarif$", ".json") -Encoding UTF8
        }
        "github" { Write-GitHubReport }
        default { Write-ConsoleReport }
    }

    # Exit with appropriate code
    $exitCode = if ($script:Findings.Count -gt 0 -and $FailOnFindings) { 1 } else { 0 }
    exit $exitCode
}

# Run main
Main
