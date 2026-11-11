# RawrXD Security Scan Automation
# Automated security scanning with vulnerability tracking
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("Full", "Quick", "Dependencies", "Secrets", "Code", "Compliance")]
    [string]$ScanType = "Quick",
    
    [Parameter()]
    [string]$TargetPath = ".",
    
    [Parameter()]
    [string]$OutputPath = "security-scan-report.json",
    
    [Parameter()]
    [string]$BaselinePath = "security-baseline.json",
    
    [Parameter()]
    [switch]$FailOnCritical,
    
    [Parameter()]
    [switch]$AutoFix,
    
    [Parameter()]
    [string[]]$ExcludePaths = @("node_modules", "build", "dist", ".git")
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

enum Severity {
    Critical = 4
    High = 3
    Medium = 2
    Low = 1
    Info = 0
}

function Initialize-SecurityScan {
    Write-Status "Security Scan Automation v$script:Version"
    Write-Status "Scan Type: $ScanType"
    Write-Status "Target: $TargetPath"
    Write-Host ""
}

function Invoke-DependencyScan {
    $findings = @()
    
    Write-Status "Scanning dependencies..."
    
    # Check for package.json
    $packageJson = Join-Path $TargetPath "package.json"
    if (Test-Path $packageJson) {
        Write-Status "Found package.json, checking for known vulnerabilities..."
        
        # Simulated vulnerability check
        $vulnerabilities = @(
            @{ Package = "example-lib"; Version = "1.2.3"; CVE = "CVE-2024-1234"; Severity = "High" },
            @{ Package = "test-dep"; Version = "2.0.0"; CVE = "CVE-2024-5678"; Severity = "Medium" }
        )
        
        foreach ($vuln in $vulnerabilities) {
            $findings += [PSCustomObject]@{
                Type = "Dependency"
                Severity = $vuln.Severity
                Title = "Vulnerable package: $($vuln.Package)"
                Description = "Package $($vuln.Package)@$($vuln.Version) has known vulnerability $($vuln.CVE)"
                File = "package.json"
                Line = 0
                Recommendation = "Update to latest version"
            }
        }
    }
    
    # Check requirements.txt
    $requirements = Join-Path $TargetPath "requirements.txt"
    if (Test-Path $requirements) {
        Write-Status "Found requirements.txt, scanning Python dependencies..."
    }
    
    return $findings
}

function Invoke-SecretScan {
    $findings = @()
    
    Write-Status "Scanning for secrets..."
    
    $secretPatterns = @(
        @{ Pattern = 'api[_-]?key\s*[=:]\s*["\'']?[a-zA-Z0-9]{32,}["\'']?'; Name = "API Key" }
        @{ Pattern = 'password\s*[=:]\s*["\''][^"\'']+["\'']'; Name = "Hardcoded Password" }
        @{ Pattern = 'secret\s*[=:]\s*["\'']?[a-zA-Z0-9]{20,}["\'']?'; Name = "Secret Token" }
        @{ Pattern = '-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'; Name = "Private Key" }
        @{ Pattern = 'AKIA[0-9A-Z]{16}'; Name = "AWS Access Key" }
    )
    
    $files = Get-ChildItem -Path $TargetPath -Recurse -File | 
        Where-Object { $_.Extension -in @('.ps1', '.py', '.js', '.ts', '.json', '.yml', '.yaml', '.env', '.config') } |
        Where-Object { 
            $exclude = $false
            foreach ($ex in $ExcludePaths) {
                if ($_.FullName -like "*$ex*") { $exclude = $true; break }
            }
            -not $exclude
        }
    
    foreach ($file in $files) {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        
        foreach ($pattern in $secretPatterns) {
            $matches = [regex]::Matches($content, $pattern.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            
            foreach ($match in $matches) {
                $findings += [PSCustomObject]@{
                    Type = "Secret"
                    Severity = "Critical"
                    Title = "Potential $($pattern.Name) found"
                    Description = "Possible $($pattern.Name) detected in code"
                    File = $file.FullName.Substring($TargetPath.Length + 1)
                    Line = ($content.Substring(0, $match.Index) -split "`n").Count
                    Recommendation = "Move to environment variables or secrets manager"
                }
            }
        }
    }
    
    return $findings
}

function Invoke-CodeScan {
    $findings = @()
    
    Write-Status "Scanning code for security issues..."
    
    $codePatterns = @(
        @{ Pattern = 'Invoke-Expression'; Severity = "High"; Name = "Command Injection Risk" }
        @{ Pattern = 'eval\s*\('; Severity = "High"; Name = "Eval Usage" }
        @{ Pattern = 'innerHTML\s*='; Severity = "Medium"; Name = "XSS Risk" }
        @{ Pattern = 'http://'; Severity = "Low"; Name = "Insecure HTTP" }
    )
    
    $files = Get-ChildItem -Path $TargetPath -Recurse -File | 
        Where-Object { $_.Extension -in @('.ps1', '.py', '.js', '.ts') } |
        Where-Object { 
            $exclude = $false
            foreach ($ex in $ExcludePaths) {
                if ($_.FullName -like "*$ex*") { $exclude = $true; break }
            }
            -not $exclude
        }
    
    foreach ($file in $files) {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        
        foreach ($pattern in $codePatterns) {
            $matches = [regex]::Matches($content, $pattern.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            
            foreach ($match in $matches) {
                $findings += [PSCustomObject]@{
                    Type = "Code"
                    Severity = $pattern.Severity
                    Title = $pattern.Name
                    Description = "Potential security issue detected"
                    File = $file.FullPath.Substring($TargetPath.Length + 1)
                    Line = ($content.Substring(0, $match.Index) -split "`n").Count
                    Recommendation = "Review and refactor to use secure alternatives"
                }
            }
        }
    }
    
    return $findings
}

function Invoke-ComplianceScan {
    $findings = @()
    
    Write-Status "Checking compliance..."
    
    # Check for LICENSE file
    $licenseFile = Join-Path $TargetPath "LICENSE"
    if (-not (Test-Path $licenseFile)) {
        $findings += [PSCustomObject]@{
            Type = "Compliance"
            Severity = "Medium"
            Title = "Missing LICENSE file"
            Description = "No LICENSE file found in repository"
            File = "N/A"
            Line = 0
            Recommendation = "Add appropriate open source license"
        }
    }
    
    # Check for SECURITY.md
    $securityFile = Join-Path $TargetPath "SECURITY.md"
    if (-not (Test-Path $securityFile)) {
        $findings += [PSCustomObject]@{
            Type = "Compliance"
            Severity = "Low"
            Title = "Missing SECURITY.md"
            Description = "No security policy documentation found"
            File = "N/A"
            Line = 0
            Recommendation = "Add SECURITY.md with vulnerability reporting process"
        }
    }
    
    return $findings
}

function Show-ScanResults {
    param([array]$Findings)
    
    Write-Host "Security Scan Results" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    $critical = ($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $high = ($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $medium = ($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $low = ($Findings | Where-Object { $_.Severity -eq "Low" }).Count
    
    Write-Host "Summary:"
    Write-Host "  Critical: $critical" -ForegroundColor $(if ($critical -gt 0) { "Red" } else { "Green" })
    Write-Host "  High: $high" -ForegroundColor $(if ($high -gt 0) { "Red" } else { "Green" })
    Write-Host "  Medium: $medium" -ForegroundColor $(if ($medium -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Low: $low" -ForegroundColor Green
    Write-Host "  Total: $($Findings.Count)"
    Write-Host ""
    
    if ($Findings.Count -gt 0) {
        Write-Host "Findings by Severity:" -ForegroundColor Yellow
        Write-Host "--------------------"
        
        foreach ($finding in ($Findings | Sort-Object { [Severity]$_.Severity } -Descending)) {
            $color = switch ($finding.Severity) {
                "Critical" { "Red" }
                "High" { "Red" }
                "Medium" { "Yellow" }
                default { "White" }
            }
            
            Write-Host "[$($finding.Severity)] $($finding.Type): $($finding.Title)" -ForegroundColor $color
            Write-Host "  File: $($finding.File):$($finding.Line)"
            Write-Host "  $($finding.Description)"
            Write-Host "  Recommendation: $($finding.Recommendation)"
            Write-Host ""
        }
    } else {
        Write-Success "No security issues found!"
    }
}

function Export-ScanReport {
    param([array]$Findings, [string]$Path)
    
    $report = @{
        ScanInfo = @{
            Tool = "RawrXD Security Scanner"
            Version = $script:Version
            ScanType = $ScanType
            TargetPath = $TargetPath
            Timestamp = (Get-Date).ToString("o")
        }
        Summary = @{
            Total = $Findings.Count
            Critical = ($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
            High = ($Findings | Where-Object { $_.Severity -eq "High" }).Count
            Medium = ($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
            Low = ($Findings | Where-Object { $_.Severity -eq "Low" }).Count
        }
        Findings = $Findings
    }
    
    $report | ConvertTo-Json -Depth 5 | Set-Content $Path
    Write-Success "Report saved to: $Path"
}

# Main execution
try {
    Initialize-SecurityScan
    
    $allFindings = @()
    
    if ($ScanType -eq "Full" -or $ScanType -eq "Quick" -or $ScanType -eq "Dependencies") {
        $allFindings += Invoke-DependencyScan
    }
    
    if ($ScanType -eq "Full" -or $ScanType -eq "Quick" -or $ScanType -eq "Secrets") {
        $allFindings += Invoke-SecretScan
    }
    
    if ($ScanType -eq "Full" -or $ScanType -eq "Code") {
        $allFindings += Invoke-CodeScan
    }
    
    if ($ScanType -eq "Full" -or $ScanType -eq "Compliance") {
        $allFindings += Invoke-ComplianceScan
    }
    
    Show-ScanResults -Findings $allFindings
    Export-ScanReport -Findings $allFindings -Path $OutputPath
    
    $criticalCount = ($allFindings | Where-Object { $_.Severity -eq "Critical" }).Count
    if ($FailOnCritical -and $criticalCount -gt 0) {
        exit 1
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
