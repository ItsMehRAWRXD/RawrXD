# RawrXD Security Audit Script
# Comprehensive security scanning and vulnerability assessment

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Quick", "Full", "Code", "Dependencies", "Configuration", "Secrets")]
    [string]$ScanType = "Quick",
    
    [string]$OutputPath = "security-reports",
    [switch]$FixIssues,
    [switch]$ExportReport,
    [string]$BaselinePath = "",
    [switch]$FailOnIssues
)

$ErrorActionPreference = "Stop"

# Security patterns to check
$SecurityPatterns = @{
    Secrets = @(
        @{ Pattern = 'api[_-]?key\s*[=:]\s*["\'][^"\']{10,}["\']'; Severity = "Critical"; Description = "Hardcoded API key" },
        @{ Pattern = 'password\s*[=:]\s*["\'][^"\']+["\']'; Severity = "Critical"; Description = "Hardcoded password" },
        @{ Pattern = 'secret\s*[=:]\s*["\'][^"\']{10,}["\']'; Severity = "Critical"; Description = "Hardcoded secret" },
        @{ Pattern = 'token\s*[=:]\s*["\'][^"\']{20,}["\']'; Severity = "High"; Description = "Hardcoded token" },
        @{ Pattern = 'private[_-]?key'; Severity = "Critical"; Description = "Private key reference" },
        @{ Pattern = 'AKIA[0-9A-Z]{16}'; Severity = "Critical"; Description = "AWS Access Key ID" },
        @{ Pattern = 'ghp_[a-zA-Z0-9]{36}'; Severity = "Critical"; Description = "GitHub Personal Access Token" }
    )
    
    Vulnerabilities = @(
        @{ Pattern = 'eval\s*\('; Severity = "High"; Description = "Dangerous eval() usage" },
        @{ Pattern = 'exec\s*\('; Severity = "High"; Description = "Dangerous exec() usage" },
        @{ Pattern = 'system\s*\('; Severity = "High"; Description = "System command execution" },
        @{ Pattern = 'malloc\s*\([^)]+\)\s*;'; Severity = "Medium"; Description = "Potential memory leak (no free)" },
        @{ Pattern = 'strcpy\s*\('; Severity = "High"; Description = "Unsafe strcpy usage" },
        @{ Pattern = 'gets\s*\('; Severity = "Critical"; Description = "Dangerous gets() usage" }
    )
    
    InsecureConfig = @(
        @{ Pattern = 'debug\s*=\s*true'; Severity = "Medium"; Description = "Debug mode enabled" },
        @{ Pattern = 'verify[_-]?ssl\s*=\s*false'; Severity = "High"; Description = "SSL verification disabled" },
        @{ Pattern = 'disable[_-]?security'; Severity = "Critical"; Description = "Security feature disabled" },
        @{ Pattern = 'allow[_-]?origin.*\*'; Severity = "Medium"; Description = "Permissive CORS policy" }
    )
}

$script:Results = @{
    Timestamp = Get-Date -Format "o"
    ScanType = $ScanType
    Findings = @()
    Summary = @{
        Critical = 0
        High = 0
        Medium = 0
        Low = 0
        Info = 0
        Total = 0
    }
}

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

function Initialize-Audit {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    Write-Status "Starting security audit ($ScanType scan)..."
}

function Test-Secrets {
    Write-Status "Scanning for hardcoded secrets..."
    
    $files = Get-ChildItem -Path "." -Recurse -File | Where-Object { 
        $_.Extension -in @(".ps1", ".py", ".js", ".ts", ".cpp", ".h", ".hpp", ".c", ".cs", ".json", ".yml", ".yaml", ".xml", ".config")
    }
    
    foreach ($file in $files) {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        
        foreach ($pattern in $SecurityPatterns.Secrets) {
            $matches = [regex]::Matches($content, $pattern.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            
            foreach ($match in $matches) {
                $finding = @{
                    File = $file.FullName
                    Line = ($content.Substring(0, $match.Index) -split "`n").Count
                    Pattern = $match.Value
                    Severity = $pattern.Severity
                    Category = "Secrets"
                    Description = $pattern.Description
                }
                
                $script:Results.Findings += $finding
                $script:Results.Summary[$pattern.Severity]++
                $script:Results.Summary.Total++
                
                if ($pattern.Severity -eq "Critical") {
                    Write-Error "[$($pattern.Severity)] $($file.Name):$($finding.Line) - $($pattern.Description)"
                } elseif ($pattern.Severity -eq "High") {
                    Write-Warning "[$($pattern.Severity)] $($file.Name):$($finding.Line) - $($pattern.Description)"
                }
            }
        }
    }
    
    Write-Success "Secret scan complete"
}

function Test-CodeVulnerabilities {
    Write-Status "Scanning for code vulnerabilities..."
    
    $sourceFiles = Get-ChildItem -Path "src" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { 
        $_.Extension -in @(".cpp", ".h", ".hpp", ".c", ".cs")
    }
    
    foreach ($file in $sourceFiles) {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        
        foreach ($pattern in $SecurityPatterns.Vulnerabilities) {
            $matches = [regex]::Matches($content, $pattern.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            
            foreach ($match in $matches) {
                $finding = @{
                    File = $file.FullName
                    Line = ($content.Substring(0, $match.Index) -split "`n").Count
                    Pattern = $match.Value
                    Severity = $pattern.Severity
                    Category = "Vulnerabilities"
                    Description = $pattern.Description
                }
                
                $script:Results.Findings += $finding
                $script:Results.Summary[$pattern.Severity]++
                $script:Results.Summary.Total++
                
                Write-Warning "[$($pattern.Severity)] $($file.Name):$($finding.Line) - $($pattern.Description)"
            }
        }
    }
    
    Write-Success "Vulnerability scan complete"
}

function Test-ConfigurationSecurity {
    Write-Status "Scanning configuration files..."
    
    $configFiles = @(
        "config.json",
        "appsettings.json",
        "web.config",
        ".env",
        "docker-compose.yml",
        "docker-compose.yaml"
    )
    
    foreach ($configFile in $configFiles) {
        if (-not (Test-Path $configFile)) { continue }
        
        $content = Get-Content $configFile -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        
        foreach ($pattern in $SecurityPatterns.InsecureConfig) {
            $matches = [regex]::Matches($content, $pattern.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            
            foreach ($match in $matches) {
                $finding = @{
                    File = $configFile
                    Line = ($content.Substring(0, $match.Index) -split "`n").Count
                    Pattern = $match.Value
                    Severity = $pattern.Severity
                    Category = "Configuration"
                    Description = $pattern.Description
                }
                
                $script:Results.Findings += $finding
                $script:Results.Summary[$pattern.Severity]++
                $script:Results.Summary.Total++
                
                Write-Warning "[$($pattern.Severity)] $configFile`:$($finding.Line) - $($pattern.Description)"
            }
        }
    }
    
    Write-Success "Configuration scan complete"
}

function Test-Dependencies {
    Write-Status "Checking dependencies for known vulnerabilities..."
    
    # Check for package files
    $packageFiles = @(
        @{ Path = "package.json"; Type = "npm" },
        @{ Path = "requirements.txt"; Type = "pip" },
        @{ Path = "Cargo.toml"; Type = "cargo" },
        @{ Path = "go.mod"; Type = "go" }
    )
    
    foreach ($pkgFile in $packageFiles) {
        if (Test-Path $pkgFile.Path) {
            Write-Status "Found $($pkgFile.Type) dependencies: $($pkgFile.Path)"
            
            # This would integrate with vulnerability databases
            # For now, just note the presence
            $finding = @{
                File = $pkgFile.Path
                Line = 0
                Pattern = "Dependency file found"
                Severity = "Info"
                Category = "Dependencies"
                Description = "$($pkgFile.Type) dependencies should be audited regularly"
            }
            
            $script:Results.Findings += $finding
            $script:Results.Summary.Info++
            $script:Results.Summary.Total++
        }
    }
    
    Write-Success "Dependency check complete"
}

function Test-FilePermissions {
    Write-Status "Checking file permissions..."
    
    $sensitiveFiles = @(
        "*.key",
        "*.pem",
        "*.p12",
        "*.pfx",
        "*.crt",
        "*.cer",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        ".env"
    )
    
    foreach ($pattern in $sensitiveFiles) {
        $files = Get-ChildItem -Path "." -Recurse -Filter $pattern -ErrorAction SilentlyContinue
        
        foreach ($file in $files) {
            $acl = Get-Acl $file.FullName
            $access = $acl.Access | Where-Object { $_.IdentityReference -eq "BUILTIN\Users" -or $_.IdentityReference -eq "Everyone" }
            
            if ($access) {
                $finding = @{
                    File = $file.FullName
                    Line = 0
                    Pattern = $file.Name
                    Severity = "High"
                    Category = "Permissions"
                    Description = "Sensitive file may have overly permissive permissions"
                }
                
                $script:Results.Findings += $finding
                $script:Results.Summary.High++
                $script:Results.Summary.Total++
                
                Write-Warning "[High] $($file.FullName) - Overly permissive permissions"
                
                if ($FixIssues) {
                    Write-Status "Fixing permissions for $($file.Name)..."
                    # Remove inherited permissions
                    $acl.SetAccessRuleProtection($true, $false)
                    
                    # Add only current user
                    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($user, "Read", "Allow")
                    $acl.AddAccessRule($rule)
                    
                    Set-Acl $file.FullName $acl
                    Write-Success "Permissions fixed"
                }
            }
        }
    }
    
    Write-Success "Permission check complete"
}

function Show-Summary {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Security Audit Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Total Findings: $($script:Results.Summary.Total)" -ForegroundColor White
    Write-Host "  Critical: $($script:Results.Summary.Critical)" -ForegroundColor Red
    Write-Host "  High: $($script:Results.Summary.High)" -ForegroundColor Magenta
    Write-Host "  Medium: $($script:Results.Summary.Medium)" -ForegroundColor Yellow
    Write-Host "  Low: $($script:Results.Summary.Low)" -ForegroundColor Gray
    Write-Host "  Info: $($script:Results.Summary.Info)" -ForegroundColor Gray
    Write-Host ""
    
    if ($script:Results.Summary.Critical -gt 0 -or $script:Results.Summary.High -gt 0) {
        Write-Error "Critical/High severity issues found! Immediate attention required."
        
        # Show top issues
        Write-Host "Top Issues:" -ForegroundColor Red
        $criticalIssues = $script:Results.Findings | Where-Object { $_.Severity -in @("Critical", "High") } | Select-Object -First 10
        foreach ($issue in $criticalIssues) {
            Write-Host "  [$($issue.Severity)] $($issue.File):$($issue.Line) - $($issue.Description)" -ForegroundColor Red
        }
    } elseif ($script:Results.Summary.Total -gt 0) {
        Write-Warning "Security issues found. Review recommended."
    } else {
        Write-Success "No security issues found!"
    }
}

function Export-Report {
    if (-not $ExportReport) {
        return
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportFile = "$OutputPath\security-audit-$timestamp.json"
    
    $script:Results | ConvertTo-Json -Depth 10 | Out-File $reportFile
    Write-Success "Report exported to: $reportFile"
    
    # Generate HTML report
    $htmlFile = "$OutputPath\security-audit-$timestamp.html"
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 20px; border-radius: 8px; }
        .critical { color: #d32f2f; }
        .high { color: #f57c00; }
        .medium { color: #fbc02d; }
        .low { color: #689f38; }
        .info { color: #1976d2; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        th { background: #4CAF50; color: white; }
        tr:hover { background: #f5f5f5; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .metric { padding: 15px; background: #f0f0f0; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>RawrXD Security Audit Report</h1>
        <p>Generated: $($script:Results.Timestamp)</p>
        <p>Scan Type: $($script:Results.ScanType)</p>
        
        <div class="summary">
            <div class="metric"><strong>Total:</strong> $($script:Results.Summary.Total)</div>
            <div class="metric critical"><strong>Critical:</strong> $($script:Results.Summary.Critical)</div>
            <div class="metric high"><strong>High:</strong> $($script:Results.Summary.High)</div>
            <div class="metric medium"><strong>Medium:</strong> $($script:Results.Summary.Medium)</div>
        </div>
        
        <table>
            <tr>
                <th>Severity</th>
                <th>Category</th>
                <th>File</th>
                <th>Line</th>
                <th>Description</th>
            </tr>
"@
    
    foreach ($finding in $script:Results.Findings | Sort-Object Severity) {
        $severityClass = $finding.Severity.ToLower()
        $html += "<tr class='$severityClass'><td>$($finding.Severity)</td><td>$($finding.Category)</td><td>$($finding.File)</td><td>$($finding.Line)</td><td>$($finding.Description)</td></tr>"
    }
    
    $html += @"
        </table>
    </div>
</body>
</html>
"@
    
    $html | Out-File $htmlFile
    Write-Success "HTML report exported to: $htmlFile"
}

# Main execution
function Main {
    Write-Host "RawrXD Security Audit" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Audit
    
    switch ($ScanType) {
        "Quick" {
            Test-Secrets
            Test-ConfigurationSecurity
        }
        "Full" {
            Test-Secrets
            Test-CodeVulnerabilities
            Test-ConfigurationSecurity
            Test-Dependencies
            Test-FilePermissions
        }
        "Code" { Test-CodeVulnerabilities }
        "Dependencies" { Test-Dependencies }
        "Configuration" { Test-ConfigurationSecurity }
        "Secrets" { Test-Secrets }
    }
    
    Show-Summary
    Export-Report
    
    # Exit code
    if ($FailOnIssues -and ($script:Results.Summary.Critical -gt 0 -or $script:Results.Summary.High -gt 0)) {
        exit 1
    }
}

Main
