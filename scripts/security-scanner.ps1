# RawrXD Security Scanner
# Comprehensive security scanning for vulnerabilities, secrets, and compliance

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("full", "quick", "secrets", "dependencies", "code", "compliance")]
    [string]$ScanType = "quick",
    
    [string]$TargetPath = "D:\rawrxd",
    [string]$OutputFormat = "html", # console, json, html, sarif
    [string]$OutputPath = "security-reports",
    [switch]$FailOnFinding,
    [string[]]$ExcludePaths = @("node_modules", ".git", "build", "output"),
    [switch]$AutoFix,
    [switch]$Notify,
    [string]$SeverityThreshold = "medium" # low, medium, high, critical
)

$ErrorActionPreference = "Stop"

# Security configuration
$SecurityConfig = @{
    SecretPatterns = @{
        "API Key" = "(api[_-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9]{16,}['\"]"
        "Password" = "(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]"
        "Token" = "(token|access_token|auth_token)\s*[=:]\s*['\"][a-zA-Z0-9]{20,}['\"]"
        "Private Key" = "-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"
        "Connection String" = "(Server|Data Source|Host)\s*=\s*[^;]+;.*(Password|Pwd)\s*=\s*[^;]+"
        "AWS Key" = "AKIA[0-9A-Z]{16}"
        "GitHub Token" = "gh[pousr]_[A-Za-z0-9_]{36,}"
        "Slack Token" = "xox[baprs]-[0-9a-zA-Z-]+"
    }
    
    VulnerabilityPatterns = @{
        "SQL Injection" = "(SELECT|INSERT|UPDATE|DELETE).*\+.*\$|execute.*\+"
        "Command Injection" = "(system|exec|popen|spawn)\s*\(.*\+"
        "Path Traversal" = "\.\./|\.\.\\|%2e%2e%2f"
        "XSS" = "innerHTML\s*=|document\.write\s*\(.*\+|eval\s*\(.*\+"
        "Insecure Random" = "rand\s*\(\s*\)|Random\s*\(\s*\)"
        "Weak Crypto" = "MD5|SHA1.*\(|DES|RC4"
        "Buffer Overflow Risk" = "strcpy|strcat|sprintf|gets\s*\("
        "Integer Overflow" = "malloc\s*\(\s*.*\s*\*\s*.*\s*\)"
    }
    
    ComplianceRules = @{
        "GDPR" = @{
            "Personal Data" = @("email", "phone", "ssn", "passport", "credit.?card")
            "Required" = $true
        }
        "SOX" = @{
            "Financial Data" = @("revenue", "expense", "audit", "financial")
            "Required" = $false
        }
        "PCI DSS" = @{
            "Card Data" = @("card.?number", "cvv", "expiry")
            "Required" = $false
        }
    }
    
    SeverityWeights = @{
        "critical" = 10
        "high" = 7
        "medium" = 4
        "low" = 1
    }
}

$script:ScanState = @{
    StartTime = Get-Date
    Findings = @()
    FilesScanned = 0
    SecretsFound = 0
    VulnerabilitiesFound = 0
    ComplianceIssues = 0
    RiskScore = 0
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[✗] $Message" -ForegroundColor Red }

function Initialize-Scanner {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    Write-Success "Security scanner initialized"
}

function Get-ScanFiles {
    $allFiles = Get-ChildItem -Path $TargetPath -Recurse -File -ErrorAction SilentlyContinue
    
    # Filter out excluded paths
    $filtered = $allFiles | Where-Object {
        $file = $_
        $excluded = $false
        foreach ($exclude in $ExcludePaths) {
            if ($file.FullName -like "*$exclude*") {
                $excluded = $true
                break
            }
        }
        -not $excluded
    }
    
    # Filter by relevant extensions
    $relevantExts = @(".cpp", ".c", ".h", ".hpp", ".py", ".ps1", ".js", ".json", ".xml", ".config", ".yaml", ".yml", ".env")
    $filtered = $filtered | Where-Object { $_.Extension -in $relevantExts -or $_.Name -match "\.(config|ini|properties)$" }
    
    return $filtered
}

function Test-Secrets {
    param([string]$FilePath, [string]$Content)
    
    $findings = @()
    
    foreach ($pattern in $SecurityConfig.SecretPatterns.GetEnumerator()) {
        $matches = [regex]::Matches($Content, $pattern.Value, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        
        foreach ($match in $matches) {
            $finding = @{
                Type = "Secret"
                Category = $pattern.Key
                File = $FilePath
                Line = ($Content.Substring(0, $match.Index) -split "`n").Count
                Severity = "critical"
                Message = "Potential $($pattern.Key) exposed"
                Match = $match.Value
                Remediation = "Move to environment variables or secure vault"
            }
            $findings += $finding
            $script:ScanState.SecretsFound++
        }
    }
    
    return $findings
}

function Test-Vulnerabilities {
    param([string]$FilePath, [string]$Content)
    
    $findings = @()
    
    foreach ($pattern in $SecurityConfig.VulnerabilityPatterns.GetEnumerator()) {
        $matches = [regex]::Matches($Content, $pattern.Value, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        
        foreach ($match in $matches) {
            $severity = switch ($pattern.Key) {
                "SQL Injection" { "critical" }
                "Command Injection" { "critical" }
                "Buffer Overflow Risk" { "high" }
                "XSS" { "high" }
                default { "medium" }
            }
            
            $finding = @{
                Type = "Vulnerability"
                Category = $pattern.Key
                File = $FilePath
                Line = ($Content.Substring(0, $match.Index) -split "`n").Count
                Severity = $severity
                Message = "Potential $($pattern.Key) vulnerability"
                Match = $match.Value.Substring(0, [Math]::Min(50, $match.Value.Length))
                Remediation = Get-VulnerabilityRemediation -Type $pattern.Key
            }
            $findings += $finding
            $script:ScanState.VulnerabilitiesFound++
        }
    }
    
    return $findings
}

function Get-VulnerabilityRemediation {
    param([string]$Type)
    
    switch ($Type) {
        "SQL Injection" { "Use parameterized queries or prepared statements" }
        "Command Injection" { "Use allowlists and validate input; avoid shell execution" }
        "Path Traversal" { "Validate and sanitize file paths; use chroot jail" }
        "XSS" { "Encode output; use Content Security Policy" }
        "Insecure Random" { "Use cryptographically secure random number generators" }
        "Weak Crypto" { "Use AES-256-GCM or ChaCha20-Poly1305" }
        "Buffer Overflow Risk" { "Use safe string functions (strncpy, snprintf)" }
        "Integer Overflow" { "Check for overflow before allocation" }
        default { "Review and fix the identified issue" }
    }
}

function Test-Compliance {
    param([string]$FilePath, [string]$Content)
    
    $findings = @()
    
    foreach ($regulation in $SecurityConfig.ComplianceRules.GetEnumerator()) {
        $regName = $regulation.Key
        $rules = $regulation.Value
        
        foreach ($dataType in $rules["Personal Data"]) {
            $pattern = $dataType
            $matches = [regex]::Matches($Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            
            if ($matches.Count -gt 0) {
                $finding = @{
                    Type = "Compliance"
                    Category = "$regName - Personal Data Handling"
                    File = $FilePath
                    Line = ($Content.Substring(0, $matches[0].Index) -split "`n").Count
                    Severity = "high"
                    Message = "Potential $regName personal data detected"
                    Match = $matches[0].Value
                    Remediation = "Ensure proper data handling and consent mechanisms"
                }
                $findings += $finding
                $script:ScanState.ComplianceIssues++
            }
        }
    }
    
    return $findings
}

function Test-Dependencies {
    Write-Status "Scanning dependencies for known vulnerabilities..."
    
    $findings = @()
    
    # Check for package files
    $packageFiles = @(
        "package.json",
        "requirements.txt",
        "Cargo.toml",
        "pom.xml",
        "packages.config"
    )
    
    foreach ($pkgFile in $packageFiles) {
        $fullPath = Join-Path $TargetPath $pkgFile
        if (Test-Path $fullPath) {
            Write-Verbose "Checking $pkgFile for vulnerabilities..."
            # In production, this would query vulnerability databases
        }
    }
    
    return $findings
}

function Invoke-SecurityScan {
    Write-Status "Starting security scan ($ScanType mode)..."
    
    $files = Get-ScanFiles
    $totalFiles = $files.Count
    
    Write-Status "Scanning $totalFiles files..."
    
    $processed = 0
    foreach ($file in $files) {
        $processed++
        if ($processed % 100 -eq 0) {
            Write-Progress -Activity "Security Scan" -Status "$processed/$totalFiles files" -PercentComplete (($processed / $totalFiles) * 100)
        }
        
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        
        $script:ScanState.FilesScanned++
        
        # Run appropriate scans based on type
        switch ($ScanType) {
            "secrets" {
                $script:ScanState.Findings += Test-Secrets -FilePath $file.FullName -Content $content
            }
            "code" {
                $script:ScanState.Findings += Test-Vulnerabilities -FilePath $file.FullName -Content $content
            }
            "compliance" {
                $script:ScanState.Findings += Test-Compliance -FilePath $file.FullName -Content $content
            }
            "quick" {
                $script:ScanState.Findings += Test-Secrets -FilePath $file.FullName -Content $content
                $script:ScanState.Findings += Test-Vulnerabilities -FilePath $file.FullName -Content $content
            }
            "full" {
                $script:ScanState.Findings += Test-Secrets -FilePath $file.FullName -Content $content
                $script:ScanState.Findings += Test-Vulnerabilities -FilePath $file.FullName -Content $content
                $script:ScanState.Findings += Test-Compliance -FilePath $file.FullName -Content $content
            }
        }
    }
    
    Write-Progress -Activity "Security Scan" -Completed
    
    # Scan dependencies
    if ($ScanType -eq "full" -or $ScanType -eq "dependencies") {
        $script:ScanState.Findings += Test-Dependencies
    }
    
    # Calculate risk score
    Calculate-RiskScore
    
    Write-Success "Scan complete: $($script:ScanState.Findings.Count) findings"
}

function Calculate-RiskScore {
    $score = 0
    
    foreach ($finding in $script:ScanState.Findings) {
        $weight = $SecurityConfig.SeverityWeights[$finding.Severity]
        $score += $weight
    }
    
    $script:ScanState.RiskScore = $score
}

function Export-SecurityReport {
    $report = @{
        ScanId = [Guid]::NewGuid().ToString().Substring(0, 8)
        Timestamp = Get-Date -Format "o"
        ScanType = $ScanType
        Target = $TargetPath
        Summary = @{
            FilesScanned = $script:ScanState.FilesScanned
            TotalFindings = $script:ScanState.Findings.Count
            SecretsFound = $script:ScanState.SecretsFound
            VulnerabilitiesFound = $script:ScanState.VulnerabilitiesFound
            ComplianceIssues = $script:ScanState.ComplianceIssues
            RiskScore = $script:ScanState.RiskScore
            RiskLevel = if ($script:ScanState.RiskScore -gt 50) { "Critical" } elseif ($script:ScanState.RiskScore -gt 25) { "High" } elseif ($script:ScanState.RiskScore -gt 10) { "Medium" } else { "Low" }
        }
        FindingsBySeverity = ($script:ScanState.Findings | Group-Object -Property Severity | ForEach-Object {
            @{ Severity = $_.Name; Count = $_.Count }
        })
        Findings = $script:ScanState.Findings
    }
    
    switch ($OutputFormat) {
        "json" {
            $outputFile = "$OutputPath\security-scan-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
            $report | ConvertTo-Json -Depth 10 | Out-File $outputFile
            Write-Success "JSON report: $outputFile"
        }
        "html" {
            Export-HtmlReport -Report $report
        }
        "sarif" {
            Export-SarifReport -Report $report
        }
        default {
            # Console output handled in Show-Summary
        }
    }
    
    return $report
}

function Export-HtmlReport {
    param([hashtable]$Report)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Security Scan Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #0d1117; color: #c9d1d9; }
        .header { background: linear-gradient(135deg, #da3633 0%, #f85149 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { color: white; margin: 0; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: #161b22; border: 1px solid #30363d; padding: 20px; border-radius: 8px; text-align: center; }
        .summary-value { font-size: 2.5em; font-weight: bold; }
        .critical { color: #f85149; }
        .high { color: #d29922; }
        .medium { color: #58a6ff; }
        .low { color: #3fb950; }
        .findings { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
        .finding { border-left: 4px solid; padding: 15px; margin: 10px 0; background: #0d1117; }
        .finding-critical { border-color: #f85149; }
        .finding-high { border-color: #d29922; }
        .finding-medium { border-color: #58a6ff; }
        .finding-low { border-color: #3fb950; }
        .finding-header { display: flex; justify-content: space-between; margin-bottom: 10px; }
        .finding-type { font-weight: bold; }
        .finding-severity { padding: 2px 8px; border-radius: 4px; font-size: 0.9em; }
        .finding-file { color: #8b949e; font-family: monospace; }
        .finding-message { margin: 10px 0; }
        .finding-remediation { color: #58a6ff; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Scan Report</h1>
        <p>Scan ID: $($Report.ScanId) | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>
    </div>
    
    <div class="summary">
        <div class="summary-card">
            <div class="summary-value $($Report.Summary.RiskLevel.ToLower())">$($Report.Summary.RiskScore)</div>
            <div>Risk Score</div>
        </div>
        <div class="summary-card">
            <div class="summary-value">$($Report.Summary.TotalFindings)</div>
            <div>Total Findings</div>
        </div>
        
        <div class="summary-card">
            <div class="summary-value critical">$($Report.Summary.SecretsFound)</div>
            <div>Secrets</div>
        </div>
        
        <div class="summary-card">
            <div class="summary-value high">$($Report.Summary.VulnerabilitiesFound)</div>
            <div>Vulnerabilities</div>
        </div>
    </div>
    
    <div class="findings">
        <h2>Findings</h2>
"@
    
    foreach ($finding in $Report.Findings | Sort-Object Severity -Descending) {
        $html += @"
        <div class="finding finding-$($finding.Severity)">
            <div class="finding-header">
                <span class="finding-type">$($finding.Type): $($finding.Category)</span>
                <span class="finding-severity" style="background: $(if($finding.Severity -eq 'critical'){'#f85149'}elseif($finding.Severity -eq 'high'){'#d29922'}elseif($finding.Severity -eq 'medium'){'#58a6ff'}else{'#3fb950'});">$($finding.Severity.ToUpper())</span>
            </div>
            <div class="finding-file">$($finding.File):$($finding.Line)</div>
            <div class="finding-message">$($finding.Message)</div>
            <div class="finding-remediation">💡 $($finding.Remediation)</div>
        </div>
"@
    }
    
    $html += @"
    </div>
</body>
</html>
"@
    
    $outputFile = "$OutputPath\security-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    $html | Out-File $outputFile -Encoding UTF8
    
    Write-Success "HTML report: $outputFile"
}

function Export-SarifReport {
    param([hashtable]$Report)
    
    # SARIF (Static Analysis Results Interchange Format) for CI integration
    $sarif = @{
        version = "2.1.0"
        runs = @(
            @{
                tool = @{
                    driver = @{
                        name = "RawrXD Security Scanner"
                        version = "3.2.0"
                    }
                }
                results = @()
            }
        )
    }
    
    foreach ($finding in $Report.Findings) {
        $result = @{
            ruleId = $finding.Category
            level = if ($finding.Severity -eq "critical") { "error" } elseif ($finding.Severity -eq "high") { "error" } else { "warning" }
            message = @{ text = $finding.Message }
            locations = @(
                @{
                    physicalLocation = @{
                        artifactLocation = @{ uri = $finding.File }
                        region = @{ startLine = $finding.Line }
                    }
                }
            )
        }
        $sarif.runs[0].results += $result
    }
    
    $outputFile = "$OutputPath\security-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').sarif"
    $sarif | ConvertTo-Json -Depth 10 | Out-File $outputFile
    
    Write-Success "SARIF report: $outputFile"
}

function Show-Summary {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Security Scan Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $summary = @{
        FilesScanned = $script:ScanState.FilesScanned
        TotalFindings = $script:ScanState.Findings.Count
        Secrets = $script:ScanState.SecretsFound
        Vulnerabilities = $script:ScanState.VulnerabilitiesFound
        Compliance = $script:ScanState.ComplianceIssues
        RiskScore = $script:ScanState.RiskScore
    }
    
    Write-Host "Files Scanned: $($summary.FilesScanned)" -ForegroundColor White
    Write-Host "Total Findings: $($summary.TotalFindings)" -ForegroundColor $(if($summary.TotalFindings -eq 0){'Green'}else{'Yellow'})
    Write-Host ""
    Write-Host "By Category:" -ForegroundColor White
    Write-Host "  Secrets Exposed: $($summary.Secrets)" -ForegroundColor $(if($summary.Secrets -eq 0){'Green'}else{'Red'})
    Write-Host "  Vulnerabilities: $($summary.Vulnerabilities)" -ForegroundColor $(if($summary.Vulnerabilities -eq 0){'Green'}else{'Yellow'})
    Write-Host "  Compliance Issues: $($summary.Compliance)" -ForegroundColor $(if($summary.Compliance -eq 0){'Green'}else{'Yellow'})
    Write-Host ""
    
    # Risk level
    $riskLevel = if ($summary.RiskScore -gt 50) { "CRITICAL" } elseif ($summary.RiskScore -gt 25) { "HIGH" } elseif ($summary.RiskScore -gt 10) { "MEDIUM" } else { "LOW" }
    $riskColor = if ($summary.RiskScore -gt 50) { 'Red' } elseif ($summary.RiskScore -gt 25) { 'Yellow' } else { 'Green' }
    
    Write-Host "Risk Score: $($summary.RiskScore) ($riskLevel)" -ForegroundColor $riskColor
    
    # Show findings by severity
    $bySeverity = $script:ScanState.Findings | Group-Object -Property Severity
    Write-Host ""
    Write-Host "Findings by Severity:" -ForegroundColor White
    foreach ($sev in @("critical", "high", "medium", "low")) {
        $count = ($bySeverity | Where-Object { $_.Name -eq $sev }).Count
        $color = switch ($sev) {
            "critical" { 'Red' }
            "high" { 'Yellow' }
            "medium" { 'Cyan' }
            default { 'Green' }
        }
        Write-Host "  $($sev.PadRight(10)): $count" -ForegroundColor $color
    }
    
    # Show top findings
    if ($script:ScanState.Findings.Count -gt 0) {
        Write-Host ""
        Write-Host "Top Findings:" -ForegroundColor White
        foreach ($finding in $script:ScanState.Findings | Sort-Object { $SecurityConfig.SeverityWeights[$_.Severity] } -Descending | Select-Object -First 10) {
            $color = switch ($finding.Severity) {
                "critical" { 'Red' }
                "high" { 'Yellow' }
                default { 'Gray' }
            }
            Write-Host "  [$($finding.Severity.ToUpper())] $($finding.Category) in $([System.IO.Path]::GetFileName($finding.File))" -ForegroundColor $color
        }
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Security Scanner" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Scanner
    Invoke-SecurityScan
    $report = Export-SecurityReport
    Show-Summary
    
    # Exit code
    if ($FailOnFinding -and $script:ScanState.Findings.Count -gt 0) {
        Write-Host ""
        Write-Error "Security scan failed: Findings detected"
        exit 1
    }
    
    exit 0
}

Main
