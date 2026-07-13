# RawrXD Security Scanner
# Automated security scanning and vulnerability detection

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Quick', 'Full', 'Compliance')]
    [string]$ScanType = 'Quick',

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "./security-scan-$(Get-Date -Format 'yyyyMMdd-HHmmss').json",

    [Parameter(Mandatory = $false)]
    [switch]$AutoFix,

    [Parameter(Mandatory = $false)]
    [switch]$ReportOnly
)

$ErrorActionPreference = 'Stop'

# Configuration
$script:Config = @{
    ScanType = $ScanType
    StartTime = Get-Date
    RulesPath = Join-Path $PSScriptRoot 'security_rules.json'
    SeverityLevels = @('Critical', 'High', 'Medium', 'Low', 'Info')
}

# Security Rules
$script:SecurityRules = @{
    FilePermissions = @{
        Name = 'File Permissions Check'
        Description = 'Verifies secure file permissions on sensitive files'
        Severity = 'High'
        Check = {
            param($Path)
            $issues = @()
            $sensitivePaths = @(
                'security/rbac/rbac_config.json',
                'security/secrets',
                'logs/audit'
            )

            foreach ($sensitivePath in $sensitivePaths) {
                $fullPath = Join-Path $Path $sensitivePath
                if (Test-Path $fullPath) {
                    $acl = Get-Acl $fullPath -ErrorAction SilentlyContinue
                    if ($acl) {
                        $usersWithWrite = $acl.Access | Where-Object {
                            $_.FileSystemRights -match 'Write|Modify|FullControl' -and
                            $_.IdentityReference -notmatch 'SYSTEM|Administrators'
                        }

                        if ($usersWithWrite) {
                            $issues += @{
                                Path = $sensitivePath
                                Issue = "Overly permissive: $($usersWithWrite.Count) non-admin users have write access"
                                Severity = 'High'
                            }
                        }
                    }
                }
            }

            return $issues
        }
    }

    SecretDetection = @{
        Name = 'Secret Detection'
        Description = 'Scans for hardcoded secrets and credentials'
        Severity = 'Critical'
        Check = {
            param($Path)
            $issues = @()
            $patterns = @(
                @{ Pattern = 'password\s*=\s*["\'][^"\']{8,}["\']'; Name = 'Hardcoded Password' },
                @{ Pattern = 'api[_-]?key\s*=\s*["\'][^"\']{16,}["\']'; Name = 'API Key' },
                @{ Pattern = 'secret\s*=\s*["\'][^"\']{16,}["\']'; Name = 'Secret' },
                @{ Pattern = 'token\s*=\s*["\'][^"\']{16,}["\']'; Name = 'Token' },
                @{ Pattern = 'connection[_-]?string.*password'; Name = 'Connection String with Password' }
            )

            $scripts = Get-ChildItem -Path $Path -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue

            foreach ($script in $scripts) {
                $content = Get-Content $script.FullName -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    foreach ($patternInfo in $patterns) {
                        if ($content -match $patternInfo.Pattern) {
                            $issues += @{
                                File = $script.FullName
                                Issue = "Potential $($patternInfo.Name) detected"
                                Severity = 'Critical'
                                Line = ($content -split "`n" | Select-String $patternInfo.Pattern | Select-Object -First 1).LineNumber
                            }
                        }
                    }
                }
            }

            return $issues
        }
    }

    RBACConfiguration = @{
        Name = 'RBAC Configuration Check'
        Description = 'Validates RBAC configuration security'
        Severity = 'High'
        Check = {
            param($Path)
            $issues = @()
            $rbacPath = Join-Path $Path 'security/rbac/rbac_config.json'

            if (Test-Path $rbacPath) {
                $config = Get-Content $rbacPath | ConvertFrom-Json

                # Check for default super-admin without restrictions
                $superAdmin = $config.roles | Where-Object { $_.name -eq 'super-admin' }
                if ($superAdmin -and $superAdmin.permissions -contains '*') {
                    $superAdminUsers = $config.users | Where-Object { $_.role -eq 'super-admin' }
                    if ($superAdminUsers.Count -gt 2) {
                        $issues += @{
                            Path = 'security/rbac/rbac_config.json'
                            Issue = "Too many super-admin users ($($superAdminUsers.Count)) - consider principle of least privilege"
                            Severity = 'Medium'
                        }
                    }
                }

                # Check for users without MFA (simulated)
                $privilegedUsers = $config.users | Where-Object {
                    $userRole = $config.roles | Where-Object { $_.name -eq $_.role }
                    $userRole.level -ge 60
                }

                if ($privilegedUsers.Count -gt 0) {
                    $issues += @{
                        Path = 'security/rbac/rbac_config.json'
                        Issue = "$($privilegedUsers.Count) privileged users should have MFA enforced"
                        Severity = 'Medium'
                    }
                }
            }
            else {
                $issues += @{
                    Path = 'security/rbac/rbac_config.json'
                    Issue = 'RBAC configuration not found'
                    Severity = 'Critical'
                }
            }

            return $issues
        }
    }

    AuditLogging = @{
        Name = 'Audit Logging Check'
        Description = 'Verifies audit logging is properly configured'
        Severity = 'Medium'
        Check = {
            param($Path)
            $issues = @()
            $auditPath = Join-Path $Path 'logs/audit'

            if (-not (Test-Path $auditPath)) {
                $issues += @{
                    Path = 'logs/audit'
                    Issue = 'Audit log directory not found'
                    Severity = 'High'
                }
            }
            else {
                $recentLogs = Get-ChildItem -Path $auditPath -Filter 'audit_*.jsonl' -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }

                if (-not $recentLogs) {
                    $issues += @{
                        Path = 'logs/audit'
                        Issue = 'No recent audit logs found (last 7 days)'
                        Severity = 'Medium'
                    }
                }
            }

            return $issues
        }
    }

    PowerShellSecurity = @{
        Name = 'PowerShell Security Check'
        Description = 'Checks PowerShell script security settings'
        Severity = 'Medium'
        Check = {
            param($Path)
            $issues = @()

            # Check execution policy
            $execPolicy = Get-ExecutionPolicy
            if ($execPolicy -eq 'Unrestricted' -or $execPolicy -eq 'Bypass') {
                $issues += @{
                    Path = 'System'
                    Issue = "Execution policy is $execPolicy - consider more restrictive policy"
                    Severity = 'Medium'
                }
            }

            # Check for scripts with dangerous functions
            $dangerousPatterns = @('Invoke-Expression', 'Invoke-Command', 'Start-Process')
            $scripts = Get-ChildItem -Path $Path -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue

            foreach ($script in $scripts) {
                $content = Get-Content $script.FullName -Raw -ErrorAction SilentlyContinue
                foreach ($pattern in $dangerousPatterns) {
                    if ($content -match $pattern) {
                        $issues += @{
                            File = $script.FullName
                            Issue = "Script contains potentially dangerous command: $pattern"
                            Severity = 'Low'
                        }
                    }
                }
            }

            return $issues
        }
    }
}

function Write-ScanProgress {
    param([string]$Activity, [string]$Status)
    Write-Progress -Activity $Activity -Status $Status -PercentComplete -1
    Write-Host "[$Activity] $Status" -ForegroundColor Cyan
}

function Invoke-SecurityScan {
    param([string]$TargetPath)

    Write-ScanProgress -Activity 'Security Scan' -Status 'Starting scan...'

    $scanResults = @{
        ScanType = $script:Config.ScanType
        StartTime = $script:Config.StartTime
        EndTime = $null
        Duration = $null
        Summary = @{
            TotalChecks = 0
            Passed = 0
            Failed = 0
            CriticalIssues = 0
            HighIssues = 0
            MediumIssues = 0
            LowIssues = 0
        }
        Results = @()
    }

    $rulesToRun = switch ($ScanType) {
        'Quick' { @('FilePermissions', 'SecretDetection', 'RBACConfiguration') }
        'Full' { $script:SecurityRules.Keys }
        'Compliance' { @('RBACConfiguration', 'AuditLogging', 'FilePermissions') }
    }

    foreach ($ruleName in $rulesToRun) {
        $rule = $script:SecurityRules[$ruleName]
        Write-ScanProgress -Activity 'Security Scan' -Status "Running: $($rule.Name)"

        $issues = & $rule.Check -Path $TargetPath

        $scanResults.Results += @{
            Rule = $ruleName
            Name = $rule.Name
            Description = $rule.Description
            Severity = $rule.Severity
            IssuesFound = $issues.Count
            Issues = $issues
            Status = if ($issues.Count -eq 0) { 'PASSED' } else { 'FAILED' }
        }

        $scanResults.Summary.TotalChecks++
        if ($issues.Count -eq 0) {
            $scanResults.Summary.Passed++
        }
        else {
            $scanResults.Summary.Failed++
            foreach ($issue in $issues) {
                switch ($issue.Severity) {
                    'Critical' { $scanResults.Summary.CriticalIssues++ }
                    'High' { $scanResults.Summary.HighIssues++ }
                    'Medium' { $scanResults.Summary.MediumIssues++ }
                    'Low' { $scanResults.Summary.LowIssues++ }
                }
            }
        }
    }

    $scanResults.EndTime = Get-Date
    $scanResults.Duration = ($scanResults.EndTime - $scanResults.StartTime).ToString()

    Write-Progress -Activity 'Security Scan' -Completed

    return $scanResults
}

function Show-ScanResults {
    param([hashtable]$Results)

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Security Scan Results" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "Summary:" -ForegroundColor White
    Write-Host "  Scan Type: $($Results.ScanType)" -ForegroundColor Gray
    Write-Host "  Duration: $($Results.Duration)" -ForegroundColor Gray
    Write-Host "  Total Checks: $($Results.Summary.TotalChecks)" -ForegroundColor Gray
    Write-Host "  Passed: $($Results.Summary.Passed)" -ForegroundColor Green
    Write-Host "  Failed: $($Results.Summary.Failed)" -ForegroundColor Red
    Write-Host ""

    if ($Results.Summary.CriticalIssues -gt 0) {
        Write-Host "  Critical Issues: $($Results.Summary.CriticalIssues)" -ForegroundColor Red
    }
    if ($Results.Summary.HighIssues -gt 0) {
        Write-Host "  High Issues: $($Results.Summary.HighIssues)" -ForegroundColor Red
    }
    if ($Results.Summary.MediumIssues -gt 0) {
        Write-Host "  Medium Issues: $($Results.Summary.MediumIssues)" -ForegroundColor Yellow
    }
    if ($Results.Summary.LowIssues -gt 0) {
        Write-Host "  Low Issues: $($Results.Summary.LowIssues)" -ForegroundColor Gray
    }

    Write-Host "`nDetailed Results:" -ForegroundColor White
    foreach ($result in $Results.Results) {
        $color = switch ($result.Status) {
            'PASSED' { 'Green' }
            'FAILED' { 'Red' }
            default { 'White' }
        }

        Write-Host "`n  [$($result.Status)] $($result.Name)" -ForegroundColor $color
        Write-Host "    Description: $($result.Description)" -ForegroundColor Gray

        if ($result.Issues.Count -gt 0) {
            Write-Host "    Issues Found: $($result.Issues.Count)" -ForegroundColor Yellow
            foreach ($issue in $result.Issues) {
                $issueColor = switch ($issue.Severity) {
                    'Critical' { 'Red' }
                    'High' { 'Red' }
                    'Medium' { 'Yellow' }
                    default { 'Gray' }
                }
                Write-Host "      - $($issue.Issue)" -ForegroundColor $issueColor
            }
        }
    }

    Write-Host "`n========================================" -ForegroundColor Cyan
}

function Export-ScanResults {
    param(
        [hashtable]$Results,
        [string]$Path
    )

    $Results | ConvertTo-Json -Depth 10 | Out-File $Path -Force
    Write-Host "`n✓ Results exported to: $Path" -ForegroundColor Green
}

# Main execution
Write-Host "RawrXD Security Scanner" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan
Write-Host "Scan Type: $ScanType" -ForegroundColor Gray
Write-Host "Auto-Fix: $AutoFix" -ForegroundColor Gray
Write-Host ""

$targetPath = Resolve-Path (Join-Path $PSScriptRoot '..')
$scanResults = Invoke-SecurityScan -TargetPath $targetPath

Show-ScanResults -Results $scanResults

if (-not $ReportOnly) {
    Export-ScanResults -Results $scanResults -Path $OutputPath
}

# Exit code based on severity
if ($scanResults.Summary.CriticalIssues -gt 0) {
    exit 2
}
elseif ($scanResults.Summary.HighIssues -gt 0) {
    exit 1
}
else {
    exit 0
}
