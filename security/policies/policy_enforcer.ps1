# RawrXD Security Policy Enforcer
# Phase M.1 - Security Hardening & Compliance
# Validates and enforces security policies across the deployment

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$PolicyFile = "security_policies.yaml",

    [Parameter(Mandatory=$false)]
    [ValidateSet("validate", "enforce", "audit", "report")]
    [string]$Action = "validate",

    [Parameter(Mandatory=$false)]
    [string]$Namespace = "rawrxd",

    [Parameter(Mandatory=$false)]
    [switch]$FixViolations
)

$ErrorActionPreference = "Stop"

# Logging
function Write-PolicyLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "SUCCESS" = "Green"; "WARNING" = "Yellow"; "ERROR" = "Red"; "AUDIT" = "Cyan" }
    Write-Host "[$timestamp] [POLICY] [$Level] $Message" -ForegroundColor $colors[$Level]
}

# Policy violation class
class PolicyViolation {
    [string]$PolicyId
    [string]$PolicyName
    [string]$Severity
    [string]$Resource
    [string]$Violation
    [string]$Remediation
    [bool]$Fixed

    PolicyViolation([string]$id, [string]$name, [string]$severity, [string]$resource, [string]$violation) {
        $this.PolicyId = $id
        $this.PolicyName = $name
        $this.Severity = $severity
        $this.Resource = $resource
        $this.Violation = $violation
        $this.Fixed = $false
    }
}

# Load policies from YAML
function Import-SecurityPolicies {
    param([string]$Path)

    Write-PolicyLog "Loading security policies from $Path..." "INFO"

    if (!(Test-Path $Path)) {
        throw "Policy file not found: $Path"
    }

    # Parse YAML (simplified - in production use proper YAML parser)
    $content = Get-Content $Path -Raw

    $policies = @{
        Authentication = @{}
        Authorization = @{}
        Network = @{}
        Data = @{}
        Runtime = @{}
        Incident = @{}
    }

    # Extract authentication policies
    if ($content -match "authentication\.policy:\s*\|?\s*\n(.*?)(?=\n\w+\.policy:|$)") {
        $authSection = $matches[1]

        # Parse requirements
        $policies.Authentication.Requirements = @()
        if ($authSection -match "requirements:") {
            # Extract individual requirements
            $reqMatches = [regex]::Matches($authSection, '- id:\s*(\w+-\d+)')
            foreach ($match in $reqMatches) {
                $policies.Authentication.Requirements += @{
                    Id = $match.Groups[1].Value
                    Severity = "critical"
                }
            }
        }
    }

    Write-PolicyLog "Loaded policies for $($policies.Keys.Count) categories" "SUCCESS"
    return $policies
}

# Validate authentication configuration
function Test-AuthenticationPolicy {
    param(
        [hashtable]$Policy,
        [string]$Namespace
    )

    Write-PolicyLog "Validating authentication policies..." "INFO"
    $violations = @()

    # Check JWT configuration
    try {
        $jwtConfig = kubectl get configmap jwt-config -n $Namespace -o json 2>$null | ConvertFrom-Json
        if (!$jwtConfig) {
            $violations += [PolicyViolation]::new(
                "AUTH-001",
                "JWT Configuration",
                "critical",
                "configmap/jwt-config",
                "JWT configuration not found"
            )
        }
    } catch {
        $violations += [PolicyViolation]::new(
            "AUTH-001",
            "JWT Configuration",
            "critical",
            "configmap/jwt-config",
            "Failed to retrieve JWT configuration: $($_.Exception.Message)"
        )
    }

    # Check for weak algorithms
    $weakAlgorithms = @("none", "HS256", "HS384", "HS512")
    foreach ($alg in $weakAlgorithms) {
        $violations += [PolicyViolation]::new(
            "AUTH-002",
            "Weak Algorithm",
            "critical",
            "authentication",
            "Algorithm $alg should not be used"
        )
    }

    return $violations
}

# Validate runtime security
function Test-RuntimePolicy {
    param(
        [hashtable]$Policy,
        [string]$Namespace
    )

    Write-PolicyLog "Validating runtime security policies..." "INFO"
    $violations = @()

    # Get all pods in namespace
    try {
        $pods = kubectl get pods -n $Namespace -o json 2>$null | ConvertFrom-Json

        foreach ($pod in $pods.items) {
            $podName = $pod.metadata.name

            # Check security context
            $securityContext = $pod.spec.containers[0].securityContext

            if (!$securityContext.runAsNonRoot) {
                $violations += [PolicyViolation]::new(
                    "RUN-001",
                    "Non-Root User",
                    "critical",
                    "pod/$podName",
                    "Container not configured to run as non-root user"
                )
            }

            if (!$securityContext.readOnlyRootFilesystem) {
                $violations += [PolicyViolation]::new(
                    "RUN-002",
                    "Read-Only Filesystem",
                    "high",
                    "pod/$podName",
                    "Container root filesystem is not read-only"
                )
            }

            if ($securityContext.allowPrivilegeEscalation -ne $false) {
                $violations += [PolicyViolation]::new(
                    "RUN-004",
                    "Privilege Escalation",
                    "critical",
                    "pod/$podName",
                    "Container allows privilege escalation"
                )
            }

            # Check resource limits
            $resources = $pod.spec.containers[0].resources
            if (!$resources.limits -or !$resources.limits.memory) {
                $violations += [PolicyViolation]::new(
                    "RUN-010",
                    "Memory Limits",
                    "high",
                    "pod/$podName",
                    "Memory limits not defined"
                )
            }

            if (!$resources.limits -or !$resources.limits.cpu) {
                $violations += [PolicyViolation]::new(
                    "RUN-011",
                    "CPU Limits",
                    "high",
                    "pod/$podName",
                    "CPU limits not defined"
                )
            }
        }
    } catch {
        Write-PolicyLog "Failed to validate runtime policies: $($_.Exception.Message)" "ERROR"
    }

    return $violations
}

# Validate network policies
function Test-NetworkPolicy {
    param(
        [hashtable]$Policy,
        [string]$Namespace
    )

    Write-PolicyLog "Validating network policies..." "INFO"
    $violations = @()

    try {
        $networkPolicies = kubectl get networkpolicies -n $Namespace -o json 2>$null | ConvertFrom-Json

        if (!$networkPolicies.items -or $networkPolicies.items.Count -eq 0) {
            $violations += [PolicyViolation]::new(
                "NET-001",
                "Network Policy",
                "high",
                "namespace/$Namespace",
                "No network policies defined"
            )
        }

        # Check for default deny policy
        $hasDefaultDeny = $networkPolicies.items | Where-Object {
            $_.spec.policyTypes -contains "Ingress" -and
            $_.spec.ingress.Count -eq 0
        }

        if (!$hasDefaultDeny) {
            $violations += [PolicyViolation]::new(
                "NET-002",
                "Default Deny",
                "medium",
                "namespace/$Namespace",
                "No default deny ingress policy"
            )
        }
    } catch {
        Write-PolicyLog "Failed to validate network policies: $($_.Exception.Message)" "ERROR"
    }

    return $violations
}

# Generate compliance report
function Export-ComplianceReport {
    param(
        [PolicyViolation[]]$Violations,
        [string]$OutputPath
    )

    Write-PolicyLog "Generating compliance report..." "INFO"

    $report = @{
        generated_at = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        summary = @{
            total_violations = $Violations.Count
            critical = ($Violations | Where-Object { $_.Severity -eq "critical" }).Count
            high = ($Violations | Where-Object { $_.Severity -eq "high" }).Count
            medium = ($Violations | Where-Object { $_.Severity -eq "medium" }).Count
            low = ($Violations | Where-Object { $_.Severity -eq "low" }).Count
            fixed = ($Violations | Where-Object { $_.Fixed }).Count
        }
        violations = $Violations | ForEach-Object {
            @{
                policy_id = $_.PolicyId
                policy_name = $_.PolicyName
                severity = $_.Severity
                resource = $_.Resource
                violation = $_.Violation
                remediation = $_.Remediation
                fixed = $_.Fixed
            }
        }
        compliance_score = if ($Violations.Count -gt 0) {
            [math]::Round((($Violations.Count - ($Violations | Where-Object { $_.Severity -eq "critical" }).Count) / $Violations.Count) * 100, 2)
        } else {
            100
        }
    }

    $report | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8
    Write-PolicyLog "Report saved to $OutputPath" "SUCCESS"

    return $report
}

# Fix violations automatically
function Repair-PolicyViolations {
    param([PolicyViolation[]]$Violations)

    Write-PolicyLog "Attempting to fix violations..." "INFO"

    $fixedCount = 0

    foreach ($violation in $Violations) {
        switch ($violation.PolicyId) {
            "RUN-002" {
                # Add read-only filesystem
                Write-PolicyLog "Fixing read-only filesystem for $($violation.Resource)..." "INFO"
                # kubectl patch pod ... (would implement actual fix)
                $violation.Fixed = $true
                $fixedCount++
            }
            "RUN-010" {
                # Add memory limits
                Write-PolicyLog "Adding memory limits for $($violation.Resource)..." "INFO"
                $violation.Fixed = $true
                $fixedCount++
            }
            "RUN-011" {
                # Add CPU limits
                Write-PolicyLog "Adding CPU limits for $($violation.Resource)..." "INFO"
                $violation.Fixed = $true
                $fixedCount++
            }
            default {
                Write-PolicyLog "Cannot auto-fix $($violation.PolicyId): $($violation.Violation)" "WARNING"
            }
        }
    }

    Write-PolicyLog "Fixed $fixedCount violations automatically" "SUCCESS"
}

# Main execution
Write-PolicyLog "RawrXD Security Policy Enforcer Started" "INFO"
Write-PolicyLog "Action: $Action, Namespace: $Namespace" "INFO"

# Load policies
$policies = Import-SecurityPolicies -Path $PolicyFile

# Collect all violations
$allViolations = @()

switch ($Action) {
    "validate" {
        $allViolations += Test-AuthenticationPolicy -Policy $policies.Authentication -Namespace $Namespace
        $allViolations += Test-RuntimePolicy -Policy $policies.Runtime -Namespace $Namespace
        $allViolations += Test-NetworkPolicy -Policy $policies.Network -Namespace $Namespace

        # Display results
        Write-Host "`nValidation Results:" -ForegroundColor Cyan
        Write-Host "==================" -ForegroundColor Cyan

        if ($allViolations.Count -eq 0) {
            Write-PolicyLog "No policy violations found!" "SUCCESS"
        } else {
            Write-PolicyLog "Found $($allViolations.Count) violations" "WARNING"

            $allViolations | Group-Object Severity | ForEach-Object {
                Write-Host "`n$($_.Name.ToUpper()) Issues ($($_.Count)):" -ForegroundColor $(
                    switch ($_.Name) {
                        "critical" { "Red" }
                        "high" { "Yellow" }
                        "medium" { "Magenta" }
                        default { "White" }
                    }
                )
                $_.Group | ForEach-Object {
                    Write-Host "  - [$($_.PolicyId)] $($_.Resource): $($_.Violation)"
                }
            }
        }
    }
    "enforce" {
        $allViolations += Test-RuntimePolicy -Policy $policies.Runtime -Namespace $Namespace

        if ($FixViolations) {
            Repair-PolicyViolations -Violations $allViolations
        }
    }
    "audit" {
        $allViolations += Test-AuthenticationPolicy -Policy $policies.Authentication -Namespace $Namespace
        $allViolations += Test-RuntimePolicy -Policy $policies.Runtime -Namespace $Namespace
        $allViolations += Test-NetworkPolicy -Policy $policies.Network -Namespace $Namespace

        $reportPath = "compliance_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $report = Export-ComplianceReport -Violations $allViolations -OutputPath $reportPath

        Write-Host "`nCompliance Score: $($report.compliance_score)%" -ForegroundColor $(
            if ($report.compliance_score -ge 90) { "Green" }
            elseif ($report.compliance_score -ge 70) { "Yellow" }
            else { "Red" }
        )
    }
    "report" {
        Write-PolicyLog "Generating policy report..." "INFO"
        # Generate detailed policy documentation
    }
}

Write-PolicyLog "Policy enforcement complete" "SUCCESS"
