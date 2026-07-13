#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase L.8: Enterprise Deployment Profiles
    
.DESCRIPTION
    Defines and validates deployment profiles for different use cases:
    - Developer: Single node, local models, community support
    - Production: Monitoring, audit, rollback, LTS runtime
    - Enterprise Sovereign: Multi-node, zero trust, federation, custom SLA
    
.PARAMETER Profile
    Deployment profile to configure: developer, production, enterprise
    
.PARAMETER OutputPath
    Output directory for configuration files
    
.PARAMETER ValidateOnly
    Only validate existing configuration without generating new files
    
.EXAMPLE
    .\deployment_profiles.ps1 -Profile enterprise -OutputPath .\config
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("developer", "production", "enterprise")]
    [string]$Profile,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\deployment",
    
    [Parameter(Mandatory=$false)]
    [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"

# Profile definitions
$Profiles = @{
    developer = @{
        name = "Developer"
        description = "Single node, local models, community support"
        tier = "community"
        nodes = @{ min = 1; max = 1; recommended = 1 }
        resources = @{
            cpu = @{ cores = 4; required = $false }
            memory = @{ gb = 16; required = $false }
            gpu = @{ vram_gb = 8; required = $false }
            storage = @{ gb = 100; required = $false }
        }
        features = @{
            hotpatch = $true
            telemetry = $false
            audit = $false
            chaos_testing = $false
            multi_node = $false
            sso = $false
            encryption = $false
        }
        support = @{
            level = "community"
            channels = @("discord", "github")
            response_time = "best effort"
        }
        security = @{
            tls = "optional"
            authentication = "none"
            authorization = "none"
            network_policy = "permissive"
        }
        monitoring = @{
            enabled = $false
            retention_days = 0
            alerting = $false
        }
        backup = @{
            enabled = $false
            schedule = "none"
            retention = "none"
        }
    }
    
    production = @{
        name = "Production"
        description = "Monitoring, audit, rollback, LTS runtime"
        tier = "standard"
        nodes = @{ min = 1; max = 4; recommended = 2 }
        resources = @{
            cpu = @{ cores = 16; required = $true }
            memory = @{ gb = 64; required = $true }
            gpu = @{ vram_gb = 16; required = $true }
            storage = @{ gb = 500; required = $true }
        }
        features = @{
            hotpatch = $true
            telemetry = $true
            audit = $true
            chaos_testing = $true
            multi_node = $true
            sso = $true
            encryption = $true
        }
        support = @{
            level = "standard"
            channels = @("email", "github", "discord")
            response_time = "24 hours"
            sla = "99.9%"
        }
        security = @{
            tls = "required"
            tls_version = "1.3"
            authentication = "token"
            authorization = "rbac"
            network_policy = "restricted"
            firewall = $true
        }
        monitoring = @{
            enabled = $true
            retention_days = 30
            alerting = $true
            metrics = @("tps", "latency", "memory", "gpu_utilization")
        }
        backup = @{
            enabled = $true
            schedule = "daily"
            retention = "30 days"
            encryption = $true
        }
        governance = @{
            enabled = $true
            mode = "adaptive"
            rollback = $true
            audit_retention_days = 90
        }
    }
    
    enterprise = @{
        name = "Enterprise Sovereign"
        description = "Multi-node, zero trust, federation, custom SLA"
        tier = "enterprise"
        nodes = @{ min = 3; max = 100; recommended = 5 }
        resources = @{
            cpu = @{ cores = 32; required = $true }
            memory = @{ gb = 128; required = $true }
            gpu = @{ vram_gb = 24; required = $true }
            storage = @{ gb = 2000; required = $true }
            network = @{ bandwidth_mbps = 10000; required = $true }
        }
        features = @{
            hotpatch = $true
            telemetry = $true
            audit = $true
            chaos_testing = $true
            multi_node = $true
            sso = $true
            encryption = $true
            federation = $true
            zero_trust = $true
            air_gap = $true
        }
        support = @{
            level = "enterprise"
            channels = @("phone", "slack", "email", "dedicated")
            response_time = "1 hour"
            sla = "99.95%"
            dedicated_engineer = $true
        }
        security = @{
            tls = "required"
            tls_version = "1.3"
            mTLS = $true
            authentication = "sso"
            sso_protocols = @("saml", "oidc")
            authorization = "rbac"
            network_policy = "zero_trust"
            firewall = $true
            ids = $true
            encryption_at_rest = $true
            encryption_in_transit = $true
            key_rotation_days = 90
        }
        monitoring = @{
            enabled = $true
            retention_days = 365
            alerting = $true
            siem_integration = $true
            metrics = @("tps", "latency", "memory", "gpu_utilization", "network", "security")
        }
        backup = @{
            enabled = $true
            schedule = "hourly"
            retention = "1 year"
            encryption = $true
            geo_redundancy = $true
        }
        governance = @{
            enabled = $true
            mode = "strict"
            rollback = $true
            audit_retention_days = 2555  # 7 years
            compliance = @("soc2", "iso27001", "gdpr")
        }
        federation = @{
            enabled = $true
            protocols = @("grpc", "rest")
            discovery = $true
            load_balancing = "weighted"
        }
    }
}

function Write-ProfileHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase L.8: Enterprise Deployment Profiles                       ║
║  Configure RawrXD for your environment                          ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
    Write-Host "Profile: $($Profiles[$Profile].name)" -ForegroundColor White
    Write-Host "Description: $($Profiles[$Profile].description)" -ForegroundColor Gray
    Write-Host ""
}

function Export-ProfileConfiguration {
    <#
    .SYNOPSIS
        Export profile configuration files
    #>
    Write-Host "[1/4] Generating configuration files..." -ForegroundColor Yellow
    
    $config = $Profiles[$Profile]
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Main configuration
    $configFile = Join-Path $OutputPath "rawrxd.config.json"
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile
    Write-Host "  ✓ Main config: $configFile" -ForegroundColor Green
    
    # Docker Compose (if applicable)
    if ($Profile -in @("production", "enterprise")) {
        $dockerCompose = @"
version: '3.8'

services:
  rawrxd:
    image: rawrxd/rawrxd:$($config.tier)
    container_name: rawrxd-$Profile
    restart: unless-stopped
    
    deploy:
      resources:
        limits:
          cpus: '$($config.resources.cpu.cores)'
          memory: $($config.resources.memory.gb)G
    
    environment:
      - RAWRXD_PROFILE=$Profile
      - RAWRXD_TIER=$($config.tier)
      - RAWRXD_TELEMETRY=$($config.features.telemetry)
      - RAWRXD_AUDIT=$($config.features.audit)
    
    volumes:
      - ./models:/models:ro
      - ./data:/data
      - ./logs:/logs
    
    ports:
      - "8080:8080"
    
    $(if ($config.security.network_policy -eq "restricted") { "networks:`n      - rawrxd-net" } else { "" })
    
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

$(if ($config.features.telemetry) { @"
  telemetry:
    image: rawrxd/telemetry:latest
    container_name: rawrxd-telemetry
    restart: unless-stopped
    
    environment:
      - RETENTION_DAYS=$($config.monitoring.retention_days)
    
    volumes:
      - ./telemetry:/data
"@ } else { "" })

$(if ($config.features.audit) { @"
  audit:
    image: rawrxd/audit:latest
    container_name: rawrxd-audit
    restart: unless-stopped
    
    environment:
      - RETENTION_DAYS=$($config.governance.audit_retention_days)
    
    volumes:
      - ./audit:/data
"@ } else { "" })

$(if ($config.security.network_policy -eq "restricted") { @"
networks:
  rawrxd-net:
    driver: bridge
    internal: true
"@ } else { "" })
"@
        
        $dockerFile = Join-Path $OutputPath "docker-compose.yml"
        $dockerCompose | Set-Content -Path $dockerFile
        Write-Host "  ✓ Docker Compose: $dockerFile" -ForegroundColor Green
    }
    
    # Kubernetes manifests (enterprise only)
    if ($Profile -eq "enterprise") {
        $k8sNamespace = @"
apiVersion: v1
kind: Namespace
metadata:
  name: rawrxd-enterprise
  labels:
    tier: enterprise
    compliance: soc2,iso27001
"@
        
        $k8sDeployment = @"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rawrxd-enterprise
  namespace: rawrxd-enterprise
spec:
  replicas: $($config.nodes.recommended)
  selector:
    matchLabels:
      app: rawrxd
      tier: enterprise
  template:
    metadata:
      labels:
        app: rawrxd
        tier: enterprise
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: rawrxd
        image: rawrxd/rawrxd:enterprise
        resources:
          requests:
            memory: "$($config.resources.memory.gb)Gi"
            cpu: "$($config.resources.cpu.cores)"
          limits:
            memory: "$($config.resources.memory.gb)Gi"
            cpu: "$($config.resources.cpu.cores)"
        ports:
        - containerPort: 8080
        env:
        - name: RAWRXD_PROFILE
          value: "enterprise"
        - name: RAWRXD_FEDERATION_ENABLED
          value: "true"
        volumeMounts:
        - name: models
          mountPath: /models
          readOnly: true
        - name: data
          mountPath: /data
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      volumes:
      - name: models
        persistentVolumeClaim:
          claimName: rawrxd-models
      - name: data
        persistentVolumeClaim:
          claimName: rawrxd-data
"@
        
        $k8sDir = Join-Path $OutputPath "kubernetes"
        New-Item -ItemType Directory -Path $k8sDir -Force | Out-Null
        
        $k8sNamespace | Set-Content -Path (Join-Path $k8sDir "namespace.yaml")
        $k8sDeployment | Set-Content -Path (Join-Path $k8sDir "deployment.yaml")
        
        Write-Host "  ✓ Kubernetes manifests: $k8sDir" -ForegroundColor Green
    }
    
    # Environment file
    $envFile = Join-Path $OutputPath ".env"
    $envContent = @"
# RawrXD Deployment Profile: $($config.name)
# Generated: $(Get-Date -Format "o")

RAWRXD_PROFILE=$Profile
RAWRXD_TIER=$($config.tier)
RAWRXD_VERSION=1.0.0

# Features
RAWRXD_HOTPATCH_ENABLED=$($config.features.hotpatch)
RAWRXD_TELEMETRY_ENABLED=$($config.features.telemetry)
RAWRXD_AUDIT_ENABLED=$($config.features.audit)
RAWRXD_CHAOS_TESTING=$($config.features.chaos_testing)

# Resources
RAWRXD_CPU_CORES=$($config.resources.cpu.cores)
RAWRXD_MEMORY_GB=$($config.resources.memory.gb)
RAWRXD_GPU_VRAM_GB=$($config.resources.gpu.vram_gb)

# Security
RAWRXD_TLS_REQUIRED=$($config.security.tls -eq "required")
RAWRXD_AUTH_MODE=$($config.security.authentication)
RAWRXD_AUTHZ_MODE=$($config.security.authorization)

# Monitoring
RAWRXD_MONITORING_ENABLED=$($config.monitoring.enabled)
RAWRXD_METRICS_RETENTION_DAYS=$($config.monitoring.retention_days)

# Governance
RAWRXD_GOVERNANCE_MODE=$($config.governance.mode)
RAWRXD_ROLLBACK_ENABLED=$($config.governance.rollback)
"@
    
    $envContent | Set-Content -Path $envFile
    Write-Host "  ✓ Environment file: $envFile" -ForegroundColor Green
}

function Export-ValidationScript {
    <#
    .SYNOPSIS
        Export environment validation script
    #>
    Write-Host "`n[2/4] Generating validation script..." -ForegroundColor Yellow
    
    $config = $Profiles[$Profile]
    
    $validationScript = @"
#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Validate $($config.name) deployment environment
#>

`$ErrorActionPreference = "Stop"

Write-Host "Validating $($config.name) deployment environment..." -ForegroundColor Cyan

`$checks = @()

# CPU Check
`$cpuCores = (Get-CimInstance Win32_Processor).NumberOfLogicalProcessors
`$cpuCheck = @{
    Name = "CPU Cores"
    Required = $($config.resources.cpu.cores)
    Actual = `$cpuCores
    Status = if (`$cpuCores -ge $($config.resources.cpu.cores)) { "PASS" } else { "FAIL" }
}
`$checks += `$cpuCheck

# Memory Check
`$memoryGB = [math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB)
`$memCheck = @{
    Name = "Memory (GB)"
    Required = $($config.resources.memory.gb)
    Actual = `$memoryGB
    Status = if (`$memoryGB -ge $($config.resources.memory.gb)) { "PASS" } else { "FAIL" }
}
`$checks += `$memCheck

# GPU Check (if required)
$(if ($config.resources.gpu.required) { @"
`$gpu = Get-CimInstance Win32_VideoController | Where-Object { `$_.AdapterRAM -gt 0 } | Select-Object -First 1
`$gpuVRAM = if (`$gpu) { [math]::Round(`$gpu.AdapterRAM / 1GB) } else { 0 }
`$gpuCheck = @{
    Name = "GPU VRAM (GB)"
    Required = $($config.resources.gpu.vram_gb)
    Actual = `$gpuVRAM
    Status = if (`$gpuVRAM -ge $($config.resources.gpu.vram_gb)) { "PASS" } else { "WARN" }
}
`$checks += `$gpuCheck
"@ } else { "" })

# Display results
Write-Host "`nValidation Results:" -ForegroundColor White
foreach (`$check in `$checks) {
    `$color = switch (`$check.Status) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
    }
    Write-Host "  [`$(`$check.Status)] `$(`$check.Name): `$(`$check.Actual)/`$(`$check.Required)" -ForegroundColor `$color
}

`$failed = `$checks | Where-Object { `$_.Status -eq "FAIL" }
if (`$failed) {
    Write-Host "`n❌ Environment validation FAILED" -ForegroundColor Red
    exit 1
} else {
    Write-Host "`n✅ Environment validation PASSED" -ForegroundColor Green
    exit 0
}
"@
    
    $validationFile = Join-Path $OutputPath "validate-environment.ps1"
    $validationScript | Set-Content -Path $validationFile
    
    Write-Host "  ✓ Validation script: $validationFile" -ForegroundColor Green
}

function Export-DeploymentGuide {
    <#
    .SYNOPSIS
        Export deployment guide
    #>
    Write-Host "`n[3/4] Generating deployment guide..." -ForegroundColor Yellow
    
    $config = $Profiles[$Profile]
    
    $guide = @"
# RawrXD $($config.name) Deployment Guide

## Overview

This guide covers deploying RawrXD in a **$($config.name)** configuration.

**Profile:** $Profile  
**Tier:** $($config.tier)  
**Nodes:** $($config.nodes.min)-$($config.nodes.max) (recommended: $($config.nodes.recommended))

---

## Prerequisites

### Hardware Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU Cores | $($config.resources.cpu.cores) | $($config.resources.cpu.cores) |
| Memory | $($config.resources.memory.gb) GB | $($config.resources.memory.gb) GB |
$(if ($config.resources.gpu.required) { "| GPU VRAM | $($config.resources.gpu.vram_gb) GB | $($config.resources.gpu.vram_gb) GB |`n" } else { "" })| Storage | 100 GB | $($config.resources.storage.gb) GB |

### Software Requirements

- Windows 10/11 or Windows Server 2019/2022
- PowerShell 7.0+
- Docker Desktop (for containerized deployment)
$(if ($Profile -eq "enterprise") { "- Kubernetes 1.28+ (for orchestrated deployment)`n" } else { "" })
---

## Quick Start

### 1. Validate Environment

```powershell
.\validate-environment.ps1
```

### 2. Configure Environment

```powershell
# Load environment variables
Get-Content .env | ForEach-Object { 
    if (`$_ -match '^([^=]+)=(.*)`$') {
        [Environment]::SetEnvironmentVariable(`$matches[1], `$matches[2])
    }
}
```

### 3. Deploy

$(if ($Profile -in @("production", "enterprise")) { @"
#### Docker Compose

```powershell
docker-compose up -d
```

#### Verify Deployment

```powershell
docker-compose ps
curl http://localhost:8080/health
```
"@ } else { @"
#### Native Deployment

```powershell
# Build from source
.\build.ps1 -Profile $Profile

# Run
.\bin\RawrXD.exe --config rawrxd.config.json
```
"@ })

$(if ($Profile -eq "enterprise") { @"
#### Kubernetes

```powershell
# Apply manifests
kubectl apply -f kubernetes/

# Verify
kubectl get pods -n rawrxd-enterprise
kubectl logs -n rawrxd-enterprise -l app=rawrxd
```
"@ } else { "" })

---

## Configuration

### Key Settings

$(if ($config.features.telemetry) { @"
**Telemetry**
- Enabled: Yes
- Retention: $($config.monitoring.retention_days) days
- Metrics: $($config.monitoring.metrics -join ", ")
"@ } else { "" })

$(if ($config.features.audit) { @"
**Audit Logging**
- Enabled: Yes
- Retention: $($config.governance.audit_retention_days) days
- Compliance: $($config.governance.compliance -join ", ")
"@ } else { "" })

$(if ($config.security.tls -eq "required") { @"
**Security**
- TLS: Required (v$($config.security.tls_version))
- Authentication: $($config.security.authentication)
- Authorization: $($config.security.authorization)
- Network Policy: $($config.security.network_policy)
"@ } else { "" })

---

## Monitoring

$(if ($config.monitoring.enabled) { @"
### Metrics Endpoints

- Health: http://localhost:8080/health
- Metrics: http://localhost:8080/metrics
- Status: http://localhost:8080/status

### Alerting

Alerts are configured for:
$(foreach ($metric in $config.monitoring.metrics) { "- $metric`n" })
"@ } else { @"
Monitoring is disabled in $Profile profile.
Enable with RAWRXD_TELEMETRY_ENABLED=true
"@ })

---

## Troubleshooting

### Common Issues

**Issue:** Out of memory errors  
**Solution:** Increase memory allocation or reduce batch size

**Issue:** GPU not detected  
**Solution:** Verify GPU drivers are installed and up to date

**Issue:** Port conflicts  
**Solution:** Change port mapping in docker-compose.yml

### Support

$(switch ($config.support.level) {
    "community" { "- Discord: https://discord.gg/rawrxd`n- GitHub Issues: https://github.com/ItsMehRAWRXD/RawrXD/issues" }
    "standard" { "- Email: support@rawrxd.ai`n- GitHub Issues: https://github.com/ItsMehRAWRXD/RawrXD/issues`n- Response time: $($config.support.response_time)" }
    "enterprise" { "- Phone: +1-555-RAW-RXD9`n- Slack: Dedicated channel`n- Email: enterprise@rawrxd.ai`n- Response time: $($config.support.response_time)`n- SLA: $($config.support.sla)" }
})

---

## Security Considerations

$(if ($config.security.network_policy -eq "zero_trust") { @"
### Zero Trust Architecture

This deployment uses zero-trust networking:
- All connections authenticated
- mTLS required
- Network segmentation enforced
- Continuous verification
"@ } elseif ($config.security.network_policy -eq "restricted") { @"
### Restricted Network Policy

- Internal networking only
- Explicit port exposure
- Firewall rules enforced
"@ } else { @"
### Permissive Network Policy

Developer profile allows broad network access.
Use production/enterprise profiles for restricted access.
"@ })

---

## Next Steps

1. Review the [LTS Policy](../../SUPPORT_POLICY.md)
2. Configure [Security Patch Validation](../phase_l6_security_patch_validation/)
3. Set up [Reproducible Builds](../phase_l7_reproducible_builds/)

---

*Generated: $(Get-Date -Format "o")*
"@
    
    $guideFile = Join-Path $OutputPath "DEPLOYMENT_GUIDE.md"
    $guide | Set-Content -Path $guideFile
    
    Write-Host "  ✓ Deployment guide: $guideFile" -ForegroundColor Green
}

function Invoke-ProfileValidation {
    <#
    .SYNOPSIS
        Validate the generated configuration
    #>
    Write-Host "`n[4/4] Validating configuration..." -ForegroundColor Yellow
    
    $config = $Profiles[$Profile]
    $validations = @()
    
    # Check required files exist
    $requiredFiles = @("rawrxd.config.json", ".env", "validate-environment.ps1", "DEPLOYMENT_GUIDE.md")
    if ($Profile -in @("production", "enterprise")) {
        $requiredFiles += "docker-compose.yml"
    }
    if ($Profile -eq "enterprise") {
        $requiredFiles += "kubernetes/deployment.yaml"
    }
    
    foreach ($file in $requiredFiles) {
        $filePath = Join-Path $OutputPath $file
        $exists = Test-Path $filePath
        $validations += @{
            Name = "File: $file"
            Status = if ($exists) { "PASS" } else { "FAIL" }
        }
    }
    
    # Validate configuration structure
    $configValid = $config.name -and $config.tier -and $config.nodes
    $validations += @{
        Name = "Configuration structure"
        Status = if ($configValid) { "PASS" } else { "FAIL" }
    }
    
    # Display results
    foreach ($validation in $validations) {
        $color = if ($validation.Status -eq "PASS") { "Green" } else { "Red" }
        Write-Host "  [$($validation.Status)] $($validation.Name)" -ForegroundColor $color
    }
    
    $failed = $validations | Where-Object { $_.Status -eq "FAIL" }
    return $failed.Count -eq 0
}

# Main execution
Write-ProfileHeader

if ($ValidateOnly) {
    Write-Host "Validation-only mode - checking existing configuration..." -ForegroundColor Yellow
    $valid = Invoke-ProfileValidation
    exit $(if ($valid) { 0 } else { 1 })
}

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Generate all artifacts
Export-ProfileConfiguration
Export-ValidationScript
Export-DeploymentGuide
$valid = Invoke-ProfileValidation

# Final summary
Write-Host "`n══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "DEPLOYMENT PROFILE CONFIGURED" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Profile: $($Profiles[$Profile].name)" -ForegroundColor White
Write-Host "Output: $OutputPath" -ForegroundColor White
Write-Host "Status: $(if ($valid) { "VALID" } else { "INVALID" })" -ForegroundColor $(if ($valid) { "Green" } else { "Red" })

Write-Host "`nNext steps:" -ForegroundColor White
Write-Host "  1. Review DEPLOYMENT_GUIDE.md" -ForegroundColor Gray
Write-Host "  2. Run .\validate-environment.ps1" -ForegroundColor Gray
Write-Host "  3. Deploy using instructions in guide" -ForegroundColor Gray

if ($valid) {
    Write-Host "`n✅ Profile configuration complete" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n❌ Profile configuration has issues" -ForegroundColor Red
    exit 1
}
