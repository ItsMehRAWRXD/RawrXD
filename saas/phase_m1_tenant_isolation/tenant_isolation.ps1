#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase M.1: Tenant Isolation Manager
    
.DESCRIPTION
    Manages multi-tenant isolation for RawrXD SaaS deployments.
    Creates isolated namespaces, resource quotas, and security policies
    for each tenant.
    
.PARAMETER Action
    Action to perform: create, delete, list, update-quota
    
.PARAMETER TenantId
    Unique identifier for the tenant
    
.PARAMETER Tier
    Service tier: free, standard, enterprise
    
.PARAMETER OutputPath
    Output directory for tenant configurations
    
.EXAMPLE
    .\tenant_isolation.ps1 -Action create -TenantId "acme-corp" -Tier enterprise
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("create", "delete", "list", "update-quota", "validate")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("free", "standard", "enterprise")]
    [string]$Tier = "standard",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\tenants"
)

$ErrorActionPreference = "Stop"

# Tenant tier definitions
$TierDefinitions = @{
    free = @{
        Name = "Free"
        MaxConcurrentRequests = 10
        MaxTokensPerMinute = 10000
        MaxContextLength = 2048
        MaxBatchSize = 1
        GPUShare = 0.1  # 10% of GPU
        StorageGB = 1
        Support = "community"
        SLA = "best-effort"
    }
    standard = @{
        Name = "Standard"
        MaxConcurrentRequests = 100
        MaxTokensPerMinute = 100000
        MaxContextLength = 8192
        MaxBatchSize = 8
        GPUShare = 0.5  # 50% of GPU
        StorageGB = 10
        Support = "email"
        SLA = "99.9%"
    }
    enterprise = @{
        Name = "Enterprise"
        MaxConcurrentRequests = 1000
        MaxTokensPerMinute = 1000000
        MaxContextLength = 32768
        MaxBatchSize = 64
        GPUShare = 1.0  # Dedicated GPU
        StorageGB = 100
        Support = "dedicated"
        SLA = "99.95%"
    }
}

# Tenant registry
$TenantRegistry = @{
    Tenants = @{}
    LastUpdated = $null
}

function Write-TenantHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase M.1: Tenant Isolation Manager                             ║
║  Multi-tenant isolation and resource management                   ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-TenantRegistry {
    $registryFile = Join-Path $OutputPath "tenant_registry.json"
    if (Test-Path $registryFile) {
        $script:TenantRegistry = Get-Content -Path $registryFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-TenantRegistry {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    $registryFile = Join-Path $OutputPath "tenant_registry.json"
    $script:TenantRegistry.LastUpdated = Get-Date -Format "o"
    $script:TenantRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryFile
}

function New-Tenant {
    param($Id, $Tier)
    
    Write-Host "`nCreating tenant '$Id' with '$Tier' tier..." -ForegroundColor Yellow
    
    if ($script:TenantRegistry.Tenants.ContainsKey($Id)) {
        Write-Error "Tenant '$Id' already exists"
        return
    }
    
    $tenant = @{
        Id = $Id
        Tier = $Tier
        CreatedAt = Get-Date -Format "o"
        Status = "active"
        Quota = $TierDefinitions[$Tier]
        Usage = @{
            TokensThisMonth = 0
            RequestsThisMonth = 0
            StorageUsedGB = 0
        }
        Config = @{
            Namespace = "tenant-$Id"
            NetworkPolicy = "isolated"
            Encryption = "aes256"
        }
    }
    
    # Create tenant directory
    $tenantDir = Join-Path $OutputPath $Id
    New-Item -ItemType Directory -Path $tenantDir -Force | Out-Null
    
    # Generate tenant configuration
    $config = @{
        tenant_id = $Id
        tier = $Tier
        quota = $tenant.Quota
        security = @{
            encryption = "aes256-gcm"
            isolation = "namespace"
            network_policy = "deny-all-allow-explicit"
        }
        resources = @{
            cpu_cores = if ($Tier -eq "enterprise") { 8 } elseif ($Tier -eq "standard") { 4 } else { 1 }
            memory_gb = if ($Tier -eq "enterprise") { 64 } elseif ($Tier -eq "standard") { 16 } else { 4 }
            gpu_share = $tenant.Quota.GPUShare
            storage_gb = $tenant.Quota.StorageGB
        }
    }
    
    $configFile = Join-Path $tenantDir "tenant_config.json"
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile
    
    # Generate Kubernetes namespace YAML
    $k8sNamespace = @"
apiVersion: v1
kind: Namespace
metadata:
  name: tenant-$Id
  labels:
    tenant: $Id
    tier: $Tier
    managed-by: rawrxd-tenant-manager
  annotations:
    created: $(Get-Date -Format "o")
    quota.tokens-per-minute: $($tenant.Quota.MaxTokensPerMinute)
    quota.concurrent-requests: $($tenant.Quota.MaxConcurrentRequests)
spec:
  finalizers:
    - kubernetes
"@
    
    $namespaceFile = Join-Path $tenantDir "namespace.yaml"
    $k8sNamespace | Set-Content -Path $namespaceFile
    
    # Generate resource quota YAML
    $k8sQuota = @"
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-$Id-quota
  namespace: tenant-$Id
spec:
  hard:
    requests.cpu: "$($config.resources.cpu_cores)"
    requests.memory: "$($config.resources.memory_gb)Gi"
    limits.cpu: "$($config.resources.cpu_cores)"
    limits.memory: "$($config.resources.memory_gb)Gi"
    persistentvolumeclaims: "1"
    services.loadbalancers: "1"
    services.nodeports: "0"
"@
    
    $quotaFile = Join-Path $tenantDir "resource_quota.yaml"
    $k8sQuota | Set-Content -Path $quotaFile
    
    # Generate network policy YAML
    $k8sNetworkPolicy = @"
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: tenant-$Id-isolation
  namespace: tenant-$Id
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: rawrxd-ingress
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: rawrxd-core
      ports:
        - protocol: TCP
          port: 8080
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
      ports:
        - protocol: UDP
          port: 53
"@
    
    $networkPolicyFile = Join-Path $tenantDir "network_policy.yaml"
    $k8sNetworkPolicy | Set-Content -Path $networkPolicyFile
    
    # Register tenant
    $script:TenantRegistry.Tenants[$Id] = $tenant
    Save-TenantRegistry
    
    Write-Host "  ✓ Tenant created successfully" -ForegroundColor Green
    Write-Host "  ✓ Configuration saved to: $tenantDir" -ForegroundColor Gray
    Write-Host "  ✓ Namespace: tenant-$Id" -ForegroundColor Gray
    Write-Host "  ✓ GPU Share: $($tenant.Quota.GPUShare * 100)%" -ForegroundColor Gray
}

function Remove-Tenant {
    param($Id)
    
    Write-Host "`nDeleting tenant '$Id'..." -ForegroundColor Yellow
    
    if (-not $script:TenantRegistry.Tenants.ContainsKey($Id)) {
        Write-Error "Tenant '$Id' not found"
        return
    }
    
    $tenantDir = Join-Path $OutputPath $Id
    if (Test-Path $tenantDir) {
        Remove-Item -Path $tenantDir -Recurse -Force
        Write-Host "  ✓ Tenant directory removed" -ForegroundColor Green
    }
    
    $script:TenantRegistry.Tenants.Remove($Id)
    Save-TenantRegistry
    
    Write-Host "  ✓ Tenant '$Id' deleted" -ForegroundColor Green
}

function Get-TenantList {
    Write-Host "`nTenant Registry:" -ForegroundColor Yellow
    Write-Host ""
    
    if ($script:TenantRegistry.Tenants.Count -eq 0) {
        Write-Host "  No tenants registered" -ForegroundColor Gray
        return
    }
    
    Write-Host "  {0,-20} {1,-12} {2,-10} {3,-20}" -f "Tenant ID", "Tier", "Status", "Created" -ForegroundColor White
    Write-Host "  $("-" * 62)" -ForegroundColor Gray
    
    foreach ($tenant in $script:TenantRegistry.Tenants.Values) {
        $created = [DateTime]::Parse($tenant.CreatedAt).ToString("yyyy-MM-dd")
        Write-Host "  {0,-20} {1,-12} {2,-10} {3,-20}" -f $tenant.Id, $tenant.Tier, $tenant.Status, $created" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "  Total tenants: $($script:TenantRegistry.Tenants.Count)" -ForegroundColor Cyan
}

function Update-TenantQuota {
    param($Id, $NewTier)
    
    Write-Host "`nUpdating tenant '$Id' to '$NewTier' tier..." -ForegroundColor Yellow
    
    if (-not $script:TenantRegistry.Tenants.ContainsKey($Id)) {
        Write-Error "Tenant '$Id' not found"
        return
    }
    
    $tenant = $script:TenantRegistry.Tenants[$Id]
    $oldTier = $tenant.Tier
    $tenant.Tier = $NewTier
    $tenant.Quota = $TierDefinitions[$NewTier]
    $tenant.UpdatedAt = Get-Date -Format "o"
    
    # Update configuration
    $tenantDir = Join-Path $OutputPath $Id
    $configFile = Join-Path $tenantDir "tenant_config.json"
    if (Test-Path $configFile) {
        $config = Get-Content -Path $configFile -Raw | ConvertFrom-Json -AsHashtable
        $config.tier = $NewTier
        $config.quota = $tenant.Quota
        $config.resources.cpu_cores = if ($NewTier -eq "enterprise") { 8 } elseif ($NewTier -eq "standard") { 4 } else { 1 }
        $config.resources.memory_gb = if ($NewTier -eq "enterprise") { 64 } elseif ($NewTier -eq "standard") { 16 } else { 4 }
        $config.resources.gpu_share = $tenant.Quota.GPUShare
        $config.resources.storage_gb = $tenant.Quota.StorageGB
        $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile
    }
    
    Save-TenantRegistry
    
    Write-Host "  ✓ Tenant upgraded from '$oldTier' to '$NewTier'" -ForegroundColor Green
    Write-Host "  ✓ New GPU Share: $($tenant.Quota.GPUShare * 100)%" -ForegroundColor Gray
    Write-Host "  ✓ New Token Limit: $($tenant.Quota.MaxTokensPerMinute)/min" -ForegroundColor Gray
}

function Test-TenantIsolation {
    Write-Host "`nValidating tenant isolation..." -ForegroundColor Yellow
    
    $issues = @()
    
    foreach ($tenant in $script:TenantRegistry.Tenants.Values) {
        $tenantDir = Join-Path $OutputPath $tenant.Id
        
        # Check if directory exists
        if (-not (Test-Path $tenantDir)) {
            $issues += "Tenant $($tenant.Id): Directory missing"
            continue
        }
        
        # Check if config exists
        $configFile = Join-Path $tenantDir "tenant_config.json"
        if (-not (Test-Path $configFile)) {
            $issues += "Tenant $($tenant.Id): Config missing"
        }
        
        # Check if namespace YAML exists
        $namespaceFile = Join-Path $tenantDir "namespace.yaml"
        if (-not (Test-Path $namespaceFile)) {
            $issues += "Tenant $($tenant.Id): Namespace YAML missing"
        }
    }
    
    if ($issues.Count -eq 0) {
        Write-Host "  ✓ All tenants validated successfully" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Issues found:" -ForegroundColor Yellow
        foreach ($issue in $issues) {
            Write-Host "    - $issue" -ForegroundColor Yellow
        }
    }
}

# Main execution
Write-TenantHeader
Initialize-TenantRegistry

switch ($Action) {
    "create" {
        if (-not $TenantId) {
            Write-Error "TenantId required for create action"
            exit 1
        }
        New-Tenant -Id $TenantId -Tier $Tier
    }
    "delete" {
        if (-not $TenantId) {
            Write-Error "TenantId required for delete action"
            exit 1
        }
        Remove-Tenant -Id $TenantId
    }
    "list" {
        Get-TenantList
    }
    "update-quota" {
        if (-not $TenantId) {
            Write-Error "TenantId required for update-quota action"
            exit 1
        }
        Update-TenantQuota -Id $TenantId -NewTier $Tier
    }
    "validate" {
        Test-TenantIsolation
    }
}

Write-Host "`n✅ Tenant operation complete" -ForegroundColor Green
