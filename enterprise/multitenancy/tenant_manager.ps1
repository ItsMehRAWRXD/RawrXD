# RawrXD Tenant Manager
# Phase K Batch 1/5: Multi-Tenancy Support
# Manages tenant isolation and resource allocation

param(
    [Parameter()]
    [ValidateSet("Create", "Delete", "List", "Get", "Update", "Allocate", "ShowStatus")]
    [string]$Action = "List",
    
    [Parameter()]
    [string]$TenantId,
    
    [Parameter()]
    [string]$TenantName,
    
    [Parameter()]
    [hashtable]$TenantConfig = @{},
    
    [Parameter()]
    [string]$DataPath = "$PSScriptRoot\tenant_data",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\enterprise"
)

# Tenant configuration defaults
$DefaultTenantConfig = @{
    MaxMemoryGB = 4
    MaxCPU = 50  # Percent
    MaxDiskGB = 10
    MaxConcurrentRequests = 10
    AllowedModels = @("phi3", "llama3")
    Features = @{
        Analytics = $true
        Autonomous = $false
        CustomModels = $false
    }
    Quota = @{
        RequestsPerDay = 10000
        TokensPerDay = 1000000
    }
}

# Ensure directories exist
if (-not (Test-Path $DataPath)) {
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
}
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$StateFile = "$PSScriptRoot\tenant_state.json"

function Write-TenantLog {
    param([string]$Message, [string]$Level = "INFO", [string]$Tenant = "system")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [Tenant:$Tenant] $Message"
    
    $logFile = Join-Path $LogPath "tenant_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "TENANT" { "Cyan" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-TenantState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        Tenants = @{}
        NextTenantId = 1
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Save-TenantState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function New-Tenant {
    param(
        [string]$Name,
        [hashtable]$Config = @{}
    )
    
    Write-TenantLog "Creating new tenant: $Name" "TENANT"
    
    $state = Get-TenantState
    $tenantId = "tenant_$($state.NextTenantId)"
    $state.NextTenantId++
    
    # Merge config with defaults
    $mergedConfig = $DefaultTenantConfig.Clone()
    foreach ($key in $Config.Keys) {
        if ($mergedConfig.ContainsKey($key)) {
            $mergedConfig[$key] = $Config[$key]
        }
    }
    
    $tenant = @{
        Id = $tenantId
        Name = $Name
        Config = $mergedConfig
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Status = "Active"
        Usage = @{
            CurrentMemoryGB = 0
            CurrentCPU = 0
            RequestsToday = 0
            TokensToday = 0
        }
        DataPath = Join-Path $DataPath $tenantId
    }
    
    # Create tenant data directory
    New-Item -ItemType Directory -Path $tenant.DataPath -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $tenant.DataPath "logs") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $tenant.DataPath "models") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $tenant.DataPath "cache") -Force | Out-Null
    
    # Save tenant config
    $tenant.Config | ConvertTo-Json -Depth 10 | Out-File (Join-Path $tenant.DataPath "config.json") -Encoding UTF8
    
    $state.Tenants[$tenantId] = $tenant
    Save-TenantState -State $state
    
    Write-TenantLog "Tenant created: $tenantId ($Name)" "SUCCESS" $tenantId
    
    return $tenant
}

function Remove-Tenant {
    param([string]$Id)
    
    Write-TenantLog "Removing tenant: $Id" "TENANT"
    
    $state = Get-TenantState
    
    if (-not $state.Tenants.ContainsKey($Id)) {
        Write-TenantLog "Tenant not found: $Id" "ERROR"
        return $false
    }
    
    $tenant = $state.Tenants[$Id]
    
    # Archive tenant data before deletion
    $archivePath = "$($tenant.DataPath)_archive_$(Get-Date -Format 'yyyyMMddHHmmss')"
    if (Test-Path $tenant.DataPath) {
        Move-Item -Path $tenant.DataPath -Destination $archivePath -Force
    }
    
    $tenant.Status = "Deleted"
    $tenant.Deleted = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $tenant.ArchivePath = $archivePath
    
    Save-TenantState -State $state
    
    Write-TenantLog "Tenant removed and archived: $Id" "SUCCESS" $Id
    return $true
}

function Get-Tenant {
    param([string]$Id)
    
    $state = Get-TenantState
    
    if ($state.Tenants.ContainsKey($Id)) {
        return $state.Tenants[$Id]
    }
    
    return $null
}

function Get-AllTenants {
    $state = Get-TenantState
    return $state.Tenants.Values | Where-Object { $_.Status -eq "Active" }
}

function Update-TenantUsage {
    param(
        [string]$Id,
        [hashtable]$Usage
    )
    
    $state = Get-TenantState
    
    if (-not $state.Tenants.ContainsKey($Id)) {
        return $false
    }
    
    $tenant = $state.Tenants[$Id]
    
    foreach ($key in $Usage.Keys) {
        if ($tenant.Usage.ContainsKey($key)) {
            $tenant.Usage[$key] = $Usage[$key]
        }
    }
    
    Save-TenantState -State $state
    return $true
}

function Test-TenantQuota {
    param([string]$Id)
    
    $tenant = Get-Tenant -Id $Id
    if (-not $tenant) {
        return @{ Allowed = $false; Reason = "Tenant not found" }
    }
    
    $checks = @()
    
    # Check memory
    if ($tenant.Usage.CurrentMemoryGB -ge $tenant.Config.MaxMemoryGB) {
        $checks += "Memory quota exceeded"
    }
    
    # Check CPU
    if ($tenant.Usage.CurrentCPU -ge $tenant.Config.MaxCPU) {
        $checks += "CPU quota exceeded"
    }
    
    # Check requests
    if ($tenant.Usage.RequestsToday -ge $tenant.Config.Quota.RequestsPerDay) {
        $checks += "Daily request quota exceeded"
    }
    
    # Check tokens
    if ($tenant.Usage.TokensToday -ge $tenant.Config.Quota.TokensPerDay) {
        $checks += "Daily token quota exceeded"
    }
    
    return @{
        Allowed = $checks.Count -eq 0
        Reason = if ($checks.Count -gt 0) { $checks -join ", " } else { $null }
        Usage = $tenant.Usage
        Quota = $tenant.Config.Quota
    }
}

function Show-TenantStatus {
    $state = Get-TenantState
    $tenants = Get-AllTenants
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Tenant Manager Status                        ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Total Tenants: $($state.Tenants.Count)" -ForegroundColor Cyan
    Write-Host "║ Active Tenants: $(($tenants | Where-Object { $_.Status -eq 'Active' }).Count)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    if ($tenants.Count -gt 0) {
        Write-Host "║ Active Tenants:" -ForegroundColor Cyan
        foreach ($tenant in $tenants | Select-Object -First 10) {
            $memoryPercent = [math]::Min(100, ($tenant.Usage.CurrentMemoryGB / $tenant.Config.MaxMemoryGB) * 100)
            $color = if ($memoryPercent -gt 90) { "Red" } elseif ($memoryPercent -gt 70) { "Yellow" } else { "Green" }
            Write-Host "║   $($tenant.Id) - $($tenant.Name)" -ForegroundColor $color
            Write-Host "║     Memory: $([math]::Round($memoryPercent, 1))% ($($tenant.Usage.CurrentMemoryGB)/$($tenant.Config.MaxMemoryGB) GB)" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "║ No active tenants" -ForegroundColor Yellow
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Create" {
        if (-not $TenantName) {
            Write-TenantLog "TenantName required for Create" "ERROR"
            exit 1
        }
        $tenant = New-Tenant -Name $TenantName -Config $TenantConfig
        $tenant | ConvertTo-Json -Depth 10
    }
    "Delete" {
        if (-not $TenantId) {
            Write-TenantLog "TenantId required for Delete" "ERROR"
            exit 1
        }
        $success = Remove-Tenant -Id $TenantId
        if ($success) { exit 0 } else { exit 1 }
    }
    "List" {
        $tenants = Get-AllTenants
        $tenants | Select-Object Id, Name, Status, Created | Format-Table -AutoSize
    }
    "Get" {
        if (-not $TenantId) {
            Write-TenantLog "TenantId required for Get" "ERROR"
            exit 1
        }
        $tenant = Get-Tenant -Id $TenantId
        if ($tenant) {
            $tenant | ConvertTo-Json -Depth 10
        }
        else {
            Write-TenantLog "Tenant not found: $TenantId" "ERROR"
            exit 1
        }
    }
    "Update" {
        if (-not $TenantId) {
            Write-TenantLog "TenantId required for Update" "ERROR"
            exit 1
        }
        # Update implementation would go here
        Write-TenantLog "Update not yet implemented" "WARN"
    }
    "Allocate" {
        if (-not $TenantId) {
            Write-TenantLog "TenantId required for Allocate" "ERROR"
            exit 1
        }
        $quota = Test-TenantQuota -Id $TenantId
        $quota | ConvertTo-Json
    }
    "ShowStatus" {
        Show-TenantStatus
    }
}
