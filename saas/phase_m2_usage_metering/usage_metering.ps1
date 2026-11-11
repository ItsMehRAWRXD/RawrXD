#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase M.2: Usage Metering & Billing
    
.DESCRIPTION
    Tracks token usage, API calls, and compute resources per tenant.
    Generates billing reports and enforces quota limits.
    
.PARAMETER Action
    Action to perform: record, report, check-quota, export-billing
    
.PARAMETER TenantId
    Target tenant identifier
    
.PARAMETER Tokens
    Number of tokens to record
    
.PARAMETER Period
    Billing period (YYYY-MM)
    
.EXAMPLE
    .\usage_metering.ps1 -Action record -TenantId "acme-corp" -Tokens 1500
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("record", "report", "check-quota", "export-billing", "dashboard")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [int]$Tokens = 0,
    
    [Parameter(Mandatory=$false)]
    [string]$Period = (Get-Date -Format "yyyy-MM"),
    
    [Parameter(Mandatory=$false)]
    [string]$DataPath = ".\metering_data"
)

$ErrorActionPreference = "Stop"

# Pricing tiers (per 1K tokens)
$Pricing = @{
    free = @{
        InputTokens = 0
        OutputTokens = 0
        StoragePerGB = 0
        ComputePerHour = 0
    }
    standard = @{
        InputTokens = 0.0001
        OutputTokens = 0.0002
        StoragePerGB = 0.10
        ComputePerHour = 0.50
    }
    enterprise = @{
        InputTokens = 0.00005
        OutputTokens = 0.0001
        StoragePerGB = 0.05
        ComputePerHour = 0.25
    }
}

# Usage database
$UsageDB = @{
    Tenants = @{}
    GlobalStats = @{
        TotalTokens = 0
        TotalRequests = 0
        TotalRevenue = 0.0
    }
}

function Write-MeteringHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase M.2: Usage Metering & Billing                              ║
║  Token tracking, quota enforcement, and billing reports          ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-UsageDB {
    $dbFile = Join-Path $DataPath "usage_db.json"
    if (Test-Path $dbFile) {
        $script:UsageDB = Get-Content -Path $dbFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-UsageDB {
    if (-not (Test-Path $DataPath)) {
        New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
    }
    $dbFile = Join-Path $DataPath "usage_db.json"
    $script:UsageDB | ConvertTo-Json -Depth 10 | Set-Content -Path $dbFile
}

function Initialize-TenantUsage {
    param($Id, $Tier)
    
    if (-not $script:UsageDB.Tenants.ContainsKey($Id)) {
        $script:UsageDB.Tenants[$Id] = @{
            Tier = $Tier
            CreatedAt = Get-Date -Format "o"
            DailyUsage = @{}
            MonthlyUsage = @{}
            TotalTokens = 0
            TotalRequests = 0
            TotalCost = 0.0
        }
    }
}

function Add-UsageRecord {
    param($Id, $Tokens, $Type = "output")
    
    if (-not $script:UsageDB.Tenants.ContainsKey($Id)) {
        Write-Error "Tenant '$Id' not found in usage database"
        return
    }
    
    $tenant = $script:UsageDB.Tenants[$Id]
    $today = Get-Date -Format "yyyy-MM-dd"
    $month = Get-Date -Format "yyyy-MM"
    $now = Get-Date -Format "o"
    
    # Initialize daily record if needed
    if (-not $tenant.DailyUsage.ContainsKey($today)) {
        $tenant.DailyUsage[$today] = @{
            Tokens = 0
            Requests = 0
            Cost = 0.0
        }
    }
    
    # Initialize monthly record if needed
    if (-not $tenant.MonthlyUsage.ContainsKey($month)) {
        $tenant.MonthlyUsage[$month] = @{
            Tokens = 0
            Requests = 0
            Cost = 0.0
        }
    }
    
    # Calculate cost
    $pricePer1K = if ($Type -eq "input") { 
        $Pricing[$tenant.Tier].InputTokens 
    } else { 
        $Pricing[$tenant.Tier].OutputTokens 
    }
    $cost = ($Tokens / 1000) * $pricePer1K
    
    # Update records
    $tenant.DailyUsage[$today].Tokens += $Tokens
    $tenant.DailyUsage[$today].Requests += 1
    $tenant.DailyUsage[$today].Cost += $cost
    
    $tenant.MonthlyUsage[$month].Tokens += $Tokens
    $tenant.MonthlyUsage[$month].Requests += 1
    $tenant.MonthlyUsage[$month].Cost += $cost
    
    $tenant.TotalTokens += $Tokens
    $tenant.TotalRequests += 1
    $tenant.TotalCost += $cost
    
    $script:UsageDB.GlobalStats.TotalTokens += $Tokens
    $script:UsageDB.GlobalStats.TotalRequests += 1
    $script:UsageDB.GlobalStats.TotalRevenue += $cost
    
    # Write detailed log
    $logEntry = @{
        Timestamp = $now
        TenantId = $Id
        Tokens = $Tokens
        Type = $Type
        Cost = $cost
    }
    
    $logFile = Join-Path $DataPath "usage_log_$(Get-Date -Format 'yyyy-MM').jsonl"
    $logEntry | ConvertTo-Json -Compress | Add-Content -Path $logFile
    
    Save-UsageDB
    
    Write-Host "  ✓ Recorded $Tokens $Type tokens for '$Id'" -ForegroundColor Green
    Write-Host "    Cost: `$$([math]::Round($cost, 4))" -ForegroundColor Gray
}

function Get-UsageReport {
    param($Id)
    
    if (-not $script:UsageDB.Tenants.ContainsKey($Id)) {
        Write-Error "Tenant '$Id' not found"
        return
    }
    
    $tenant = $script:UsageDB.Tenants[$Id]
    $currentMonth = Get-Date -Format "yyyy-MM"
    $monthlyUsage = if ($tenant.MonthlyUsage.ContainsKey($currentMonth)) {
        $tenant.MonthlyUsage[$currentMonth]
    } else {
        @{ Tokens = 0; Requests = 0; Cost = 0.0 }
    }
    
    Write-Host "`nUsage Report for '$Id':" -ForegroundColor Yellow
    Write-Host "  Tier: $($tenant.Tier)" -ForegroundColor Gray
    Write-Host "  ─────────────────────────────────────" -ForegroundColor Gray
    Write-Host "  Current Month ($currentMonth):" -ForegroundColor White
    Write-Host "    Tokens:    $($monthlyUsage.Tokens.ToString('N0'))" -ForegroundColor Gray
    Write-Host "    Requests:  $($monthlyUsage.Requests.ToString('N0'))" -ForegroundColor Gray
    Write-Host "    Cost:      `$$("{0:F2}" -f $monthlyUsage.Cost)" -ForegroundColor Gray
    Write-Host "  ─────────────────────────────────────" -ForegroundColor Gray
    Write-Host "  Lifetime Totals:" -ForegroundColor White
    Write-Host "    Tokens:    $($tenant.TotalTokens.ToString('N0'))" -ForegroundColor Gray
    Write-Host "    Requests:  $($tenant.TotalRequests.ToString('N0'))" -ForegroundColor Gray
    Write-Host "    Cost:      `$$("{0:F2}" -f $tenant.TotalCost)" -ForegroundColor Gray
    
    return $tenant
}

function Test-QuotaLimit {
    param($Id)
    
    if (-not $script:UsageDB.Tenants.ContainsKey($Id)) {
        Write-Error "Tenant '$Id' not found"
        return
    }
    
    $tenant = $script:UsageDB.Tenants[$Id]
    $currentMonth = Get-Date -Format "yyyy-MM"
    $monthlyTokens = if ($tenant.MonthlyUsage.ContainsKey($currentMonth)) {
        $tenant.MonthlyUsage[$currentMonth].Tokens
    } else { 0 }
    
    # Get tier limits from tenant config
    $tenantConfigPath = ".\tenants\$Id\tenant_config.json"
    $tierLimits = if (Test-Path $tenantConfigPath) {
        $config = Get-Content -Path $tenantConfigPath -Raw | ConvertFrom-Json
        $config.quota
    } else {
        @{ MaxTokensPerMinute = 100000 }
    }
    
    $usagePercent = [math]::Min(100, ($monthlyTokens / $tierLimits.MaxTokensPerMinute) * 100)
    $status = if ($usagePercent -ge 90) { "CRITICAL" } elseif ($usagePercent -ge 75) { "WARNING" } else { "OK" }
    $color = if ($status -eq "CRITICAL") { "Red" } elseif ($status -eq "WARNING") { "Yellow" } else { "Green" }
    
    Write-Host "`nQuota Check for '$Id':" -ForegroundColor Yellow
    Write-Host "  Monthly Usage: $($monthlyTokens.ToString('N0')) / $($tierLimits.MaxTokensPerMinute.ToString('N0')) tokens" -ForegroundColor Gray
    Write-Host "  Usage: $([math]::Round($usagePercent, 1))%" -ForegroundColor $color
    Write-Host "  Status: $status" -ForegroundColor $color
    
    return @{
        TenantId = $Id
        UsagePercent = $usagePercent
        Status = $status
        TokensUsed = $monthlyTokens
        TokensLimit = $tierLimits.MaxTokensPerMinute
    }
}

function Export-BillingReport {
    param($Period)
    
    Write-Host "`nGenerating billing report for $Period..." -ForegroundColor Yellow
    
    $report = @{
        Period = $Period
        GeneratedAt = Get-Date -Format "o"
        Tenants = @()
        TotalRevenue = 0.0
    }
    
    foreach ($tenantId in $script:UsageDB.Tenants.Keys) {
        $tenant = $script:UsageDB.Tenants[$tenantId]
        $monthlyUsage = if ($tenant.MonthlyUsage.ContainsKey($Period)) {
            $tenant.MonthlyUsage[$Period]
        } else {
            @{ Tokens = 0; Requests = 0; Cost = 0.0 }
        }
        
        $report.Tenants += @{
            TenantId = $tenantId
            Tier = $tenant.Tier
            Tokens = $monthlyUsage.Tokens
            Requests = $monthlyUsage.Requests
            Cost = $monthlyUsage.Cost
        }
        
        $report.TotalRevenue += $monthlyUsage.Cost
    }
    
    # Save report
    $reportFile = Join-Path $DataPath "billing_report_$Period.json"
    $report | ConvertTo-Json -Depth 10 | Set-Content -Path $reportFile
    
    # Generate CSV
    $csvFile = Join-Path $DataPath "billing_report_$Period.csv"
    $csvData = $report.Tenants | ForEach-Object {
        [PSCustomObject]@{
            TenantId = $_.TenantId
            Tier = $_.Tier
            Tokens = $_.Tokens
            Requests = $_.Requests
            Cost = $_.Cost
        }
    }
    $csvData | Export-Csv -Path $csvFile -NoTypeInformation
    
    Write-Host "  ✓ Billing report generated" -ForegroundColor Green
    Write-Host "    JSON: $reportFile" -ForegroundColor Gray
    Write-Host "    CSV:  $csvFile" -ForegroundColor Gray
    Write-Host "    Total Revenue: `$$("{0:F2}" -f $report.TotalRevenue)" -ForegroundColor Cyan
    
    return $report
}

function Show-MeteringDashboard {
    Write-Host "`nUsage Metering Dashboard" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    $currentMonth = Get-Date -Format "yyyy-MM"
    $today = Get-Date -Format "yyyy-MM-dd"
    
    # Global stats
    Write-Host "`nGlobal Statistics:" -ForegroundColor White
    Write-Host "  Total Tenants:     $($script:UsageDB.Tenants.Count)" -ForegroundColor Gray
    Write-Host "  Total Tokens:      $($script:UsageDB.GlobalStats.TotalTokens.ToString('N0'))" -ForegroundColor Gray
    Write-Host "  Total Requests:    $($script:UsageDB.GlobalStats.TotalRequests.ToString('N0'))" -ForegroundColor Gray
    Write-Host "  Total Revenue:     `$$("{0:F2}" -f $script:UsageDB.GlobalStats.TotalRevenue)" -ForegroundColor Green
    
    # Today's usage
    $todayTokens = 0
    $todayRequests = 0
    foreach ($tenant in $script:UsageDB.Tenants.Values) {
        if ($tenant.DailyUsage.ContainsKey($today)) {
            $todayTokens += $tenant.DailyUsage[$today].Tokens
            $todayRequests += $tenant.DailyUsage[$today].Requests
        }
    }
    
    Write-Host "`nToday's Activity:" -ForegroundColor White
    Write-Host "  Tokens:   $todayTokens" -ForegroundColor Gray
    Write-Host "  Requests: $todayRequests" -ForegroundColor Gray
    
    # Top tenants this month
    Write-Host "`nTop 5 Tenants (Current Month):" -ForegroundColor White
    $topTenants = $script:UsageDB.Tenants.GetEnumerator() | ForEach-Object {
        $usage = if ($_.Value.MonthlyUsage.ContainsKey($currentMonth)) {
            $_.Value.MonthlyUsage[$currentMonth].Tokens
        } else { 0 }
        [PSCustomObject]@{
            Id = $_.Key
            Tokens = $usage
        }
    } | Sort-Object Tokens -Descending | Select-Object -First 5
    
    $rank = 1
    foreach ($t in $topTenants) {
        Write-Host "  $rank. $($t.Id): $($t.Tokens.ToString('N0')) tokens" -ForegroundColor Gray
        $rank++
    }
    
    Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

# Main execution
Write-MeteringHeader
Initialize-UsageDB

switch ($Action) {
    "record" {
        if (-not $TenantId) {
            Write-Error "TenantId required for record action"
            exit 1
        }
        Add-UsageRecord -Id $TenantId -Tokens $Tokens
    }
    "report" {
        if (-not $TenantId) {
            Write-Error "TenantId required for report action"
            exit 1
        }
        Get-UsageReport -Id $TenantId
    }
    "check-quota" {
        if (-not $TenantId) {
            Write-Error "TenantId required for check-quota action"
            exit 1
        }
        Test-QuotaLimit -Id $TenantId
    }
    "export-billing" {
        Export-BillingReport -Period $Period
    }
    "dashboard" {
        Show-MeteringDashboard
    }
}

Write-Host "`n✅ Metering operation complete" -ForegroundColor Green
