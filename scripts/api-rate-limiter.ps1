# RawrXD API Rate Limiter
# Manages API rate limiting with token bucket algorithm
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("Status", "Configure", "Check", "Reset", "Ban", "Unban")]
    [string]$Action = "Status",
    
    [Parameter()]
    [string]$ClientId = "default",
    
    [Parameter()]
    [int]$RequestsPerSecond = 10,
    
    [Parameter()]
    [int]$BurstSize = 20,
    
    [Parameter()]
    [int]$WindowSeconds = 60,
    
    [Parameter()]
    [string]$Endpoint = "/api/v1/generate",
    
    [Parameter()]
    [switch]$Global
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Get-RateLimitPath {
    return "$PSScriptRoot\.rate-limits.json"
}

function Get-RateLimitData {
    $path = Get-RateLimitPath
    if (Test-Path $path) {
        return Get-Content $path | ConvertFrom-Json
    }
    return @{ Clients = @{}; Global = @{ RequestsPerSecond = 100; BurstSize = 200; WindowSeconds = 60 }; BannedClients = @() }
}

function Save-RateLimitData {
    param([hashtable]$Data)
    $Data | ConvertTo-Json -Depth 5 | Set-Content (Get-RateLimitPath)
}

function Show-RateLimitStatus {
    $data = Get-RateLimitData
    
    Write-Host "`nAPI Rate Limiter Status" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Global Settings:"
    Write-Host "  Requests/Second: $($data.Global.RequestsPerSecond)"
    Write-Host "  Burst Size: $($data.Global.BurstSize)"
    Write-Host "  Window: $($data.Global.WindowSeconds)s"
    Write-Host ""
    
    if ($data.Clients.PSObject.Properties.Count -gt 0) {
        Write-Host "Client-Specific Limits:"
        Write-Host "Client ID          RPS    Burst    Window    Current"
        Write-Host "---------          ---    -----    ------    -------"
        
        foreach ($client in $data.Clients.PSObject.Properties) {
            $clientData = $client.Value
            $current = if ($clientData.CurrentRequests) { $clientData.CurrentRequests } else { 0 }
            Write-Host ($client.Name).PadRight(19) -NoNewline
            Write-Host $clientData.RequestsPerSecond.ToString().PadRight(7) -NoNewline
            Write-Host $clientData.BurstSize.ToString().PadRight(9) -NoNewline
            Write-Host "$($clientData.WindowSeconds)s".PadRight(10) -NoNewline
            Write-Host $current
        }
    }
    
    if ($data.BannedClients.Count -gt 0) {
        Write-Host ""
        Write-Host "Banned Clients: $($data.BannedClients.Count)" -ForegroundColor Red
        foreach ($banned in $data.BannedClients) {
            Write-Host "  ❌ $banned" -ForegroundColor Red
        }
    }
    Write-Host ""
}

function Set-RateLimitConfig {
    $data = Get-RateLimitData
    
    if ($Global) {
        Write-Status "Configuring global rate limits..."
        $data.Global.RequestsPerSecond = $RequestsPerSecond
        $data.Global.BurstSize = $BurstSize
        $data.Global.WindowSeconds = $WindowSeconds
    } else {
        Write-Status "Configuring rate limits for client: $ClientId"
        
        if (-not $data.Clients.$ClientId) {
            $data.Clients.$ClientId = @{}
        }
        
        $data.Clients.$ClientId.RequestsPerSecond = $RequestsPerSecond
        $data.Clients.$ClientId.BurstSize = $BurstSize
        $data.Clients.$ClientId.WindowSeconds = $WindowSeconds
        $data.Clients.$ClientId.CurrentRequests = 0
        $data.Clients.$ClientId.LastRequest = $null
    }
    
    Save-RateLimitData -Data $data
    Write-Success "Rate limit configuration saved"
}

function Test-RateLimit {
    param([string]$Client)
    
    $data = Get-RateLimitData
    
    # Check if banned
    if ($data.BannedClients -contains $Client) {
        return @{ Allowed = $false; Reason = "Client is banned"; RetryAfter = 3600 }
    }
    
    # Get client config or use global
    $config = if ($data.Clients.$Client) { $data.Clients.$Client } else { $data.Global }
    
    $now = Get-Date
    $lastRequest = if ($config.LastRequest) { [datetime]$config.LastRequest } else { $now.AddSeconds(-$config.WindowSeconds) }
    $timeSinceLast = ($now - $lastRequest).TotalSeconds
    
    # Token bucket algorithm
    $tokensToAdd = [math]::Floor($timeSinceLast * $config.RequestsPerSecond)
    $config.CurrentRequests = [math]::Min($config.BurstSize, $config.CurrentRequests + $tokensToAdd)
    
    if ($config.CurrentRequests -gt 0) {
        $config.CurrentRequests--
        $config.LastRequest = $now.ToString("o")
        Save-RateLimitData -Data $data
        
        return @{ Allowed = $true; Remaining = $config.CurrentRequests; ResetTime = ($now.AddSeconds(1)).ToString("o") }
    } else {
        $retryAfter = [math]::Ceiling(1 / $config.RequestsPerSecond)
        return @{ Allowed = $false; Reason = "Rate limit exceeded"; RetryAfter = $retryAfter }
    }
}

function Invoke-RateLimitCheck {
    $result = Test-RateLimit -Client $ClientId
    
    if ($result.Allowed) {
        Write-Success "Request allowed for client: $ClientId"
        Write-Status "Remaining tokens: $($result.Remaining)"
    } else {
        Write-Error "Request denied for client: $ClientId"
        Write-Status "Reason: $($result.Reason)"
        Write-Status "Retry after: $($result.RetryAfter) seconds"
    }
}

function Reset-RateLimit {
    $data = Get-RateLimitData
    
    if ($Global) {
        Write-Status "Resetting global rate limit counters..."
        $data.Global.CurrentRequests = $data.Global.BurstSize
    } else {
        Write-Status "Resetting rate limit for client: $ClientId"
        if ($data.Clients.$ClientId) {
            $data.Clients.$ClientId.CurrentRequests = $data.Clients.$ClientId.BurstSize
        }
    }
    
    Save-RateLimitData -Data $data
    Write-Success "Rate limit counters reset"
}

function Add-BannedClient {
    $data = Get-RateLimitData
    
    if ($data.BannedClients -notcontains $ClientId) {
        $data.BannedClients += $ClientId
        Save-RateLimitData -Data $data
        Write-Success "Client $ClientId has been banned"
    } else {
        Write-Warning "Client $ClientId is already banned"
    }
}

function Remove-BannedClient {
    $data = Get-RateLimitData
    
    if ($data.BannedClients -contains $ClientId) {
        $data.BannedClients = $data.BannedClients | Where-Object { $_ -ne $ClientId }
        Save-RateLimitData -Data $data
        Write-Success "Client $ClientId has been unbanned"
    } else {
        Write-Warning "Client $ClientId is not banned"
    }
}

# Main execution
try {
    switch ($Action) {
        "Status" { Show-RateLimitStatus }
        "Configure" { Set-RateLimitConfig }
        "Check" { Invoke-RateLimitCheck }
        "Reset" { Reset-RateLimit }
        "Ban" { Add-BannedClient }
        "Unban" { Remove-BannedClient }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
