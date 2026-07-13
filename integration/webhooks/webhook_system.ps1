# RawrXD Webhook System
# Phase M Batch 2/5: Event-Driven Integrations
# Manages webhook subscriptions and event delivery

param(
    [Parameter()]
    [ValidateSet("Subscribe", "Unsubscribe", "List", "Trigger", "Test", "ShowStatus")]
    [string]$Action = "ShowStatus",
    
    [Parameter()]
    [string]$WebhookId,
    
    [Parameter()]
    [string]$Url,
    
    [Parameter()]
    [array]$Events = @(),
    
    [Parameter()]
    [string]$Secret,
    
    [Parameter()]
    [hashtable]$Payload = @{},
    
    [Parameter()]
    [ValidateSet("active", "paused", "disabled")]
    [string]$Status = "active",
    
    [Parameter()]
    [int]$RetryCount = 3,
    
    [Parameter()]
    [string]$DataPath = "$PSScriptRoot\webhook_data",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\integration"
)

# Event types
$EventTypes = @{
    "model.loaded" = @{ Description = "Model loaded into memory"; Category = "Model" }
    "model.unloaded" = @{ Description = "Model unloaded from memory"; Category = "Model" }
    "inference.started" = @{ Description = "Inference request started"; Category = "Inference" }
    "inference.completed" = @{ Description = "Inference request completed"; Category = "Inference" }
    "inference.failed" = @{ Description = "Inference request failed"; Category = "Inference" }
    "session.created" = @{ Description = "New session created"; Category = "Session" }
    "session.ended" = @{ Description = "Session ended"; Category = "Session" }
    "system.startup" = @{ Description = "System startup"; Category = "System" }
    "system.shutdown" = @{ Description = "System shutdown"; Category = "System" }
    "error.critical" = @{ Description = "Critical error occurred"; Category = "Error" }
    "metrics.threshold" = @{ Description = "Performance threshold crossed"; Category = "Metrics" }
    "security.alert" = @{ Description = "Security alert triggered"; Category = "Security" }
    "tenant.created" = @{ Description = "New tenant created"; Category = "Enterprise" }
    "tenant.deleted" = @{ Description = "Tenant deleted"; Category = "Enterprise" }
}

# HTTP Methods
$HttpMethods = @("POST", "PUT", "PATCH")

# Content Types
$ContentTypes = @(
    "application/json",
    "application/x-www-form-urlencoded",
    "text/plain"
)

# Ensure directories exist
if (-not (Test-Path $DataPath)) {
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
}
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$StateFile = "$PSScriptRoot\webhook_state.json"

function Write-WebhookLog {
    param([string]$Message, [string]$Level = "INFO", [string]$Webhook = "")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $webhookTag = if ($Webhook) { "[$Webhook]" } else { "" }
    $logEntry = "[$timestamp] [$Level] [WEBHOOK]$webhookTag $Message"
    
    $logFile = Join-Path $LogPath "webhooks_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "WEBHOOK" { "Cyan" }
        "DELIVERY" { "Magenta" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-WebhookState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        Subscriptions = @{}
        Deliveries = @()
        EventStats = @{}
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Save-WebhookState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function New-WebhookSubscription {
    param(
        [string]$Url,
        [array]$Events,
        [string]$Secret,
        [string]$Status = "active",
        [int]$RetryCount = 3
    )
    
    Write-WebhookLog "Creating webhook subscription for $Url" "WEBHOOK"
    
    # Validate URL
    try {
        $uri = [System.Uri]$Url
        if ($uri.Scheme -notin @("http", "https")) {
            throw "URL must use HTTP or HTTPS"
        }
    }
    catch {
        Write-WebhookLog "Invalid URL: $_" "ERROR"
        return $null
    }
    
    # Validate events
    $validEvents = @()
    foreach ($event in $Events) {
        if ($EventTypes.ContainsKey($event)) {
            $validEvents += $event
        }
        else {
            Write-WebhookLog "Unknown event type: $event" "WARN"
        }
    }
    
    if ($validEvents.Count -eq 0) {
        Write-WebhookLog "No valid events specified" "ERROR"
        return $null
    }
    
    # Generate webhook ID and secret
    $webhookId = [System.Guid]::NewGuid().ToString()
    if (-not $Secret) {
        $Secret = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 } | ForEach-Object { [byte]$_ }))
    }
    
    $subscription = @{
        Id = $webhookId
        Url = $Url
        Events = $validEvents
        Secret = $Secret
        Status = $Status
        RetryCount = $RetryCount
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        LastDelivery = $null
        DeliveryCount = 0
        SuccessCount = 0
        FailureCount = 0
    }
    
    $state = Get-WebhookState
    $state.Subscriptions[$webhookId] = $subscription
    Save-WebhookState -State $state
    
    Write-WebhookLog "Webhook created: $webhookId" "SUCCESS"
    
    # Return without secret for display
    $display = $subscription.Clone()
    $display.Secret = "***"
    return $display
}

function Remove-WebhookSubscription {
    param([string]$WebhookId)
    
    Write-WebhookLog "Removing webhook: $WebhookId" "WEBHOOK"
    
    $state = Get-WebhookState
    
    if (-not $state.Subscriptions.ContainsKey($WebhookId)) {
        Write-WebhookLog "Webhook not found: $WebhookId" "ERROR"
        return $false
    }
    
    $state.Subscriptions.Remove($WebhookId)
    Save-WebhookState -State $state
    
    Write-WebhookLog "Webhook removed: $WebhookId" "SUCCESS"
    return $true
}

function Invoke-WebhookDelivery {
    param(
        [string]$WebhookId,
        [string]$Event,
        [hashtable]$Payload
    )
    
    $state = Get-WebhookState
    $subscription = $state.Subscriptions[$WebhookId]
    
    if (-not $subscription) {
        Write-WebhookLog "Webhook not found: $WebhookId" "ERROR"
        return $null
    }
    
    if ($subscription.Status -ne "active") {
        Write-WebhookLog "Webhook $WebhookId is not active (status: $($subscription.Status))" "WARN"
        return $null
    }
    
    if ($subscription.Events -notcontains $Event) {
        Write-WebhookLog "Event $Event not subscribed by webhook $WebhookId" "WARN"
        return $null
    }
    
    # Build payload
    $deliveryPayload = @{
        event = $Event
        webhook_id = $WebhookId
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        data = $Payload
    }
    
    $jsonPayload = $deliveryPayload | ConvertTo-Json -Depth 10
    
    # Generate signature
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($subscription.Secret)
    $signature = [Convert]::ToBase64String($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($jsonPayload)))
    
    # Simulate delivery
    Write-WebhookLog "Delivering $Event to $($subscription.Url)" "DELIVERY" $WebhookId
    
    $delivery = @{
        Id = [System.Guid]::NewGuid().ToString()
        WebhookId = $WebhookId
        Event = $Event
        Payload = $deliveryPayload
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Attempts = @()
    }
    
    # Simulate retry logic
    $success = $false
    for ($attempt = 1; $attempt -le $subscription.RetryCount; $attempt++) {
        $attemptInfo = @{
            Number = $attempt
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        # Simulate HTTP request (would be real HTTP in production)
        $statusCode = if ((Get-Random -Maximum 10) -gt 2) { 200 } else { 500 }
        
        if ($statusCode -eq 200) {
            $attemptInfo.StatusCode = $statusCode
            $attemptInfo.Success = $true
            $success = $true
            $delivery.Attempts += $attemptInfo
            break
        }
        else {
            $attemptInfo.StatusCode = $statusCode
            $attemptInfo.Success = $false
            $attemptInfo.Error = "HTTP $statusCode"
            $delivery.Attempts += $attemptInfo
            
            if ($attempt -lt $subscription.RetryCount) {
                $delay = [math]::Pow(2, $attempt)  # Exponential backoff
                Write-WebhookLog "Retry $attempt/$($subscription.RetryCount) after ${delay}s" "DELIVERY" $WebhookId
                Start-Sleep -Seconds $delay
            }
        }
    }
    
    $delivery.Success = $success
    $delivery.FinalStatus = if ($success) { "delivered" } else { "failed" }
    
    # Update subscription stats
    $subscription.LastDelivery = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $subscription.DeliveryCount++
    if ($success) {
        $subscription.SuccessCount++
    }
    else {
        $subscription.FailureCount++
    }
    
    # Update event stats
    if (-not $state.EventStats.ContainsKey($Event)) {
        $state.EventStats[$Event] = @{ Count = 0; Success = 0; Failed = 0 }
    }
    $state.EventStats[$Event].Count++
    if ($success) {
        $state.EventStats[$Event].Success++
    }
    else {
        $state.EventStats[$Event].Failed++
    }
    
    $state.Deliveries += $delivery
    Save-WebhookState -State $state
    
    if ($success) {
        Write-WebhookLog "Delivery successful" "SUCCESS" $WebhookId
    }
    else {
        Write-WebhookLog "Delivery failed after $($subscription.RetryCount) attempts" "ERROR" $WebhookId
    }
    
    return $delivery
}

function Test-Webhook {
    param([string]$WebhookId)
    
    Write-WebhookLog "Testing webhook: $WebhookId" "WEBHOOK"
    
    $testPayload = @{
        message = "This is a test event"
        test = $true
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    }
    
    $result = Invoke-WebhookDelivery -WebhookId $WebhookId -Event "webhook.test" -Payload $testPayload
    
    return $result
}

function Get-WebhookDeliveries {
    param(
        [string]$WebhookId,
        [int]$Limit = 10
    )
    
    $state = Get-WebhookState
    
    $deliveries = $state.Deliveries
    if ($WebhookId) {
        $deliveries = $deliveries | Where-Object { $_.WebhookId -eq $WebhookId }
    }
    
    return $deliveries | Sort-Object Timestamp -Descending | Select-Object -First $Limit
}

function Show-WebhookStatus {
    $state = Get-WebhookState
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Webhook System Status                        ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Active Subscriptions: $(($state.Subscriptions.Values | Where-Object { $_.Status -eq 'active' }).Count)" -ForegroundColor Cyan
    Write-Host "║ Total Subscriptions: $($state.Subscriptions.Count)" -ForegroundColor Cyan
    Write-Host "║ Total Deliveries: $($state.Deliveries.Count)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    Write-Host "║ Event Types:" -ForegroundColor Cyan
    foreach ($event in $EventTypes.Keys | Sort-Object) {
        $info = $EventTypes[$event]
        $count = if ($state.EventStats.ContainsKey($event)) { $state.EventStats[$event].Count } else { 0 }
        Write-Host "║   $event ($count) - $($info.Description)" -ForegroundColor Gray
    }
    
    if ($state.Subscriptions.Count -gt 0) {
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║ Active Subscriptions:" -ForegroundColor Cyan
        foreach ($sub in $state.Subscriptions.Values | Where-Object { $_.Status -eq 'active' } | Select-Object -First 5) {
            $successRate = if ($sub.DeliveryCount -gt 0) { 
                [math]::Round(($sub.SuccessCount / $sub.DeliveryCount) * 100, 1) 
            } else { 100 }
            Write-Host "║   $($sub.Id.Substring(0,8))... - $($sub.Url.Substring(0,30))..." -ForegroundColor Gray
            Write-Host "║     Events: $($sub.Events.Count) | Success: $successRate%" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Subscribe" {
        if (-not $Url -or $Events.Count -eq 0) {
            Write-WebhookLog "Url and Events required" "ERROR"
            exit 1
        }
        $sub = New-WebhookSubscription -Url $Url -Events $Events -Secret $Secret -Status $Status -RetryCount $RetryCount
        if ($sub) {
            $sub | ConvertTo-Json
        }
        else {
            exit 1
        }
    }
    "Unsubscribe" {
        if (-not $WebhookId) {
            Write-WebhookLog "WebhookId required" "ERROR"
            exit 1
        }
        $success = Remove-WebhookSubscription -WebhookId $WebhookId
        exit ($success ? 0 : 1)
    }
    "List" {
        $state = Get-WebhookState
        $displaySubs = $state.Subscriptions.Values | ForEach-Object {
            $sub = $_ | Select-Object Id, Url, Events, Status, Created, DeliveryCount, SuccessCount
            $sub.Secret = "***"
            return $sub
        }
        $displaySubs | ConvertTo-Json
    }
    "Trigger" {
        if (-not $WebhookId -or $Events.Count -eq 0) {
            Write-WebhookLog "WebhookId and Event required" "ERROR"
            exit 1
        }
        $result = Invoke-WebhookDelivery -WebhookId $WebhookId -Event $Events[0] -Payload $Payload
        if ($result) {
            $result | ConvertTo-Json -Depth 10
        }
    }
    "Test" {
        if (-not $WebhookId) {
            Write-WebhookLog "WebhookId required" "ERROR"
            exit 1
        }
        $result = Test-Webhook -WebhookId $WebhookId
        $result | ConvertTo-Json -Depth 10
    }
    "ShowStatus" {
        Show-WebhookStatus
    }
}
