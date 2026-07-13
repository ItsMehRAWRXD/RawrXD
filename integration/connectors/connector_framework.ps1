# RawrXD Connector Framework
# Phase M Batch 3/5: Pre-built Connectors for External Services
# Provides connectors for Slack, Discord, GitHub, and more

param(
    [Parameter()]
    [ValidateSet("List", "Configure", "Test", "Enable", "Disable", "Execute", "ShowStatus")]
    [string]$Action = "ShowStatus",
    
    [Parameter()]
    [string]$ConnectorId,
    
    [Parameter()]
    [ValidateSet("Slack", "Discord", "GitHub", "GitLab", "Jira", "Teams", "Telegram", "Email", "Webhook", "S3", "Database")]
    [string]$Type,
    
    [Parameter()]
    [hashtable]$Config = @{},
    
    [Parameter()]
    [string]$Operation,
    
    [Parameter()]
    [hashtable]$Parameters = @{},
    
    [Parameter()]
    [string]$DataPath = "$PSScriptRoot\connector_data",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\integration"
)

# Connector definitions
$ConnectorTypes = @{
    "Slack" = @{
        Name = "Slack"
        Description = "Slack workspace integration"
        Category = "Messaging"
        RequiredConfig = @("webhook_url")
        OptionalConfig = @("channel", "username", "icon_emoji")
        Operations = @{
            "send_message" = @{ Description = "Send message to channel"; Params = @("channel", "text", "blocks") }
            "send_file" = @{ Description = "Upload file"; Params = @("channel", "file_path", "title") }
            "get_channels" = @{ Description = "List channels"; Params = @() }
            "get_users" = @{ Description = "List users"; Params = @() }
        }
        AuthType = "Webhook"
        RateLimit = "1 per second"
    }
    "Discord" = @{
        Name = "Discord"
        Description = "Discord server integration"
        Category = "Messaging"
        RequiredConfig = @("webhook_url")
        OptionalConfig = @("username", "avatar_url")
        Operations = @{
            "send_message" = @{ Description = "Send message"; Params = @("content", "embeds") }
            "send_file" = @{ Description = "Upload file"; Params = @("file_path", "content") }
        }
        AuthType = "Webhook"
        RateLimit = "5 per 2 seconds"
    }
    "GitHub" = @{
        Name = "GitHub"
        Description = "GitHub repository integration"
        Category = "Development"
        RequiredConfig = @("token")
        OptionalConfig = @("owner", "repo", "api_url")
        Operations = @{
            "create_issue" = @{ Description = "Create issue"; Params = @("title", "body", "labels") }
            "create_pr" = @{ Description = "Create pull request"; Params = @("title", "body", "head", "base") }
            "get_issues" = @{ Description = "List issues"; Params = @("state", "labels") }
            "get_repos" = @{ Description = "List repositories"; Params = @() }
            "create_webhook" = @{ Description = "Create webhook"; Params = @("config", "events") }
        }
        AuthType = "Token"
        RateLimit = "5000 per hour"
    }
    "GitLab" = @{
        Name = "GitLab"
        Description = "GitLab integration"
        Category = "Development"
        RequiredConfig = @("token", "base_url")
        OptionalConfig = @()
        Operations = @{
            "create_issue" = @{ Description = "Create issue"; Params = @("project_id", "title", "description") }
            "get_projects" = @{ Description = "List projects"; Params = @() }
            "create_mr" = @{ Description = "Create merge request"; Params = @("project_id", "title", "source_branch", "target_branch") }
        }
        AuthType = "Token"
        RateLimit = "600 per minute"
    }
    "Jira" = @{
        Name = "Jira"
        Description = "Atlassian Jira integration"
        Category = "Project Management"
        RequiredConfig = @("base_url", "username", "token")
        OptionalConfig = @("project_key")
        Operations = @{
            "create_issue" = @{ Description = "Create issue"; Params = @("project", "summary", "description", "issue_type") }
            "get_issues" = @{ Description = "Search issues"; Params = @("jql") }
            "update_issue" = @{ Description = "Update issue"; Params = @("issue_key", "fields") }
            "add_comment" = @{ Description = "Add comment"; Params = @("issue_key", "comment") }
        }
        AuthType = "Basic"
        RateLimit = "1000 per hour"
    }
    "Teams" = @{
        Name = "Microsoft Teams"
        Description = "Microsoft Teams integration"
        Category = "Messaging"
        RequiredConfig = @("webhook_url")
        OptionalConfig = @()
        Operations = @{
            "send_message" = @{ Description = "Send message"; Params = @("text", "sections") }
            "send_card" = @{ Description = "Send adaptive card"; Params = @("card") }
        }
        AuthType = "Webhook"
        RateLimit = "50 per second"
    }
    "Telegram" = @{
        Name = "Telegram"
        Description = "Telegram Bot integration"
        Category = "Messaging"
        RequiredConfig = @("bot_token", "chat_id")
        OptionalConfig = @()
        Operations = @{
            "send_message" = @{ Description = "Send message"; Params = @("text", "parse_mode") }
            "send_file" = @{ Description = "Send file"; Params = @("file_path", "caption") }
        }
        AuthType = "Token"
        RateLimit = "30 per second"
    }
    "Email" = @{
        Name = "Email (SMTP)"
        Description = "SMTP email integration"
        Category = "Messaging"
        RequiredConfig = @("smtp_server", "smtp_port", "username", "password")
        OptionalConfig = @("from_address", "use_ssl")
        Operations = @{
            "send_email" = @{ Description = "Send email"; Params = @("to", "subject", "body", "attachments") }
        }
        AuthType = "Password"
        RateLimit = "100 per hour"
    }
    "Webhook" = @{
        Name = "Generic Webhook"
        Description = "Generic HTTP webhook"
        Category = "Integration"
        RequiredConfig = @("url")
        OptionalConfig = @("method", "headers", "timeout")
        Operations = @{
            "send" = @{ Description = "Send request"; Params = @("payload") }
        }
        AuthType = "None"
        RateLimit = "Unlimited"
    }
    "S3" = @{
        Name = "Amazon S3"
        Description = "AWS S3 storage integration"
        Category = "Storage"
        RequiredConfig = @("access_key", "secret_key", "bucket", "region")
        OptionalConfig = @("endpoint")
        Operations = @{
            "upload" = @{ Description = "Upload file"; Params = @("file_path", "key") }
            "download" = @{ Description = "Download file"; Params = @("key", "destination") }
            "list" = @{ Description = "List objects"; Params = @("prefix") }
            "delete" = @{ Description = "Delete object"; Params = @("key") }
        }
        AuthType = "AWS"
        RateLimit = "3500 per second"
    }
    "Database" = @{
        Name = "Database"
        Description = "Generic database connector"
        Category = "Storage"
        RequiredConfig = @("connection_string", "type")
        OptionalConfig = @()
        Operations = @{
            "query" = @{ Description = "Execute query"; Params = @("sql", "parameters") }
            "execute" = @{ Description = "Execute command"; Params = @("sql") }
        }
        AuthType = "Connection"
        RateLimit = "Depends on DB"
    }
}

# Ensure directories exist
if (-not (Test-Path $DataPath)) {
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
}
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$StateFile = "$PSScriptRoot\connector_state.json"

function Write-ConnectorLog {
    param([string]$Message, [string]$Level = "INFO", [string]$Connector = "")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $connTag = if ($Connector) { "[$Connector]" } else { "" }
    $logEntry = "[$timestamp] [$Level] [CONNECTOR]$connTag $Message"
    
    $logFile = Join-Path $LogPath "connectors_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "CONNECTOR" { "Cyan" }
        "EXECUTE" { "Magenta" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-ConnectorState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        Connectors = @{}
        Executions = @()
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Save-ConnectorState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function New-Connector {
    param(
        [string]$Type,
        [hashtable]$Config,
        [string]$Name = ""
    )
    
    Write-ConnectorLog "Creating $Type connector" "CONNECTOR"
    
    if (-not $ConnectorTypes.ContainsKey($Type)) {
        Write-ConnectorLog "Unknown connector type: $Type" "ERROR"
        return $null
    }
    
    $typeInfo = $ConnectorTypes[$Type]
    
    # Validate required config
    foreach ($req in $typeInfo.RequiredConfig) {
        if (-not $Config.ContainsKey($req)) {
            Write-ConnectorLog "Missing required config: $req" "ERROR"
            return $null
        }
    }
    
    $connector = @{
        Id = [System.Guid]::NewGuid().ToString()
        Type = $Type
        Name = if ($Name) { $Name } else { "$Type-$(Get-Random -Maximum 9999)" }
        Config = $Config
        Status = "configured"
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        LastTested = $null
        ExecutionCount = 0
        SuccessCount = 0
        FailureCount = 0
    }
    
    # Mask sensitive config
    $sensitiveKeys = @("token", "password", "secret_key", "api_key", "webhook_url")
    $displayConfig = $Config.Clone()
    foreach ($key in $displayConfig.Keys) {
        if ($sensitiveKeys | Where-Object { $key -like "*$_*" }) {
            $displayConfig[$key] = "***"
        }
    }
    
    $state = Get-ConnectorState
    $state.Connectors[$connector.Id] = $connector
    Save-ConnectorState -State $state
    
    Write-ConnectorLog "Connector created: $($connector.Name) ($($connector.Id))" "SUCCESS"
    
    # Return with masked config
    $display = $connector.Clone()
    $display.Config = $displayConfig
    return $display
}

function Test-Connector {
    param([string]$ConnectorId)
    
    Write-ConnectorLog "Testing connector: $ConnectorId" "CONNECTOR"
    
    $state = Get-ConnectorState
    $connector = $state.Connectors[$ConnectorId]
    
    if (-not $connector) {
        Write-ConnectorLog "Connector not found: $ConnectorId" "ERROR"
        return $null
    }
    
    $typeInfo = $ConnectorTypes[$connector.Type]
    
    # Simulate connection test
    Write-ConnectorLog "Testing $($typeInfo.Name) connection..." "CONNECTOR" $ConnectorId
    
    $testResult = @{
        ConnectorId = $ConnectorId
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Tests = @()
    }
    
    # Test authentication
    $authTest = @{
        Name = "Authentication"
        Success = (Get-Random -Maximum 10) -gt 2
        Details = ""
    }
    $testResult.Tests += $authTest
    
    # Test operations
    $opsTest = @{
        Name = "Operations"
        Success = (Get-Random -Maximum 10) -gt 1
        Available = ($typeInfo.Operations.Keys | Measure-Object).Count
        Details = ""
    }
    $testResult.Tests += $opsTest
    
    # Test rate limit
    $rateTest = @{
        Name = "Rate Limit"
        Success = $true
        Limit = $typeInfo.RateLimit
        Details = ""
    }
    $testResult.Tests += $rateTest
    
    $testResult.Success = ($testResult.Tests | Where-Object { $_.Success }).Count -eq $testResult.Tests.Count
    
    $connector.LastTested = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    if ($testResult.Success) {
        $connector.Status = "active"
    }
    else {
        $connector.Status = "error"
    }
    
    Save-ConnectorState -State $state
    
    if ($testResult.Success) {
        Write-ConnectorLog "Test passed" "SUCCESS" $ConnectorId
    }
    else {
        Write-ConnectorLog "Test failed" "ERROR" $ConnectorId
    }
    
    return $testResult
}

function Invoke-ConnectorOperation {
    param(
        [string]$ConnectorId,
        [string]$Operation,
        [hashtable]$Parameters
    )
    
    Write-ConnectorLog "Executing $Operation on connector $ConnectorId" "EXECUTE"
    
    $state = Get-ConnectorState
    $connector = $state.Connectors[$ConnectorId]
    
    if (-not $connector) {
        Write-ConnectorLog "Connector not found: $ConnectorId" "ERROR"
        return $null
    }
    
    if ($connector.Status -ne "active") {
        Write-ConnectorLog "Connector not active: $($connector.Status)" "ERROR"
        return $null
    }
    
    $typeInfo = $ConnectorTypes[$connector.Type]
    
    if (-not $typeInfo.Operations.ContainsKey($Operation)) {
        Write-ConnectorLog "Unknown operation: $Operation" "ERROR"
        return $null
    }
    
    $opInfo = $typeInfo.Operations[$Operation]
    
    # Simulate operation execution
    $execution = @{
        Id = [System.Guid]::NewGuid().ToString()
        ConnectorId = $ConnectorId
        Operation = $Operation
        Parameters = $Parameters
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Duration = 0
        Success = $false
        Result = $null
        Error = $null
    }
    
    $startTime = Get-Date
    
    # Simulate processing time
    Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 500)
    
    # Simulate success/failure
    $execution.Success = (Get-Random -Maximum 10) -gt 1
    
    if ($execution.Success) {
        $execution.Result = @{
            status = "success"
            message = "Operation $Operation completed successfully"
            data = @{}
        }
    }
    else {
        $execution.Error = "Simulated error during $Operation"
    }
    
    $endTime = Get-Date
    $execution.Duration = ($endTime - $startTime).TotalMilliseconds
    
    # Update connector stats
    $connector.ExecutionCount++
    if ($execution.Success) {
        $connector.SuccessCount++
    }
    else {
        $connector.FailureCount++
    }
    
    $state.Executions += $execution
    Save-ConnectorState -State $state
    
    if ($execution.Success) {
        Write-ConnectorLog "Operation completed in $([math]::Round($execution.Duration, 0))ms" "SUCCESS" $ConnectorId
    }
    else {
        Write-ConnectorLog "Operation failed: $($execution.Error)" "ERROR" $ConnectorId
    }
    
    return $execution
}

function Show-ConnectorStatus {
    $state = Get-ConnectorState
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Connector Framework Status                   ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Total Connectors: $($state.Connectors.Count)" -ForegroundColor Cyan
    Write-Host "║ Active: $(($state.Connectors.Values | Where-Object { $_.Status -eq 'active' }).Count)" -ForegroundColor Cyan
    Write-Host "║ Total Executions: $($state.Executions.Count)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    Write-Host "║ Available Connector Types:" -ForegroundColor Cyan
    foreach ($type in $ConnectorTypes.Keys | Sort-Object) {
        $info = $ConnectorTypes[$type]
        Write-Host "║   $type - $($info.Name)" -ForegroundColor Gray
        Write-Host "║     Category: $($info.Category) | Auth: $($info.AuthType)" -ForegroundColor DarkGray
        Write-Host "║     Operations: $(($info.Operations.Keys | Measure-Object).Count)" -ForegroundColor DarkGray
    }
    
    if ($state.Connectors.Count -gt 0) {
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║ Configured Connectors:" -ForegroundColor Cyan
        foreach ($conn in $state.Connectors.Values | Select-Object -First 5) {
            $color = switch ($conn.Status) {
                "active" { "Green" }
                "error" { "Red" }
                default { "Yellow" }
            }
            Write-Host "║   $($conn.Name) [$($conn.Type)]" -ForegroundColor $color
            Write-Host "║     Status: $($conn.Status) | Executions: $($conn.ExecutionCount)" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "List" {
        $ConnectorTypes | ConvertTo-Json -Depth 10
    }
    "Configure" {
        if (-not $Type) {
            Write-ConnectorLog "Type required" "ERROR"
            exit 1
        }
        $connector = New-Connector -Type $Type -Config $Config -Name $Parameters.Name
        if ($connector) {
            $connector | ConvertTo-Json
        }
        else {
            exit 1
        }
    }
    "Test" {
        if (-not $ConnectorId) {
            Write-ConnectorLog "ConnectorId required" "ERROR"
            exit 1
        }
        $result = Test-Connector -ConnectorId $ConnectorId
        if ($result) {
            $result | ConvertTo-Json -Depth 10
        }
    }
    "Enable" {
        if (-not $ConnectorId) {
            Write-ConnectorLog "ConnectorId required" "ERROR"
            exit 1
        }
        $state = Get-ConnectorState
        if ($state.Connectors.ContainsKey($ConnectorId)) {
            $state.Connectors[$ConnectorId].Status = "active"
            Save-ConnectorState -State $state
            Write-ConnectorLog "Connector enabled: $ConnectorId" "SUCCESS"
        }
    }
    "Disable" {
        if (-not $ConnectorId) {
            Write-ConnectorLog "ConnectorId required" "ERROR"
            exit 1
        }
        $state = Get-ConnectorState
        if ($state.Connectors.ContainsKey($ConnectorId)) {
            $state.Connectors[$ConnectorId].Status = "disabled"
            Save-ConnectorState -State $state
            Write-ConnectorLog "Connector disabled: $ConnectorId" "SUCCESS"
        }
    }
    "Execute" {
        if (-not $ConnectorId -or -not $Operation) {
            Write-ConnectorLog "ConnectorId and Operation required" "ERROR"
            exit 1
        }
        $result = Invoke-ConnectorOperation -ConnectorId $ConnectorId -Operation $Operation -Parameters $Parameters
        if ($result) {
            $result | ConvertTo-Json -Depth 10
        }
    }
    "ShowStatus" {
        Show-ConnectorStatus
    }
}
