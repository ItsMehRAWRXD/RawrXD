# RawrXD REST API Gateway
# Phase M Batch 1/5: OpenAPI-Compliant HTTP Endpoints
# Provides RESTful API for all RawrXD services

param(
    [Parameter()]
    [ValidateSet("Start", "Stop", "Restart", "Status", "GenerateOpenAPI", "ShowRoutes")]
    [string]$Action = "Status",
    
    [Parameter()]
    [int]$Port = 8080,
    
    [Parameter()]
    [string]$BindAddress = "0.0.0.0",
    
    [Parameter()]
    [string]$ConfigPath,
    
    [Parameter()]
    [switch]$EnableSSL,
    
    [Parameter()]
    [string]$SSLCertPath,
    
    [Parameter()]
    [string]$SSLKeyPath,
    
    [Parameter()]
    [int]$MaxRequestsPerSecond = 1000,
    
    [Parameter()]
    [string]$DataPath = "$PSScriptRoot\gateway_data",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\integration"
)

# API Version and Info
$APIInfo = @{
    Title = "RawrXD API"
    Description = "RESTful API for RawrXD Sovereign Inferencer"
    Version = "1.0.0"
    Contact = @{
        Name = "RawrXD Support"
        Email = "support@rawrxd.io"
    }
    License = @{
        Name = "MIT"
        Url = "https://opensource.org/licenses/MIT"
    }
}

# API Routes Definition
$APIRoutes = @{
    # Health & Status
    "GET /health" = @{
        Summary = "Health check"
        Description = "Returns API health status"
        Tags = @("System")
        Response = @{
            "200" = @{ Description = "Healthy"; Schema = "HealthResponse" }
        }
    }
    "GET /status" = @{
        Summary = "System status"
        Description = "Returns detailed system status"
        Tags = @("System")
        Response = @{
            "200" = @{ Description = "Status info"; Schema = "StatusResponse" }
        }
    }
    
    # Model Management
    "GET /v1/models" = @{
        Summary = "List models"
        Description = "List all available models"
        Tags = @("Models")
        Response = @{
            "200" = @{ Description = "List of models"; Schema = "ModelList" }
        }
    }
    "GET /v1/models/{model_id}" = @{
        Summary = "Get model info"
        Description = "Get detailed information about a model"
        Tags = @("Models")
        Parameters = @(
            @{ Name = "model_id"; In = "path"; Required = $true; Type = "string" }
        )
        Response = @{
            "200" = @{ Description = "Model details"; Schema = "Model" }
            "404" = @{ Description = "Model not found" }
        }
    }
    "POST /v1/models/load" = @{
        Summary = "Load model"
        Description = "Load a model into memory"
        Tags = @("Models")
        Body = @{ Schema = "LoadModelRequest"; Required = $true }
        Response = @{
            "200" = @{ Description = "Model loaded"; Schema = "LoadModelResponse" }
            "400" = @{ Description = "Invalid request" }
        }
    }
    "POST /v1/models/unload" = @{
        Summary = "Unload model"
        Description = "Unload a model from memory"
        Tags = @("Models")
        Body = @{ Schema = "UnloadModelRequest"; Required = $true }
        Response = @{
            "200" = @{ Description = "Model unloaded" }
        }
    }
    
    # Inference
    "POST /v1/completions" = @{
        Summary = "Create completion"
        Description = "Generate text completion"
        Tags = @("Inference")
        Body = @{ Schema = "CompletionRequest"; Required = $true }
        Response = @{
            "200" = @{ Description = "Completion result"; Schema = "CompletionResponse" }
        }
    }
    "POST /v1/chat/completions" = @{
        Summary = "Create chat completion"
        Description = "Generate chat completion"
        Tags = @("Inference")
        Body = @{ Schema = "ChatCompletionRequest"; Required = $true }
        Response = @{
            "200" = @{ Description = "Chat completion"; Schema = "ChatCompletionResponse" }
        }
    }
    "POST /v1/embeddings" = @{
        Summary = "Create embeddings"
        Description = "Generate text embeddings"
        Tags = @("Inference")
        Body = @{ Schema = "EmbeddingRequest"; Required = $true }
        Response = @{
            "200" = @{ Description = "Embeddings"; Schema = "EmbeddingResponse" }
        }
    }
    
    # Sessions
    "POST /v1/sessions" = @{
        Summary = "Create session"
        Description = "Create a new inference session"
        Tags = @("Sessions")
        Body = @{ Schema = "CreateSessionRequest" }
        Response = @{
            "201" = @{ Description = "Session created"; Schema = "Session" }
        }
    }
    "GET /v1/sessions/{session_id}" = @{
        Summary = "Get session"
        Description = "Get session information"
        Tags = @("Sessions")
        Parameters = @(
            @{ Name = "session_id"; In = "path"; Required = $true; Type = "string" }
        )
        Response = @{
            "200" = @{ Description = "Session info"; Schema = "Session" }
            "404" = @{ Description = "Session not found" }
        }
    }
    "DELETE /v1/sessions/{session_id}" = @{
        Summary = "Delete session"
        Description = "Delete an inference session"
        Tags = @("Sessions")
        Parameters = @(
            @{ Name = "session_id"; In = "path"; Required = $true; Type = "string" }
        )
        Response = @{
            "204" = @{ Description = "Session deleted" }
            "404" = @{ Description = "Session not found" }
        }
    }
    
    # Analytics
    "GET /v1/analytics/usage" = @{
        Summary = "Get usage stats"
        Description = "Get API usage statistics"
        Tags = @("Analytics")
        Parameters = @(
            @{ Name = "start_date"; In = "query"; Type = "string"; Format = "date" }
            @{ Name = "end_date"; In = "query"; Type = "string"; Format = "date" }
        )
        Response = @{
            "200" = @{ Description = "Usage statistics"; Schema = "UsageStats" }
        }
    }
    "GET /v1/analytics/performance" = @{
        Summary = "Get performance metrics"
        Description = "Get system performance metrics"
        Tags = @("Analytics")
        Response = @{
            "200" = @{ Description = "Performance metrics"; Schema = "PerformanceMetrics" }
        }
    }
}

# Schema Definitions
$Schemas = @{
    HealthResponse = @{
        Type = "object"
        Properties = @{
            status = @{ Type = "string"; Enum = @("healthy", "degraded", "unhealthy") }
            timestamp = @{ Type = "string"; Format = "date-time" }
            version = @{ Type = "string" }
        }
    }
    StatusResponse = @{
        Type = "object"
        Properties = @{
            status = @{ Type = "string" }
            uptime = @{ Type = "number" }
            memory = @{ Type = "object" }
            cpu = @{ Type = "object" }
            active_models = @{ Type = "array" }
            active_sessions = @{ Type = "integer" }
        }
    }
    Model = @{
        Type = "object"
        Properties = @{
            id = @{ Type = "string" }
            name = @{ Type = "string" }
            size = @{ Type = "integer" }
            format = @{ Type = "string" }
            loaded = @{ Type = "boolean" }
            parameters = @{ Type = "object" }
        }
    }
    ModelList = @{
        Type = "object"
        Properties = @{
            models = @{ Type = "array"; Items = @{ Ref = "#/components/schemas/Model" } }
            total = @{ Type = "integer" }
        }
    }
    CompletionRequest = @{
        Type = "object"
        Required = @("model", "prompt")
        Properties = @{
            model = @{ Type = "string"; Description = "Model ID" }
            prompt = @{ Type = "string" }
            max_tokens = @{ Type = "integer"; Default = 256 }
            temperature = @{ Type = "number"; Default = 0.7; Minimum = 0; Maximum = 2 }
            top_p = @{ Type = "number"; Default = 0.9 }
            top_k = @{ Type = "integer"; Default = 40 }
            stream = @{ Type = "boolean"; Default = $false }
        }
    }
    CompletionResponse = @{
        Type = "object"
        Properties = @{
            id = @{ Type = "string" }
            model = @{ Type = "string" }
            choices = @{ Type = "array" }
            usage = @{ Type = "object" }
        }
    }
    ChatCompletionRequest = @{
        Type = "object"
        Required = @("model", "messages")
        Properties = @{
            model = @{ Type = "string" }
            messages = @{ 
                Type = "array"
                Items = @{
                    Type = "object"
                    Properties = @{
                        role = @{ Type = "string"; Enum = @("system", "user", "assistant") }
                        content = @{ Type = "string" }
                    }
                }
            }
            max_tokens = @{ Type = "integer"; Default = 256 }
            temperature = @{ Type = "number"; Default = 0.7 }
            stream = @{ Type = "boolean"; Default = $false }
        }
    }
    EmbeddingRequest = @{
        Type = "object"
        Required = @("model", "input")
        Properties = @{
            model = @{ Type = "string" }
            input = @{ Type = "string" }
        }
    }
    EmbeddingResponse = @{
        Type = "object"
        Properties = @{
            model = @{ Type = "string" }
            embedding = @{ Type = "array"; Items = @{ Type = "number" } }
            usage = @{ Type = "object" }
        }
    }
}

# Ensure directories exist
if (-not (Test-Path $DataPath)) {
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
}
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$StateFile = "$PSScriptRoot\gateway_state.json"
$PIDFile = "$DataPath\gateway.pid"

function Write-GatewayLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [API-GATEWAY] $Message"
    
    $logFile = Join-Path $LogPath "gateway_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "API" { "Cyan" }
        "REQUEST" { "Magenta" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-GatewayState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        Running = $false
        Port = $Port
        BindAddress = $BindAddress
        StartTime = $null
        TotalRequests = 0
        ErrorCount = 0
        Routes = @{}
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Save-GatewayState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function New-OpenAPISpec {
    $spec = @{
        openapi = "3.0.3"
        info = @{
            title = $APIInfo.Title
            description = $APIInfo.Description
            version = $APIInfo.Version
            contact = $APIInfo.Contact
            license = $APIInfo.License
        }
        servers = @(
            @{ url = "http://localhost:$Port"; description = "Local server" }
        )
        paths = @{}
        components = @{
            schemas = $Schemas
        }
    }
    
    # Build paths from routes
    foreach ($route in $APIRoutes.Keys) {
        $parts = $route -split ' ', 2
        $method = $parts[0].ToLower()
        $path = $parts[1]
        
        $routeInfo = $APIRoutes[$route]
        
        if (-not $spec.paths.ContainsKey($path)) {
            $spec.paths[$path] = @{}
        }
        
        $spec.paths[$path][$method] = @{
            summary = $routeInfo.Summary
            description = $routeInfo.Description
            tags = $routeInfo.Tags
            responses = $routeInfo.Response
        }
        
        if ($routeInfo.ContainsKey("Parameters")) {
            $spec.paths[$path][$method].parameters = $routeInfo.Parameters
        }
        
        if ($routeInfo.ContainsKey("Body")) {
            $spec.paths[$path][$method].requestBody = @{
                required = $routeInfo.Body.Required
                content = @{
                    "application/json" = @{
                        schema = @{ `$ref = "#/components/schemas/$($routeInfo.Body.Schema)" }
                    }
                }
            }
        }
    }
    
    return $spec
}

function Start-APIGateway {
    param(
        [int]$Port,
        [string]$BindAddress,
        [switch]$EnableSSL
    )
    
    Write-GatewayLog "Starting API Gateway on $BindAddress`:$Port" "API"
    
    $state = Get-GatewayState
    
    if ($state.Running) {
        Write-GatewayLog "Gateway already running" "WARN"
        return $false
    }
    
    # Create HTTP listener
    $prefix = if ($EnableSSL) { "https" } else { "http" }
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("$prefix`://$BindAddress`:$Port/")
    
    try {
        $listener.Start()
        Write-GatewayLog "HTTP listener started" "SUCCESS"
    }
    catch {
        Write-GatewayLog "Failed to start listener: $_" "ERROR"
        return $false
    }
    
    # Update state
    $state.Running = $true
    $state.Port = $Port
    $state.BindAddress = $BindAddress
    $state.StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Save-GatewayState -State $state
    
    # Save PID
    $PID | Out-File $PIDFile
    
    Write-GatewayLog "API Gateway started successfully" "SUCCESS"
    Write-GatewayLog "Listening on $prefix`://$BindAddress`:$Port/" "API"
    
    # Run listener loop (in production this would be async)
    # For demo purposes, we'll just keep it running briefly
    $endTime = (Get-Date).AddSeconds(5)
    while ((Get-Date) -lt $endTime -and $listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        $state.TotalRequests++
        Save-GatewayState -State $state
        
        Write-GatewayLog "$($request.HttpMethod) $($request.Url.PathAndQuery)" "REQUEST"
        
        # Simple response
        $responseJson = @{
            status = "ok"
            path = $request.Url.PathAndQuery
            timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        } | ConvertTo-Json
        
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseJson)
        $response.ContentLength64 = $buffer.Length
        $response.ContentType = "application/json"
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
        $response.OutputStream.Close()
    }
    
    $listener.Stop()
    Write-GatewayLog "API Gateway stopped" "API"
    
    $state.Running = $false
    Save-GatewayState -State $state
    
    return $true
}

function Stop-APIGateway {
    Write-GatewayLog "Stopping API Gateway" "API"
    
    $state = Get-GatewayState
    
    if (-not $state.Running) {
        Write-GatewayLog "Gateway not running" "WARN"
        return $false
    }
    
    # In production, this would signal the process to stop
    # For demo, we just update state
    $state.Running = $false
    Save-GatewayState -State $state
    
    if (Test-Path $PIDFile) {
        Remove-Item $PIDFile -Force
    }
    
    Write-GatewayLog "API Gateway stopped" "SUCCESS"
    return $true
}

function Show-GatewayStatus {
    $state = Get-GatewayState
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD REST API Gateway Status                      ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Status: $(if($state.Running){'Running'}else{'Stopped'})" -ForegroundColor $(if($state.Running){"Green"}else{"Red"})
    Write-Host "║ Address: $($state.BindAddress):$($state.Port)" -ForegroundColor Cyan
    Write-Host "║ Total Requests: $($state.TotalRequests)" -ForegroundColor Cyan
    Write-Host "║ Error Count: $($state.ErrorCount)" -ForegroundColor Cyan
    if ($state.StartTime) {
        Write-Host "║ Started: $($state.StartTime)" -ForegroundColor Cyan
    }
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    Write-Host "║ Available Routes: $($APIRoutes.Count)" -ForegroundColor Cyan
    Write-Host "║ API Version: $($APIInfo.Version)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    Write-Host "║ Route Categories:" -ForegroundColor Cyan
    $categories = $APIRoutes.Values | ForEach-Object { $_.Tags } | Select-Object -Unique | Sort-Object
    foreach ($cat in $categories) {
        $count = ($APIRoutes.Values | Where-Object { $_.Tags -contains $cat }).Count
        Write-Host "║   $cat`: $count routes" -ForegroundColor Gray
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

function Show-Routes {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD API Routes                                   ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    $categories = $APIRoutes.Values | ForEach-Object { $_.Tags[0] } | Select-Object -Unique | Sort-Object
    
    foreach ($category in $categories) {
        Write-Host "║" -ForegroundColor Cyan
        Write-Host "║ $category`:" -ForegroundColor Yellow
        
        $catRoutes = $APIRoutes.GetEnumerator() | Where-Object { $_.Value.Tags -contains $category } | Sort-Object Key
        
        foreach ($route in $catRoutes) {
            $method = ($route.Key -split ' ')[0]
            $path = ($route.Key -split ' ', 2)[1]
            $color = switch ($method) {
                "GET" { "Green" }
                "POST" { "Cyan" }
                "PUT" { "Yellow" }
                "DELETE" { "Red" }
                default { "White" }
            }
            Write-Host "║   " -NoNewline -ForegroundColor Cyan
            Write-Host "$method " -NoNewline -ForegroundColor $color
            Write-Host $path -ForegroundColor Gray
            Write-Host "║      $($route.Value.Summary)" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Start" {
        $success = Start-APIGateway -Port $Port -BindAddress $BindAddress -EnableSSL:$EnableSSL
        exit ($success ? 0 : 1)
    }
    "Stop" {
        $success = Stop-APIGateway
        exit ($success ? 0 : 1)
    }
    "Restart" {
        Stop-APIGateway | Out-Null
        Start-Sleep -Seconds 1
        $success = Start-APIGateway -Port $Port -BindAddress $BindAddress -EnableSSL:$EnableSSL
        exit ($success ? 0 : 1)
    }
    "Status" {
        Show-GatewayStatus
    }
    "GenerateOpenAPI" {
        $spec = New-OpenAPISpec
        $spec | ConvertTo-Json -Depth 20 | Out-File "$DataPath\openapi.json" -Encoding UTF8
        Write-GatewayLog "OpenAPI spec generated: $DataPath\openapi.json" "SUCCESS"
        $spec | ConvertTo-Json -Depth 10
    }
    "ShowRoutes" {
        Show-Routes
    }
}
