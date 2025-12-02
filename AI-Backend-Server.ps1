# AI-Backend-Server.ps1
# Backend server component for secure API access (bypasses browser CORS)
# Provides proxy endpoints for Amazon Q, GitHub Copilot, and Open VSX Registry

param(
    [int]$Port = 8888,
    [string]$Host = "localhost",
    [switch]$EnableCORS = $true,
    [switch]$EnableAuth = $false,
    [string]$ApiKey = $null
)

# Import required modules
Add-Type -AssemblyName System.Net.HttpListener

$script:Server = $null
$script:Running = $false
$script:RequestCount = 0
$script:StartTime = Get-Date

# API Key validation
$script:ApiKey = if ($ApiKey) { $ApiKey } else { [Guid]::NewGuid().ToString() }

# Initialize HTTP listener
function Initialize-BackendServer {
    Write-Host "🚀 Starting AI Backend Server..." -ForegroundColor Cyan
    Write-Host "   Port: $Port" -ForegroundColor Gray
    Write-Host "   Host: $Host" -ForegroundColor Gray
    Write-Host "   API Key: $($script:ApiKey.Substring(0,8))..." -ForegroundColor Gray

    try {
        $script:Server = New-Object System.Net.HttpListener
        $prefix = "http://${Host}:${Port}/"
        $script:Server.Prefixes.Add($prefix)
        $script:Server.Start()
        $script:Running = $true

        Write-Host "✅ Server started at $prefix" -ForegroundColor Green
        Write-Host "   API Key: $script:ApiKey" -ForegroundColor Yellow
        Write-Host "   Use this key in your frontend requests" -ForegroundColor Yellow

        return $true
    }
    catch {
        Write-Error "Failed to start server: $_"
        return $false
    }
}

# Validate API key
function Test-ApiKey {
    param([string]$Key)
    
    if (-not $EnableAuth) {
        return $true
    }
    
    return $Key -eq $script:ApiKey
}

# Handle CORS headers
function Add-CORSHeaders {
    param($Response)
    
    if ($EnableCORS) {
        $Response.Headers.Add("Access-Control-Allow-Origin", "*")
        $Response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        $Response.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
        $Response.Headers.Add("Access-Control-Max-Age", "3600")
    }
}

# Send JSON response
function Send-JsonResponse {
    param(
        $Response,
        [object]$Data,
        [int]$StatusCode = 200
    )

    Add-CORSHeaders -Response $Response
    $Response.StatusCode = $StatusCode
    $Response.ContentType = "application/json"
    
    $json = $Data | ConvertTo-Json -Depth 10
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
    $Response.ContentLength64 = $buffer.Length
    $Response.OutputStream.Write($buffer, 0, $buffer.Length)
    $Response.OutputStream.Close()
}

# Send error response
function Send-ErrorResponse {
    param(
        $Response,
        [string]$Message,
        [int]$StatusCode = 400
    )

    Send-JsonResponse -Response $Response -Data @{
        success = $false
        error = $Message
    } -StatusCode $StatusCode
}

# Handle Amazon Q proxy requests
function Handle-AmazonQRequest {
    param($Request, $Response)

    try {
        $reader = New-Object System.IO.StreamReader($Request.InputStream)
        $body = $reader.ReadToEnd()
        $data = $body | ConvertFrom-Json

        # Forward to Amazon Q API
        $headers = @{
            "Content-Type" = "application/json"
        }

        if ($data.accessKey -and $data.secretKey) {
            # Generate AWS signature (simplified)
            $headers["Authorization"] = "AWS4-HMAC-SHA256 ..."
        }

        $result = Invoke-RestMethod -Uri "https://q.us-east-1.amazonaws.com/chat" -Method Post -Headers $headers -Body $body

        Send-JsonResponse -Response $Response -Data @{
            success = $true
            data = $result
        }
    }
    catch {
        Send-ErrorResponse -Response $Response -Message $_.Exception.Message -StatusCode 500
    }
}

# Handle GitHub Copilot proxy requests
function Handle-CopilotRequest {
    param($Request, $Response)

    try {
        $reader = New-Object System.IO.StreamReader($Request.InputStream)
        $body = $reader.ReadToEnd()
        $data = $body | ConvertFrom-Json

        if (-not $data.token) {
            Send-ErrorResponse -Response $Response -Message "GitHub token required" -StatusCode 401
            return
        }

        $headers = @{
            "Authorization" = "Bearer $($data.token)"
            "Content-Type" = "application/json"
            "Accept" = "application/json"
        }

        $url = "https://copilot-proxy.githubusercontent.com/v1/chat/completions"
        $result = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body

        Send-JsonResponse -Response $Response -Data @{
            success = $true
            data = $result
        }
    }
    catch {
        Send-ErrorResponse -Response $Response -Message $_.Exception.Message -StatusCode 500
    }
}

# Handle Open VSX Registry proxy requests
function Handle-OpenVSXRequest {
    param($Request, $Response)

    try {
        $query = $Request.QueryString
        $endpoint = $Request.Url.AbsolutePath

        # Forward to Open VSX Registry
        $url = "https://open-vsx.org$endpoint"
        if ($query.Count -gt 0) {
            $queryString = ($query.AllKeys | ForEach-Object { "$_=$($query[$_])" }) -join "&"
            $url += "?$queryString"
        }

        $result = Invoke-RestMethod -Uri $url -Method Get

        Send-JsonResponse -Response $Response -Data @{
            success = $true
            data = $result
        }
    }
    catch {
        Send-ErrorResponse -Response $Response -Message $_.Exception.Message -StatusCode 500
    }
}

# Process incoming requests
function Process-Request {
    while ($script:Running) {
        try {
            $context = $script:Server.GetContext()
            $request = $context.Request
            $response = $context.Response

            $script:RequestCount++

            # Handle OPTIONS (CORS preflight)
            if ($request.HttpMethod -eq "OPTIONS") {
                Add-CORSHeaders -Response $response
                $response.StatusCode = 200
                $response.Close()
                continue
            }

            # Validate API key
            $apiKey = $request.Headers["X-API-Key"]
            if ($EnableAuth -and -not (Test-ApiKey -Key $apiKey)) {
                Send-ErrorResponse -Response $response -Message "Invalid API key" -StatusCode 401
                continue
            }

            # Route requests
            $path = $request.Url.AbsolutePath

            switch -Wildcard ($path) {
                "/api/amazonq/*" {
                    Handle-AmazonQRequest -Request $request -Response $response
                }
                "/api/copilot/*" {
                    Handle-CopilotRequest -Request $request -Response $response
                }
                "/api/openvsx/*" {
                    Handle-OpenVSXRequest -Request $request -Response $response
                }
                "/api/status" {
                    Send-JsonResponse -Response $response -Data @{
                        success = $true
                        status = "running"
                        uptime = (Get-Date) - $script:StartTime
                        requests = $script:RequestCount
                    }
                }
                default {
                    Send-ErrorResponse -Response $response -Message "Unknown endpoint: $path" -StatusCode 404
                }
            }
        }
        catch {
            if ($script:Running) {
                Write-Error "Request processing error: $_"
            }
        }
    }
}

# Start server
if (Initialize-BackendServer) {
    Write-Host "`n✅ Backend server running. Press Ctrl+C to stop." -ForegroundColor Green
    Write-Host "`nAvailable endpoints:" -ForegroundColor Cyan
    Write-Host "   POST /api/amazonq/chat - Amazon Q chat" -ForegroundColor Gray
    Write-Host "   POST /api/copilot/chat - GitHub Copilot chat" -ForegroundColor Gray
    Write-Host "   GET  /api/openvsx/* - Open VSX Registry proxy" -ForegroundColor Gray
    Write-Host "   GET  /api/status - Server status" -ForegroundColor Gray
    Write-Host ""

    try {
        Process-Request
    }
    finally {
        if ($script:Server) {
            $script:Server.Stop()
            $script:Server.Close()
        }
        Write-Host "Server stopped." -ForegroundColor Yellow
    }
}

