#!/usr/bin/env pwsh
#==============================================================================
# RawrXD Sovereign Inferencer - Load Balancer
# Phase G.2 Batch 2/5: Dynamic Request Distribution
#==============================================================================
# Distributes inference requests across workers based on real-time metrics
#==============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [int]$Port = 9998,

    [Parameter()]
    [string]$ConfigPath = ".\lb_config.json",

    [Parameter()]
    [string[]]$BackendServers = @("localhost:8081", "localhost:8082", "localhost:8083"),

    [Parameter()]
    [ValidateSet("RoundRobin", "LeastConnections", "WeightedResponseTime", "Adaptive")]
    [string]$Algorithm = "Adaptive",

    [Parameter()]
    [switch]$Daemon
)

#==============================================================================
# Load Balancer Configuration
#==============================================================================

$script:LBConfig = @{
    Version = "1.0.0"
    
    HealthCheck = @{
        Enabled = $true
        IntervalSeconds = 5
        TimeoutMs = 2000
        Path = "/health"
    }
    
    Algorithms = @{
        RoundRobin = @{ Description = "Sequential distribution" }
        LeastConnections = @{ Description = "Fewest active connections" }
        WeightedResponseTime = @{ Description = "Based on response time" }
        Adaptive = @{ Description = "ML-based dynamic weighting" }
    }
    
    Weights = @{
        TPS = 0.4
        Latency = 0.4
        ErrorRate = 0.2
    }
    
    CircuitBreaker = @{
        Enabled = $true
        FailureThreshold = 5
        RecoveryTimeoutSeconds = 30
    }
}

#==============================================================================
# Load Balancer Classes
#==============================================================================

enum BackendStatus {
    Healthy
    Unhealthy
    CircuitOpen
}

class BackendServer {
    [string]$Id
    [string]$Address
    [BackendStatus]$Status
    [int]$ActiveConnections
    [double]$Weight
    [hashtable]$Metrics
    [System.Collections.ArrayList]$ResponseTimes
    [int]$FailureCount
    [datetime]$LastFailure
    [datetime]$LastHealthCheck

    BackendServer([string]$id, [string]$address) {
        $this.Id = $id
        $this.Address = $address
        $this.Status = [BackendStatus]::Healthy
        $this.ActiveConnections = 0
        $this.Weight = 1.0
        $this.Metrics = @{
            TPS = 0
            Latency = 0
            ErrorRate = 0
        }
        $this.ResponseTimes = @()
        $this.FailureCount = 0
    }

    [void] RecordResponseTime([int]$ms) {
        $this.ResponseTimes.Add($ms)
        if ($this.ResponseTimes.Count -gt 100) {
            $this.ResponseTimes.RemoveAt(0)
        }
        
        # Update average latency
        if ($this.ResponseTimes.Count -gt 0) {
            $this.Metrics.Latency = ($this.ResponseTimes | Measure-Object -Average).Average
        }
    }

    [void] RecordFailure() {
        $this.FailureCount++
        $this.LastFailure = Get-Date
        
        if ($this.FailureCount -ge $script:LBConfig.CircuitBreaker.FailureThreshold) {
            $this.Status = [BackendStatus]::CircuitOpen
            Write-Warning "Circuit breaker opened for $($this.Id)"
        }
    }

    [void] RecordSuccess() {
        if ($this.FailureCount -gt 0) {
            $this.FailureCount = [Math]::Max(0, $this.FailureCount - 1)
        }
        
        # Check if circuit should close
        if ($this.Status -eq [BackendStatus]::CircuitOpen) {
            $elapsed = (Get-Date) - $this.LastFailure
            if ($elapsed.TotalSeconds -ge $script:LBConfig.CircuitBreaker.RecoveryTimeoutSeconds) {
                $this.Status = [BackendStatus]::Healthy
                $this.FailureCount = 0
                Write-Host "Circuit breaker closed for $($this.Id)" -ForegroundColor Green
            }
        }
    }

    [bool] IsAvailable() {
        return $this.Status -eq [BackendStatus]::Healthy
    }
}

class LoadBalancer {
    [int]$Port
    [string]$Algorithm
    [System.Collections.ArrayList]$Backends
    [hashtable]$Config
    [int]$CurrentIndex
    [System.Net.HttpListener]$Listener
    [bool]$IsRunning
    [hashtable]$RequestStats

    LoadBalancer([int]$port, [string]$algorithm, [string[]]$servers, [string]$configPath) {
        $this.Port = $port
        $this.Algorithm = $algorithm
        $this.Backends = @()
        $this.CurrentIndex = 0
        $this.IsRunning = $false
        $this.RequestStats = @{
            TotalRequests = 0
            SuccessfulRequests = 0
            FailedRequests = 0
            StartTime = Get-Date
        }
        
        $this.LoadConfig($configPath)
        $this.InitializeBackends($servers)
    }

    [void] LoadConfig([string]$configPath) {
        if (Test-Path $configPath) {
            $this.Config = Get-Content $configPath | ConvertFrom-Json -AsHashtable
            Write-Host "✓ Config loaded from: $configPath" -ForegroundColor Green
        }
        else {
            $this.Config = $script:LBConfig
            $this.Config | ConvertTo-Json -Depth 10 | Out-File $configPath
            Write-Host "✓ Default config created: $configPath" -ForegroundColor Green
        }
    }

    [void] InitializeBackends([string[]]$servers) {
        $id = 0
        foreach ($server in $servers) {
            $backend = [BackendServer]::new("backend_$id", $server)
            $this.Backends.Add($backend)
            Write-Host "  Added backend: $server" -ForegroundColor Gray
            $id++
        }
        
        Write-Host "✓ Initialized $($this.Backends.Count) backends" -ForegroundColor Green
    }

    [void] Start() {
        $this.IsRunning = $true
        
        Write-Host "`n=== Starting Load Balancer ===" -ForegroundColor Cyan
        Write-Host "Algorithm: $($this.Algorithm)" -ForegroundColor White
        Write-Host "Port: $($this.Port)" -ForegroundColor White
        Write-Host "Backends: $($this.Backends.Count)" -ForegroundColor White
        
        # Start HTTP listener
        $this.Listener = [System.Net.HttpListener]::new()
        $this.Listener.Prefixes.Add("http://localhost:$($this.Port)/")
        $this.Listener.Start()
        
        Write-Host "✓ Load balancer listening on port $($this.Port)" -ForegroundColor Green
        
        # Start health check loop in background
        if ($this.Config.HealthCheck.Enabled) {
            Start-Job -ScriptBlock {
                param($balancer)
                while ($balancer.IsRunning) {
                    $balancer.CheckHealth()
                    Start-Sleep -Seconds $balancer.Config.HealthCheck.IntervalSeconds
                }
            } -ArgumentList $this | Out-Null
        }
        
        # Main request loop
        while ($this.IsRunning) {
            try {
                $context = $this.Listener.GetContext()
                $this.HandleRequest($context)
            }
            catch {
                if ($this.IsRunning) {
                    Write-Warning "Request error: $_"
                }
            }
        }
    }

    [void] HandleRequest([System.Net.HttpListenerContext]$context) {
        $request = $context.Request
        $response = $context.Response
        $startTime = Get-Date
        
        $this.RequestStats.TotalRequests++
        
        # Select backend
        $backend = $this.SelectBackend()
        
        if (-not $backend) {
            $response.StatusCode = 503
            $this.SendJsonResponse($response, @{ error = "No healthy backends available" })
            $this.RequestStats.FailedRequests++
            return
        }
        
        $backend.ActiveConnections++
        
        try {
            # Forward request to backend
            $result = $this.ForwardRequest($request, $backend)
            
            # Record metrics
            $duration = (Get-Date) - $startTime
            $backend.RecordResponseTime($duration.TotalMilliseconds)
            $backend.RecordSuccess()
            
            # Send response
            $response.StatusCode = 200
            $this.SendJsonResponse($response, $result)
            $this.RequestStats.SuccessfulRequests++
        }
        catch {
            $backend.RecordFailure()
            $response.StatusCode = 502
            $this.SendJsonResponse($response, @{ error = "Backend error: $_.Exception.Message" })
            $this.RequestStats.FailedRequests++
        }
        finally {
            $backend.ActiveConnections--
        }
    }

    [BackendServer] SelectBackend() {
        $available = $this.Backends | Where-Object { $_.IsAvailable() }
        
        if ($available.Count -eq 0) {
            return $null
        }
        
        switch ($this.Algorithm) {
            "RoundRobin" {
                $selected = $available[$this.CurrentIndex % $available.Count]
                $this.CurrentIndex++
                return $selected
            }
            "LeastConnections" {
                return $available | Sort-Object -Property ActiveConnections | Select-Object -First 1
            }
            "WeightedResponseTime" {
                # Calculate weights based on response time (lower is better)
                $totalWeight = 0
                foreach ($backend in $available) {
                    $latency = [Math]::Max($backend.Metrics.Latency, 1)
                    $backend.Weight = 1.0 / $latency
                    $totalWeight += $backend.Weight
                }
                
                # Weighted random selection
                $random = Get-Random -Minimum 0 -Maximum $totalWeight
                $cumulative = 0
                foreach ($backend in $available) {
                    $cumulative += $backend.Weight
                    if ($random -le $cumulative) {
                        return $backend
                    }
                }
                return $available[0]
            }
            "Adaptive" {
                # Calculate composite score for each backend
                $scores = @()
                foreach ($backend in $available) {
                    $tpsScore = [Math]::Min($backend.Metrics.TPS / 50, 1) * $script:LBConfig.Weights.TPS
                    $latencyScore = (1 - [Math]::Min($backend.Metrics.Latency / 100, 1)) * $script:LBConfig.Weights.Latency
                    $errorScore = (1 - $backend.Metrics.ErrorRate) * $script:LBConfig.Weights.ErrorRate
                    
                    $totalScore = $tpsScore + $latencyScore + $errorScore
                    $scores += @{ Backend = $backend; Score = $totalScore }
                }
                
                # Select backend with highest score
                return ($scores | Sort-Object -Property Score -Descending | Select-Object -First 1).Backend
            }
        }
        
        return $available[0]
    }

    [hashtable] ForwardRequest([System.Net.HttpListenerRequest]$request, [BackendServer]$backend) {
        # Simulate forwarding to backend
        # In production, this would make actual HTTP request to backend
        
        $delay = Get-Random -Minimum 10 -Maximum 100
        Start-Sleep -Milliseconds $delay
        
        # Simulate occasional failures
        if ((Get-Random -Minimum 0 -Maximum 100) -lt 5) {
            throw "Simulated backend failure"
        }
        
        return @{
            backend = $backend.Id
            address = $backend.Address
            processing_time_ms = $delay
            timestamp = Get-Date -Format "o"
        }
    }

    [void] CheckHealth() {
        foreach ($backend in $this.Backends) {
            try {
                # Simulate health check
                $healthy = (Get-Random -Minimum 0 -Maximum 100) -lt 95  # 95% health check success
                
                if ($healthy) {
                    if ($backend.Status -eq [BackendStatus]::Unhealthy) {
                        $backend.Status = [BackendStatus]::Healthy
                        Write-Host "Backend $($backend.Id) is now healthy" -ForegroundColor Green
                    }
                }
                else {
                    if ($backend.Status -eq [BackendStatus]::Healthy) {
                        $backend.Status = [BackendStatus]::Unhealthy
                        Write-Warning "Backend $($backend.Id) is now unhealthy"
                    }
                }
                
                $backend.LastHealthCheck = Get-Date
            }
            catch {
                $backend.Status = [BackendStatus]::Unhealthy
            }
        }
    }

    [void] SendJsonResponse([System.Net.HttpListenerResponse]$response, [hashtable]$data) {
        $json = $data | ConvertTo-Json -Depth 10
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
        $response.ContentType = "application/json"
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
        $response.Close()
    }

    [void] DisplayStatus() {
        Clear-Host
        Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Load Balancer                                     ║
║           Phase G.2 Batch 2/5: Dynamic Request Distribution                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
        
        Write-Host "`nAlgorithm: $($this.Algorithm)" -ForegroundColor Yellow
        Write-Host "Port: $($this.Port)" -ForegroundColor White
        
        Write-Host "`nBackend Status:" -ForegroundColor Yellow
        Write-Host "─" * 70 -ForegroundColor Gray
        Write-Host "ID          | Address          | Status | Connections | Latency | Weight" -ForegroundColor White
        Write-Host "─" * 70 -ForegroundColor Gray
        
        foreach ($backend in $this.Backends) {
            $statusColor = switch ($backend.Status) {
                "Healthy" { "Green" }
                "Unhealthy" { "Red" }
                "CircuitOpen" { "Yellow" }
            }
            
            $id = $backend.Id.PadRight(11)
            $addr = $backend.Address.PadRight(16)
            $status = $backend.Status.ToString().PadRight(6)
            $conns = $backend.ActiveConnections.ToString().PadRight(11)
            $latency = [Math]::Round($backend.Metrics.Latency, 1).ToString().PadRight(7)
            $weight = [Math]::Round($backend.Weight, 2)
            
            Write-Host "$id | $addr | $status | $conns | $latency | $weight" -ForegroundColor $statusColor
        }
        
        Write-Host "─" * 70 -ForegroundColor Gray
        
        $duration = (Get-Date) - $this.RequestStats.StartTime
        Write-Host "`nRequest Statistics:" -ForegroundColor Yellow
        Write-Host "  Total: $($this.RequestStats.TotalRequests)" -ForegroundColor White
        Write-Host "  Successful: $($this.RequestStats.SuccessfulRequests)" -ForegroundColor Green
        Write-Host "  Failed: $($this.RequestStats.FailedRequests)" -ForegroundColor Red
        Write-Host "  Uptime: $([Math]::Round($duration.TotalMinutes, 2)) minutes" -ForegroundColor White
        
        Write-Host "`nPress Ctrl+C to stop..." -ForegroundColor DarkGray
    }

    [void] Stop() {
        $this.IsRunning = $false
        $this.Listener.Stop()
        Write-Host "`n✓ Load balancer stopped" -ForegroundColor Green
    }
}

#==============================================================================
# Main Execution
#==============================================================================

Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Load Balancer                                     ║
║           Phase G.2 Batch 2/5: Dynamic Request Distribution                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$lb = [LoadBalancer]::new($Port, $Algorithm, $BackendServers, $ConfigPath)

if ($Daemon) {
    # Handle Ctrl+C
    [Console]::CancelKeyPress.AddListener({
        param($sender, $e)
        $e.Cancel = $true
        $lb.Stop()
        exit 0
    })
    
    # Status display loop
    Start-Job -ScriptBlock {
        param($balancer)
        while ($balancer.IsRunning) {
            $balancer.DisplayStatus()
            Start-Sleep -Seconds 2
        }
    } -ArgumentList $lb | Out-Null
    
    $lb.Start()
}
else {
    Write-Host "`nPress Enter to start load balancer (Ctrl+C to stop)..." -ForegroundColor Yellow
    Read-Host
    
    try {
        $lb.Start()
    }
    finally {
        $lb.Stop()
    }
}
